//! Process execution, secret environment lifetime, and verification receipts.
use crate::{
    build,
    secrets::{secret_authority, zeroize_env, MAX_LEASE_ID},
    verification, ToolError, ToolGateway, ToolResult,
};
use aivm_audit::AuditRecord;
use aivm_cube::Cube;
use aivm_policy::Decision;
use aivm_sandbox::{ExecSpec, SandboxLevel};
use aivm_secrets::{zeroize_secret, SecretError, SecretInjector};
use std::path::{Path, PathBuf};

// RAII ล้าง environment ทั้งเมื่อรันสำเร็จและ return ก่อน spawn
struct SecretEnvGuard(Vec<(String, String)>);
impl Drop for SecretEnvGuard {
    fn drop(&mut self) {
        zeroize_env(&mut self.0);
    }
}
struct SecretExecSpec(ExecSpec);
impl std::ops::Deref for SecretExecSpec {
    type Target = ExecSpec;
    fn deref(&self) -> &ExecSpec {
        &self.0
    }
}
impl std::ops::DerefMut for SecretExecSpec {
    fn deref_mut(&mut self) -> &mut ExecSpec {
        &mut self.0
    }
}
impl Drop for SecretExecSpec {
    fn drop(&mut self) {
        zeroize_env(&mut self.0.env_extra);
    }
}

impl ToolGateway {
    /// `process.exec`: รัน exe ที่ allowlist ไว้เท่านั้น (MVP-B)
    ///
    /// สายบังคับใช้: ประตู sandbox (exe/policy/arg/env/cwd) -> execute
    /// capability (action=execute resource=process scope=exe canonical) ->
    /// `run_checked` (ตรวจประตูซ้ำข้างใน = defense in depth + บีบ TOCTOU) ->
    /// audit พร้อม exit code ไม่ผ่านขั้นไหนเลยคือ DENY และไม่ spawn
    ///
    /// ไม่มี secret (ใช้กับ secret ผ่าน dispatch `process.exec` รูป object
    /// หรือ `exec_inner` โดยตรง)
    pub fn exec(
        &mut self,
        cube: &mut Cube,
        exe: &str,
        args: &[String],
    ) -> Result<ToolResult, ToolError> {
        self.exec_inner(cube, exe, args, None, &[])
    }

    /// `process.exec` แบบแนบ secret lease (G4 §26): lease มาจาก
    /// `secret.request` (lease_id เท่านั้น — value ไม่มีทางผ่านช่องนี้)
    /// value ถูก inject เข้า child env แล้ว zeroize ทันทีหลังรัน
    /// (`secret.request` คืนแต่ id; ใครไม่มี lease ที่ใช้ได้ = DENY)
    pub(super) fn exec_inner(
        &mut self,
        cube: &mut Cube,
        exe: &str,
        args: &[String],
        lease_id: Option<&str>,
        outputs: &[String],
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "execute", exe)?;
        let verifier = self.verifier.clone().filter(|contract| {
            contract.executable == exe
                && contract.argv == args
                && lease_id.is_none()
                && outputs.is_empty()
        });
        let artifact = if let Some(name) = exe.strip_prefix("build:") {
            match self.build.artifact_path(&self.workspace, name) {
                Ok(path) => Some(path.to_string_lossy().into_owned()),
                Err(error) => {
                    self.audit_decision(
                        cube,
                        "execute",
                        exe,
                        "deny",
                        "build-artifact-denied",
                        "error",
                    )?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let exe = artifact.as_deref().unwrap_or(exe);
        let artifact_executable =
            Path::new(exe).parent() == Some(self.workspace.join(build::DIRECTORY).as_path());
        // secret ระดับ microvm ยัง inject ไม่ได้ (guest ไม่รับ env_extra) —
        // fail-closed ตั้งแต่ต้น ไม่เงียบทิ้ง (G4)
        if lease_id.is_some()
            && matches!(self.level, SandboxLevel::MicroVm | SandboxLevel::Hardware)
        {
            let rule = if self.level == SandboxLevel::MicroVm {
                "secret-unsupported-microvm"
            } else {
                "secret-unsupported-hardware"
            };
            self.audit_decision(cube, "execute", exe, "deny", rule, "error")?;
            return Err(ToolError::Denied(
                "secret injection not supported at this isolation level".into(),
            ));
        }
        if (!outputs.is_empty() || artifact_executable)
            && (lease_id.is_some() || self.level != SandboxLevel::Process)
        {
            self.audit_decision(
                cube,
                "execute",
                exe,
                "deny",
                "build-profile-unsupported",
                "error",
            )?;
            return Err(ToolError::Denied(
                "build outputs require a process sandbox without secrets".into(),
            ));
        }
        let mut spec = SecretExecSpec(ExecSpec {
            exe: PathBuf::from(exe),
            args: args.to_vec(),
            cwd: self.workspace.clone(),
            workspace: self.workspace.clone(),
            env_extra: vec![],
            timeout_ms: 30000,
            build: None,
            limits: self.limits.clone(),
        });
        // ประตูชั้นแรก (fail-closed ไม่ spawn) หมายเหตุ: ประตูนี้ตรวจซ้ำ
        // อีกรอบใน run_checked ข้างล่างโดยตั้งใจ
        let canon = aivm_sandbox::validate(&spec, &self.policy).map_err(|e| {
            self.audit_decision(cube, "execute", exe, "deny", "exec-gate", "error")
                .err()
                .unwrap_or_else(|| ToolError::Denied(e.to_string()))
        })?;
        let scope = canon.to_string_lossy().to_string();
        let auth_ctx = aivm_capability::AuthorizationContext {
            timeout_ms: Some(spec.timeout_ms),
            ..Default::default()
        };
        if self
            .caps
            .authorize_with_context("execute", "process", &scope, &auth_ctx)
            .is_err()
        {
            self.audit_decision(cube, "execute", &scope, "deny", "no-capability", "error")?;
            return Err(ToolError::Denied("no capability".into()));
        }
        // process policy แบบมีเงื่อนไข (deny rule/state gate ที่มี `when`)
        // ต้องเห็น state จริงของ cube — sandbox ชั้นในไม่มี ctx จึงเช็กซ้ำ
        // ตรงนี้ด้วย ctx จริง (fail-closed ทั้งสองชั้น)
        let (proc_decision, proc_reason) =
            self.policy.evaluate_process(&scope, &Self::ctx_of(cube));
        if proc_decision == Decision::Deny {
            let rule = proc_reason.unwrap_or_else(|| "process-policy".into());
            self.audit_decision(cube, "execute", &scope, "deny", &rule, "error")?;
            return Err(ToolError::Denied(rule));
        }
        // secret lease (G4): resolve หลัง validate+caps (deny ก่อนหน้าไม่เผา
        // one-time lease) — value เข้า env_extra ช่องเดียว ไม่มีทางอื่น
        // หมายเหตุ borrow: คุยกับ broker ให้จบใน block เดียว (owned ออกมา)
        // แล้วค่อย audit — ไม่ถือ borrow ข้าม audit call เด็ดขาด
        let mut lease_tag = "-".to_string();
        let mut secret_env = SecretEnvGuard(vec![]);
        if let Some(lid) = lease_id {
            if lid.is_empty() || lid.len() > MAX_LEASE_ID {
                self.audit_decision(cube, "execute", &scope, "deny", "bad-lease-id", "error")?;
                return Err(ToolError::Denied("bad secret lease id".into()));
            }
            enum Resolve {
                Ready {
                    id: String,
                    env: Vec<(String, String)>,
                },
                Deny {
                    rule: &'static str,
                    msg: String,
                },
            }
            let resolved = match self.secret_broker.as_mut() {
                None => Resolve::Deny {
                    rule: "secret-unconfigured",
                    msg: "secret broker not configured".into(),
                },
                Some(broker) => match broker.get_lease(lid) {
                    // tool-binding: lease ผูกกับ consumer ตั้งแต่ขอ (กันสลับใช้ข้าม tool)
                    None => Resolve::Deny {
                        rule: "lease-not-found",
                        msg: "unknown secret lease".into(),
                    },
                    Some(l) if l.request.tool != "process.exec" => Resolve::Deny {
                        rule: "secret-tool-mismatch",
                        msg: "lease bound to another tool".into(),
                    },
                    Some(l) if !secret_authority(&self.caps, cube, &l.request) => Resolve::Deny {
                        rule: "secret-capability-revoked",
                        msg: "secret issuing capability is no longer granted".into(),
                    },
                    Some(l) => {
                        let id = l.id.clone();
                        let env = SecretInjector::inject_env(l);
                        // เผา one use (status/expiry/uses ตรวจตรงนี้) ค่าที่คืน
                        // มาล้างทันที (ค่าจริงอยู่ใน env แล้ว — ช่องเดียวที่ส่งต่อ)
                        match broker.use_lease(lid) {
                            Ok(mut v) => {
                                zeroize_secret(&mut v);
                                Resolve::Ready { id, env }
                            }
                            Err(e) => {
                                let rule = match e {
                                    SecretError::LeaseExhausted => "lease-exhausted",
                                    SecretError::LeaseExpired => "lease-expired",
                                    SecretError::LeaseRevoked => "lease-revoked",
                                    SecretError::NotApproved => "lease-not-approved",
                                    _ => "secret-error",
                                };
                                let mut env = env;
                                zeroize_env(&mut env);
                                Resolve::Deny {
                                    rule,
                                    msg: "secret lease unusable".into(),
                                }
                            }
                        }
                    }
                },
            };
            match resolved {
                Resolve::Ready { id, env } => {
                    lease_tag = id;
                    secret_env.0 = env;
                }
                Resolve::Deny { rule, msg } => {
                    self.audit_decision(cube, "execute", &scope, "deny", rule, "error")?;
                    return Err(ToolError::Denied(msg));
                }
            }
        }
        self.audit_decision(
            cube,
            "execute",
            &scope,
            "allow",
            "exec-authorized",
            "authorized",
        )?;
        self.checkpoint(cube)?;
        if !outputs.is_empty() || artifact_executable {
            spec.build = match self.build.prepare(&self.workspace, outputs, &self.limits) {
                Ok(build) => Some(build),
                Err(error) => {
                    self.audit_decision(
                        cube,
                        "execute",
                        &scope,
                        "deny",
                        "build-output-denied",
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
            };
        }
        let verification = match verifier {
            Some(config) => {
                match verification::PreparedVerification::new(config, &self.workspace, &canon) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => {
                        self.audit_decision(
                            cube,
                            "verification",
                            &scope,
                            "deny",
                            "verifier-inputs",
                            &error.to_string(),
                        )?;
                        return Err(error);
                    }
                }
            }
            None => None,
        };
        spec.env_extra = std::mem::take(&mut secret_env.0);
        let mut run_result = if self.level == SandboxLevel::Container {
            aivm_sandbox::container::run(&spec, &self.policy, &self.container_cfg)
                .map_err(|e| (e, aivm_sandbox::RunVerdict::Clean))
        } else if self.level == SandboxLevel::Hardware {
            // ระดับ Hardware: มี config จริงใช้ config นั้น ไม่มีใช้ default
            // ที่ deny ตั้งแต่ artifact หาย (fail-closed ไม่มีทางรันโดยไม่ตั้งใจ)
            #[cfg(feature = "hardware")]
            {
                match &self.hardware_cfg {
                    Some(cfg) => aivm_sandbox::run_checked_with_level_and_cfg_hardware(
                        &spec,
                        &self.policy,
                        self.level,
                        cfg,
                    ),
                    None => aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level),
                }
            }
            #[cfg(not(feature = "hardware"))]
            aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level)
        } else {
            #[cfg(feature = "microvm")]
            {
                match &self.microvm_cfg {
                    Some(cfg) => aivm_sandbox::run_checked_with_level_and_cfg(
                        &spec,
                        &self.policy,
                        self.level,
                        cfg,
                    ),
                    None => aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level),
                }
            }
            #[cfg(not(feature = "microvm"))]
            aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level)
        };
        // value ใน env ล้างทันทีที่ spawn เสร็จ (child ได้สำเนาของตัวเองไปแล้ว
        // broker เก็บต้นฉบับตาม max_uses — gateway ไม่ถือค้าง)
        for (_, v) in spec.env_extra.iter_mut() {
            if !v.is_empty() {
                if let Ok(outcome) = &mut run_result {
                    outcome.stdout = "[REDACTED]".into();
                    outcome.stderr = "[REDACTED]".into();
                }
            }
            zeroize_secret(v);
        }
        // verdict ลง audit ทุก decision (G3): allow = verdict:clean เสมอ
        // (จบบริบูรณ์ถึง allow ได้) deny = verdict ที่แนบมากับ error
        let outcome = match run_result {
            Ok(o) => o,
            // ระดับที่ยังไม่มี backend ต้อง DENY พร้อม audit (I-7) ไม่ใช่เงียบหาย
            Err((aivm_sandbox::SandboxError::Disabled(msg), v)) => {
                self.audit_decision(
                    cube,
                    "execute",
                    &scope,
                    "deny",
                    "level-disabled",
                    &format!("verdict:{}:{}", v.label(), v.reason()),
                )?;
                return Err(ToolError::Denied(msg));
            }
            // ระดับ non-Process ที่ตายด้วย Invalid (เช่น artifact ไม่ผ่าน
            // supply chain) ก็เป็น decision ด้านความปลอดภัย ต้อง audit เช่นกัน
            // (Process คงพฤติกรรมเดิมทุกประการเพื่อไม่ให้เทสต์เก่าขยับ)
            Err((e, v)) if self.level != SandboxLevel::Process => {
                self.audit_decision(
                    cube,
                    "execute",
                    &scope,
                    "deny",
                    "level-invalid",
                    &format!("verdict:{}:{}", v.label(), v.reason()),
                )?;
                return Err(ToolError::Denied(e.to_string()));
            }
            Err((e, _)) => {
                self.audit_decision(cube, "execute", &scope, "deny", "exec-failed", "error")?;
                return Err(ToolError::Denied(e.to_string()));
            }
        };
        self.audit_decision(
            cube,
            "execute",
            &scope,
            "allow",
            &format!(
                "exit:{} verdict:clean dna:{} secret:{}",
                outcome.code.unwrap_or(-1),
                if outcome.dna.is_empty() {
                    "-"
                } else {
                    &outcome.dna
                },
                lease_tag,
            ),
            "success",
        )?;
        let verification = if let Some(prepared) = verification {
            let record = prepared.finish(&self.workspace, outcome.code, &outcome.stdout);
            Some(self.publish_verification_with_hook(cube, &scope, record, &mut |_| Ok(()))?)
        } else {
            None
        };
        Ok(ToolResult {
            verification,
            ok: outcome.success(),
            decision: "allow".into(),
            output: if lease_id.is_some() {
                "[REDACTED]".into()
            } else {
                format!(
                    "exit status: {}\n{}{}",
                    outcome
                        .code
                        .map(|c| c.to_string())
                        .unwrap_or("signal".into()),
                    outcome.stdout,
                    outcome.stderr
                )
            },
        })
    }

    pub(super) fn publish_verification_with_hook(
        &mut self,
        cube: &Cube,
        scope: &str,
        mut record: verification::VerificationRecord,
        hook: &mut impl FnMut(&str) -> std::io::Result<()>,
    ) -> Result<verification::VerificationRecord, ToolError> {
        self.req_counter += 1;
        let mut audit = AuditRecord::new(
            0,
            &self.agent,
            &self.session_id,
            &format!("verification_{:06}", self.req_counter),
            &cube.current_state().to_string(),
            "verification",
            scope,
            if record.status == verification::VerificationStatus::Verified {
                "allow"
            } else {
                "deny"
            },
            &self.policy.name,
        );
        audit.result =
            serde_json::to_string(&record).map_err(|error| ToolError::Io(error.to_string()))?;
        let audit = self
            .audit
            .append_with_hook(audit, &mut |stage| hook(&format!("receipt-{stage}")))
            .map_err(|error| ToolError::Audit(error.to_string()))?;
        record.audit_id = audit.hash_entry;
        if self.active_task.is_some() {
            self.issued_verifications
                .insert(record.audit_id.clone(), record.clone());
        }
        hook("receipt-delivered").map_err(|error| ToolError::Io(error.to_string()))?;
        Ok(record)
    }
}
