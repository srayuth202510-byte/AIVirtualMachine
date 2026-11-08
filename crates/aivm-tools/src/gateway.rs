//! Shared authorization, audit, checkpointing, and dispatch.
use crate::{
    build, contracts, filesystem::is_boundary_path, state_store, verification, CapabilitySet,
    DenyTracker, ExecContent, ToolError, ToolGateway, ToolRequest, ToolResult,
};
use aivm_audit::{AuditRecord, AuditWriter};
use aivm_cube::{AgentState, Cube};
use aivm_policy::{Decision, EvalContext, Policy};
use aivm_sandbox::{ResourceLimits, SandboxLevel};
use std::{collections::HashMap, path::PathBuf, time::Instant};

impl ToolGateway {
    pub fn new(
        workspace: PathBuf,
        policy: Policy,
        caps: CapabilitySet,
        audit: AuditWriter,
        agent: &str,
        session_id: &str,
    ) -> Self {
        Self {
            workspace,
            policy,
            caps,
            audit,
            agent: agent.to_string(),
            session_id: session_id.to_string(),
            // ค่าเริ่มต้นคงพฤติกรรม MVP-B เดิม; Runtime จะเขียนทับจาก config
            level: SandboxLevel::Process,
            #[cfg(feature = "microvm")]
            microvm_cfg: None,
            #[cfg(feature = "hardware")]
            hardware_cfg: None,
            container_cfg: aivm_sandbox::container::ContainerConfig::default(),
            limits: ResourceLimits::default(),
            state_path: None,
            build: build::BuildConfig::default(),
            verifier: None,
            blocked: false,
            req_counter: 0,
            deny_tracker: DenyTracker::default(),
            read_cache: HashMap::new(),
            active_task: None,
            last_outcome: None,
            issued_verifications: HashMap::new(),
            secret_broker: None,
        }
    }

    /// ธุรกรรมที่ผลยังไม่แน่นอนต้องหยุดทุก tool จนกว่าจะเปิด runtime ใหม่
    pub fn block_operations(&mut self) {
        self.blocked = true;
    }

    /// Start a fresh agent run with no assumptions about workspace contents.
    pub fn clear_read_cache(&mut self) {
        self.read_cache.clear();
    }

    /// ตั้งระดับ isolation แบบ builder (ใช้ในเทสต์/อนาคตที่ backend พร้อม)
    pub fn with_level(mut self, level: SandboxLevel) -> Self {
        self.level = level;
        self
    }

    /// ล้าง quarantine + ตัวนับ probing (operator เท่านั้น — runtime เรียก
    /// จาก transition ที่ guard มาจากฝั่งคน)
    pub fn clear_quarantine(&mut self) {
        self.deny_tracker.clear();
    }

    /// consume quota/lease ลงดิสก์ก่อน side effect ป้องกัน replay หลัง crash
    pub(super) fn checkpoint(&self, cube: &Cube) -> Result<(), ToolError> {
        self.checkpoint_with_hook(cube, &mut |_| Ok(()))
    }

    pub(super) fn checkpoint_with_hook(
        &self,
        cube: &Cube,
        hook: &mut impl FnMut(&str) -> std::io::Result<()>,
    ) -> Result<(), ToolError> {
        if let Some(path) = &self.state_path {
            // เส้นทาง serialize ค่าลับทางเดียว: ผ่าน LeaseState ลง state
            // file 0600 เท่านั้น (SecretLease ไม่มี serde derive — regression #30)
            let leases_state: Vec<aivm_secrets::LeaseState> = self
                .live_secret_leases()
                .iter()
                .map(aivm_secrets::LeaseState::from_lease)
                .collect();
            let text = serde_json::to_string(&serde_json::json!({
                "cube": cube, "caps": self.caps, "leases": leases_state
            }))
            .map_err(|e| ToolError::Io(e.to_string()))?;
            state_store::write_private_with_hook(path, &text, &mut |stage| {
                hook(&format!("quota-{stage}"))
            })
            .map_err(|e| ToolError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// G1: ประตู quarantine สำหรับทุก tool method (complete mediation —
    /// เรียกตรงโดยไม่ผ่าน dispatch ก็หนีไม่พ้น) อยู่ใน quarantine = DENY
    /// พร้อม audit ของตัวเอง
    pub(super) fn check_quarantine(
        &mut self,
        cube: &mut Cube,
        action: &str,
        resource: &str,
    ) -> Result<(), ToolError> {
        if self.blocked {
            return Err(ToolError::Denied(
                "runtime transaction requires recovery".into(),
            ));
        }
        if self.deny_tracker.quarantined(Instant::now()) {
            self.audit_decision(
                cube,
                action,
                resource,
                "deny",
                "quarantine-probing",
                "error",
            )?;
            return Err(ToolError::Denied(
                "gateway quarantined after deny burst".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn ctx_of(cube: &Cube) -> EvalContext {
        EvalContext {
            state: cube.current_state().to_string(),
            confidence: cube.confidence(),
            tests_passed: cube.tests_passed(),
        }
    }

    pub(super) fn audit_decision(
        &mut self,
        cube: &mut Cube,
        action: &str,
        resource: &str,
        decision: &str,
        rule: &str,
        result: &str,
    ) -> Result<(), ToolError> {
        self.req_counter += 1;
        let mut rec = AuditRecord::new(
            0,
            &self.agent,
            &self.session_id,
            &format!("req_{:06}", self.req_counter),
            &cube.current_state().to_string(),
            action,
            resource,
            decision,
            &self.policy.name,
        );
        rec.rule_matched = rule.to_string();
        rec.result = result.to_string();
        if decision == "deny" {
            cube.record_denial(rule);
            // G1: deny ทุกครั้งเข้าหน้าต่างเฝ้าระวัง ครบ threshold = quarantine
            // (record แยกอีกบรรทัด — I-7: การเริ่ม quarantine ต้องมีรอยของตัวเอง)
            if self.deny_tracker.record_deny(Instant::now()) {
                self.req_counter += 1;
                let mut q = AuditRecord::new(
                    0,
                    &self.agent,
                    &self.session_id,
                    &format!("req_{:06}", self.req_counter),
                    &cube.current_state().to_string(),
                    "quarantine",
                    resource,
                    "deny",
                    &self.policy.name,
                );
                q.rule_matched = "probing-threshold".to_string();
                q.result = "quarantine-started".to_string();
                self.audit
                    .append(q)
                    .map_err(|e| ToolError::Audit(e.to_string()))?;
            }
        }
        self.audit
            .append(rec)
            .map_err(|e| ToolError::Audit(e.to_string()))?;
        Ok(())
    }

    /// บังคับใช้ร่วมกัน: canonicalize -> capability -> policy
    /// คืน canonical path เมื่อ ALLOW
    pub(super) fn enforce(
        &mut self,
        cube: &mut Cube,
        action: &str, // read|write|search
        requested: &str,
    ) -> Result<(PathBuf, usize), ToolError> {
        // I-7: แม้ deny ตั้งแต่ขั้น canonicalize ก็ต้องมี audit record
        // (complete mediation นับ denied attempts ด้วย)
        let canon = match self.canonicalize(requested) {
            Ok(c) => c,
            Err(e) => {
                let label = match &e {
                    ToolError::Denied(m) if m.contains("traversal") => "path-traversal".to_string(),
                    ToolError::Denied(m) if m.contains("symlink") => "symlink-escape".to_string(),
                    ToolError::Denied(m) => m.clone(),
                    ToolError::Io(m) => format!("canonicalize-io:{m}"),
                    ToolError::Audit(m) => format!("audit:{m}"),
                };
                self.audit_decision(cube, action, requested, "deny", &label, "error")?;
                return Err(e);
            }
        };
        let scope = canon.to_string_lossy().to_string();
        let ctx = Self::ctx_of(cube);

        // ไฟล์ขอบเขต: ห้ามเขียนผ่าน gateway เด็ดขาด (deny เชิงโครงสร้าง)
        if action == "write" && is_boundary_path(&canon) {
            self.audit_decision(cube, action, &scope, "deny", "boundary-write", "error")?;
            return Err(ToolError::Denied("boundary path is read-only".into()));
        }

        // ผูก constraints กับใบที่ consume จริง ไม่ใช้ใบอื่นที่หมดอายุ/หมดโควต้า
        // ใช้ context-aware authorize เพื่อบังคับ constraint ทั้ง max_bytes/max_calls/
        // timeout/cumulative budget ให้ครบทุก tool (ไม่ใช่แค่ network)
        let auth_ctx = aivm_capability::AuthorizationContext::default();
        let cap_index =
            match self
                .caps
                .authorize_with_context(action, "filesystem", &scope, &auth_ctx)
            {
                Ok(index) => index,
                Err(_) if action == "search" => {
                    match self
                        .caps
                        .authorize_with_context("read", "filesystem", &scope, &auth_ctx)
                    {
                        Ok(index) => index,
                        Err(_) => {
                            self.audit_decision(
                                cube,
                                action,
                                &scope,
                                "deny",
                                "no-capability",
                                "error",
                            )?;
                            return Err(ToolError::Denied("no capability".into()));
                        }
                    }
                }
                Err(_) => {
                    self.audit_decision(cube, action, &scope, "deny", "no-capability", "error")?;
                    return Err(ToolError::Denied("no capability".into()));
                }
            };

        // เช็ก policy (fail-closed)
        let policy_action = if action == "search" { "read" } else { action };
        let (d, rule) = self.policy.evaluate_fs(policy_action, &scope, &ctx);
        match d {
            Decision::Allow => {
                // ตรวจซ้ำหลัง canonicalize (กัน TOCTOU): สตริง scope
                // คือ canonical path ที่ได้มาใหม่แล้ว
                self.audit_decision(
                    cube,
                    action,
                    &scope,
                    "allow",
                    rule.as_deref().unwrap_or(""),
                    "authorized",
                )?;
                self.checkpoint(cube)?;
                Ok((canon, cap_index))
            }
            Decision::Deny => {
                // ยกเลิกค่าใช้จ่าย capability ที่ชาร์จไปแล้ว เพราะ policy ปฏิเสธ
                // (budget ไม่ควรถูกหักเมื่อ insurance ปฏิเสธ)
                self.caps.caps[cap_index].used_count =
                    self.caps.caps[cap_index].used_count.saturating_sub(1);
                self.audit_decision(
                    cube,
                    action,
                    &scope,
                    "deny",
                    rule.as_deref().unwrap_or("default-deny"),
                    "error",
                )?;
                Err(ToolError::Denied(rule.unwrap_or("default-deny".into())))
            }
        }
    }

    pub fn dispatch(
        &mut self,
        cube: &mut Cube,
        req: &ToolRequest,
    ) -> Result<ToolResult, ToolError> {
        // G1: อยู่ใน quarantine = DENY ทุก tool ตั้งแต่ประตู (fail-closed
        // escalation) — operator ปลดผ่าน transition หรือรอหมด cooldown
        // (ไม่ยืดเวลาเอง) ตรวจซ้ำในแต่ละ method ด้วย (complete mediation)
        self.check_quarantine(cube, req.tool.as_str(), req.path.as_str())?;
        // มีแค่ tool ที่ผ่านตัวกลางตามรายการ อย่างอื่นคือ DENY
        match req.tool.as_str() {
            "filesystem.read" => self.read(cube, &req.path),
            "filesystem.write" => match req.content.as_deref() {
                Some(content) => self.write(cube, &req.path, content),
                None => {
                    self.audit_decision(
                        cube,
                        "write",
                        &req.path,
                        "deny",
                        "missing-content",
                        "error",
                    )?;
                    Err(ToolError::Denied(
                        "filesystem.write requires content".into(),
                    ))
                }
            },
            "code.search" => self.search(cube, &req.path),
            "process.exec" => {
                // A build or test command can change any workspace file.
                self.read_cache.clear();
                // argv มาจาก JSON array ล้วน (เดิม) หรือ object {argv, secret?, outputs?}
                // (G4) — parse ไม่ได้เลย = DENY (กัน shell interpolation:
                // ไม่มีจุดไหนต่อสตริงเป็นคำสั่งเลย)
                let (args, lease, outputs): (Vec<String>, Option<String>, Vec<String>) =
                    match req.content.as_deref() {
                        Some(s) => {
                            if let Ok(a) = serde_json::from_str::<Vec<String>>(s) {
                                (a, None, vec![])
                            } else {
                                match serde_json::from_str::<ExecContent>(s) {
                                    Ok(c) => (c.argv, c.secret, c.outputs),
                                    Err(_) => {
                                        self.audit_decision(
                                            cube, "execute", &req.path, "deny", "bad-argv", "error",
                                        )?;
                                        return Err(ToolError::Denied(
                                            "argv must be a JSON array of strings".into(),
                                        ));
                                    }
                                }
                            }
                        }
                        None => (vec![], None, vec![]),
                    };
                self.exec_inner(cube, &req.path, &args, lease.as_deref(), &outputs)
            }
            "secret.request" => self.secret_request(cube, req.content.as_deref()),
            "network.fetch" => {
                // content: JSON { "method": "GET", "headers": {}, "body": null }
                self.network_fetch(cube, &req.path, req.content.as_deref())
            }
            "network.connect" => {
                // content: JSON { "protocol": "tcp", "port": 443 }
                self.network_connect(cube, &req.path, req.content.as_deref())
            }
            other => {
                self.audit_decision(cube, other, &req.path, "deny", "unknown-tool", "error")?;
                Err(ToolError::Denied(format!("unknown tool: {other}")))
            }
        }
    }

    /// ตัวช่วยเทสต์: ป้ายชื่อ state ปัจจุบัน
    pub fn _state_label(cube: &Cube) -> String {
        let _: AgentState = cube.current_state();
        cube.current_state().to_string()
    }

    /// บันทึกการปฏิเสธที่ระดับ intent (parse ไม่ผ่าน หรืออ้าง tool ที่ไม่รู้จัก)
    /// I-7: ทุก decision ต้องมี audit แม้ยังไม่ถึงขั้น dispatch (complete mediation)
    /// `raw` คือข้อความดิบจากโมเดล — ผู้เรียกควรตัดให้สั้นก่อนส่งเข้ามา
    pub fn audit_intent_deny(
        &mut self,
        cube: &mut Cube,
        reason: &str,
        raw: &str,
    ) -> Result<(), ToolError> {
        self.audit_decision(cube, "intent", raw, "deny", "invalid-intent", reason)
    }

    /// Audit a runtime guard decision that occurs after a valid intent has
    /// been parsed (for example, a repeated successful action).
    pub fn audit_agent_guard_deny(
        &mut self,
        cube: &mut Cube,
        resource: &str,
        reason: &str,
    ) -> Result<(), ToolError> {
        self.audit_decision(cube, "agent", resource, "deny", "agent-guard", reason)
    }

    /// ใช้โดย controller เท่านั้น ไม่เปิดเป็น tool และไม่สร้างสิทธิ์อ่านเนื้อหาไฟล์ให้โมเดล
    pub fn workspace_digest(&self) -> Result<String, ToolError> {
        verification::workspace_digest(&self.workspace).map(|hash| format!("sha256:{hash}"))
    }

    /// เก็บ ledger ที่ผูกกับ task จริงใน audit; payload ไม่ใช่ verification authority
    pub fn audit_repair_state(
        &mut self,
        cube: &mut Cube,
        task: &contracts::TaskContract,
        state: &str,
    ) -> Result<(), ToolError> {
        let known_task = self.active_task.as_ref() == Some(task)
            || self
                .last_outcome
                .as_ref()
                .is_some_and(|(issued, _)| issued == task);
        if !known_task || state.len() > 65536 {
            return Err(ToolError::Denied(
                "repair state requires the active task and bounded data".into(),
            ));
        }
        let value: serde_json::Value =
            serde_json::from_str(state).map_err(|error| ToolError::Denied(error.to_string()))?;
        if value.get("task_id").and_then(|value| value.as_str()) != Some(task.task_id.as_str())
            || value.get("schema").and_then(|value| value.as_u64()) != Some(1)
        {
            return Err(ToolError::Denied(
                "repair ledger task/schema mismatch".into(),
            ));
        }
        self.audit_decision(
            cube,
            "repair-state",
            &task.task_id,
            "allow",
            "host-repair-state",
            state,
        )
    }
}
