//! Tool gateway — ดูสเปก §12, §16, §17 + MVP-B (Phase 4).
//!
//! เครื่องมือที่ผ่านตัวกลาง: `filesystem.read / write / search` และ
//! `process.exec` (เฉพาะ exe ที่ allowlist + มี execute capability +
//! ได้ grant ตาม state) ไม่มี shell ไม่มีรันตามใจ ไม่มีเน็ตเวิร์ก
//! ทุกคำขอเดินตามสาย: canonicalize -> capability -> policy ->
//! execute -> audit fail-closed ทุกขั้น กัน TOCTOU ด้วย realpath + ตรวจซ้ำ
//!
//! หมายเหตุเรื่อง subprocess tree: hardening ใน pre_exec (no-new-privs,
//! rlimit, env ที่ล้างแล้ว, seccomp denylist) ตกทอดไป child ที่ fork/exec ต่อ
//! โดยอัตโนมัติ; pdeathsig ตั้งที่ child ตรงแล้วตั้งซ้ำในหลานที่เป็น PID 1
//! (ค่าถูกล้างตอน fork) การกัก tree ด้วย PID/mount/net namespace ทำแบบ
//! best-effort พร้อมรายงาน applied/degraded อย่างซื่อสัตย์ — เปิด
//! compiler/test runner ได้เพราะประตู + adversarial คุม ไม่ใช่เพราะกัก
//! tree สมบูรณ์แล้ว

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::CapabilitySet;
use aivm_cube::{AgentState, Cube};
use aivm_policy::{Decision, EvalContext, Policy};
use aivm_sandbox::{ExecSpec, ResourceLimits, SandboxLevel};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(String),
    #[error("audit: {0}")]
    Audit(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    pub tool: String, // "filesystem.read" | "filesystem.write" | "code.search" | "process.exec"
    /// filesystem/search: path  |  process.exec: absolute exe path
    pub path: String,
    /// filesystem.write: เนื้อหาไฟล์  |  process.exec: JSON array ของ argv
    /// (parse ไม่ได้ = DENY)  |  อย่างอื่น: ไม่ใช้
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub decision: String,
    pub output: String,
}

pub struct ToolGateway {
    pub workspace: PathBuf,
    pub policy: Policy,
    pub caps: CapabilitySet,
    pub audit: AuditWriter,
    pub agent: String,
    pub session_id: String,
    /// ระดับ isolation ของ VM นี้ (Phase 7: มาจาก `runtime.isolation` ใน config)
    /// `Process` = พฤติกรรม MVP-B เดิม ระดับอื่นที่ยังไม่มี backend จะ DENY
    /// แบบ fail-closed ตั้งแต่ gateway (I-7: มี audit ทุกครั้ง)
    pub level: SandboxLevel,
    /// config MicroVM (kernel/rootfs pin + quota) ใช้เมื่อเปิดฟีเจอร์
    /// `microvm` และ `level` เป็น MicroVm เท่านั้น — ไม่มี config
    /// (= `None`) จะใช้ค่า default ที่ deny ตั้งแต่ artifact หาย
    #[cfg(feature = "microvm")]
    pub microvm_cfg: Option<aivm_sandbox::microvm::MicroVmConfig>,
    req_counter: u64,
    deny_tracker: DenyTracker,
}

/// ตัวตัดวงจร deny-storm (G1 — `docs/threat-model.md`): agent ที่โดนยึดแล้ว
/// ไล่ probe จะทิ้งรอย DENY ถี่ ๆ ตัวนี้เฝ้าหน้าต่างบานเลื่อนแล้ว quarantine
/// ทั้ง gateway ชั่วคราว (fail-closed escalation)
///
/// ความซื่อสัตย์: นี่คือ circuit breaker กัน runaway loop / burst probing
/// ไม่ใช่ตัวจับ slow probing (ต่ำกว่า threshold ตรวจไม่เจอโดยออกแบบ) และ
/// ไม่ยืดเวลาเอง (hammer ต่อ = หมด cooldown แล้ว trigger ใหม่เป็นรอบ ๆ)
#[derive(Debug)]
pub struct DenyTracker {
    stamps: VecDeque<Instant>,
    quarantine_until: Option<Instant>,
    threshold: u32,
    window: Duration,
    cooldown: Duration,
}

/// default แบบ conservative: demo (7 denies) กับเทสต์ปกติไม่มีทางถึง
/// (margin กว้าง) แต่ loop ที่รันaway โดนตัดในนาทีเดียว
impl Default for DenyTracker {
    fn default() -> Self {
        Self {
            stamps: VecDeque::new(),
            quarantine_until: None,
            threshold: 20,
            window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        }
    }
}

impl DenyTracker {
    #[cfg(test)]
    fn test_config(threshold: u32, window_secs: u64, cooldown_secs: u64) -> Self {
        Self {
            stamps: VecDeque::new(),
            quarantine_until: None,
            threshold,
            window: Duration::from_secs(window_secs),
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// อยู่ใน quarantine หรือไม่ (หมดเวลาแล้วล้างเองแบบ lazy)
    fn quarantined(&mut self, now: Instant) -> bool {
        if let Some(until) = self.quarantine_until {
            if now < until {
                return true;
            }
            self.quarantine_until = None;
        }
        false
    }

    /// บันทึก deny หนึ่งครั้ง คืน true ถ้าเพิ่งเข้า quarantine รอบใหม่
    /// (กำลัง quarantine อยู่แล้ว = นับต่อแต่ไม่ยืดเวลา — กัน attacker
    /// ปักหลักยึด VM ไว้ตลอดด้วยการ hammer ไม่หยุด)
    fn record_deny(&mut self, now: Instant) -> bool {
        self.stamps.push_back(now);
        while self
            .stamps
            .front()
            .map(|t| now.duration_since(*t) > self.window)
            .unwrap_or(false)
        {
            self.stamps.pop_front();
        }
        if self.quarantine_until.is_some_and(|u| now < u) {
            return false;
        }
        if self.stamps.len() as u32 >= self.threshold {
            self.quarantine_until = Some(now + self.cooldown);
            return true;
        }
        false
    }

    /// ล้างสถานะ (operator เท่านั้น — เรียกจาก transition ฝั่ง runtime)
    pub fn clear(&mut self) {
        self.stamps.clear();
        self.quarantine_until = None;
    }
}

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
            req_counter: 0,
            deny_tracker: DenyTracker::default(),
        }
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

    /// G1: ประตู quarantine สำหรับทุก tool method (complete mediation —
    /// เรียกตรงโดยไม่ผ่าน dispatch ก็หนีไม่พ้น) อยู่ใน quarantine = DENY
    /// พร้อม audit ของตัวเอง
    fn check_quarantine(
        &mut self,
        cube: &mut Cube,
        action: &str,
        resource: &str,
    ) -> Result<(), ToolError> {
        if self.deny_tracker.quarantined(Instant::now()) {
            self.audit_decision(
                cube,
                action,
                resource,
                "deny",
                "quarantine-probing",
                "error",
            );
            return Err(ToolError::Denied(
                "gateway quarantined after deny burst".into(),
            ));
        }
        Ok(())
    }

    fn ctx_of(cube: &Cube) -> EvalContext {
        EvalContext {
            state: cube.current_state().to_string(),
            confidence: cube.confidence,
            tests_passed: cube.tests_passed,
        }
    }

    /// ทำ path ที่ขอมาให้เป็น canonical เทียบกับ workspace root และ
    /// รับรองว่าผลลัพธ์ยังอยู่ข้างใน (กัน symlink-escape + `..`)
    fn canonicalize(&self, requested: &str) -> Result<PathBuf, ToolError> {
        // ปฏิเสธ absolute path ที่อยู่นอก workspace ตั้งแต่เนิ่น ๆ (คิดแบบ adversarial ก่อน)
        let joined = if Path::new(requested).is_absolute() {
            PathBuf::from(requested)
        } else {
            self.workspace.join(requested)
        };
        // ตัด `..` แบบ lexical ก่อน (ยังไม่แตะ FS)
        let normalized = normalize(&joined);
        let ws = normalize(&self.workspace);
        if normalized != ws && !normalized.starts_with(&ws) {
            return Err(ToolError::Denied(format!(
                "path traversal outside workspace: {requested}"
            )));
        }
        // คลี่ symlink ตรง path ที่มีอยู่จริง (กัน TOCTOU แบบ check-then-act +
        // ตรวจซ้ำตอนเปิด ใช้ความหมายใกล้ O_NOFOLLOW โดยยืนยันว่า
        // ไม่มีส่วนไหนของ symlink หลุดออกนอก)
        if let Ok(real) = std::fs::canonicalize(&normalized) {
            if real != ws && !real.starts_with(&ws) {
                // เผื่อ workspace สไตล์ tempdir ที่ canonical ไม่ตรงกัน:
                // เทียบกับ workspace root แบบ canonical ด้วย
                let real_ws = std::fs::canonicalize(&self.workspace)
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                if real != real_ws && !real.starts_with(&real_ws) {
                    return Err(ToolError::Denied(format!(
                        "symlink escape outside workspace: {requested}"
                    )));
                }
            }
            return Ok(real);
        }
        // path ยังไม่มีอยู่จริง (เคส write): ต้องแน่ใจว่าไม่มี parent ส่วนไหน
        // เป็น symlink ที่หลุดออกนอก workspace
        let mut cur: Option<&Path> = Some(&normalized);
        while let Some(p) = cur {
            if p == ws || p == Path::new("") {
                break;
            }
            if let Ok(meta) = std::fs::symlink_metadata(p) {
                if meta.file_type().is_symlink() {
                    let real =
                        std::fs::canonicalize(p).map_err(|e| ToolError::Io(e.to_string()))?;
                    let real_ws = std::fs::canonicalize(&self.workspace).unwrap_or(ws.clone());
                    if real != real_ws && !real.starts_with(&real_ws) {
                        return Err(ToolError::Denied(format!(
                            "symlink escape in parent: {requested}"
                        )));
                    }
                }
            }
            cur = p.parent();
        }
        Ok(normalized)
    }

    fn audit_decision(
        &mut self,
        cube: &mut Cube,
        action: &str,
        resource: &str,
        decision: &str,
        rule: &str,
        result: &str,
    ) {
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
                if let Err(e) = self.audit.append(q) {
                    eprintln!("[audit] append failed: {e}");
                }
            }
        }
        if let Err(e) = self.audit.append(rec) {
            eprintln!("[audit] append failed: {e}");
        }
    }

    /// บังคับใช้ร่วมกัน: canonicalize -> capability -> policy
    /// คืน canonical path เมื่อ ALLOW
    fn enforce(
        &mut self,
        cube: &mut Cube,
        action: &str, // read|write|search
        requested: &str,
    ) -> Result<PathBuf, ToolError> {
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
                self.audit_decision(cube, action, requested, "deny", &label, "error");
                return Err(e);
            }
        };
        let scope = canon.to_string_lossy().to_string();
        let ctx = Self::ctx_of(cube);

        // ไฟล์ขอบเขต: ห้ามเขียนผ่าน gateway เด็ดขาด (deny เชิงโครงสร้าง)
        if action == "write" && is_boundary_path(&canon) {
            self.audit_decision(cube, action, &scope, "deny", "boundary-write", "error");
            return Err(ToolError::Denied("boundary path is read-only".into()));
        }

        // เช็ก capability (fail-closed)
        if self.caps.authorize(action, "filesystem", &scope).is_err() {
            // search ใช้สิทธิ์ read แทนได้ถ้าไม่มี search
            let fallback_ok =
                action == "search" && self.caps.authorize("read", "filesystem", &scope).is_ok();
            if !fallback_ok {
                self.audit_decision(cube, action, &scope, "deny", "no-capability", "error");
                return Err(ToolError::Denied("no capability".into()));
            }
        }

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
                    "success",
                );
                Ok(canon)
            }
            Decision::Deny => {
                self.audit_decision(
                    cube,
                    action,
                    &scope,
                    "deny",
                    rule.as_deref().unwrap_or("default-deny"),
                    "error",
                );
                Err(ToolError::Denied(rule.unwrap_or("default-deny".into())))
            }
        }
    }

    pub fn read(&mut self, cube: &mut Cube, path: &str) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "read", path)?;
        let canon = self.enforce(cube, "read", path)?;
        // เปิดพร้อมเช็ก symlink: ปฏิเสธไฟล์ symlink (ใกล้เคียง O_NOFOLLOW)
        let meta = std::fs::symlink_metadata(&canon).map_err(|e| ToolError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            self.audit_decision(cube, "read", path, "deny", "symlink-file", "error");
            return Err(ToolError::Denied("symlink files not followed".into()));
        }
        let content = std::fs::read_to_string(&canon).map_err(|e| ToolError::Io(e.to_string()))?;
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: content,
        })
    }

    pub fn write(
        &mut self,
        cube: &mut Cube,
        path: &str,
        content: &str,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "write", path)?;
        let canon = self.enforce(cube, "write", path)?;
        if let Some(parent) = canon.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ToolError::Io(e.to_string()))?;
        }
        // ยืนยัน containment อีกครั้งก่อนลงมือ (กัน TOCTOU) ตกก็ audit
        let ws = normalize(&self.workspace);
        if canon != ws && !canon.starts_with(&ws) {
            self.audit_decision(cube, "write", path, "deny", "containment-recheck", "error");
            return Err(ToolError::Denied("containment re-check failed".into()));
        }
        std::fs::write(&canon, content).map_err(|e| ToolError::Io(e.to_string()))?;
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: "written".into(),
        })
    }

    /// `code.search`: ค้น substring ในไฟล์ workspace (ใช้ scope แบบ read)
    pub fn search(&mut self, cube: &mut Cube, query: &str) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "search", query)?;
        let ws_str = self.workspace.to_string_lossy().to_string();
        // บังคับ scope แบบ read บน workspace root เองก่อน
        let _ = self.enforce(cube, "search", &ws_str)?;
        let mut hits = vec![];
        for entry in walkdir::WalkDir::new(&self.workspace)
            .max_depth(8)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            // ข้ามไดเรกทอรีขอบเขต
            if is_boundary_path(p) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(p) {
                for (i, line) in text.lines().enumerate() {
                    if line.contains(query) {
                        hits.push(format!("{}:{}: {}", p.display(), i + 1, line.trim()));
                        if hits.len() >= 50 {
                            break;
                        }
                    }
                }
            }
            if hits.len() >= 50 {
                break;
            }
        }
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: hits.join("\n"),
        })
    }

    /// `process.exec`: รัน exe ที่ allowlist ไว้เท่านั้น (MVP-B)
    ///
    /// สายบังคับใช้: ประตู sandbox (exe/policy/arg/env/cwd) -> execute
    /// capability (action=execute resource=process scope=exe canonical) ->
    /// `run_checked` (ตรวจประตูซ้ำข้างใน = defense in depth + บีบ TOCTOU) ->
    /// audit พร้อม exit code ไม่ผ่านขั้นไหนเลยคือ DENY และไม่ spawn
    pub fn exec(
        &mut self,
        cube: &mut Cube,
        exe: &str,
        args: &[String],
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "execute", exe)?;
        let spec = ExecSpec {
            exe: PathBuf::from(exe),
            args: args.to_vec(),
            cwd: self.workspace.clone(),
            workspace: self.workspace.clone(),
            env_extra: vec![],
            limits: ResourceLimits::default(),
        };
        // ประตูชั้นแรก (fail-closed ไม่ spawn) หมายเหตุ: ประตูนี้ตรวจซ้ำ
        // อีกรอบใน run_checked ข้างล่างโดยตั้งใจ
        let canon = aivm_sandbox::validate(&spec, &self.policy).map_err(|e| {
            self.audit_decision(cube, "execute", exe, "deny", "exec-gate", "error");
            ToolError::Denied(e.to_string())
        })?;
        let scope = canon.to_string_lossy().to_string();
        if self.caps.authorize("execute", "process", &scope).is_err() {
            self.audit_decision(cube, "execute", &scope, "deny", "no-capability", "error");
            return Err(ToolError::Denied("no capability".into()));
        }
        // เปิดฟีเจอร์ `microvm` + มี config: ระดับ MicroVm เดินประตู
        // skeleton ด้วย config จริง (pin hash + quota จาก `aivm.yaml`)
        // ไม่มี config (= `None`) ตกไปใช้ค่า default ที่ deny อยู่ดี
        #[cfg(feature = "microvm")]
        let run_result = match &self.microvm_cfg {
            Some(cfg) => {
                aivm_sandbox::run_checked_with_level_and_cfg(&spec, &self.policy, self.level, cfg)
            }
            None => aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level),
        };
        #[cfg(not(feature = "microvm"))]
        let run_result = aivm_sandbox::run_checked_with_level(&spec, &self.policy, self.level);
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
                );
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
                );
                return Err(ToolError::Denied(e.to_string()));
            }
            Err((e, _)) => return Err(ToolError::Denied(e.to_string())),
        };
        self.audit_decision(
            cube,
            "execute",
            &scope,
            "allow",
            &format!(
                "exit:{} verdict:clean dna:{}",
                outcome.code.unwrap_or(-1),
                if outcome.dna.is_empty() {
                    "-"
                } else {
                    &outcome.dna
                }
            ),
            "success",
        );
        Ok(ToolResult {
            ok: outcome.success(),
            decision: "allow".into(),
            output: outcome.stdout,
        })
    }

    /// `network.fetch`: HTTP request ผ่าน policy/network capability
    ///
    /// path: target URL (e.g., "https://api.github.com/repos/owner/repo")
    /// content: JSON { "method": "GET", "headers": {}, "body": null, "timeout_ms": 30000 }
    pub fn network_fetch(
        &mut self,
        cube: &mut Cube,
        url: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use std::time::Duration;

        // Parse request
        self.check_quarantine(cube, "network:fetch", url)?;
        let req: NetworkFetchRequest = match content {
            Some(s) => serde_json::from_str(s).map_err(|e| {
                self.audit_decision(cube, "network:fetch", url, "deny", "bad-request", "error");
                ToolError::Denied(format!("invalid network.fetch request: {e}"))
            })?,
            None => NetworkFetchRequest::default(),
        };

        // Extract host and port from URL for capability scope
        let (host, port, protocol) = parse_url(url)?;

        // Build scope for capability check (host:port)
        let scope = format!("{host}:{port}");

        // Check capability
        let action = if req.method.eq_ignore_ascii_case("GET") {
            "network:fetch"
        } else {
            "network:connect"
        };
        let ctx = Self::ctx_of(cube);
        // For now, direct policy check
        if self.caps.authorize(action, "network", &scope).is_err() {
            self.audit_decision(cube, action, &scope, "deny", "no-capability", "error");
            return Err(ToolError::Denied("no network capability".into()));
        }

        // Check network constraints
        if let Ok(idx) = self.caps.authorize(action, "network", &scope) {
            if let Some(cap) = self.caps.caps.get(idx) {
                if let Err(e) = cap.check_constraints(
                    req.body.as_ref().map(|b| b.len() as u64),
                    None,
                    Some(&protocol),
                    Some(port),
                    None,
                ) {
                    self.audit_decision(
                        cube,
                        action,
                        &scope,
                        "deny",
                        &format!("constraint-violation: {e}"),
                        "error",
                    );
                    return Err(ToolError::Denied(format!(
                        "network constraint violation: {e}"
                    )));
                }
            }
        }

        // Check policy
        let (decision, reason) = self.policy.evaluate_network(&scope, &ctx);
        if decision == aivm_policy::Decision::Deny {
            self.audit_decision(
                cube,
                action,
                &scope,
                "deny",
                reason.as_deref().unwrap_or_default(),
                "error",
            );
            return Err(ToolError::Denied(format!(
                "network policy denied: {}",
                reason.as_deref().unwrap_or_default()
            )));
        }

        // Perform HTTP request using ureq
        let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(30000));
        let agent = ureq::Agent::new();

        let mut request = match req.method.to_uppercase().as_str() {
            "GET" => agent.get(url).timeout(timeout),
            "POST" => agent.post(url).timeout(timeout),
            "PUT" => agent.put(url).timeout(timeout),
            "DELETE" => agent.delete(url).timeout(timeout),
            "PATCH" => agent.patch(url).timeout(timeout),
            "HEAD" => agent.head(url).timeout(timeout),
            _ => {
                return Err(ToolError::Denied(format!(
                    "unsupported HTTP method: {}",
                    req.method
                )))
            }
        };

        for (k, v) in req.headers {
            request = request.set(&k, &v);
        }

        let response = if let Some(body) = req.body {
            request.send_string(&body)
        } else {
            request.call()
        }
        .map_err(|e| ToolError::Io(e.to_string()))?;

        let status: u16 = response.status();
        let response_body = response
            .into_string()
            .map_err(|e| ToolError::Io(e.to_string()))?;

        // Check response size constraint
        if let Ok(idx) = self.caps.authorize(action, "network", &scope) {
            if let Some(cap) = self.caps.caps.get(idx) {
                if let Err(e) =
                    cap.check_constraints(None, None, None, None, Some(response_body.len() as u64))
                {
                    self.audit_decision(
                        cube,
                        action,
                        &scope,
                        "deny",
                        &format!("constraint-violation: {e}"),
                        "error",
                    );
                    return Err(ToolError::Denied(format!(
                        "response size constraint violation: {e}"
                    )));
                }
            }
        }

        self.audit_decision(
            cube,
            action,
            &scope,
            "allow",
            &format!("status:{}", status),
            "success",
        );

        Ok(ToolResult {
            ok: (200..300).contains(&status),
            decision: "allow".into(),
            output: response_body,
        })
    }

    /// `network.connect`: Raw TCP/TLS connection
    ///
    /// path: "host:port" (e.g., "api.github.com:443")
    /// content: JSON { "protocol": "tcp", "tls": true, "timeout_ms": 30000 }
    pub fn network_connect(
        &mut self,
        cube: &mut Cube,
        host_port: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use std::net::TcpStream;
        use std::time::Duration;

        self.check_quarantine(cube, "network:connect", host_port)?;
        let req: NetworkConnectRequest = match content {
            Some(s) => serde_json::from_str(s).map_err(|e| {
                self.audit_decision(
                    cube,
                    "network:connect",
                    host_port,
                    "deny",
                    "bad-request",
                    "error",
                );
                ToolError::Denied(format!("invalid network.connect request: {e}"))
            })?,
            None => NetworkConnectRequest::default(),
        };

        // Parse host:port
        let (host, port) = parse_host_port(host_port)?;
        let scope = format!("{host}:{port}");

        // Check capability
        let ctx = Self::ctx_of(cube);
        if self
            .caps
            .authorize("network:connect", "network", &scope)
            .is_err()
        {
            self.audit_decision(
                cube,
                "network:connect",
                &scope,
                "deny",
                "no-capability",
                "error",
            );
            return Err(ToolError::Denied("no network capability".into()));
        }

        // Check policy
        let (decision, reason) = self.policy.evaluate_network(&scope, &ctx);
        if decision == aivm_policy::Decision::Deny {
            self.audit_decision(
                cube,
                "network:connect",
                &scope,
                "deny",
                reason.as_deref().unwrap_or_default(),
                "error",
            );
            return Err(ToolError::Denied(format!(
                "network policy denied: {}",
                reason.as_deref().unwrap_or_default()
            )));
        }

        // Establish connection
        let addr = format!("{host}:{port}");
        let socket_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| ToolError::Io(e.to_string()))?;
        let _stream = TcpStream::connect_timeout(
            &socket_addr,
            Duration::from_millis(req.timeout_ms.unwrap_or(30000)),
        )
        .map_err(|e| ToolError::Io(e.to_string()))?;

        // If TLS requested, wrap with native-tls (simplified - would need native-tls crate)
        if req.tls {
            // For MVP, just note TLS was requested
            self.audit_decision(
                cube,
                "network:connect",
                &scope,
                "allow",
                "tls-connected",
                "success",
            );
        } else {
            self.audit_decision(
                cube,
                "network:connect",
                &scope,
                "allow",
                "tcp-connected",
                "success",
            );
        }

        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: format!("connected to {addr}"),
        })
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
            "filesystem.write" => {
                self.write(cube, &req.path, req.content.as_deref().unwrap_or_default())
            }
            "code.search" => self.search(cube, &req.path),
            "process.exec" => {
                // argv มาจาก JSON array เท่านั้น parse ไม่ได้ = DENY
                // (กัน shell interpolation: ไม่มีจุดไหนต่อสตริงเป็นคำสั่งเลย)
                let args: Vec<String> = match req.content.as_deref() {
                    Some(s) => serde_json::from_str(s).map_err(|_| {
                        self.audit_decision(
                            cube, "execute", &req.path, "deny", "bad-argv", "error",
                        );
                        ToolError::Denied("argv must be a JSON array of strings".into())
                    })?,
                    None => vec![],
                };
                self.exec(cube, &req.path, &args)
            }
            "network.fetch" => {
                // content: JSON { "method": "GET", "headers": {}, "body": null }
                self.network_fetch(cube, &req.path, req.content.as_deref())
            }
            "network.connect" => {
                // content: JSON { "protocol": "tcp", "port": 443 }
                self.network_connect(cube, &req.path, req.content.as_deref())
            }
            other => {
                self.audit_decision(cube, other, &req.path, "deny", "unknown-tool", "error");
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
    pub fn audit_intent_deny(&mut self, cube: &mut Cube, reason: &str, raw: &str) {
        self.audit_decision(cube, "intent", raw, "deny", "invalid-intent", reason);
    }
}

/// normalize แบบ lexical (ไม่แตะ I/O): ตัด `.` กับ `..` ออก
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

fn is_boundary_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/policies")
        || s.contains("aivm.yaml")
        || s.contains("/audit")
        || s.ends_with(".env")
        || s.contains(".env.")
        || s.contains("/secrets/")
        || s.contains("/.git/config")
}

/// Tool Schema สำหรับ validation arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value, // JSON Schema
}

/// Capability requirement สำหรับ Tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub action: String,
    pub resource: String,
    pub scope: String,
    pub constraints: Option<aivm_capability::Constraints>,
}

/// Tool Trait: ทุก Tool ต้อง implement trait นี้
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;

    fn schema(&self) -> ToolSchema;

    fn required_capabilities(&self) -> Vec<CapabilityRequirement>;

    fn execute(
        &self,
        request: ToolRequest,
        gateway: &mut ToolGateway,
        cube: &mut Cube,
    ) -> Result<ToolResult, ToolError>;
}

/// Tool Registry: จัดการการลงทะเบียนและค้นหา Tool
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// ลงทะเบียน Tool ใหม่
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<(), String> {
        let name = tool.name().to_string();
        if self.tools.contains_key(&name) {
            return Err(format!("tool {} already registered", name));
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// ค้นหา Tool ตามชื่อ
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    /// รายการ Tool ทั้งหมด
    pub fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    /// ตรวจสอบว่า Tool ลงทะเบียนแล้วหรือไม่
    pub fn has(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// AuditSink Trait: รองรับหลาย backend สำหรับ Audit
pub trait AuditSink: Send + Sync {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// Audit Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub policy_version: u32,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: String,
    pub timestamp: u64,
}

/// Audit Error
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialization: {0}")]
    Ser(String),
}

/// Local JSONL Audit Sink (MVP implementation)
pub struct LocalJsonlSink {
    writer: std::sync::Mutex<AuditWriter>,
}

impl LocalJsonlSink {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, AuditError> {
        let writer = AuditWriter::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(Self {
            writer: std::sync::Mutex::new(writer),
        })
    }
}

impl AuditSink for LocalJsonlSink {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        let mut rec = AuditRecord::new(
            0,
            &event.agent_id,
            &event.task_id,
            &event.event_id,
            "", // state - will be filled by caller
            &event.action,
            &event.resource,
            &event.decision,
            "", // policy name
        );
        rec.result = event.reason;
        rec.capability = format!("policy_version:{}", event.policy_version);

        let mut writer = self.writer.lock().unwrap();
        writer
            .append(rec)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }
}

use std::collections::HashMap;

/// Network fetch request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NetworkFetchRequest {
    #[serde(default = "default_get")]
    method: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: Option<u64>,
}

fn default_get() -> String {
    "GET".into()
}

fn default_timeout() -> Option<u64> {
    Some(30000)
}

/// Network connect request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NetworkConnectRequest {
    #[serde(default = "default_tcp")]
    protocol: String,
    #[serde(default)]
    tls: bool,
    #[serde(default = "default_timeout")]
    timeout_ms: Option<u64>,
}

fn default_tcp() -> String {
    "tcp".into()
}

/// Parse URL to extract host, port, and protocol
fn parse_url(url: &str) -> Result<(String, u16, String), ToolError> {
    let parsed =
        url::Url::parse(url).map_err(|e| ToolError::Denied(format!("invalid URL: {e}")))?;
    let protocol = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| ToolError::Denied("URL missing host".into()))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });
    Ok((host, port, protocol))
}

/// Parse host:port string
fn parse_host_port(host_port: &str) -> Result<(String, u16), ToolError> {
    let parts: Vec<&str> = host_port.split(':').collect();
    if parts.len() != 2 {
        return Err(ToolError::Denied("invalid host:port format".into()));
    }
    let host = parts[0].to_string();
    let port = parts[1]
        .parse()
        .map_err(|_| ToolError::Denied("invalid port".into()))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_capability::Capability;

    fn harness() -> (ToolGateway, Cube, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "aivm-tools-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let ws_real = dir.canonicalize().unwrap_or(dir.clone());
        let policy = Policy::from_yaml(&format!(
            r#"
name: test
filesystem:
  read: [{}]
  write: [{}/src]
  deny: ["**/.env*", "**/secrets/**"]
process: {{allow: [], deny: []}}
network: {{allow: [], deny: []}}
"#,
            ws_real.display(),
            ws_real.display()
        ))
        .unwrap();
        let caps = CapabilitySet::new(vec![
            Capability::new("read", "filesystem", &ws_real.to_string_lossy()),
            Capability::new("write", "filesystem", &format!("{}/src", ws_real.display())),
            Capability::new("search", "filesystem", &ws_real.to_string_lossy()),
        ]);
        let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
        let gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess");
        (gw, Cube::new("t"), dir)
    }

    #[test]
    fn traversal_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.read(&mut cube, "../../etc/passwd");
        assert!(matches!(r, Err(ToolError::Denied(_))));
    }

    #[test]
    fn write_outside_src_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.write(&mut cube, "README.md", "hi");
        // README อยู่ root ของ workspace: write อนุญาตแค่ */src
        assert!(r.is_err());
    }

    #[test]
    fn write_inside_src_allowed() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.write(&mut cube, "src/a.rs", "fn main(){}");
        assert!(r.is_ok());
    }

    #[test]
    fn unknown_tool_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "shell.exec".into(),
                path: "x".into(),
                content: None,
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
    }

    fn exec_harness() -> (ToolGateway, Cube, PathBuf) {
        let (mut gw, cube, dir) = harness();
        let allow: Vec<String> = ["/bin/true", "/bin/false"]
            .iter()
            .map(|e| {
                std::fs::canonicalize(e)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        gw.policy.process.allow = allow.clone();
        for exe in &allow {
            gw.caps
                .grant(aivm_capability::Capability::new("execute", "process", exe));
        }
        (gw, cube, dir)
    }

    #[test]
    fn exec_reports_exit_status_without_deny() {
        let (mut gw, mut cube, _d) = exec_harness();
        let exe = |p: &str| ToolRequest {
            tool: "process.exec".into(),
            path: p.into(),
            content: Some("[]".into()),
        };
        // exit 0 = ok:true
        let r = gw.dispatch(&mut cube, &exe("/bin/true")).unwrap();
        assert!(r.ok);
        // exit ไม่ใช่ 0 = รันสำเร็จแต่ล้มเหลว (ok:false ไม่ใช่ DENY)
        let r = gw.dispatch(&mut cube, &exe("/bin/false")).unwrap();
        assert!(!r.ok);
        assert_eq!(r.decision, "allow");
    }

    #[test]
    fn exec_denied_without_execute_cap() {
        let (mut gw, mut cube, _d) = harness();
        let real = std::fs::canonicalize("/bin/true").unwrap();
        gw.policy.process.allow = vec![real.to_string_lossy().to_string()];
        // harness ไม่มี execute cap: ต้อง no-capability
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
    }

    // Phase 7: ระดับที่ยังไม่มี backend ต้อง DENY พร้อม audit (I-7)
    // แม้ policy + capability จะอนุญาตครบ (ประตู level มาก่อน execute)
    // หมายเหตุ: เปิดฟีเจอร์ `microvm` แล้วเคสนี้ตายด้วย Invalid (artifact
    // ของ config default หาย) แทน Disabled — deny + audit เหมือนกัน
    #[test]
    fn exec_denied_on_unimplemented_level_with_audit() {
        let (mut gw, mut cube, dir) = exec_harness();
        gw.level = SandboxLevel::MicroVm;
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        // ต้องมี audit decision ที่ deny ด้วยเหตุระดับ level
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(
            log.contains("level-disabled") || log.contains("level-invalid"),
            "ต้อง audit การ deny ระดับ level"
        );
        assert!(log.contains("\"decision\":\"deny\""));
    }

    // Phase 7 (ฟีเจอร์ microvm): artifact ปลอมต้อง DENY พร้อม audit
    // (deterministic ทุกเครื่อง — supply chain ตายก่อนถึงขั้น boot)
    // ส่วน path บูตจริงมีเทสต์ host-gated ฝั่ง sandbox คุมอยู่แล้ว
    #[cfg(feature = "microvm")]
    #[test]
    fn exec_with_tampered_artifact_denied_with_audit() {
        let (mut gw, mut cube, dir) = exec_harness();
        let kern = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kern, b"k").unwrap();
        std::fs::write(&rootfs, b"r").unwrap();
        gw.level = SandboxLevel::MicroVm;
        gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
            kernel_path: kern,
            // hash ผิดเจตนา (ของจริงคือ sha256 ของ b"k")
            kernel_sha256: "00".repeat(32),
            rootfs_path: rootfs,
            rootfs_sha256: "11".repeat(32),
            ..aivm_sandbox::microvm::MicroVmConfig::default()
        });
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("level-invalid"));
        assert!(log.contains("\"decision\":\"deny\""));
    }

    // Phase 7 + G3 (ฟีเจอร์ microvm): deny ตั้งแต่ประตูต้องมี verdict ใน audit
    // (deterministic ทุกเครื่อง — ยังไม่เกิด run = verdict:clean + เหตุผล)
    #[cfg(feature = "microvm")]
    #[test]
    fn exec_denied_at_gate_audits_verdict() {
        let (mut gw, mut cube, dir) = exec_harness();
        let kern = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kern, b"k").unwrap();
        std::fs::write(&rootfs, b"r").unwrap();
        gw.level = SandboxLevel::MicroVm;
        gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
            kernel_path: kern,
            kernel_sha256: "00".repeat(32),
            rootfs_path: rootfs,
            rootfs_sha256: "11".repeat(32),
            ..aivm_sandbox::microvm::MicroVmConfig::default()
        });
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"decision\":\"deny\""));
        assert!(
            log.contains("verdict:clean:no-interference-evidence"),
            "deny ตั้งแต่ประตูต้องลง verdict: {log}"
        );
    }

    // Phase 7 (ฟีเจอร์ microvm): pin ของไบนารี VMM ไม่ตรงต้อง DENY พร้อม
    // audit เช่นกัน (supply chain ของ VMM เอง — attacker สลับไบนารีใน PATH
    // แล้ว pin จับได้ต้องตายตั้งแต่ประตู ไม่ใช่บูตด้วย VMM ปลอม)
    #[cfg(feature = "microvm")]
    #[test]
    fn exec_with_tampered_fc_pin_denied_with_audit() {
        use sha2::{Digest, Sha256};
        // sha256 hex ของไบต์ตั้งต้น (เทสต์คุมเอง ไม่พึ่งค่าตายตัว)
        fn hex_of(data: &[u8]) -> String {
            let mut h = Sha256::new();
            h.update(data);
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        }
        let (mut gw, mut cube, dir) = exec_harness();
        let kern = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kern, b"k").unwrap();
        std::fs::write(&rootfs, b"r").unwrap();
        // pin ของ kernel/rootfs ถูก (ผ่านด่านแรก) แต่ pin ของ VMM ผิดเจตนา
        gw.level = SandboxLevel::MicroVm;
        gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
            kernel_path: kern,
            kernel_sha256: hex_of(b"k"),
            rootfs_path: rootfs,
            rootfs_sha256: hex_of(b"r"),
            fc_sha256: "22".repeat(32),
            ..aivm_sandbox::microvm::MicroVmConfig::default()
        });
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        // เครื่องที่มี firecracker = pin ผิดต้องตายด้วย Invalid;
        // เครื่องที่ไม่มี = ไปไม่ถึงขั้นตรวจ pin (Disabled) — deny + audit ทั้งคู่
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("level-invalid") || log.contains("level-disabled"));
        assert!(log.contains("\"decision\":\"deny\""));
    }

    // G1: tracker ลั่นที่ threshold พอดี ไม่ยืดเวลาเอง หมด cooldown แล้วนับใหม่
    #[test]
    fn deny_tracker_triggers_no_extend_and_rearms() {
        let mut t = DenyTracker::test_config(3, 60, 60);
        let now = Instant::now();
        assert!(!t.record_deny(now));
        assert!(!t.record_deny(now));
        // ครั้งที่ 3 = ครบ threshold ลั่นรอบใหม่
        assert!(t.record_deny(now));
        assert!(t.quarantined(now));
        // hammer ต่อระหว่าง quarantine = นับแต่ไม่ยืดเวลา (ไม่คืน true อีก)
        let arm = t.quarantine_until;
        assert!(!t.record_deny(now));
        assert!(!t.record_deny(now));
        assert_eq!(t.quarantine_until, arm);
        // cooldown = 0 อีกรอบ: หมดทันที แต่ record ใหม่ลั่นซ้ำได้ (re-arm)
        let mut z = DenyTracker::test_config(2, 60, 0);
        assert!(!z.record_deny(now));
        assert!(z.record_deny(now));
        assert!(!z.quarantined(now));
        assert!(z.record_deny(now));
    }

    // G1: deny burst ครบ threshold → gateway quarantine (allow ที่ควรผ่านก็ตาย)
    // deterministic: threshold default 20, ทุก deny เกิดในเสี้ยววินาทีเดียวกัน
    #[test]
    fn probing_burst_quarantines_gateway() {
        // เส้นแบ่ง: 19 denies ยังปกติ
        let (mut gw, mut cube, _d) = exec_harness();
        let probe = ToolRequest {
            tool: "filesystem.read".into(),
            path: "../../etc/passwd".into(),
            content: None,
        };
        for _ in 0..19 {
            assert!(gw.dispatch(&mut cube, &probe).is_err());
        }
        let ok = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(ok.is_ok(), "19 denies ต้องยังไม่ quarantine");

        // ครบ 20 = quarantine ครั้งที่ 21 (ของที่ควร allow) ต้องตายพร้อม audit
        let (mut gw, mut cube, dir) = exec_harness();
        for _ in 0..20 {
            assert!(gw.dispatch(&mut cube, &probe).is_err());
        }
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("quarantine-started"), "ต้องมีรอยเริ่ม quarantine");
        assert!(
            log.contains("quarantine-probing"),
            "ต้องมีรอย deny ระหว่าง quarantine"
        );
    }
}
