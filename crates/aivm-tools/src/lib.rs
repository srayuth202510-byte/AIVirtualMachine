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
use aivm_secrets::{
    zeroize_secret, RiskLevel, SecretBroker, SecretError, SecretInjector, SecretLease,
    SecretRequest,
};
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
#[serde(deny_unknown_fields)]
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

/// body ของ `process.exec` รูป object (G4): ใช้แทน argv array ล้วนเมื่อต้อง
/// แนบ secret lease — strict schema (`deny_unknown_fields` + parse ไม่ได้
/// = DENY) ฟิลด์นอก argv/secret/outputs = DENY ทันที
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecContent {
    pub argv: Vec<String>,
    /// lease id จาก `secret.request` (ไม่มี = รันปกติไม่มี secret)
    #[serde(default)]
    pub secret: Option<String>,
    /// ชื่อ output slots ใน .aivm-build (ต้องเปิด profile โดย operator)
    #[serde(default)]
    pub outputs: Vec<String>,
}

/// body ของ `secret.request` (G4 §26 — structured schema เท่านั้น):
/// ฟิลด์ขาด/เกิน/type ผิด = DENY (fail-closed ไม่เดา)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequestBody {
    /// tool ที่จะใช้ secret (MVP: `"process.exec"` เท่านั้น อย่างอื่น = DENY)
    pub tool: String,
    /// resource ที่ขอ (เช่น `"github_token"`)
    pub resource: String,
    /// scope ที่ขอ (เช่น `"read"`)
    pub scope: String,
    /// เป้าหมาย (metadata ลง audit เท่านั้น ไม่ใช่ trust signal)
    pub purpose: String,
    /// ใช้ได้กี่ครั้ง (default 1 = one-time lease)
    pub max_uses: Option<u32>,
    /// อายุวินาที (default 300)
    pub ttl_seconds: Option<u64>,
    /// `"low"` | `"high"` (default `"high"` = conservative)
    pub risk: Option<String>,
}

/// เพดานความยาวฟิลด์คำขอ secret (กัน log บวม — secret value ไม่มีทางผ่านช่องนี้)
const MAX_SECRET_FIELD: usize = 256;
/// เพดานความยาว lease id (uuid ~36 ตัวอักษร)
const MAX_LEASE_ID: usize = 128;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub mod build;
mod secure_fs;
pub mod state_store;

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
    /// config Hardware Isolation (TEE pins + quota) ใช้เมื่อเปิดฟีเจอร์
    /// `hardware` และ `level` เป็น Hardware เท่านั้น — ไม่มี config
    /// (= `None`) จะใช้ค่า default ที่ deny ตั้งแต่ artifact หาย
    #[cfg(feature = "hardware")]
    pub hardware_cfg: Option<aivm_sandbox::hardware::HardwareConfig>,
    pub container_cfg: aivm_sandbox::container::ContainerConfig,
    pub limits: ResourceLimits,
    pub state_path: Option<PathBuf>,
    pub build: build::BuildConfig,
    req_counter: u64,
    deny_tracker: DenyTracker,
    /// File contents read during the current agent run. Authorization and audit
    /// still happen on every request; writes and process execution invalidate it.
    read_cache: HashMap<PathBuf, String>,
    /// Secret broker (G4 §26): `None` = ไม่ตั้งค่า → `secret.request` และ
    /// exec แบบแนบ secret ถูก DENY (fail-closed ไม่มีทางเงียบผ่าน)
    secret_broker: Option<SecretBroker>,
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
            #[cfg(feature = "hardware")]
            hardware_cfg: None,
            container_cfg: aivm_sandbox::container::ContainerConfig::default(),
            limits: ResourceLimits::default(),
            state_path: None,
            build: build::BuildConfig::default(),
            req_counter: 0,
            deny_tracker: DenyTracker::default(),
            read_cache: HashMap::new(),
            secret_broker: None,
        }
    }

    /// Start a fresh agent run with no assumptions about workspace contents.
    pub fn clear_read_cache(&mut self) {
        self.read_cache.clear();
    }

    /// ติด secret broker แบบ builder (operator ประกอบที่ runtime — ดู
    /// `Runtime::init`: broker เปล่า = deny หมด, มี secrets = ตาม policy)
    pub fn with_secret_broker(mut self, broker: SecretBroker) -> Self {
        self.secret_broker = Some(broker);
        self
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

    /// broker สำหรับ rehydrate leases (G4b — runtime เท่านั้น)
    pub fn secret_broker_mut(&mut self) -> Option<&mut SecretBroker> {
        self.secret_broker.as_mut()
    }

    /// leases ที่ยังมีชีวิตไว้ persist (G4b — runtime เท่านั้น)
    pub fn live_secret_leases(&self) -> Vec<aivm_secrets::SecretLease> {
        match &self.secret_broker {
            Some(b) => b.live_leases(),
            None => vec![],
        }
    }

    /// consume quota/lease ลงดิสก์ก่อน side effect ป้องกัน replay หลัง crash
    fn checkpoint(&self, cube: &Cube) -> Result<(), ToolError> {
        if let Some(path) = &self.state_path {
            let text = serde_json::to_string(&serde_json::json!({
                "cube": cube, "caps": self.caps, "leases": self.live_secret_leases()
            }))
            .map_err(|e| ToolError::Io(e.to_string()))?;
            state_store::write_private(path, &text).map_err(|e| ToolError::Io(e.to_string()))?;
        }
        Ok(())
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
            )?;
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
    fn enforce(
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

    fn check_file_size(&self, cap_index: usize, bytes: u64) -> Result<(), ToolError> {
        if bytes > MAX_FILE_BYTES {
            return Err(ToolError::Denied("file size limit exceeded".into()));
        }
        self.caps.caps[cap_index]
            .check_constraints(Some(bytes), None, None, None, None)
            .map_err(|_| ToolError::Denied("file size constraint exceeded".into()))
    }

    /// บันทึกโควต้าไบต์ก่อนคืนข้อมูลหรือเริ่มเขียน เพื่อไม่ให้ restart แล้ว
    /// ทำให้ยอดสะสมของ capability กลับเป็นศูนย์
    fn charge_bytes(&mut self, cube: &Cube, cap_index: usize, bytes: u64) -> Result<(), ToolError> {
        self.check_file_size(cap_index, bytes)?;
        self.caps.account_bytes(cap_index, bytes);
        self.checkpoint(cube)
    }

    pub fn read(&mut self, cube: &mut Cube, path: &str) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "read", path)?;
        let (canon, cap_index) = self.enforce(cube, "read", path)?;
        if let Some(content) = self.read_cache.get(&canon).cloned() {
            if let Err(error) = self.check_file_size(cap_index, content.len() as u64) {
                self.audit_decision(cube, "read", path, "deny", "size-constraint", "error")?;
                return Err(error);
            }
            self.charge_bytes(cube, cap_index, content.len() as u64)?;
            self.audit_decision(cube, "read", path, "allow", "cache-hit", "success")?;
            return Ok(ToolResult {
                ok: true,
                decision: "allow".into(),
                output: content,
            });
        }
        use std::io::Read;
        let result = (|| {
            let file = secure_fs::open(&self.workspace, &canon, false)?;
            let size = file
                .metadata()
                .map_err(|e| ToolError::Io(e.to_string()))?
                .len();
            self.check_file_size(cap_index, size)?;
            let mut content = String::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_string(&mut content)
                .map_err(|e| ToolError::Io(e.to_string()))?;
            self.check_file_size(cap_index, content.len() as u64)?;
            Ok::<_, ToolError>(content)
        })();
        let content = match result {
            Ok(content) => content,
            Err(error) => {
                self.audit_decision(cube, "read", path, "deny", "outcome", "error")?;
                return Err(error);
            }
        };
        if let Err(error) = self.charge_bytes(cube, cap_index, content.len() as u64) {
            self.audit_decision(cube, "read", path, "deny", "size-constraint", "error")?;
            return Err(error);
        }
        self.audit_decision(cube, "read", path, "allow", "outcome", "success")?;
        self.read_cache.insert(canon, content.clone());
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
        let (canon, cap_index) = self.enforce(cube, "write", path)?;
        use std::io::{Read, Write};
        if let Err(error) = self.check_file_size(cap_index, content.len() as u64) {
            self.audit_decision(cube, "write", path, "deny", "size-constraint", "error")?;
            return Err(error);
        }
        let unchanged = secure_fs::open(&self.workspace, &canon, false)
            .ok()
            .and_then(|file| {
                let size = file.metadata().ok()?.len();
                (size == content.len() as u64).then_some(file)
            })
            .and_then(|file| {
                let mut existing = Vec::with_capacity(content.len());
                file.take(content.len() as u64 + 1)
                    .read_to_end(&mut existing)
                    .ok()
                    .map(|_| existing)
            })
            .is_some_and(|existing| existing == content.as_bytes());
        if unchanged {
            self.charge_bytes(cube, cap_index, content.len() as u64)?;
            self.read_cache.insert(canon, content.to_string());
            self.audit_decision(cube, "write", path, "allow", "unchanged", "success")?;
            return Ok(ToolResult {
                ok: true,
                decision: "allow".into(),
                output: "unchanged".into(),
            });
        }
        let result = (|| {
            self.check_file_size(cap_index, content.len() as u64)?;
            let used = walkdir::WalkDir::new(&self.workspace)
                .into_iter()
                .try_fold(0u64, |used, entry| {
                    let entry = entry.map_err(|e| ToolError::Io(e.to_string()))?;
                    let meta = entry.metadata().map_err(|e| ToolError::Io(e.to_string()))?;
                    Ok::<_, ToolError>(used.saturating_add(if meta.is_file() {
                        meta.len()
                    } else {
                        0
                    }))
                })?;
            let previous = std::fs::symlink_metadata(&canon)
                .map(|m| m.len())
                .unwrap_or(0);
            if used
                .saturating_sub(previous)
                .saturating_add(content.len() as u64)
                > self.limits.storage_mb.saturating_mul(1024 * 1024)
            {
                return Err(ToolError::Denied("workspace storage quota exceeded".into()));
            }
            // บันทึกโควต้าไบต์ก่อนแก้ไฟล์ เพื่อไม่ให้การทำงานซ้ำหลัง crash ใช้งบเดิม
            self.charge_bytes(cube, cap_index, content.len() as u64)?;
            secure_fs::open(&self.workspace, &canon, true).and_then(|mut file| {
                file.write_all(content.as_bytes())
                    .map_err(|e| ToolError::Io(e.to_string()))
            })
        })();
        self.audit_decision(
            cube,
            "write",
            path,
            if result.is_ok() { "allow" } else { "deny" },
            "outcome",
            if result.is_ok() { "success" } else { "error" },
        )?;
        result?;
        self.read_cache.insert(canon, content.to_string());
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: "written".into(),
        })
    }

    /// `code.search`: ค้น substring ในไฟล์ workspace (ใช้ scope แบบ read)
    /// อ่าน context ผ่าน gateway เท่านั้น ไม่รับ root จากผู้เรียก RAG
    pub fn context_files(&mut self, cube: &mut Cube) -> Result<Vec<(String, String)>, ToolError> {
        let paths: Vec<PathBuf> = walkdir::WalkDir::new(&self.workspace)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();
        let mut files = Vec::new();
        let mut total = 0usize;
        for path in paths {
            let scope = path.to_string_lossy();
            if is_boundary_path(&path)
                || self
                    .policy
                    .evaluate_fs("read", &scope, &Self::ctx_of(cube))
                    .0
                    != Decision::Allow
                || !self.caps.caps.iter().any(|cap| {
                    cap.check_usable().is_ok() && cap.covers("read", "filesystem", &scope)
                })
            {
                continue;
            }
            match self.read(cube, &scope) {
                Ok(result) => {
                    total += result.output.len();
                    if total > 8 * 1024 * 1024 {
                        break;
                    }
                    let rel = path
                        .strip_prefix(&self.workspace)
                        .map_err(|e| ToolError::Denied(e.to_string()))?;
                    files.push((rel.to_string_lossy().into_owned(), result.output));
                }
                Err(ToolError::Audit(e)) => return Err(ToolError::Audit(e)),
                Err(_) => continue,
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(files)
    }

    pub fn search(&mut self, cube: &mut Cube, query: &str) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "search", query)?;
        let workspace = self.workspace.clone();
        self.enforce(cube, "search", &workspace.to_string_lossy())?;
        let mut hits = Vec::new();
        for (path, content) in self.context_files(cube)? {
            for (line_number, line) in content.lines().enumerate() {
                if line.contains(query) {
                    hits.push(format!(
                        "{}:{}: {}",
                        self.workspace.join(&path).display(),
                        line_number + 1,
                        line.trim()
                    ));
                    if hits.len() == 50 {
                        break;
                    }
                }
            }
            if hits.len() == 50 {
                break;
            }
        }
        self.audit_decision(cube, "search", query, "allow", "mediated-search", "success")?;
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
    fn exec_inner(
        &mut self,
        cube: &mut Cube,
        exe: &str,
        args: &[String],
        lease_id: Option<&str>,
        outputs: &[String],
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "execute", exe)?;
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
        let mut spec = ExecSpec {
            exe: PathBuf::from(exe),
            args: args.to_vec(),
            cwd: self.workspace.clone(),
            workspace: self.workspace.clone(),
            env_extra: vec![],
            timeout_ms: 30000,
            build: None,
            limits: self.limits.clone(),
        };
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
        // secret lease (G4): resolve หลัง validate+caps (deny ก่อนหน้าไม่เผา
        // one-time lease) — value เข้า env_extra ช่องเดียว ไม่มีทางอื่น
        // หมายเหตุ borrow: คุยกับ broker ให้จบใน block เดียว (owned ออกมา)
        // แล้วค่อย audit — ไม่ถือ borrow ข้าม audit call เด็ดขาด
        let mut lease_tag = "-".to_string();
        let mut secret_env: Vec<(String, String)> = vec![];
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
                    secret_env = env;
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
        spec.env_extra = secret_env;
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
        Ok(ToolResult {
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
        self.check_quarantine(cube, "network:fetch", url)?;
        let result = self.fetch_checked(cube, url, content);
        if let Err(ref error) = result {
            self.audit_decision(
                cube,
                "network:fetch",
                url,
                "deny",
                "fetch-failed",
                &error.to_string(),
            )?;
        }
        result
    }

    fn fetch_checked(
        &mut self,
        cube: &mut Cube,
        url: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use aivm_capability::AuthorizationContext;
        use std::io::Read;
        let req: NetworkFetchRequest = serde_json::from_str(content.unwrap_or("{}"))
            .map_err(|e| ToolError::Denied(format!("invalid network.fetch request: {e}")))?;
        let (host, port, protocol) = parse_url(url)?;
        let scope = network_scope(&host, port);
        let action =
            if req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD") {
                "network:fetch"
            } else {
                "network:connect"
            };
        let timeout_ms = req.timeout_ms.unwrap_or(30000);
        if !(1..=60000).contains(&timeout_ms) {
            return Err(ToolError::Denied("invalid timeout".into()));
        }
        let context = AuthorizationContext {
            request_bytes: req.body.as_ref().map(|v| v.len() as u64),
            protocol: Some(&protocol),
            port: Some(port),
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        };
        let idx = self
            .caps
            .authorize_with_context(action, "network", &scope, &context)
            .map_err(|e| ToolError::Denied(format!("network capability or constraint: {e}")))?;
        if self.policy.evaluate_network(&scope, &Self::ctx_of(cube)).0 != Decision::Allow {
            return Err(ToolError::Denied("network policy denied".into()));
        }
        let method = req.method.to_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD"
        ) {
            return Err(ToolError::Denied("unsupported HTTP method".into()));
        }
        if req.headers.keys().any(|key| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding"
            )
        }) {
            return Err(ToolError::Denied("protected HTTP header".into()));
        }
        // resolve ครั้งเดียว ตรวจทุก IP แล้วตรึง resolver; ไม่ตาม redirect
        let addresses = public_addresses(&host, port)?;
        let request_bytes = req.body.as_ref().map_or(0, |body| body.len() as u64);
        self.audit_decision(
            cube,
            action,
            &scope,
            "allow",
            "network-authorized",
            "authorized",
        )?;
        // หักไบต์ขาออกก่อนส่งคำขอ; นับเฉพาะคำตอบจะเปิดทางให้ส่งข้อมูลออกไม่จำกัด
        self.caps.account_bytes(idx, request_bytes);
        self.checkpoint(cube)?;
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .resolver(move |_: &str| Ok(addresses.clone()))
            .build();
        let mut request = agent
            .request(&method, url)
            .timeout(Duration::from_millis(timeout_ms));
        for (key, value) in req.headers {
            request = request.set(&key, &value);
        }
        let response = match if let Some(body) = req.body {
            request.send_string(&body)
        } else {
            request.call()
        } {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => return Err(ToolError::Io(error.to_string())),
        };
        let status = response.status();
        if (300..400).contains(&status) {
            return Err(ToolError::Denied(
                "redirects are disabled; authorize target separately".into(),
            ));
        }
        let limit = self.caps.caps[idx]
            .constraints
            .max_response_bytes
            .unwrap_or(MAX_FILE_BYTES)
            .min(MAX_FILE_BYTES);
        let mut body = Vec::new();
        response
            .into_reader()
            .take(limit + 1)
            .read_to_end(&mut body)
            .map_err(|e| ToolError::Io(e.to_string()))?;
        if body.len() as u64 > limit {
            return Err(ToolError::Denied("response size limit exceeded".into()));
        }
        if self.caps.caps[idx]
            .constraints
            .max_total_bytes
            .is_some_and(|max| {
                self.caps.caps[idx]
                    .used_bytes
                    .saturating_add(body.len() as u64)
                    > max
            })
        {
            return Err(ToolError::Denied("network byte budget exceeded".into()));
        }
        // นับไบต์ขากลับด้วย เพื่อให้โควต้าเครือข่ายครอบคลุมทั้งสองทิศทาง
        self.caps.account_bytes(idx, body.len() as u64);
        self.checkpoint(cube)?;
        let output =
            String::from_utf8(body).map_err(|_| ToolError::Io("response is not UTF-8".into()))?;
        self.audit_decision(
            cube,
            action,
            &scope,
            "allow",
            &format!("status:{status}"),
            "success",
        )?;
        Ok(ToolResult {
            ok: (200..300).contains(&status),
            decision: "allow".into(),
            output,
        })
    }

    pub fn network_connect(
        &mut self,
        cube: &mut Cube,
        host_port: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "network:connect", host_port)?;
        let result = self.connect_checked(cube, host_port, content);
        if let Err(ref error) = result {
            self.audit_decision(
                cube,
                "network:connect",
                host_port,
                "deny",
                "connect-failed",
                &error.to_string(),
            )?;
        }
        result
    }

    fn connect_checked(
        &mut self,
        cube: &mut Cube,
        host_port: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use aivm_capability::AuthorizationContext;
        let req: NetworkConnectRequest = serde_json::from_str(content.unwrap_or("{}"))
            .map_err(|e| ToolError::Denied(format!("invalid network.connect request: {e}")))?;
        if req.protocol != "tcp" {
            return Err(ToolError::Denied("protocol must be tcp".into()));
        }
        let (host, port) = parse_host_port(host_port)?;
        let scope = network_scope(&host, port);
        let timeout_ms = req.timeout_ms.unwrap_or(30000);
        if !(1..=60000).contains(&timeout_ms) {
            return Err(ToolError::Denied("invalid timeout".into()));
        }
        let protocol = if req.tls { "https" } else { "tcp" };
        let context = AuthorizationContext {
            protocol: Some(protocol),
            port: Some(port),
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        };
        self.caps
            .authorize_with_context("network:connect", "network", &scope, &context)
            .map_err(|e| ToolError::Denied(format!("network capability or constraint: {e}")))?;
        if self.policy.evaluate_network(&scope, &Self::ctx_of(cube)).0 != Decision::Allow {
            return Err(ToolError::Denied("network policy denied".into()));
        }
        let addresses = public_addresses(&host, port)?;
        self.audit_decision(
            cube,
            "network:connect",
            &scope,
            "allow",
            "network-authorized",
            "authorized",
        )?;
        self.checkpoint(cube)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut stream = None;
        for addr in addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(connected) = std::net::TcpStream::connect_timeout(&addr, remaining) {
                stream = Some(connected);
                break;
            }
        }
        let mut stream = stream.ok_or_else(|| ToolError::Io("connection failed".into()))?;
        if req.tls {
            use ureq::rustls;
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| ToolError::Denied("invalid TLS server name".into()))?;
            let mut tls = rustls::ClientConnection::new(std::sync::Arc::new(config), server)
                .map_err(|e| ToolError::Io(e.to_string()))?;
            while tls.is_handshaking() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ToolError::Io("TLS handshake timeout".into()));
                }
                stream
                    .set_read_timeout(Some(remaining))
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                stream
                    .set_write_timeout(Some(remaining))
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                tls.complete_io(&mut stream)
                    .map_err(|e| ToolError::Io(format!("TLS handshake: {e}")))?;
            }
        }
        self.audit_decision(
            cube,
            "network:connect",
            &scope,
            "allow",
            if req.tls {
                "tls-connected"
            } else {
                "tcp-connected"
            },
            "success",
        )?;
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: format!("connected to {scope}"),
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

    /// `secret.request`: ขอ one-time lease สำหรับ secret (G4 §26)
    ///
    /// สายบังคับใช้: structured schema เข้ม (ขาด/เกิน/type ผิด = DENY) ->
    /// broker ตรวจ capability + policy -> Low ออก lease ให้เลย, High ที่ไม่มี
    /// approval = DENY + audit `hitl-required` (approve flow แยกต่างหาก)
    ///
    /// คืนเฉพาะ lease_id + metadata — **secret value ไม่มีทางกลับไป
    /// AI context** (I-2/tool-scoped: ค่าถูก inject เข้า child env ตอน exec
    /// เท่านั้น แล้ว zeroize)
    pub fn secret_request(
        &mut self,
        cube: &mut Cube,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "secret.request", "-")?;
        let body: SecretRequestBody = match content {
            Some(s) => serde_json::from_str(s).map_err(|_| {
                self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "secret.request needs a JSON object",
                )
            })?,
            None => {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "secret.request needs a JSON object",
                ));
            }
        };
        // ฟิลด์ต้องไม่ว่างและไม่ยาวเกิน (กัน log บวม — value ไม่มีทางผ่านช่องนี้)
        for (name, v) in [
            ("tool", &body.tool),
            ("resource", &body.resource),
            ("scope", &body.scope),
            ("purpose", &body.purpose),
        ] {
            if v.is_empty() || v.len() > MAX_SECRET_FIELD {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    &format!("bad secret.request field: {name}"),
                ));
            }
        }
        // consumer binding: MVP มีผู้ใช้แค่ process.exec (อย่างอื่น = DENY)
        if body.tool != "process.exec" {
            return Err(self.deny_secret(
                cube,
                "secret-tool-unknown",
                "secret consumer must be process.exec",
            ));
        }
        let risk = match body.risk.as_deref() {
            None | Some("high") => RiskLevel::High,
            Some("low") => RiskLevel::Low,
            Some(_) => {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "risk must be low or high",
                ));
            }
        };
        let req = SecretRequest {
            tool: body.tool.clone(),
            resource: body.resource.clone(),
            scope: body.scope.clone(),
            purpose: body.purpose.clone(),
            max_uses: body.max_uses.unwrap_or(1),
            ttl_seconds: body.ttl_seconds.unwrap_or(300),
            risk,
        };
        let scope = format!("{}:{}", req.resource, req.scope);
        let broker = match self.secret_broker.as_mut() {
            Some(b) => b,
            None => {
                return Err(self.deny_secret(
                    cube,
                    "secret-unconfigured",
                    "secret broker not configured",
                ));
            }
        };
        // borrow broker จบใน match นี้ (owned ออกมา) แล้วค่อย audit
        // pending lease id (high-risk) ส่งต่อใน audit result ให้ operator
        // เอาไป approve (id ไม่ใช่ secret บอกได้)
        enum Outcome {
            Allow(SecretLease),
            Deny {
                rule: &'static str,
                msg: String,
                audit_result: String,
            },
        }
        let outcome = match broker.request_lease(req, cube, &mut self.caps, false, None) {
            Ok(lease) => Outcome::Allow(lease),
            Err(e) => {
                let (rule, msg, audit_result) = match &e {
                    SecretError::HitlRequired(id) => (
                        "hitl-required",
                        "high-risk secret requires operator approval".to_string(),
                        format!("pending:{id}"),
                    ),
                    SecretError::CapabilityDenied(_) => {
                        ("no-capability", "no capability".into(), "error".into())
                    }
                    SecretError::PolicyDenied(_) => (
                        "secret-policy",
                        "secret denied by policy".into(),
                        "error".into(),
                    ),
                    // ไม่บอกว่ามี resource อะไรบ้าง (กัน enumerate)
                    SecretError::SecretNotFound(_) => (
                        "secret-unknown",
                        "unknown secret resource".into(),
                        "error".into(),
                    ),
                    SecretError::InvalidRequest(_) => (
                        "bad-secret-request",
                        "bad secret request".into(),
                        "error".into(),
                    ),
                    _ => (
                        "secret-error",
                        "secret request failed".into(),
                        "error".into(),
                    ),
                };
                Outcome::Deny {
                    rule,
                    msg,
                    audit_result,
                }
            }
        };
        match outcome {
            Outcome::Allow(lease) => {
                let out = serde_json::json!({
                    "lease_id": lease.id,
                    "resource": lease.request.resource,
                    "scope": lease.request.scope,
                    "max_uses": lease.request.max_uses,
                    "hitl_approved": lease.hitl_approved,
                })
                .to_string();
                self.audit_decision(
                    cube,
                    "secret.request",
                    &scope,
                    "allow",
                    "lease-issued",
                    "success",
                )?;
                self.checkpoint(cube)?;
                Ok(ToolResult {
                    ok: true,
                    decision: "allow".into(),
                    output: out,
                })
            }
            Outcome::Deny {
                rule,
                msg,
                audit_result,
            } => {
                self.audit_decision(cube, "secret.request", &scope, "deny", rule, &audit_result)?;
                self.checkpoint(cube)?;
                Err(ToolError::Denied(msg))
            }
        }
    }

    /// deny  helper ของ `secret.request` (audit + Err ในรูปเดียว — resource
    /// ยังไม่รู้ตอน parse จึงใช้ "-")
    fn deny_secret(&mut self, cube: &mut Cube, rule: &str, msg: &str) -> ToolError {
        if let Err(e) = self.audit_decision(cube, "secret.request", "-", "deny", rule, "error") {
            return e;
        }
        ToolError::Denied(msg.to_string())
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
        || s.ends_with("/secrets.yaml")
        || s.ends_with("/state.json")
        || p.components()
            .any(|part| part.as_os_str() == build::DIRECTORY)
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    if !matches!(protocol.as_str(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ToolError::Denied(
            "HTTP(S) URL without credentials required".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ToolError::Denied("URL missing host".into()))?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ToolError::Denied("URL missing port".into()))?;
    if port == 0 {
        return Err(ToolError::Denied("invalid port".into()));
    }
    Ok((host, port, protocol))
}

fn parse_host_port(target: &str) -> Result<(String, u16), ToolError> {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| ToolError::Denied("host:port required".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ToolError::Denied("invalid port".into()))?;
    if host.is_empty() || host.contains(['/', '@', ':']) || port == 0 {
        return Err(ToolError::Denied("invalid host:port".into()));
    }
    Ok((host.to_ascii_lowercase(), port))
}
fn network_scope(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn public_addresses(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, ToolError> {
    use std::net::ToSocketAddrs;
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| ToolError::Io(e.to_string()))?
        .collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|a| !aivm_policy::is_public_address(a.ip()))
    {
        return Err(ToolError::Denied(
            "private, loopback, or reserved destination".into(),
        ));
    }
    Ok(addresses)
}

/// ล้างค่า secret ใน env pairs (best-effort zeroize — เรียกทุกทางออก
/// หลัง secret เข้าสู่มือ gateway แล้ว)
fn zeroize_env(env: &mut [(String, String)]) {
    for (_, v) in env.iter_mut() {
        zeroize_secret(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_capability::Capability;

    #[test]
    fn cached_reads_enforce_current_size_constraints() {
        let (mut gw, mut cube, dir) = harness();
        std::fs::write(dir.join("src/data.txt"), "0123456789").unwrap();
        gw.read(&mut cube, "src/data.txt").unwrap();
        gw.caps
            .caps
            .iter_mut()
            .find(|c| c.action == "read")
            .unwrap()
            .constraints
            .max_bytes = Some(1);
        assert!(matches!(
            gw.read(&mut cube, "src/data.txt"),
            Err(ToolError::Denied(_))
        ));
        assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .contains("size-constraint"));

        // A write must not prime a cache entry that bypasses a limited read.
        gw.write(&mut cube, "src/data.txt", "more data").unwrap();
        assert!(gw.read(&mut cube, "src/data.txt").is_err());
        gw.write(&mut cube, "src/data.txt", "x").unwrap();
        assert_eq!(gw.read(&mut cube, "src/data.txt").unwrap().output, "x");
        aivm_audit::clear_flags(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_write_content_never_truncates_a_file() {
        let (mut gw, mut cube, dir) = harness();
        std::fs::write(dir.join("src/data.txt"), "keep me").unwrap();
        for json in [
            r#"{"tool":"filesystem.write","path":"src/data.txt"}"#,
            r#"{"tool":"filesystem.write","path":"src/data.txt","content":null}"#,
        ] {
            let request: ToolRequest = serde_json::from_str(json).unwrap();
            assert!(matches!(
                gw.dispatch(&mut cube, &request),
                Err(ToolError::Denied(_))
            ));
            assert_eq!(
                std::fs::read_to_string(dir.join("src/data.txt")).unwrap(),
                "keep me"
            );
        }
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(log.matches("missing-content").count(), 2);
        gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "filesystem.write".into(),
                path: "src/data.txt".into(),
                content: Some(String::new()),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("src/data.txt")).unwrap().len(),
            0
        );
        aivm_audit::clear_flags(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unsupported_guest_secret_injection_preserves_the_lease() {
        for (level, rule) in [
            (SandboxLevel::MicroVm, "secret-unsupported-microvm"),
            (SandboxLevel::Hardware, "secret-unsupported-hardware"),
        ] {
            let (mut gw, mut cube, dir) = secret_harness();
            let response = gw
                .dispatch(
                    &mut cube,
                    &ToolRequest {
                        tool: "secret.request".into(),
                        path: "-".into(),
                        content: Some(secret_body("process.exec", "test_token", "read", "low")),
                    },
                )
                .unwrap();
            let value: serde_json::Value = serde_json::from_str(&response.output).unwrap();
            let id = value["lease_id"].as_str().unwrap();
            gw.level = level;
            let result = gw.dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "process.exec".into(),
                    path: "/bin/true".into(),
                    content: Some(serde_json::json!({"argv": [], "secret": id}).to_string()),
                },
            );
            assert!(matches!(result, Err(ToolError::Denied(_))));
            let broker = gw.secret_broker_mut().unwrap();
            assert_eq!(broker.get_lease(id).unwrap().uses, 0);
            assert_eq!(broker.use_lease(id).unwrap(), "TOP-SECRET-XYZ");
            assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
                .unwrap()
                .contains(rule));
            aivm_audit::clear_flags(&dir);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

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
    fn file_reads_are_cached_and_writes_are_idempotent() {
        let (mut gw, mut cube, dir) = harness();
        let path = dir.join("src/cache.txt");
        std::fs::write(&path, "original").unwrap();

        assert_eq!(
            gw.read(&mut cube, "src/cache.txt").unwrap().output,
            "original"
        );
        // An agent run reuses what it already loaded, even if an out-of-band
        // change occurs. Mediated writes and process execution invalidate it.
        std::fs::write(&path, "external change").unwrap();
        assert_eq!(
            gw.read(&mut cube, "src/cache.txt").unwrap().output,
            "original"
        );

        let changed = gw.write(&mut cube, "src/cache.txt", "original").unwrap();
        assert_eq!(changed.output, "written");
        let unchanged = gw.write(&mut cube, "src/cache.txt", "original").unwrap();
        assert_eq!(unchanged.output, "unchanged");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");

        gw.write(&mut cube, "src/cache.txt", "updated").unwrap();
        assert_eq!(
            gw.read(&mut cube, "src/cache.txt").unwrap().output,
            "updated"
        );
        std::fs::remove_dir_all(dir).unwrap();
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

    // harness สำหรับ secrets: broker + นโยบาย allow แคบ + secret ค่าปลอม
    // (+ execute cap สำหรับ /usr/bin/printenv ไว้พิสูจน์ injection —
    // `env` ตรง ๆ โดน interpreter denylist ถูกต้องแล้ว)
    fn secret_harness() -> (ToolGateway, Cube, PathBuf) {
        let (mut gw, cube, dir) = exec_harness();
        let env_real = std::fs::canonicalize("/usr/bin/printenv")
            .unwrap()
            .to_string_lossy()
            .to_string();
        gw.policy.process.allow.push(env_real.clone());
        gw.caps.grant(aivm_capability::Capability::new(
            "execute", "process", &env_real,
        ));
        let mut broker = aivm_secrets::SecretBroker::new(
            aivm_secrets::SecretPolicy {
                low_risk_allow: vec!["*".into()],
                allow: vec!["test_token:read".into(), "test_token:write".into()],
                deny: vec![],
                hitl_required_for: vec![aivm_secrets::RiskLevel::High],
                max_ttl_seconds: 3600,
                max_uses_allowed: 5,
            },
            None,
        );
        broker.register_secret("test_token".into(), "TOP-SECRET-XYZ".into());
        let mut gw = gw.with_secret_broker(broker);
        for scope in ["test_token:read", "test_token:write"] {
            gw.caps
                .grant(aivm_capability::Capability::new("use", "secret", scope));
        }
        (gw, cube, dir)
    }

    fn secret_body(tool: &str, resource: &str, scope: &str, risk: &str) -> String {
        serde_json::json!({
            "tool": tool,
            "resource": resource,
            "scope": scope,
            "purpose": "test",
            "risk": risk,
        })
        .to_string()
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

    #[test]
    fn exec_honors_capability_timeout_constraint() {
        let (mut gw, mut cube, _dir) = harness();
        let exe = std::fs::canonicalize("/bin/true").unwrap();
        let exe = exe.to_string_lossy().to_string();
        gw.policy.process.allow.push(exe.clone());
        gw.caps.grant(
            aivm_capability::Capability::new("execute", "process", &exe)
                .with_constraints(aivm_capability::Constraints::new().with_timeout_ms(1)),
        );
        assert!(matches!(
            gw.exec(&mut cube, &exe, &[]),
            Err(ToolError::Denied(_))
        ));
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

    // Level 3 (Hardware): ไม่ว่าเปิดฟีเจอร์หรือไม่ ต้อง DENY พร้อม audit
    // ไม่มีฟีเจอร์ = Disabled (level-disabled); มีฟีเจอร์ + config default
    // (= `None`) = Invalid ตั้งแต่ artifact หาย (level-invalid) — deny +
    // audit เหมือนกัน (I-7)
    #[test]
    fn exec_denied_on_hardware_level_with_audit() {
        let (mut gw, mut cube, dir) = exec_harness();
        gw.level = SandboxLevel::Hardware;
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
        assert!(
            log.contains("level-disabled") || log.contains("level-invalid"),
            "ต้อง audit การ deny ระดับ hardware"
        );
        assert!(log.contains("\"decision\":\"deny\""));
    }

    // Level 3 (ฟีเจอร์ hardware): artifact ปลอมต้อง DENY พร้อม audit
    // (deterministic ทุกเครื่อง — supply chain ตายก่อนถึงขั้น launch)
    #[cfg(feature = "hardware")]
    #[test]
    fn exec_with_tampered_hardware_artifact_denied_with_audit() {
        let (mut gw, mut cube, dir) = exec_harness();
        let kern = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kern, b"k").unwrap();
        std::fs::write(&rootfs, b"r").unwrap();
        gw.level = SandboxLevel::Hardware;
        gw.hardware_cfg = Some(aivm_sandbox::hardware::HardwareConfig {
            kernel_path: kern,
            // hash ผิดเจตนา (ของจริงคือ sha256 ของ b"k")
            kernel_sha256: "00".repeat(32),
            rootfs_path: rootfs,
            rootfs_sha256: "11".repeat(32),
            tee_type: aivm_sandbox::hardware::TeeType::Generic,
            attestation_mode: aivm_sandbox::hardware::AttestationMode::None,
            ..aivm_sandbox::hardware::HardwareConfig::default()
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
        assert!(
            log.contains("verdict:clean:no-interference-evidence"),
            "deny ตั้งแต่ประตูต้องลง verdict: {log}"
        );
    }

    #[test]
    fn container_prerequisite_denial_is_audited() {
        let (mut gw, mut cube, dir) = exec_harness();
        gw.level = SandboxLevel::Container;
        gw.container_cfg.bubblewrap = dir.join("missing-bwrap");
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            },
        );
        assert!(
            matches!(r, Err(ToolError::Denied(ref msg)) if msg.contains("container prerequisites"))
        );
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("level-disabled"));
        assert!(log.contains("\"decision\":\"deny\""));
        assert!(log.contains("verdict:clean"));
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

    // G4: secret.request low-risk ออก lease ให้ (คืนแต่ id + metadata —
    // value ห้ามปรากฏทั้งใน output และ audit)
    #[test]
    fn secret_request_issues_lease_without_value() {
        let (mut gw, mut cube, dir) = secret_harness();
        let r = gw
            .dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "secret.request".into(),
                    path: "-".into(),
                    content: Some(secret_body("process.exec", "test_token", "read", "low")),
                },
            )
            .unwrap();
        assert!(r.ok);
        assert_eq!(r.decision, "allow");
        let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
        let lease_id = v["lease_id"].as_str().expect("ต้องมี lease_id");
        assert!(!lease_id.is_empty());
        assert!(
            !r.output.contains("TOP-SECRET-XYZ"),
            "value ห้ามกลับไป AI context"
        );
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("lease-issued"));
        assert!(!log.contains("TOP-SECRET-XYZ"), "value ห้ามลง audit");
    }

    // G4: high-risk ไม่มี approval = DENY + audit hitl-required
    #[test]
    fn secret_request_high_risk_denies_hitl() {
        let (mut gw, mut cube, dir) = secret_harness();
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(secret_body("process.exec", "test_token", "write", "high")),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("hitl-required"));
    }

    // G4: schema ผิด = DENY (non-JSON, ขาดฟิลด์, เกินฟิลด์, tool ผิด)
    #[test]
    fn secret_request_malformed_denies() {
        let (mut gw, mut cube, dir) = secret_harness();
        let bad = vec![
            "not json".to_string(),
            serde_json::json!({"tool": "process.exec"}).to_string(),
            serde_json::json!({
                "tool": "process.exec", "resource": "test_token", "scope": "read",
                "purpose": "t", "risk": "low", "extra": 1,
            })
            .to_string(),
            secret_body("network.fetch", "test_token", "read", "low"),
        ];
        for b in &bad {
            let r = gw.dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "secret.request".into(),
                    path: "-".into(),
                    content: Some(b.clone()),
                },
            );
            assert!(matches!(r, Err(ToolError::Denied(_))), "ต้อง deny: {b}");
        }
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"decision\":\"deny\""));
    }

    // G4: ไม่มี broker = DENY (fail-closed ไม่มีทางเงียบผ่าน)
    #[test]
    fn secret_request_unconfigured_denies() {
        let (mut gw, mut cube, dir) = exec_harness();
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(secret_body("process.exec", "test_token", "read", "low")),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("secret-unconfigured"));
    }

    // G4: exec แนบ lease ฉีด secret เข้า child env (อ่านค่าผ่าน printenv)
    // แต่ audit ต้องไม่มีค่า + lease ใช้ซ้ำไม่ได้ (one-time)
    #[test]
    fn secret_exec_injects_and_redacts_and_burns() {
        let (mut gw, mut cube, dir) = secret_harness();
        let r = gw
            .dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "secret.request".into(),
                    path: "-".into(),
                    content: Some(secret_body("process.exec", "test_token", "read", "low")),
                },
            )
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
        let lease_id = v["lease_id"].as_str().unwrap().to_string();
        // คีย์ env ตาม SecretInjector (resource/scope ตัวใหญ่ _ แทน -/:)
        let key = "AIVM_SECRET_TEST_TOKEN_READ";
        let run = |gw: &mut ToolGateway, cube: &mut Cube, lease: Option<String>| {
            gw.dispatch(
                cube,
                &ToolRequest {
                    tool: "process.exec".into(),
                    path: "/usr/bin/printenv".into(),
                    content: Some(serde_json::json!({"argv": [key], "secret": lease}).to_string()),
                },
            )
        };
        // ครั้งแรก: inject สำเร็จ เห็นค่าใน stdout
        let r = run(&mut gw, &mut cube, Some(lease_id.clone())).unwrap();
        assert!(r.ok);
        assert_eq!(
            r.output, "[REDACTED]",
            "output ของ secret consumer ต้องไม่เข้าบริบทโมเดล"
        );
        // ใช้ซ้ำ: one-time lease หมดแล้ว
        let r = run(&mut gw, &mut cube, Some(lease_id));
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("lease-exhausted"));
        // audit ทั้งไฟล์ต้องไม่มีค่า secret เลย
        assert!(!log.contains("TOP-SECRET-XYZ"), "value ห้ามลง audit เด็ดขาด");
    }

    // G4: exec ไม่แนบ lease = ไม่มี secret ใน env (ไม่รั่วข้าม run)
    // (printenv ตัวแปรที่ไม่มี exit 1 — decision ต้อง allow แต่ output ว่าง)
    #[test]
    fn secret_exec_without_lease_has_no_secret() {
        let (mut gw, mut cube, _d) = secret_harness();
        let r = gw
            .dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "process.exec".into(),
                    path: "/usr/bin/printenv".into(),
                    content: Some(
                        serde_json::json!({"argv": ["AIVM_SECRET_TEST_TOKEN_READ"]}).to_string(),
                    ),
                },
            )
            .unwrap();
        assert_eq!(r.decision, "allow");
        assert!(!r.output.contains("TOP-SECRET-XYZ"));
    }

    // G4: exec แนบ secret ระดับ microvm = DENY (inject ไม่ได้ — ไม่เงียบทิ้ง)
    #[test]
    fn secret_exec_microvm_level_denies() {
        let (mut gw, mut cube, dir) = secret_harness();
        gw.level = SandboxLevel::MicroVm;
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some(serde_json::json!({"argv": [], "secret": "lease-xyz"}).to_string()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("secret-unsupported-microvm"));
    }

    // regression: search/RAG ต้องไม่คืนไฟล์ที่ policy ห้ามอ่าน
    #[test]
    fn search_and_context_respect_file_denials() {
        let (mut gw, mut cube, dir) = harness();
        std::fs::write(dir.join("private.txt"), "PRIVATE-REGRESSION").unwrap();
        gw.policy
            .filesystem
            .deny
            .push(dir.join("private.txt").display().to_string());
        assert!(gw.read(&mut cube, "private.txt").is_err());
        assert!(!gw
            .search(&mut cube, "PRIVATE-REGRESSION")
            .unwrap()
            .output
            .contains("PRIVATE-REGRESSION"));
        assert!(!gw
            .context_files(&mut cube)
            .unwrap()
            .iter()
            .any(|(_, text)| text.contains("PRIVATE-REGRESSION")));
    }

    #[test]
    fn audit_failure_prevents_write() {
        let (mut gw, mut cube, dir) = harness();
        aivm_audit::clear_flags(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            gw.write(&mut cube, "src/blocked.rs", "x"),
            Err(ToolError::Audit(_))
        ));
        assert!(!dir.join("src/blocked.rs").exists());
    }

    #[test]
    fn file_size_constraints_apply_to_reads_and_writes() {
        let (mut gw, mut cube, dir) = harness();
        std::fs::write(dir.join("src/large.rs"), "too large").unwrap();
        for cap in &mut gw.caps.caps {
            cap.constraints.max_bytes = Some(1);
        }
        assert!(gw.read(&mut cube, "src/large.rs").is_err());
        assert!(gw.write(&mut cube, "src/new.rs", "too large").is_err());
        assert!(!dir.join("src/new.rs").exists());
    }

    #[test]
    fn consumed_read_bytes_are_checkpointed_before_returning_content() {
        let (mut gw, mut cube, dir) = harness();
        let path = gw.workspace.join("src/budget.txt");
        std::fs::write(&path, "123456").unwrap();
        gw.state_path = Some(dir.join("state.json"));
        let read_cap = gw
            .caps
            .caps
            .iter_mut()
            .find(|cap| cap.action == "read")
            .unwrap();
        read_cap.constraints.max_total_bytes = Some(100);

        assert_eq!(
            gw.read(&mut cube, "src/budget.txt").unwrap().output,
            "123456"
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
        let saved_cap = saved["caps"]["caps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cap| cap["action"] == "read")
            .unwrap();
        assert_eq!(saved_cap["used_bytes"], 6);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn network_constraints_cannot_be_skipped_when_quota_exhausts() {
        let (mut gw, mut cube, _) = harness();
        gw.policy.network.allow = vec!["example.com".into()];
        gw.policy.require_test_before_network = false;
        gw.caps.grant(
            Capability::new("network:connect", "network", "example.com:443")
                .with_max_uses(1)
                .with_constraints(aivm_capability::Constraints::new().with_max_bytes(1)),
        );
        let result = gw.network_fetch(
            &mut cube,
            "https://example.com/",
            Some(r#"{"method":"POST","body":"xx"}"#),
        );
        assert!(matches!(result, Err(ToolError::Denied(_))));
        let cap = gw
            .caps
            .caps
            .iter()
            .find(|c| c.resource == "network")
            .unwrap();
        assert_eq!(cap.used_count, 0, "constraint ต้องตรวจครบก่อน consume/ส่งข้อมูล");
    }

    #[test]
    fn private_network_destinations_and_unknown_schema_are_denied() {
        for host in ["127.0.0.2", "10.1.2.3", "::ffff:127.0.0.1", "::1"] {
            assert!(public_addresses(host, 443).is_err());
        }
        assert!(parse_url("file:///etc/passwd").is_err());
        assert!(parse_url("https://user:pass@example.com/").is_err());
        assert!(serde_json::from_str::<NetworkFetchRequest>(r#"{"redirects":true}"#).is_err());
        assert_eq!(parse_host_port("[::1]:443").unwrap(), ("::1".into(), 443));
    }
    #[test]
    fn exhausted_capability_cannot_supply_larger_file_constraints() {
        let (mut gw, mut cube, dir) = harness();
        std::fs::write(dir.join("src/large.rs"), "large").unwrap();
        let scope = dir.display().to_string();
        gw.caps = CapabilitySet::new(vec![
            Capability::new("read", "filesystem", &scope)
                .with_max_uses(1)
                .with_constraints(aivm_capability::Constraints::new().with_max_bytes(1)),
            Capability::new("read", "filesystem", &scope)
                .with_max_uses(0)
                .with_constraints(aivm_capability::Constraints::new().with_max_bytes(100)),
        ]);
        assert!(gw.read(&mut cube, "src/large.rs").is_err());
    }
}
