//! Tool gateway — ดูสเปก §12, §16, §17 + MVP-B (Phase 4).
//!
//! เครื่องมือที่ผ่านตัวกลาง: `filesystem.read / write / search` และ
//! `process.exec` (เฉพาะ exe ที่ allowlist + มี execute capability +
//! ได้ grant ตาม state) และ network.fetch/network.connect ภายใต้ policy/quotas
//! ไม่มี shell หรือการรันที่ข้าม gateway
//! ทุกคำขอเดินตามสาย: canonicalize -> capability -> policy ->
//! execute -> audit fail-closed ทุกขั้น กัน TOCTOU ด้วย realpath + ตรวจซ้ำ
//!
//! หมายเหตุเรื่อง subprocess tree: hardening ใน pre_exec (no-new-privs,
//! rlimit, env ที่ล้างแล้ว, hybrid seccomp แบบ default-kill) ตกทอดไป child ที่ fork/exec ต่อ
//! โดยอัตโนมัติ; pdeathsig ตั้งที่ child ตรงแล้วตั้งซ้ำในหลานที่เป็น PID 1
//! (ค่าถูกล้างตอน fork) การกัก tree ด้วย PID/mount/net namespace ทำแบบ
//! best-effort พร้อมรายงาน applied/degraded อย่างซื่อสัตย์ — เปิด
//! compiler/test runner ได้เพราะประตู + adversarial คุม ไม่ใช่เพราะกัก
//! tree สมบูรณ์แล้ว

use aivm_audit::AuditWriter;
use aivm_capability::CapabilitySet;
use aivm_policy::Policy;
use aivm_sandbox::{ResourceLimits, SandboxLevel};
use aivm_secrets::SecretBroker;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

mod api;
pub mod build;
pub mod contracts;
mod deny_tracker;
mod filesystem;
mod gateway;
mod network;
mod process;
mod registry;
mod secrets;
mod secure_fs;
pub mod state_store;
pub mod verification;

pub use api::{ExecContent, SecretRequestBody, ToolError, ToolRequest, ToolResult};
pub use deny_tracker::DenyTracker;
pub use registry::{
    AuditError, AuditEvent, AuditSink, CapabilityRequirement, LocalJsonlSink, Tool, ToolRegistry,
    ToolSchema,
};

/// Runtime เรียกตอนถือ VM lease ก่อนรับงาน; ไม่เป็น tool ที่โมเดลเรียกได้
pub fn recover_workspace_writes(workspace: &Path) -> Result<usize, ToolError> {
    secure_fs::recover_pending(workspace)
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
    /// config Hardware Isolation (TEE pins + quota) ใช้เมื่อเปิดฟีเจอร์
    /// `hardware` และ `level` เป็น Hardware เท่านั้น — ไม่มี config
    /// (= `None`) จะใช้ค่า default ที่ deny ตั้งแต่ artifact หาย
    #[cfg(feature = "hardware")]
    pub hardware_cfg: Option<aivm_sandbox::hardware::HardwareConfig>,
    pub container_cfg: aivm_sandbox::container::ContainerConfig,
    pub limits: ResourceLimits,
    pub state_path: Option<PathBuf>,
    pub build: build::BuildConfig,
    pub verifier: Option<verification::VerifierConfig>,
    blocked: bool,
    req_counter: u64,
    deny_tracker: DenyTracker,
    /// File contents read during the current agent run. Authorization and audit
    /// still happen on every request; writes and process execution invalidate it.
    read_cache: HashMap<PathBuf, String>,
    active_task: Option<contracts::TaskContract>,
    last_outcome: Option<(contracts::TaskContract, contracts::TaskOutcome)>,
    issued_verifications: HashMap<String, verification::VerificationRecord>,
    /// Secret broker (G4 §26): `None` = ไม่ตั้งค่า → `secret.request` และ
    /// exec แบบแนบ secret ถูก DENY (fail-closed ไม่มีทางเงียบผ่าน)
    secret_broker: Option<SecretBroker>,
}

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod tests;
