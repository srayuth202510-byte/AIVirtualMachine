//! ชั้น Sandbox — ดูสเปก §27.
//!
//! MVP-A: มีแค่ workspace แบบผ่านตัวกลาง (ห้าม spawn process)
//! MVP-B จะเติม namespaces/cgroups/seccomp ผ่าน interface ของ crate นี้
//! จนกว่าจะถึงตอนนั้น `Sandbox::spawn` ปฏิเสธแบบ fail-closed เสมอ

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("mvp-a: process execution disabled: {0}")]
    Disabled(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu: u32,
    pub memory_mb: u64,
    pub pids_max: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu: 2,
            memory_mb: 1024,
            pids_max: 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxLevel {
    Process,
    Container,
    MicroVm,
    Hardware,
}

pub struct Sandbox {
    pub level: SandboxLevel,
    pub limits: ResourceLimits,
}

impl Sandbox {
    pub fn new(level: SandboxLevel, limits: ResourceLimits) -> Self {
        Self { level, limits }
    }

    /// MVP-A: ปฏิเสธเสมอ ของจริงที่ isolate ระดับ OS มาใน MVP-B
    pub fn spawn(&self, _exe: &str, _args: &[String]) -> Result<(), SandboxError> {
        Err(SandboxError::Disabled(
            "arbitrary process execution is disabled in MVP-A; use mediated tools".into(),
        ))
    }
}
