//! Network gateway — ดูสเปก §18.
//!
//! MVP-A: **ไม่มีเน็ตเวิร์ก** crate นี้มีไว้เพื่อให้ทางปฏิเสธชัดแจ้ง
//! และเทสต์ได้: ทุกคำขอถูกปฏิเสธจนกว่า milestone หลังจะเพิ่ม
//! egress gateway แบบ allowlist fail-closed โดยโครงสร้าง

use aivm_policy::{EvalContext, Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("denied: {0}")]
    Denied(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRequest {
    pub host: String,
    pub protocol: String,
    pub port: u16,
}

pub struct NetworkGateway {
    policy: Policy,
}

impl NetworkGateway {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// MVP-A ปฏิเสธเสมอ (ไม่มี egress) แต่ยังประเมิน policy เพื่อให้
    /// เหตุผลปฏิเสธมีป้าย rule ที่ถูกต้องสำหรับ audit
    pub fn request(&self, req: &NetworkRequest, ctx: &EvalContext) -> Result<(), NetworkError> {
        if req.protocol != "https" {
            return Err(NetworkError::Denied("protocol-not-https".into()));
        }
        let (d, rule) = self.policy.evaluate_network(&req.host, ctx);
        match d {
            aivm_policy::Decision::Allow => Err(NetworkError::Denied(format!(
                "mvp-a-no-egress (policy would allow via {})",
                rule.unwrap_or_default()
            ))),
            aivm_policy::Decision::Deny => {
                Err(NetworkError::Denied(rule.unwrap_or("default-deny".into())))
            }
        }
    }
}
