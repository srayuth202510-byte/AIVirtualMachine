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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_yaml(
            r#"name: t
filesystem:
  deny: ['**/.env*']
process:
  deny: [/bin/sh]
network:
  allow: ['example.com']
  deny: ['evil.com', '10.0.0.0/8']
"#,
        )
        .unwrap()
    }

    fn req(host: &str, protocol: &str) -> NetworkRequest {
        NetworkRequest {
            host: host.into(),
            protocol: protocol.into(),
            port: 443,
        }
    }

    #[test]
    fn non_https_is_denied_before_policy() {
        let gw = NetworkGateway::new(policy());
        match gw.request(&req("example.com", "http"), &EvalContext::default()) {
            Err(NetworkError::Denied(m)) => assert_eq!(m, "protocol-not-https"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_allow_still_denied_in_mvp_a() {
        let gw = NetworkGateway::new(policy());
        match gw.request(&req("example.com", "https"), &EvalContext::default()) {
            Err(NetworkError::Denied(m)) => assert!(m.contains("mvp-a-no-egress"), "{m}"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_deny_reports_rule_label() {
        let gw = NetworkGateway::new(policy());
        match gw.request(&req("evil.com", "https"), &EvalContext::default()) {
            Err(NetworkError::Denied(m)) => assert!(m.contains("deny-list"), "{m}"),
            other => panic!("expected deny, got {other:?}"),
        }
    }
}
