//! Network gateway — spec §18.
//!
//! MVP-A: **no network**. This crate exists so the deny path is explicit
//! and testable: every request is denied until a later milestone adds an
//! allowlisted egress gateway. Fail-closed by construction.

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

    /// MVP-A always denies (no egress). Still evaluates policy so denials
    /// carry the correct rule label for audit.
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
