//! Capability model — spec §10.
//!
//! Granular least-privilege permissions. Default deny: every action
//! starts DENY, only an explicit, non-expired, within-budget capability
//! allows it (invariants I-2, I-6, I-8).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability expired")]
    Expired,
    #[error("usage budget exceeded (max_uses={0})")]
    BudgetExceeded(u64),
    #[error("scope mismatch: capability scope '{0}' does not cover '{1}'")]
    ScopeMismatch(String, String),
    #[error("action/resource mismatch")]
    Mismatch,
}

/// Primitive actions from spec §10.1.
pub mod actions {
    pub const READ: &str = "read";
    pub const WRITE: &str = "write";
    pub const EXECUTE: &str = "execute";
    pub const NETWORK: &str = "network";
    pub const SPAWN: &str = "spawn";
    pub const GPU: &str = "gpu";
    pub const SECRET: &str = "secret";
    pub const DEPLOY: &str = "deploy";
    pub const DELETE: &str = "delete";
    pub const RENAME: &str = "rename";
    pub const MOUNT: &str = "mount";
    pub const SEARCH: &str = "search";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Condition {
    /// e.g. protocol == https, state == VALIDATE. MVP: opaque map.
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub require_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub action: String,
    pub resource: String,
    pub scope: String,
    #[serde(default)]
    pub condition: Option<Condition>,
    /// Unix timestamp (secs). None = no expiry.
    #[serde(default)]
    pub expiration: Option<u64>,
    #[serde(default)]
    pub max_uses: Option<u64>,
    #[serde(default)]
    pub used_count: u64,
}

impl Capability {
    pub fn new(action: &str, resource: &str, scope: &str) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.to_string(),
            scope: scope.to_string(),
            condition: None,
            expiration: None,
            max_uses: None,
            used_count: 0,
        }
    }

    pub fn with_expiration(mut self, secs_from_now: u64) -> Self {
        self.expiration = Some(now_secs() + secs_from_now);
        self
    }

    pub fn with_max_uses(mut self, n: u64) -> Self {
        self.max_uses = Some(n);
        self
    }

    pub fn is_expired(&self) -> bool {
        match self.expiration {
            Some(exp) => now_secs() > exp,
            None => false,
        }
    }

    pub fn uses_remaining(&self) -> Option<u64> {
        self.max_uses.map(|m| m.saturating_sub(self.used_count))
    }

    /// Fail-closed check: expired or exhausted => Err (DENY).
    pub fn check_usable(&self) -> Result<(), CapabilityError> {
        if self.is_expired() {
            return Err(CapabilityError::Expired);
        }
        if let Some(max) = self.max_uses {
            if self.used_count >= max {
                return Err(CapabilityError::BudgetExceeded(max));
            }
        }
        Ok(())
    }

    /// Does this capability cover (action, resource, scope)?
    /// Scope matching: exact prefix match on canonical paths, or
    /// glob-style `/**` suffix (workspace semantics).
    pub fn covers(&self, action: &str, resource: &str, scope: &str) -> bool {
        if self.action != action || self.resource != resource {
            return false;
        }
        scope_covers(&self.scope, scope)
    }

    /// Authorize one use: verifies usability + coverage, then bumps counter.
    pub fn authorize(
        &mut self,
        action: &str,
        resource: &str,
        scope: &str,
    ) -> Result<(), CapabilityError> {
        self.check_usable()?;
        if !self.covers(action, resource, scope) {
            return Err(CapabilityError::ScopeMismatch(
                self.scope.clone(),
                scope.to_string(),
            ));
        }
        self.used_count += 1;
        Ok(())
    }
}

/// `/workspace` covers `/workspace/src/main.rs` but not `/workspace2` or `/etc`.
/// A scope ending in `/**` or `/*` is treated as prefix; otherwise exact-or-prefix-dir.
pub fn scope_covers(cap_scope: &str, requested: &str) -> bool {
    let base = cap_scope
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('/');
    let req = requested.trim_end_matches('/');
    if base.is_empty() || base == "*" {
        return true;
    }
    if req == base {
        return true;
    }
    req.starts_with(&format!("{base}/"))
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A set of capabilities with deny-by-default resolution (spec §10.3, §14).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub caps: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new(caps: Vec<Capability>) -> Self {
        Self { caps }
    }

    /// Find a usable capability covering the request (mutable for use-count).
    /// Returns index on success. Fail-closed: None means DENY.
    pub fn authorize(
        &mut self,
        action: &str,
        resource: &str,
        scope: &str,
    ) -> Result<usize, CapabilityError> {
        // Try each cap; first usable+covering wins. Skip expired/exhausted.
        let mut mismatch: Option<CapabilityError> = None;
        for (i, cap) in self.caps.iter_mut().enumerate() {
            if cap.check_usable().is_err() {
                continue;
            }
            match cap.authorize(action, resource, scope) {
                Ok(()) => return Ok(i),
                Err(e) => {
                    // Undo is not needed: authorize only bumps on success.
                    // But note check_usable passed then covers failed.
                    mismatch = Some(e);
                }
            }
        }
        Err(mismatch.unwrap_or(CapabilityError::Mismatch))
    }

    /// Revoke caps whose condition requires a state we no longer hold (§14.3).
    pub fn revoke_where(&mut self, pred: impl Fn(&Capability) -> bool) -> usize {
        let before = self.caps.len();
        self.caps.retain(|c| !pred(c));
        before - self.caps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deny_no_caps() {
        let mut set = CapabilitySet::default();
        assert!(set.authorize("read", "filesystem", "/workspace").is_err());
    }

    #[test]
    fn expiry_is_deny() {
        let mut cap = Capability::new("read", "filesystem", "/workspace")
            .with_expiration(0);
        // force expiry
        cap.expiration = Some(1);
        assert!(matches!(cap.check_usable(), Err(CapabilityError::Expired)));
    }

    #[test]
    fn max_uses_enforced() {
        let mut cap =
            Capability::new("secret", "github_token", "repo:write").with_max_uses(1);
        assert!(cap.authorize("secret", "github_token", "repo:write").is_ok());
        assert!(matches!(
            cap.authorize("secret", "github_token", "repo:write"),
            Err(CapabilityError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn scope_prefix_no_escape() {
        assert!(scope_covers("/workspace", "/workspace/src/a.rs"));
        assert!(!scope_covers("/workspace", "/workspace2/evil"));
        assert!(!scope_covers("/workspace", "/etc/passwd"));
    }
}
