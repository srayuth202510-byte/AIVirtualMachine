//! โมเดล Capability — ดูสเปก §10.
//!
//! สิทธิ์แบบละเอียดยิบตามหลัก least-privilege โดยค่าเริ่มต้นคือปฏิเสธ
//! ทุกอย่าง (default deny): ทุก action เริ่มจาก DENY มีเพียง capability
//! ที่ระบุชัด ยังไม่หมดอายุ และใช้ไม่เกินโควต้าเท่านั้นจึงจะ ALLOW
//! (invariants I-2, I-6, I-8).

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

/// action พื้นฐานตามสเปก §10.1
pub mod actions {
    pub const READ: &str = "read";
    pub const WRITE: &str = "write";
    pub const EXECUTE: &str = "execute";
    pub const NETWORK: &str = "network";
    pub const NETWORK_CONNECT: &str = "network:connect";
    pub const NETWORK_FETCH: &str = "network:fetch";
    pub const NETWORK_LISTEN: &str = "network:listen";
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
    /// ตัวอย่างเช่น protocol == https, state == VALIDATE (MVP: เก็บแบบ opaque)
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub require_state: Option<String>,
    /// state ที่ capability นี้ยังใช้ได้ (ดูสเปก §14.3 เรื่อง re-evaluation)
    /// ถ้าว่างเปล่า = ใช้ได้ทุก state (สิทธิ์พื้นฐานอย่าง read/search)
    #[serde(default)]
    pub valid_states: Vec<String>,
}

/// Constraints เพิ่มเติมสำหรับ Capability (Phase 1)
/// รองรับการจำกัดขนาดข้อมูล จำนวนครั้ง และ timeout
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Constraints {
    /// จำกัดขนาดข้อมูลสูงสุด (bytes) สำหรับ read/write
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// จำกัดจำนวนครั้งที่เรียกใช้งาน (แยกจาก max_uses ที่เป็น quota)
    #[serde(default)]
    pub max_calls: Option<u32>,
    /// จำกัดเวลารอสูงสุด (milliseconds)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Network-specific: allowed protocols (http, https)
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    /// Network-specific: allowed ports
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    /// Network-specific: max response size
    #[serde(default)]
    pub max_response_bytes: Option<u64>,
    /// Network-specific: require TLS
    #[serde(default)]
    pub require_tls: bool,
}

impl Constraints {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = Some(bytes);
        self
    }

    pub fn with_max_calls(mut self, calls: u32) -> Self {
        self.max_calls = Some(calls);
        self
    }

    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Network constraint builders
    pub fn with_allowed_protocols(mut self, protocols: Vec<String>) -> Self {
        self.allowed_protocols = protocols;
        self
    }

    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = ports;
        self
    }

    pub fn with_max_response_bytes(mut self, bytes: u64) -> Self {
        self.max_response_bytes = Some(bytes);
        self
    }

    pub fn with_require_tls(mut self, require: bool) -> Self {
        self.require_tls = require;
        self
    }
}

impl Condition {
    /// เช็กความสดแบบ fail-closed: lease ที่ผูกกับ state ไว้
    /// จะถือว่า stale ทันทีเมื่ออยู่ state อื่น
    pub fn is_stale_in(&self, state: &str) -> bool {
        if !self.valid_states.is_empty() && !self.valid_states.iter().any(|s| s == state) {
            return true;
        }
        if let Some(req) = &self.require_state {
            return req != state;
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub action: String,
    pub resource: String,
    pub scope: String,
    #[serde(default)]
    pub condition: Option<Condition>,
    /// Constraints เพิ่มเติม: max_bytes, max_calls, timeout_ms
    #[serde(default)]
    pub constraints: Constraints,
    /// timestamp แบบ Unix (วินาที) None = ไม่หมดอายุ
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
            constraints: Constraints::default(),
            expiration: None,
            max_uses: None,
            used_count: 0,
        }
    }

    pub fn with_constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = constraints;
        self
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

    /// เช็กแบบ fail-closed: หมดอายุหรือใช้เกินโควต้าแล้วจะได้ Err (DENY)
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

    /// ตรวจสอบ constraints (max_bytes, max_calls, timeout_ms, network constraints)
    pub fn check_constraints(
        &self,
        request_bytes: Option<u64>,
        call_count: Option<u32>,
        protocol: Option<&str>,
        port: Option<u16>,
        response_bytes: Option<u64>,
    ) -> Result<(), CapabilityError> {
        if let Some(max_bytes) = self.constraints.max_bytes {
            if let Some(bytes) = request_bytes {
                if bytes > max_bytes {
                    return Err(CapabilityError::BudgetExceeded(max_bytes));
                }
            }
        }
        if let Some(max_calls) = self.constraints.max_calls {
            if let Some(count) = call_count {
                if count > max_calls {
                    return Err(CapabilityError::BudgetExceeded(max_calls as u64));
                }
            }
        }
        // Network constraints
        if !self.constraints.allowed_protocols.is_empty() {
            if let Some(proto) = protocol {
                if !self
                    .constraints
                    .allowed_protocols
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(proto))
                {
                    return Err(CapabilityError::ScopeMismatch(
                        format!("protocol not allowed: {}", proto),
                        "protocol".into(),
                    ));
                }
            } else {
                return Err(CapabilityError::ScopeMismatch(
                    "protocol required but not provided".into(),
                    "protocol".into(),
                ));
            }
        }
        if !self.constraints.allowed_ports.is_empty() {
            if let Some(p) = port {
                if !self.constraints.allowed_ports.contains(&p) {
                    return Err(CapabilityError::ScopeMismatch(
                        format!("port not allowed: {}", p),
                        "port".into(),
                    ));
                }
            } else {
                return Err(CapabilityError::ScopeMismatch(
                    "port required but not provided".into(),
                    "port".into(),
                ));
            }
        }
        if self.constraints.require_tls {
            if let Some(proto) = protocol {
                if !proto.eq_ignore_ascii_case("https") {
                    return Err(CapabilityError::ScopeMismatch(
                        "TLS required but protocol is not https".into(),
                        "protocol".into(),
                    ));
                }
            } else {
                return Err(CapabilityError::ScopeMismatch(
                    "TLS required but protocol not specified".into(),
                    "protocol".into(),
                ));
            }
        }
        if let Some(max_resp) = self.constraints.max_response_bytes {
            if let Some(resp_bytes) = response_bytes {
                if resp_bytes > max_resp {
                    return Err(CapabilityError::BudgetExceeded(max_resp));
                }
            }
        }
        Ok(())
    }

    /// capability นี้ครอบคลุม (action, resource, scope) ที่ขอมาหรือไม่?
    /// การเทียบ scope: เทียบ prefix ตรง ๆ บน canonical path หรือ
    /// แบบ glob ลงท้าย `/**` (ความหมายแบบ workspace)
    pub fn covers(&self, action: &str, resource: &str, scope: &str) -> bool {
        if self.action != action || self.resource != resource {
            return false;
        }
        scope_covers(&self.scope, scope)
    }

    /// อนุมัติการใช้งานหนึ่งครั้ง: ตรวจว่ายังใช้ได้ + ครอบคลุม แล้วเพิ่มตัวนับ
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
        // ตรวจสอบ max_calls constraint (network params not available here, checked in PolicyEvaluator)
        self.check_constraints(None, Some(self.used_count as u32 + 1), None, None, None)?;
        self.used_count += 1;
        Ok(())
    }
}

/// `/workspace` ครอบคลุม `/workspace/src/main.rs` แต่ไม่คลุม `/workspace2` หรือ `/etc`
/// scope ที่ลงท้าย `/**` หรือ `/*` ถือเป็น prefix นอกนั้นต้องตรงกันพอดีหรือเป็น prefix แบบไดเรกทอรี
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

/// ชุด capability ที่ตัดสินแบบ deny-by-default (สเปก §10.3, §14)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub caps: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new(caps: Vec<Capability>) -> Self {
        Self { caps }
    }

    /// หา capability ที่ยังใช้ได้และครอบคลุมคำขอ (mutable เพราะต้องนับการใช้)
    /// สำเร็จคืน index ถ้าไม่เจอคือ DENY (fail-closed: None หมายถึง DENY)
    pub fn authorize(
        &mut self,
        action: &str,
        resource: &str,
        scope: &str,
    ) -> Result<usize, CapabilityError> {
        // ลองทีละใบ ใบแรกที่ผ่านทั้ง usability + coverage ชนะ ข้ามใบที่หมดอายุ/หมดโควต้า
        let mut mismatch: Option<CapabilityError> = None;
        for (i, cap) in self.caps.iter_mut().enumerate() {
            if cap.check_usable().is_err() {
                continue;
            }
            match cap.authorize(action, resource, scope) {
                Ok(()) => return Ok(i),
                Err(e) => {
                    // ไม่ต้อง undo: authorize เพิ่มตัวนับเฉพาะตอนสำเร็จ
                    // หมายเหตุ: ผ่าน check_usable แล้วแต่ covers ไม่ผ่าน
                    mismatch = Some(e);
                }
            }
        }
        Err(mismatch.unwrap_or(CapabilityError::Mismatch))
    }

    /// เพิกถอนใบที่ condition ผูกกับ state ที่เราไม่ได้อยู่แล้ว (§14.3)
    pub fn revoke_where(&mut self, pred: impl Fn(&Capability) -> bool) -> usize {
        let before = self.caps.len();
        self.caps.retain(|c| !pred(c));
        before - self.caps.len()
    }

    /// ทิ้ง lease ที่ผูกกับ state ทุกใบที่ stale ใน `state`
    /// สิทธิ์พื้นฐาน (ไม่มี condition / valid_states ว่าง) รอดเสมอ
    pub fn revoke_stale(&mut self, state: &str) -> usize {
        self.revoke_where(|c| match &c.condition {
            Some(cond) => cond.is_stale_in(state),
            None => false,
        })
    }

    /// ให้สิทธิ์แบบ idempotent: ข้ามถ้ามีใบที่ใช้ได้ครอบคลุมอยู่แล้ว
    /// คืน true เมื่อเพิ่ม lease ใหม่จริง
    pub fn grant(&mut self, cap: Capability) -> bool {
        let usable_exists = self
            .caps
            .iter()
            .any(|c| c.check_usable().is_ok() && c.covers(&cap.action, &cap.resource, &cap.scope));
        if usable_exists {
            return false;
        }
        self.caps.push(cap);
        true
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
        let mut cap = Capability::new("read", "filesystem", "/workspace").with_expiration(0);
        // บังคับให้หมดอายุ
        cap.expiration = Some(1);
        assert!(matches!(cap.check_usable(), Err(CapabilityError::Expired)));
    }

    #[test]
    fn max_uses_enforced() {
        let mut cap = Capability::new("secret", "github_token", "repo:write").with_max_uses(1);
        assert!(cap
            .authorize("secret", "github_token", "repo:write")
            .is_ok());
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

    fn lease(action: &str, states: &[&str]) -> Capability {
        let mut c = Capability::new(action, "filesystem", "/workspace/src");
        c.condition = Some(Condition {
            protocol: None,
            require_state: None,
            valid_states: states.iter().map(|s| s.to_string()).collect(),
        });
        c
    }

    #[test]
    fn stale_lease_revoked_on_state_exit() {
        let mut set = CapabilitySet::new(vec![
            Capability::new("read", "filesystem", "/workspace"),
            lease("write", &["MODIFY", "VALIDATE"]),
        ]);
        assert!(set
            .authorize("write", "filesystem", "/workspace/src/a.rs")
            .is_ok());
        assert_eq!(set.revoke_stale("VALIDATE"), 0);
        assert!(set
            .authorize("write", "filesystem", "/workspace/src/a.rs")
            .is_ok());
        assert_eq!(set.revoke_stale("ANALYZE"), 1);
        assert!(set
            .authorize("write", "filesystem", "/workspace/src/a.rs")
            .is_err());
        // สิทธิ์พื้นฐานรอดทุก transition
        assert!(set
            .authorize("read", "filesystem", "/workspace/a.rs")
            .is_ok());
    }

    #[test]
    fn grant_is_idempotent() {
        let mut set = CapabilitySet::default();
        assert!(set.grant(lease("write", &["MODIFY"])));
        assert!(!set.grant(lease("write", &["MODIFY"])));
        assert_eq!(set.caps.len(), 1);
    }

    #[test]
    fn expired_lease_is_not_regranted_as_usable() {
        let mut set = CapabilitySet::default();
        let mut c = lease("write", &["MODIFY"]);
        c.expiration = Some(1); // หมดอายุไปนานแล้ว
        set.caps.push(c);
        // ใบที่หมดอายุไม่ขวางการให้สิทธิ์ใหม่
        assert!(set.grant(lease("write", &["MODIFY"])));
        assert!(set
            .authorize("write", "filesystem", "/workspace/src/a.rs")
            .is_ok());
    }

    #[test]
    fn constraints_max_bytes_enforced() {
        let cap = Capability::new("write", "filesystem", "/workspace/src")
            .with_constraints(Constraints::new().with_max_bytes(100));
        // ข้อมูลเล็กกว่าขีดจำกัด = OK
        assert!(cap
            .check_constraints(Some(50), None, None, None, None)
            .is_ok());
        // ข้อมูลใหญ่กว่าขีดจำกัด = DENY
        assert!(matches!(
            cap.check_constraints(Some(200), None, None, None, None),
            Err(CapabilityError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn constraints_max_calls_enforced() {
        let cap = Capability::new("read", "filesystem", "/workspace")
            .with_constraints(Constraints::new().with_max_calls(2));
        // เรียกครั้งที่ 1 = OK
        assert!(cap
            .check_constraints(None, Some(1), None, None, None)
            .is_ok());
        // เรียกครั้งที่ 2 = OK
        assert!(cap
            .check_constraints(None, Some(2), None, None, None)
            .is_ok());
        // เรียกครั้งที่ 3 = DENY
        assert!(matches!(
            cap.check_constraints(None, Some(3), None, None, None),
            Err(CapabilityError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn authorize_respects_max_calls_constraint() {
        let mut cap = Capability::new("read", "filesystem", "/workspace")
            .with_constraints(Constraints::new().with_max_calls(2));
        // ครั้งที่ 1
        assert!(cap
            .authorize("read", "filesystem", "/workspace/a.rs")
            .is_ok());
        // ครั้งที่ 2
        assert!(cap
            .authorize("read", "filesystem", "/workspace/b.rs")
            .is_ok());
        // ครั้งที่ 3 = DENY
        assert!(matches!(
            cap.authorize("read", "filesystem", "/workspace/c.rs"),
            Err(CapabilityError::BudgetExceeded(_))
        ));
    }
}
