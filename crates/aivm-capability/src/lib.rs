//! โมเดล Capability — ดูสเปก §10.
//!
//! สิทธิ์แบบละเอียดยิบตามหลัก least-privilege โดยค่าเริ่มต้นคือปฏิเสธ
//! ทุกอย่าง (default deny): ทุก action เริ่มจาก DENY มีเพียง capability
//! ที่ระบุชัด ยังไม่หมดอายุ และใช้ไม่เกินโควต้าเท่านั้นจึงจะ ALLOW
//! (invariants I-2, I-6, I-8).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability expired")]
    Expired,
    #[error("usage budget exceeded (max_uses={0})")]
    BudgetExceeded(u64),
    #[error("scope mismatch: capability scope '{0}' does not cover '{1}'")]
    ScopeMismatch(String, String),
    #[error("action/resource mismatch")]
    Mismatch,
    #[error("timeout constraint unsatisfiable (timeout_ms<={0})")]
    TimeoutUnmet(u64),
    #[error("capability constraint needs an AuthorizationContext that was not provided")]
    MissingContext,
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
    /// เพดานสะสม (bytes) ตลอดอายุ lease (กันดูดทีละน้อยแต่รวมกันมาก)
    #[serde(default)]
    pub max_total_bytes: Option<u64>,
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

    pub fn with_max_total_bytes(mut self, bytes: u64) -> Self {
        self.max_total_bytes = Some(bytes);
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
    /// ไบต์สะสมที่ใช้ไปแล้วตลอดอายุ lease (เทียบกับ max_total_bytes)
    #[serde(default)]
    pub used_bytes: u64,
}

/// ข้อมูลสำหรับตรวจ constraints และ consume สิทธิ์ครั้งเดียว
#[derive(Default)]
pub struct AuthorizationContext<'a> {
    pub request_bytes: Option<u64>,
    pub protocol: Option<&'a str>,
    pub port: Option<u16>,
    pub response_bytes: Option<u64>,
    pub timeout_ms: Option<u64>,
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
            used_bytes: 0,
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
        // เพดานสะสมหมดแล้ว = ใช้ไม่ได้อีก แม้ request 0 ไบต์
        if let Some(max) = self.constraints.max_total_bytes {
            if self.used_bytes >= max {
                return Err(CapabilityError::BudgetExceeded(max));
            }
        }
        Ok(())
    }

    /// บันทึกไบต์ที่ใช้จริงหลัง side effect (saturating กัน overflow)
    /// เรียกเฉพาะหลัง authorize สำเร็จเท่านั้น
    pub fn account_bytes(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_add(bytes);
    }

    pub fn bytes_remaining(&self) -> Option<u64> {
        self.constraints
            .max_total_bytes
            .map(|m| m.saturating_sub(self.used_bytes))
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
        // เพดานสะสม: request นี้จะล้นเพดาน = ปฏิเสธก่อน side effect
        if let Some(max) = self.constraints.max_total_bytes {
            let want = request_bytes.unwrap_or(0);
            if self.used_bytes.saturating_add(want) > max {
                return Err(CapabilityError::BudgetExceeded(max));
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
        if resource == "network" {
            if let (Some((allowed_host, allowed_port)), Some((host, port))) =
                (self.scope.rsplit_once(':'), scope.rsplit_once(':'))
            {
                if allowed_port != port {
                    return false;
                }
                if let Some(suffix) = allowed_host.strip_prefix("*.") {
                    return host.ends_with(&format!(".{suffix}")) && host.len() > suffix.len() + 1;
                }
                return allowed_host == host || allowed_host == "*";
            }
            return self.scope == scope;
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
        if self
            .constraints
            .max_calls
            .is_some_and(|max| self.used_count >= u64::from(max))
        {
            return Err(CapabilityError::BudgetExceeded(
                self.constraints.max_calls.unwrap() as u64,
            ));
        }
        // fail-closed: ไม่มี AuthorizationContext → constraint ที่ต้องใช้ค่าคำขอ
        // (max_bytes / timeout / response size) และ condition.protocol ตรวจไม่ได้
        // → ห้ามอนุมัติ (เดิมข้ามไปเงียบ ๆ = fail-open ของ API สาธารณะนี้)
        if self.constraints.max_bytes.is_some()
            || self.constraints.timeout_ms.is_some()
            || self.constraints.max_response_bytes.is_some()
        {
            return Err(CapabilityError::MissingContext);
        }
        if self
            .condition
            .as_ref()
            .is_some_and(|c| c.protocol.is_some())
        {
            return Err(CapabilityError::MissingContext);
        }
        self.check_constraints(None, None, None, None, None)?;
        self.used_count += 1;
        Ok(())
    }
}

/// `/workspace` ครอบคลุม `/workspace/src/main.rs` แต่ไม่คลุม `/workspace2` หรือ `/etc`
/// scope ที่ลงท้าย `/**` หรือ `/*` ถือเป็น prefix นอกนั้นต้องตรงกันพอดีหรือเป็น prefix แบบไดเรกทอรี
/// fail-closed: ปิด path ที่มี component `.`/`..`ทั้งสองฝั่ง เพราะ capability
/// layer ไม่ได้ canonicalize — `/workspace/../etc` ต้องไม่ถือว่าอยู่ใน `/workspace`
pub fn scope_covers(cap_scope: &str, requested: &str) -> bool {
    if has_relative_component(cap_scope) || has_relative_component(requested) {
        return false;
    }
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

/// จริงเมื่อ path มี component แบบ relative (`.`หรือ`..`) ที่ยังไม่ถูก normalize
fn has_relative_component(path: &str) -> bool {
    path.split('/').any(|c| c == "." || c == "..")
}

/// ตรวจ scope ที่กว้างเกินไปสำหรับ filesystem (root/empty/wildcard) —
/// ห้ามใช้ในการให้สิทธิ์ anything goes (F-9)
pub fn broad_fs_scope(scope: &str) -> bool {
    let base = scope
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('/');
    base.is_empty() || base == "*"
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
            // fail-closed: lease ที่ scope กว้างเกินไป (root) ไม่ถือว่าใช้ได้
            // (กัน priviledge escalation ถึงแม้ถูก grant มา)
            if cap.resource == "filesystem" && broad_fs_scope(&cap.scope) {
                continue;
            }
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

    pub fn authorize_with_context(
        &mut self,
        action: &str,
        resource: &str,
        scope: &str,
        ctx: &AuthorizationContext<'_>,
    ) -> Result<usize, CapabilityError> {
        // จำเหตุผลงบหมดไว้คืนแทน Mismatch (caller แยกแยะ deny งบหมดออกจากผิด scope ได้)
        let mut budget_err: Option<CapabilityError> = None;
        for (index, cap) in self.caps.iter_mut().enumerate() {
            if cap.resource == "filesystem" && broad_fs_scope(&cap.scope) {
                continue;
            }
            if let Err(e) = cap.check_usable() {
                if matches!(e, CapabilityError::BudgetExceeded(_)) {
                    budget_err = Some(e);
                }
                continue;
            }
            if !cap.covers(action, resource, scope) {
                continue;
            }
            // fail-closed: คำขอไม่บอก timeout → บังคับ constraint timeout ไม่ได้
            // (เดิม is_some_and ปล่อยผ่าน = fail-open)
            if let Some(max) = cap.constraints.timeout_ms {
                if ctx.timeout_ms.is_none_or(|value| value > max) {
                    budget_err = Some(CapabilityError::TimeoutUnmet(max));
                    continue;
                }
            }
            // condition.protocol ต้องตรงกับ protocol ของคำขอ
            // (ไม่ทราบทะเบียน = ไม่ผ่าน — fail-closed ของ field ที่เคยเป็น dead)
            if let Some(want) = cap.condition.as_ref().and_then(|c| c.protocol.as_ref()) {
                if !ctx.protocol.is_some_and(|p| p.eq_ignore_ascii_case(want)) {
                    continue;
                }
            }
            if let Err(e) = cap.check_constraints(
                ctx.request_bytes,
                None,
                ctx.protocol,
                ctx.port,
                ctx.response_bytes,
            ) {
                if matches!(e, CapabilityError::BudgetExceeded(_)) {
                    budget_err = Some(e);
                }
                continue;
            }
            if cap
                .constraints
                .max_calls
                .is_some_and(|max| cap.used_count >= u64::from(max))
            {
                budget_err = Some(CapabilityError::BudgetExceeded(
                    cap.constraints.max_calls.unwrap() as u64,
                ));
                continue;
            }
            cap.used_count += 1;
            return Ok(index);
        }
        Err(budget_err.unwrap_or(CapabilityError::Mismatch))
    }

    /// บันทึกไบต์ที่ใช้จริงหลัง side effect สำเร็จ (index จาก authorize_with_context)
    /// saturating ทั้งคู่ กัน overflow พาเพดานแตก
    pub fn account_bytes(&mut self, index: usize, bytes: u64) {
        if let Some(cap) = self.caps.get_mut(index) {
            cap.account_bytes(bytes);
        }
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
        if cap.resource == "filesystem" && broad_fs_scope(&cap.scope) {
            return false;
        }
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

    // เพดานสะสม: ดูดทีละน้อยแต่รวมกันเกิน = DENY (กัน slow exfiltration)
    #[test]
    fn cumulative_byte_budget_exhausts() {
        use crate::AuthorizationContext;
        let mut set = CapabilitySet::new(vec![Capability::new(
            "network:fetch",
            "network",
            "example.com:443",
        )
        .with_constraints(Constraints::new().with_max_total_bytes(100))]);
        let ctx = AuthorizationContext {
            request_bytes: Some(10),
            ..Default::default()
        };
        // 10 ครั้ง × 10 ไบต์ = ครบ 100 พอดี
        for _ in 0..10 {
            let idx = set
                .authorize_with_context("network:fetch", "network", "example.com:443", &ctx)
                .expect("within budget");
            set.account_bytes(idx, 10);
        }
        // ครั้งที่ 11 = DENY แม้ request แค่ 10 ไบต์ (เพดานหมดแล้ว)
        assert!(matches!(
            set.authorize_with_context("network:fetch", "network", "example.com:443", &ctx),
            Err(CapabilityError::BudgetExceeded(_))
        ));
    }

    // request เดียวที่จะล้นเพดาน = ปฏิเสธก่อน side effect (ไม่ต้องรอให้เกิดก่อน)
    #[test]
    fn single_request_overflowing_budget_denied_prefetch() {
        use crate::AuthorizationContext;
        let mut set = CapabilitySet::new(vec![Capability::new(
            "network:fetch",
            "network",
            "example.com:443",
        )
        .with_constraints(Constraints::new().with_max_total_bytes(100))]);
        let idx = set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    request_bytes: Some(60),
                    ..Default::default()
                },
            )
            .expect("first fits");
        set.account_bytes(idx, 60);
        // เหลือ 40 ขอ 50 = DENY ก่อนส่ง
        assert!(set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    request_bytes: Some(50),
                    ..Default::default()
                },
            )
            .is_err());
        // เหลือ 40 ขอ 40 = ผ่านพอดี
        assert!(set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    request_bytes: Some(40),
                    ..Default::default()
                },
            )
            .is_ok());
    }

    // #6: authorize() แบบไม่มี context ต้องปฏิเสธ cap ที่มี constraint ที่
    // ต้องใช้ค่าคำขอ — เดิมข้าม max_bytes/timeout เงียบ ๆ (fail-open)
    #[test]
    fn plain_authorize_denies_context_dependent_constraints() {
        let mut cap = Capability::new("read", "filesystem", "/workspace")
            .with_constraints(Constraints::new().with_max_bytes(100));
        assert!(matches!(
            cap.authorize("read", "filesystem", "/workspace/a.rs"),
            Err(CapabilityError::MissingContext)
        ));
        // ยังไม่ถูกนับการใช้ (deny ไม่กินงบ)
        assert_eq!(cap.used_count, 0);

        let mut with_timeout = Capability::new("execute", "process", "/usr/bin/true")
            .with_constraints(Constraints::new().with_timeout_ms(5000));
        assert!(matches!(
            with_timeout.authorize("execute", "process", "/usr/bin/true"),
            Err(CapabilityError::MissingContext)
        ));

        // condition.protocol ก็ต้องมี context เช่นกัน
        let mut cond_cap = Capability::new("network:fetch", "network", "example.com:443");
        cond_cap.condition = Some(crate::Condition {
            protocol: Some("https".into()),
            require_state: None,
            valid_states: vec![],
        });
        assert!(matches!(
            cond_cap.authorize("network:fetch", "network", "example.com:443"),
            Err(CapabilityError::MissingContext)
        ));
        // ไม่มี constraint ที่ต้องใช้ context → ทำงานเหมือนเดิม
        let mut plain = Capability::new("read", "filesystem", "/workspace");
        assert!(plain
            .authorize("read", "filesystem", "/workspace/a.rs")
            .is_ok());
    }

    // #7: timeout constraint ที่คำขอไม่บอกค่า = DENY (เดิม fail-open)
    #[test]
    fn timeout_constraint_denies_when_request_omits_timeout() {
        use crate::{AuthorizationContext, CapabilitySet};
        let cap = Capability::new("execute", "process", "/usr/bin/true")
            .with_constraints(Constraints::new().with_timeout_ms(5000));
        let mut set = CapabilitySet::new(vec![cap]);
        // ไม่บอก timeout → DENY
        assert!(matches!(
            set.authorize_with_context(
                "execute",
                "process",
                "/usr/bin/true",
                &AuthorizationContext::default()
            ),
            Err(CapabilityError::TimeoutUnmet(5000))
        ));
        // บอก timeout เกิน → DENY
        assert!(matches!(
            set.authorize_with_context(
                "execute",
                "process",
                "/usr/bin/true",
                &AuthorizationContext {
                    timeout_ms: Some(6000),
                    ..Default::default()
                }
            ),
            Err(CapabilityError::TimeoutUnmet(5000))
        ));
        // บอก timeout อยู่ในเกณฑ์ → ALLOW
        assert!(set
            .authorize_with_context(
                "execute",
                "process",
                "/usr/bin/true",
                &AuthorizationContext {
                    timeout_ms: Some(1000),
                    ..Default::default()
                }
            )
            .is_ok());
    }

    // #8: condition.protocol ไม่ใช่ dead field อีกต่อไป
    #[test]
    fn condition_protocol_is_enforced() {
        use crate::{AuthorizationContext, CapabilitySet};
        let mut cap = Capability::new("network:fetch", "network", "example.com:443");
        cap.condition = Some(crate::Condition {
            protocol: Some("https".into()),
            require_state: None,
            valid_states: vec![],
        });
        let mut set = CapabilitySet::new(vec![cap]);
        // protocol ผิด / ไม่ระบุ → DENY
        assert!(set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    protocol: Some("http"),
                    ..Default::default()
                }
            )
            .is_err());
        assert!(set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext::default()
            )
            .is_err());
        // protocol ตรง → ALLOW
        assert!(set
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    protocol: Some("https"),
                    ..Default::default()
                }
            )
            .is_ok());
    }

    // #9: capability layer ไม่ canonicalize → path ที่มี `..`/`.` ต้องไม่ผ่าน
    #[test]
    fn scope_covers_rejects_relative_components() {
        assert!(!scope_covers("/workspace", "/workspace/../etc"));
        assert!(!scope_covers("/workspace", "/workspace/./src"));
        assert!(!scope_covers("/workspace/..", "/workspace"));
        assert!(!scope_covers("/workspace/**", "/workspace/../etc/passwd"));
        // canonical path ยังคงทำงานเหมือนเดิม
        assert!(scope_covers("/workspace", "/workspace"));
        assert!(scope_covers("/workspace", "/workspace/src/main.rs"));
        assert!(!scope_covers("/workspace", "/workspace2"));
    }
}
