//! Secret Support — Tool-scoped secret injection with HITL and zeroization.
//!
//! สเปก §26: Secret Request → Capability Check → Policy Check → Risk Evaluation
//! → HITL Gate (High-Risk) → Secret Broker → Tool Executor (Injection) → Zeroize

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// ระดับความเสี่ยงของ Secret (ใช้ตัดสิน HITL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low-risk: read-only, scoped แคบ (อาจ auto-allow ตาม policy)
    Low,
    /// High-risk: write/deploy, production access, destructive ops (default: require HITL)
    #[default]
    High,
}

/// Secret Request Schema (สเปก §26.2 จุด 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRequest {
    /// Tool ที่ต้องการ secret (เช่น "git.push", "docker.build")
    pub tool: String,
    /// Resource identifier (เช่น "github_token", "aws_creds", "docker_registry")
    pub resource: String,
    /// Scope ที่ขอ (เช่น "repo:write", "s3:read", "registry:push")
    pub scope: String,
    /// เป้าหมายการใช้งาน (metadata สำหรับ audit, ไม่ใช่ trust signal)
    pub purpose: String,
    /// จำนวนครั้งสูงสุดที่ใช้ได้ (default: 1 = one-time lease)
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    /// อายุการใช้งาน (วินาที, default: 300 = 5 นาที)
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// Risk level (default: High = require HITL)
    #[serde(default)]
    pub risk: RiskLevel,
}

fn default_max_uses() -> u32 {
    1
}
fn default_ttl_seconds() -> u64 {
    300
}

/// Secret Lease — ตั๋วอนุญาตใช้งาน secret ชั่วคราว
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretLease {
    /// Unique lease ID
    pub id: String,
    /// Secret request ที่เกี่ยวข้อง
    pub request: SecretRequest,
    /// Secret value (จะถูก zeroize หลังใช้งาน)
    /// หมายเหตุ: serialize ได้ (ต้องใช้ตอน persist ข้าม restart — ไฟล์
    /// 0600 ระดับเดียวกับ secrets.yaml) ห้าม serialize ผ่านช่องอื่น
    /// (API/summary/audit ใช้ LeaseSummary หรือ field เลือกเองเสมอ)
    pub value: String,
    /// สถานะ
    pub status: LeaseStatus,
    /// สร้างเมื่อไหร่
    pub created_at: DateTime<Utc>,
    /// หมดอายุเมื่อไหร่
    pub expires_at: DateTime<Utc>,
    /// ใช้ไปแล้วกี่ครั้ง
    pub uses: u32,
    /// HITL approval (ถ้ามี)
    pub hitl_approved: bool,
    /// Approved by (operator identity)
    pub approved_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseStatus {
    Pending,   // รอ HITL approval
    Active,    // พร้อมใช้งาน
    Exhausted, // ใช้ครบ max_uses แล้ว
    Expired,   // หมดอายุ
    Revoked,   // ถูก revoke ก่อนเวลา
}

/// Secret Capability — ขยาย capability model สำหรับ secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretCapability {
    pub action: String,   // "read" | "use"
    pub resource: String, // "secret"
    pub scope: String,    // resource:scope pattern
    pub risk_level: RiskLevel,
    pub max_uses: u32,
    pub ttl_seconds: u64,
}

/// Secret Policy — policy สำหรับ secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// Allow list: resource:scope patterns ที่อนุญาต
    #[serde(default)]
    pub allow: Vec<String>,
    /// scope ที่ operator อนุญาตให้เป็น Low-risk (ค่าเริ่มต้นไม่มี)
    #[serde(default)]
    pub low_risk_allow: Vec<String>,
    /// Deny list: resource:scope patterns ที่ห้าม
    #[serde(default)]
    pub deny: Vec<String>,
    /// Require HITL สำหรับ risk level (default: High)
    #[serde(default = "default_hitl")]
    pub hitl_required_for: Vec<RiskLevel>,
    /// Max TTL ที่อนุญาต (seconds, 0 = unlimited)
    #[serde(default)]
    pub max_ttl_seconds: u64,
    /// Max uses ที่อนุญาต (0 = unlimited)
    #[serde(default)]
    pub max_uses_allowed: u32,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            allow: vec![],
            low_risk_allow: vec![],
            deny: vec![],
            hitl_required_for: default_hitl(),
            max_ttl_seconds: 0,
            max_uses_allowed: 0,
        }
    }
}

fn default_hitl() -> Vec<RiskLevel> {
    vec![RiskLevel::High]
}

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("hitl required but not approved (pending lease: {0})")]
    HitlRequired(String),
    #[error("lease not found: {0}")]
    LeaseNotFound(String),
    #[error("lease exhausted (max uses reached)")]
    LeaseExhausted,
    #[error("lease expired")]
    LeaseExpired,
    #[error("lease revoked")]
    LeaseRevoked,
    #[error("lease pending approval (not approved yet)")]
    NotApproved,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("secret not found in broker: {0}")]
    SecretNotFound(String),
    #[error("audit error: {0}")]
    AuditError(String),
}

/// สรุป lease แบบไม่มี value (G4b — operator ดูก่อน approve)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSummary {
    pub id: String,
    pub tool: String,
    pub resource: String,
    pub scope: String,
    pub purpose: String,
    pub status: LeaseStatus,
    pub uses: u32,
    pub max_uses: u32,
    pub hitl_approved: bool,
    pub approved_by: Option<String>,
}

/// Secret Broker — trusted component outside sandbox that manages secrets
pub struct SecretBroker {
    secrets: HashMap<String, String>,     // resource -> secret value
    leases: HashMap<String, SecretLease>, // lease_id -> lease
    policy: SecretPolicy,
    audit: Option<aivm_audit::AuditWriter>,
}

impl SecretBroker {
    pub fn new(policy: SecretPolicy, audit: Option<aivm_audit::AuditWriter>) -> Self {
        Self {
            secrets: HashMap::new(),
            leases: HashMap::new(),
            policy,
            audit,
        }
    }

    /// Register a secret with the broker (operator-only operation)
    pub fn register_secret(&mut self, resource: String, value: String) {
        self.secrets.insert(resource, value);
    }

    /// Remove a secret from broker
    pub fn remove_secret(&mut self, resource: &str) -> Option<String> {
        self.secrets.remove(resource)
    }

    /// Request a secret lease (AI-initiated, goes through capability/policy/HITL)
    pub fn request_lease(
        &mut self,
        mut request: SecretRequest,
        _cube: &aivm_cube::Cube,
        caps: &mut aivm_capability::CapabilitySet,
        hitl_approved: bool,
        approved_by: Option<String>,
    ) -> Result<SecretLease, SecretError> {
        if request.max_uses == 0
            || request.max_uses > 1000
            || request.ttl_seconds == 0
            || request.ttl_seconds > 86400
        {
            return Err(SecretError::InvalidRequest(
                "invalid lease lifetime or usage limit".into(),
            ));
        }
        // 1. Capability check
        let scope = format!("{}:{}", request.resource, request.scope);
        caps.authorize("use", "secret", &scope)
            .map_err(|e| SecretError::CapabilityDenied(e.to_string()))?;

        // 2. Policy check
        self.check_policy(&request)?;

        // 3. Risk evaluation + HITL (G4b): High-risk ที่ไม่มี approval ไม่ทิ้ง
        // แต่เก็บเป็น PENDING lease ให้ operator approve ต่อได้ (lease id
        // อยู่ใน error — ไม่ใช่ secret จึงบอกได้)
        if request.risk == RiskLevel::Low
            && !self
                .policy
                .low_risk_allow
                .iter()
                .any(|pattern| Self::match_pattern(pattern, &scope))
        {
            request.risk = RiskLevel::High;
        }
        let requires_hitl = self.policy.hitl_required_for.contains(&request.risk);
        let pre_approved = hitl_approved;

        // 4. Validate TTL and max_uses against policy
        if self.policy.max_ttl_seconds > 0 && request.ttl_seconds > self.policy.max_ttl_seconds {
            return Err(SecretError::InvalidRequest(format!(
                "TTL {} exceeds policy max {}",
                request.ttl_seconds, self.policy.max_ttl_seconds
            )));
        }
        if self.policy.max_uses_allowed > 0 && request.max_uses > self.policy.max_uses_allowed {
            return Err(SecretError::InvalidRequest(format!(
                "max_uses {} exceeds policy max {}",
                request.max_uses, self.policy.max_uses_allowed
            )));
        }

        // 5. Get secret value
        let value = self
            .secrets
            .get(&request.resource)
            .ok_or_else(|| SecretError::SecretNotFound(request.resource.clone()))?
            .clone();

        // 6. Create lease (High-risk ที่ยังไม่ approve = PENDING ไว้ก่อน)
        let resource_for_audit = request.resource.clone();
        let ttl_seconds = request.ttl_seconds;
        let now = Utc::now();
        let pending = requires_hitl && !pre_approved;
        let lease = SecretLease {
            id: format!("lease-{}", uuid::Uuid::new_v4()),
            request,
            value,
            status: if pending {
                LeaseStatus::Pending
            } else {
                LeaseStatus::Active
            },
            created_at: now,
            expires_at: now + Duration::from_secs(ttl_seconds),
            uses: 0,
            hitl_approved: pre_approved,
            approved_by: if pre_approved { approved_by } else { None },
        };

        let lease_id = lease.id.clone();
        self.leases.insert(lease_id.clone(), lease.clone());

        // Audit (pending = deny/hitl-required ไว้ก่อน ไม่ใช่ allow)
        if let Some(audit) = &mut self.audit {
            let mut rec = aivm_audit::AuditRecord::new(
                0,
                "secret-broker",
                "secret-broker",
                &format!("lease_{}", lease_id),
                "INIT",
                "secret.lease",
                &resource_for_audit,
                if pending { "deny" } else { "allow" },
                "secret-policy",
            );
            rec.rule_matched = if pending {
                format!("hitl-required:{lease_id}")
            } else {
                format!("lease_created:{lease_id}")
            };
            rec.result = "success".into();
            let _ = audit.append(rec);
        }

        if pending {
            return Err(SecretError::HitlRequired(lease_id));
        }
        Ok(lease)
    }

    /// Inspect a lease without consuming a use (gateway ตรวจ tool-binding
    /// ก่อน inject; การนับ use เกิดใน `use_lease` เท่านั้น)
    pub fn get_lease(&self, lease_id: &str) -> Option<&SecretLease> {
        self.leases.get(lease_id)
    }

    /// Use a lease to get secret value (tool executor calls this)
    pub fn use_lease(&mut self, lease_id: &str) -> Result<String, SecretError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or(SecretError::LeaseNotFound(lease_id.to_string()))?;

        // Check status
        match lease.status {
            LeaseStatus::Active => {}
            LeaseStatus::Exhausted => return Err(SecretError::LeaseExhausted),
            LeaseStatus::Expired => return Err(SecretError::LeaseExpired),
            LeaseStatus::Revoked => return Err(SecretError::LeaseRevoked),
            // PENDING ใช้ไม่ได้จนกว่า operator จะ approve (G4b) — แยก variant
            // จาก InvalidRequest ทั่วไปเพื่อให้ gateway ลง audit ถูก
            LeaseStatus::Pending => return Err(SecretError::NotApproved),
        }

        // Check expiration
        if Utc::now() > lease.expires_at {
            lease.status = LeaseStatus::Expired;
            return Err(SecretError::LeaseExpired);
        }

        // Check max uses
        if lease.uses >= lease.request.max_uses {
            lease.status = LeaseStatus::Exhausted;
            return Err(SecretError::LeaseExhausted);
        }

        // Increment use count
        lease.uses += 1;
        if lease.uses >= lease.request.max_uses {
            lease.status = LeaseStatus::Exhausted;
        }

        // Return secret value (caller must zeroize after use)
        Ok(lease.value.clone())
    }

    /// Revoke a lease early
    pub fn revoke_lease(&mut self, lease_id: &str) -> Result<(), SecretError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or(SecretError::LeaseNotFound(lease_id.to_string()))?;
        lease.status = LeaseStatus::Revoked;
        Ok(())
    }

    /// Approve a PENDING lease (G4b — operator เท่านั้น, ไม่ใช่ agent):
    /// ตรวจ exact id + ต้อง pending อยู่ + ไม่หมดอายุ + ระบุผู้ approve
    /// (กัน approve ลม ๆ แล้ง ๆ) approve แล้วใช้ได้ตาม max_uses/TTL เดิม
    /// (ไม่ต่ออายุตอน approve — TTL นับจากตอนขอเสมอ)
    pub fn approve_lease(
        &mut self,
        lease_id: &str,
        approved_by: &str,
    ) -> Result<SecretLease, SecretError> {
        if approved_by.is_empty() {
            return Err(SecretError::InvalidRequest("approver required".into()));
        }
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or(SecretError::LeaseNotFound(lease_id.to_string()))?;
        match lease.status {
            LeaseStatus::Pending => {}
            _ => {
                return Err(SecretError::InvalidRequest(
                    "only pending leases can be approved".into(),
                ));
            }
        }
        if Utc::now() > lease.expires_at {
            lease.status = LeaseStatus::Expired;
            return Err(SecretError::LeaseExpired);
        }
        lease.status = LeaseStatus::Active;
        lease.hitl_approved = true;
        lease.approved_by = Some(approved_by.to_string());
        Ok(lease.clone())
    }

    /// สรุป leases ทั้งหมดแบบไม่มี value (ไว้แสดงให้ operator ดูก่อน approve —
    /// value ไม่มีทางออกทางช่องนี้)
    pub fn summaries(&self) -> Vec<LeaseSummary> {
        let mut out: Vec<LeaseSummary> = self
            .leases
            .values()
            .map(|l| LeaseSummary {
                id: l.id.clone(),
                tool: l.request.tool.clone(),
                resource: l.request.resource.clone(),
                scope: l.request.scope.clone(),
                purpose: l.request.purpose.clone(),
                status: l.status,
                uses: l.uses,
                max_uses: l.request.max_uses,
                hitl_approved: l.hitl_approved,
                approved_by: l.approved_by.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// คืนชีพ leases จาก persistence (G4b): รับเฉพาะ Active/Pending ที่ยังไม่
    /// หมดอายุ ที่เหลือทิ้ง (fail-closed ข้าม restart) คืนจำนวนที่รับไว้
    pub fn restore(&mut self, leases: Vec<SecretLease>) -> usize {
        let now = Utc::now();
        let mut kept = 0;
        for mut l in leases {
            match l.status {
                LeaseStatus::Active | LeaseStatus::Pending => {}
                _ => continue,
            }
            if now > l.expires_at {
                continue;
            }
            if l.uses >= l.request.max_uses {
                continue;
            }
            if self.check_policy(&l.request).is_err() {
                continue;
            }
            let scope = format!("{}:{}", l.request.resource, l.request.scope);
            if l.request.risk == RiskLevel::Low
                && !self
                    .policy
                    .low_risk_allow
                    .iter()
                    .any(|p| Self::match_pattern(p, &scope))
            {
                l.request.risk = RiskLevel::High;
            }
            l.status =
                if l.hitl_approved || !self.policy.hitl_required_for.contains(&l.request.risk) {
                    LeaseStatus::Active
                } else {
                    LeaseStatus::Pending
                };
            self.leases.insert(l.id.clone(), l);
            kept += 1;
        }
        kept
    }

    /// leases ที่ยังมีชีวิต (ไว้ persist — ที่จบแล้วไม่ต้องเก็บ)
    pub fn live_leases(&self) -> Vec<SecretLease> {
        self.leases
            .values()
            .filter(|l| matches!(l.status, LeaseStatus::Active | LeaseStatus::Pending))
            .cloned()
            .collect()
    }

    /// Clean up expired/exhausted leases
    pub fn cleanup(&mut self) {
        let now = Utc::now();
        self.leases.retain(|_, lease| {
            if lease.status == LeaseStatus::Active && now > lease.expires_at {
                lease.status = LeaseStatus::Expired;
                false
            } else {
                !matches!(
                    lease.status,
                    LeaseStatus::Exhausted | LeaseStatus::Revoked | LeaseStatus::Expired
                )
            }
        });
    }

    fn check_policy(&self, request: &SecretRequest) -> Result<(), SecretError> {
        let scope = format!("{}:{}", request.resource, request.scope);

        // Check deny list first (deny overrides)
        for pattern in &self.policy.deny {
            if Self::match_pattern(pattern, &scope) {
                return Err(SecretError::PolicyDenied(format!(
                    "denied by pattern: {}",
                    pattern
                )));
            }
        }

        // Check allow list
        if !self.policy.allow.is_empty() {
            let mut allowed = false;
            for pattern in &self.policy.allow {
                if Self::match_pattern(pattern, &scope) {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(SecretError::PolicyDenied("not in allow list".into()));
            }
        }

        Ok(())
    }

    fn match_pattern(pattern: &str, scope: &str) -> bool {
        // Simple glob-style matching: * matches anything
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return scope.starts_with(prefix);
        }
        pattern == scope
    }
}

/// Tool-scoped secret injection helper
pub struct SecretInjector;

impl SecretInjector {
    /// Inject secret into tool execution environment
    /// Returns env vars to set for the tool process
    pub fn inject_env(lease: &SecretLease) -> Vec<(String, String)> {
        let mut env = Vec::new();

        // Inject as environment variable with standardized naming
        // Format: AIVM_SECRET_{RESOURCE}_{SCOPE}
        let key = format!(
            "AIVM_SECRET_{}_{}",
            lease.request.resource.to_uppercase().replace('-', "_"),
            lease.request.scope.to_uppercase().replace([':', '-'], "_")
        );
        env.push((key, lease.value.clone()));

        // Also inject lease metadata for audit trail
        env.push(("AIVM_SECRET_LEASE_ID".into(), lease.id.clone()));
        env.push(("AIVM_SECRET_PURPOSE".into(), lease.request.purpose.clone()));

        env
    }

    /// Inject secret via file descriptor (more secure, for high-risk)
    /// Returns path to temp file with secret (caller must clean up)
    pub fn inject_file(lease: &SecretLease) -> Result<PathBuf, SecretError> {
        let mut path = std::env::temp_dir();
        path.push(format!("aivm-secret-{}.tmp", lease.id));

        std::fs::write(&path, &lease.value)
            .map_err(|e| SecretError::AuditError(format!("failed to write secret file: {}", e)))?;

        // Make file readable only by owner
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| SecretError::AuditError(e.to_string()))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)
                .map_err(|e| SecretError::AuditError(e.to_string()))?;
        }

        Ok(path)
    }
}

/// Zeroize secret from memory (best effort)
pub fn zeroize_secret(secret: &mut String) {
    // Overwrite with zeros
    let bytes = unsafe { secret.as_bytes_mut() };
    for b in bytes.iter_mut() {
        *b = 0;
    }
    // Clear the string
    secret.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_capability::CapabilitySet;
    use aivm_cube::Cube;

    fn test_broker() -> SecretBroker {
        let mut broker = SecretBroker::new(
            SecretPolicy {
                low_risk_allow: vec!["*".into()],
                allow: vec!["github_token:*".into()],
                deny: vec!["github_token:admin".into()],
                hitl_required_for: vec![RiskLevel::High],
                max_ttl_seconds: 3600,
                max_uses_allowed: 5,
            },
            None,
        );

        broker.register_secret("github_token".into(), "ghp_test123".into());
        broker
    }

    #[test]
    fn test_lease_creation_low_risk_auto_allow() {
        let mut broker = test_broker();
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:read",
        )]);
        let cube = Cube::new("test");

        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "read".into(),
            purpose: "read repo".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::Low,
        };

        let lease = broker
            .request_lease(request, &cube, &mut caps, true, Some("operator".into()))
            .unwrap();
        assert_eq!(lease.status, LeaseStatus::Active);
        assert_eq!(lease.request.risk, RiskLevel::Low);
    }

    #[test]
    fn test_lease_creation_high_risk_requires_hitl() {
        let mut broker = test_broker();
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:write",
        )]);
        let cube = Cube::new("test");

        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "write".into(),
            purpose: "push to repo".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::High,
        };

        // Without HITL should fail but leave a PENDING lease with id
        let result = broker.request_lease(request.clone(), &cube, &mut caps, false, None);
        let pending_id = match result {
            Err(SecretError::HitlRequired(id)) => id,
            other => panic!("expected HitlRequired, got {other:?}"),
        };
        assert!(!pending_id.is_empty());
        let stored = broker
            .get_lease(&pending_id)
            .expect("pending must be stored");
        assert_eq!(stored.status, LeaseStatus::Pending);
        assert!(!stored.hitl_approved);

        // Using a pending lease must fail distinctly (not approved yet)
        assert!(matches!(
            broker.use_lease(&pending_id),
            Err(SecretError::NotApproved)
        ));

        // With HITL should succeed
        let lease = broker
            .request_lease(request, &cube, &mut caps, true, Some("operator".into()))
            .unwrap();
        assert_eq!(lease.status, LeaseStatus::Active);
        assert!(lease.hitl_approved);
    }

    // G4b: approve flow — pending → active, ใช้ได้, approve ซ้ำ/ผิด id ไม่ได้
    #[test]
    fn test_approve_flow() {
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:write",
        )]);
        // policy ตรง ๆ สำหรับเคสนี้ (test_broker allow แค่ read)
        let mut broker = SecretBroker::new(
            SecretPolicy {
                low_risk_allow: vec!["*".into()],
                allow: vec!["github_token:write".into()],
                deny: vec![],
                hitl_required_for: vec![RiskLevel::High],
                max_ttl_seconds: 3600,
                max_uses_allowed: 5,
            },
            None,
        );
        broker.register_secret("github_token".into(), "ghp_test123".into());
        let cube = Cube::new("test");
        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "write".into(),
            purpose: "push".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::High,
        };
        let Err(SecretError::HitlRequired(id)) =
            broker.request_lease(request, &cube, &mut caps, false, None)
        else {
            panic!("expected pending");
        };
        // approve id มั่วต้องไม่ผ่าน (กันเดา/confused deputy)
        assert!(matches!(
            broker.approve_lease("lease-nope", "operator"),
            Err(SecretError::LeaseNotFound(_))
        ));
        // approve ไม่ระบุคนต้องไม่ผ่าน
        assert!(matches!(
            broker.approve_lease(&id, ""),
            Err(SecretError::InvalidRequest(_))
        ));
        // approve จริง → active + ใช้ได้ครั้งเดียวตาม max_uses
        let approved = broker.approve_lease(&id, "operator").unwrap();
        assert_eq!(approved.status, LeaseStatus::Active);
        assert_eq!(approved.approved_by.as_deref(), Some("operator"));
        assert_eq!(broker.use_lease(&id).unwrap(), "ghp_test123");
        // approve ซ้ำ (ไม่ pending แล้ว) ต้องไม่ผ่าน
        assert!(matches!(
            broker.approve_lease(&id, "operator"),
            Err(SecretError::InvalidRequest(_))
        ));
        // summaries ไม่มี value
        let sums = broker.summaries();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].id, id);
    }

    // G4b: restore รับเฉพาะ lease ที่ยังใช้ได้ (หมดอายุ/หมดโควต้า/จบแล้วทิ้ง)
    #[test]
    fn test_restore_filters_terminal_leases() {
        let mut broker = test_broker();
        let now = Utc::now();
        let mk = |status| SecretLease {
            id: format!("lease-r-{}", uuid::Uuid::new_v4()),
            request: SecretRequest {
                tool: "t".into(),
                resource: "github_token".into(),
                scope: "read".into(),
                purpose: "p".into(),
                max_uses: 1,
                ttl_seconds: 300,
                risk: RiskLevel::Low,
            },
            value: "v".into(),
            status,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(300),
            uses: 0,
            hitl_approved: true,
            approved_by: None,
        };
        let mut expired = mk(LeaseStatus::Active);
        expired.expires_at = now - chrono::Duration::seconds(1);
        let kept = broker.restore(vec![
            mk(LeaseStatus::Active),
            mk(LeaseStatus::Pending),
            expired,
            mk(LeaseStatus::Exhausted),
            mk(LeaseStatus::Revoked),
        ]);
        assert_eq!(kept, 2);
        assert_eq!(broker.leases.len(), 2);
    }

    #[test]
    fn test_lease_use_and_exhaustion() {
        let mut broker = test_broker();
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:read",
        )]);
        let cube = Cube::new("test");

        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "read".into(),
            purpose: "read repo".into(),
            max_uses: 2,
            ttl_seconds: 300,
            risk: RiskLevel::Low,
        };

        let lease = broker
            .request_lease(request, &cube, &mut caps, true, Some("operator".into()))
            .unwrap();
        let lease_id = lease.id.clone();

        // First use
        let value = broker.use_lease(&lease_id).unwrap();
        assert_eq!(value, "ghp_test123");

        // Second use (max_uses=2)
        let value = broker.use_lease(&lease_id).unwrap();
        assert_eq!(value, "ghp_test123");

        // Third use should fail
        let result = broker.use_lease(&lease_id);
        assert!(matches!(result, Err(SecretError::LeaseExhausted)));
    }

    #[test]
    fn test_deny_pattern_overrides() {
        let mut broker = test_broker();
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:admin",
        )]);
        let cube = Cube::new("test");

        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "admin".into(),
            purpose: "admin access".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::High,
        };

        let result = broker.request_lease(request, &cube, &mut caps, true, Some("operator".into()));
        assert!(matches!(result, Err(SecretError::PolicyDenied(_))));
    }

    #[test]
    fn caller_cannot_downgrade_secret_risk() {
        let policy = SecretPolicy {
            allow: vec!["credential:read".into()],
            ..Default::default()
        };
        let mut broker = SecretBroker::new(policy, None);
        broker.register_secret("credential".into(), "VALUE".into());
        let mut caps = aivm_capability::CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "credential:read",
        )]);
        let request = SecretRequest {
            tool: "process.exec".into(),
            resource: "credential".into(),
            scope: "read".into(),
            purpose: "test".into(),
            risk: RiskLevel::Low,
            max_uses: 1,
            ttl_seconds: 300,
        };
        assert!(matches!(
            broker.request_lease(
                request,
                &aivm_cube::Cube::new("test"),
                &mut caps,
                false,
                None
            ),
            Err(SecretError::HitlRequired(_))
        ));
    }
}
