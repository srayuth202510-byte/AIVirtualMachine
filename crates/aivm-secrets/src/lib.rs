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
    #[serde(skip_serializing)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    /// Allow list: resource:scope patterns ที่อนุญาต
    #[serde(default)]
    pub allow: Vec<String>,
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

fn default_hitl() -> Vec<RiskLevel> {
    vec![RiskLevel::High]
}

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("hitl required but not approved")]
    HitlRequired,
    #[error("lease not found: {0}")]
    LeaseNotFound(String),
    #[error("lease exhausted (max uses reached)")]
    LeaseExhausted,
    #[error("lease expired")]
    LeaseExpired,
    #[error("lease revoked")]
    LeaseRevoked,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("secret not found in broker: {0}")]
    SecretNotFound(String),
    #[error("audit error: {0}")]
    AuditError(String),
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
        request: SecretRequest,
        _cube: &aivm_cube::Cube,
        caps: &mut aivm_capability::CapabilitySet,
        hitl_approved: bool,
        approved_by: Option<String>,
    ) -> Result<SecretLease, SecretError> {
        // 1. Capability check
        let scope = format!("{}:{}", request.resource, request.scope);
        caps.authorize("use", "secret", &scope)
            .map_err(|e| SecretError::CapabilityDenied(e.to_string()))?;

        // 2. Policy check
        self.check_policy(&request)?;

        // 3. Risk evaluation + HITL
        let requires_hitl = self.policy.hitl_required_for.contains(&request.risk);
        if requires_hitl && !hitl_approved {
            return Err(SecretError::HitlRequired);
        }

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

        // 6. Create lease
        let resource_for_audit = request.resource.clone();
        let ttl_seconds = request.ttl_seconds;
        let now = Utc::now();
        let lease = SecretLease {
            id: format!("lease-{}", uuid::Uuid::new_v4()),
            request,
            value,
            status: LeaseStatus::Active,
            created_at: now,
            expires_at: now + Duration::from_secs(ttl_seconds),
            uses: 0,
            hitl_approved,
            approved_by,
        };

        let lease_id = lease.id.clone();
        self.leases.insert(lease_id.clone(), lease.clone());

        // Audit
        if let Some(audit) = &mut self.audit {
            let mut rec = aivm_audit::AuditRecord::new(
                0,
                "secret-broker",
                "secret-broker",
                &format!("lease_{}", lease_id),
                "INIT",
                "secret.lease",
                &resource_for_audit,
                "allow",
                "secret-policy",
            );
            rec.rule_matched = format!("lease_created:{}", lease_id);
            rec.result = "success".into();
            let _ = audit.append(rec);
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
            LeaseStatus::Pending => {
                return Err(SecretError::InvalidRequest("lease not approved".into()))
            }
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

        // Without HITL should fail
        let result = broker.request_lease(request.clone(), &cube, &mut caps, false, None);
        assert!(matches!(result, Err(SecretError::HitlRequired)));

        // With HITL should succeed
        let lease = broker
            .request_lease(request, &cube, &mut caps, true, Some("operator".into()))
            .unwrap();
        assert_eq!(lease.status, LeaseStatus::Active);
        assert!(lease.hitl_approved);
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
}
