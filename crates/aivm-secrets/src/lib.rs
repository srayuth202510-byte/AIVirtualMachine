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
///
/// ไม่ derive `Debug` — `value` ต้องไม่มีทางหลุดเข้า log/panic message
/// (ใช้ `impl Debug` ที่ redact ด้านล่างแทน)
#[derive(Clone, Serialize, Deserialize)]
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

/// Debug ที่ redact `value` เสมอ — log/`{:?}`/panic ห้ามโชว์ secret จริง
/// (regression #25: derive Debug เดิมพิมพ์ค่า plain text ออกมาด้วย)
impl std::fmt::Debug for SecretLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretLease")
            .field("id", &self.id)
            .field("request", &self.request)
            .field("value", &"<redacted>")
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("uses", &self.uses)
            .field("hitl_approved", &self.hitl_approved)
            .field("approved_by", &self.approved_by)
            .finish()
    }
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
        if self.secrets.get(&resource).is_some_and(|old| old != &value) {
            self.revoke_resource_leases(&resource);
        }
        self.secrets.insert(resource, value);
    }

    /// Remove a secret and invalidate every outstanding lease for it.
    pub fn remove_secret(&mut self, resource: &str) -> Option<String> {
        self.revoke_resource_leases(resource);
        self.secrets.remove(resource)
    }

    fn revoke_resource_leases(&mut self, resource: &str) {
        for lease in self
            .leases
            .values_mut()
            .filter(|l| l.request.resource == resource)
        {
            lease.status = LeaseStatus::Revoked;
            zeroize_secret(&mut lease.value);
        }
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
        self.check_request_limits(&request)?;
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

        // 4. Get secret value
        let value = self
            .secrets
            .get(&request.resource)
            .ok_or_else(|| SecretError::SecretNotFound(request.resource.clone()))?
            .clone();

        // 5. Create lease (High-risk ที่ยังไม่ approve = PENDING ไว้ก่อน)
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
            // A lease is bound to the operator's current value and limits.
            // Persisted values cannot resurrect removed or rotated credentials.
            if self.secrets.get(&l.request.resource) != Some(&l.value)
                || self.check_request_limits(&l.request).is_err()
                || self.check_policy(&l.request).is_err()
            {
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

    fn check_request_limits(&self, request: &SecretRequest) -> Result<(), SecretError> {
        if request.max_uses == 0
            || request.max_uses > 1000
            || request.ttl_seconds == 0
            || request.ttl_seconds > 86400
        {
            return Err(SecretError::InvalidRequest(
                "invalid lease lifetime or usage limit".into(),
            ));
        }
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

        Ok(())
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

        // Empty allow lists deny all secret access.
        if !self
            .policy
            .allow
            .iter()
            .any(|pattern| Self::match_pattern(pattern, &scope))
        {
            return Err(SecretError::PolicyDenied("not in allow list".into()));
        }

        Ok(())
    }

    fn match_pattern(pattern: &str, scope: &str) -> bool {
        // "globs" ล้วน (`*`, `**`) = ตรงทุกอย่าง (เดิม `**` ตกไปเทียบ prefix
        // ผิด ๆ แล้ว deny หุบปาก)
        if !pattern.is_empty() && pattern.chars().all(|c| c == '*') {
            return true;
        }
        // รูป `prefix*` ยังคงนิยาม prefix-match เดิมไว้ (scope อาจมี `/` กลาง
        // ซึ่ง glob `*` ข้ามไม่ได้ในบาง mode — ของเดิมทำแบบนี้และใช้งานได้)
        if let Some(prefix) = pattern.strip_suffix('*') {
            if !prefix.contains(['*', '?', '[']) {
                return scope.starts_with(prefix);
            }
        }
        // wildcard กลาง/ต้น pattern (เช่น `*token*`, `?[ab]`) ต้องเทียบด้วย
        // glob จริง — regression #27: เดิม `*token*` ถูกตัดเป็น prefix `"*token"`
        // แล้วไม่เคยตรงกับ scope ไหนเลย = deny list ไม่มีผล (fail-open)
        match glob::Pattern::new(pattern) {
            Ok(p) => p.matches(scope),
            // pattern ไม่ถูกต้อง: เทียบตรงตัว — allow = fail-closed เสมอ
            Err(_) => pattern == scope,
        }
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
        // ชื่อไฟล์สุ่ม — เดิมใช้ `lease.id` ซึ่งเดาได้และมี `/` (path traversal
        // ออกจาก temp dir ได้)
        let mut path = std::env::temp_dir();
        path.push(format!("aivm-secret-{}.tmp", uuid::Uuid::new_v4()));

        // เปิดด้วย mode 0600 ตั้งแต่สร้างไฟล์: ไม่มีช่วง write-then-chmod ที่
        // ไฟล์ถูก umask เปิดกว้างชั่วคราว + `create_new` กัน symlink ทับ
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&path)
            .map_err(|e| SecretError::AuditError(format!("failed to create secret file: {}", e)))?;
        std::io::Write::write_all(&mut file, lease.value.as_bytes())
            .map_err(|e| SecretError::AuditError(format!("failed to write secret file: {}", e)))?;
        // ยืนยัน flush ก่อนคืน path (กัน caller อ่านได้ไฟล์เปล่า)
        std::io::Write::flush(&mut file)
            .map_err(|e| SecretError::AuditError(format!("failed to flush secret file: {}", e)))?;

        Ok(path)
    }
}

/// Zeroize secret จากหน่วยความจำ (กัน compiler ตัด dead store ทิ้ง)
pub fn zeroize_secret(secret: &mut String) {
    // volatile write: คำสั่งเขียนนี้เป็น side effect ที่ LLVM ห้ามลบ
    // (regression #28: เดิมเป็น dead store ปกติแล้วถูก optimize ทิ้งได้)
    // SAFETY: เขียนทับ byte ของ string ตัวนี้เท่านั้น ไม่อ่านค่าเก่า
    let bytes = unsafe { secret.as_bytes_mut() };
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8) };
    }
    // กันการย้าย/ตัดคำสั่งข้ามขอบเขตนี้อีกชั้น
    std::hint::black_box(&*secret);
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
            value: "ghp_test123".into(),
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

    fn test_lease(value: &str) -> SecretLease {
        SecretLease {
            id: "lease-1234".into(),
            request: SecretRequest {
                tool: "git.push".into(),
                resource: "github_token".into(),
                scope: "read".into(),
                purpose: "read repo".into(),
                max_uses: 1,
                ttl_seconds: 300,
                risk: RiskLevel::Low,
            },
            value: value.into(),
            status: LeaseStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            uses: 0,
            hitl_approved: false,
            approved_by: None,
        }
    }

    // regression #25: Debug ห้ามโชว์ secret จริง (derive เดิมหลุดทุก {:?})
    #[test]
    fn lease_debug_redacts_value() {
        let lease = test_lease("ghp_super_secret_value");
        let dbg = format!("{:?}", lease);
        assert!(
            !dbg.contains("ghp_super_secret_value"),
            "Debug leaked secret: {}",
            dbg
        );
        assert!(dbg.contains("<redacted>"));
        // panic/Result ที่ถือ lease ผ่าน {:?} ก็ต้องไม่หลุดเหมือนกัน
        let err = format!("{:?}", Ok::<SecretLease, ()>(lease));
        assert!(!err.contains("ghp_super_secret_value"));
    }

    // regression #27: deny pattern ขึ้นต้น wildcard ต้องยิงจริง (fail-closed)
    #[test]
    fn deny_pattern_with_leading_wildcard_is_enforced() {
        let mut broker = SecretBroker::new(
            SecretPolicy {
                deny: vec!["*admin*".into()],
                ..Default::default()
            },
            None,
        );
        broker.register_secret("github_token".into(), "ghp_x".into());
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:admin",
        )]);
        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "admin".into(),
            purpose: "admin".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::High,
        };
        let Err(SecretError::PolicyDenied(msg)) = broker.request_lease(
            request,
            &Cube::new("test"),
            &mut caps,
            true,
            Some("operator".into()),
        ) else {
            panic!("wildcard deny pattern must fire");
        };
        // ต้องมาจาก deny branch (ไม่ใช่ "not in allow list")
        assert!(msg.contains("denied by pattern"), "wrong branch: {}", msg);
        assert!(msg.contains("*admin*"), "wrong pattern: {}", msg);
    }

    // regression #27: `**` (glob ล้วน) = deny ทุกอย่าง ไม่ใช่เทียบ prefix ผิด ๆ
    #[test]
    fn deny_glob_only_pattern_blocks_everything() {
        let mut broker = SecretBroker::new(
            SecretPolicy {
                deny: vec!["**".into()],
                ..Default::default()
            },
            None,
        );
        broker.register_secret("github_token".into(), "ghp_x".into());
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:read",
        )]);
        let request = SecretRequest {
            tool: "git.push".into(),
            resource: "github_token".into(),
            scope: "read".into(),
            purpose: "read".into(),
            max_uses: 1,
            ttl_seconds: 300,
            risk: RiskLevel::High,
        };
        let Err(SecretError::PolicyDenied(msg)) = broker.request_lease(
            request,
            &Cube::new("test"),
            &mut caps,
            true,
            Some("operator".into()),
        ) else {
            panic!("`**` deny must fire");
        };
        assert!(msg.contains("denied by pattern"), "wrong branch: {}", msg);
    }

    // regression #26: ไฟล์ inject ต้อง 0600 ตั้งแต่สร้าง + ชื่อเดาไม่ได้
    #[cfg(unix)]
    #[test]
    fn inject_file_is_private_and_unguessable() {
        use std::os::unix::fs::PermissionsExt;

        let lease = test_lease("ghp_injected_value");
        let p1 = SecretInjector::inject_file(&lease).unwrap();

        let meta = std::fs::metadata(&p1).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // ชื่อไฟล์ไม่ผูกกับ lease id (เดาได้/มี ../ แทรกแซงได้ในแบบเดิม)
        let name = p1.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains(&lease.id));
        assert!(p1.starts_with(std::env::temp_dir()));
        // เนื้อหาถูกเขียนครบ
        assert_eq!(std::fs::read_to_string(&p1).unwrap(), "ghp_injected_value");
        // เรียกซ้ำ = คนละ path (ไม่เขียนทับกัน)
        let p2 = SecretInjector::inject_file(&lease).unwrap();
        assert_ne!(p1, p2);

        let _ = std::fs::remove_file(p1);
        let _ = std::fs::remove_file(p2);
    }

    // regression #28: zeroize ต้องล้างค่าจริง (และไม่ panic กับ string ว่าง)
    #[test]
    fn zeroize_clears_secret() {
        let mut secret = String::from("ghp_zer0ize_me");
        zeroize_secret(&mut secret);
        assert!(secret.is_empty());

        let mut empty = String::new();
        zeroize_secret(&mut empty);
        assert!(empty.is_empty());
    }
    fn restorable_lease() -> SecretLease {
        let mut lease = test_lease("ghp_test123");
        lease.expires_at = lease.created_at + chrono::Duration::seconds(300);
        lease.request.max_uses = 3;
        lease
    }

    #[test]
    fn restore_rejects_removed_or_rotated_secret_values() {
        let lease = restorable_lease();
        let mut unchanged = test_broker();
        assert_eq!(unchanged.restore(vec![lease.clone()]), 1);
        for rotated in [false, true] {
            let mut broker = test_broker();
            if rotated {
                broker.register_secret("github_token".into(), "rotated-value".into());
            } else {
                broker.remove_secret("github_token");
            }
            assert_eq!(broker.restore(vec![lease.clone()]), 0);
            assert!(broker.use_lease(&lease.id).is_err());
        }
    }

    #[test]
    fn restore_enforces_current_limits_and_default_deny() {
        let lease = restorable_lease();
        for change in ["uses", "ttl", "allow"] {
            let mut broker = test_broker();
            match change {
                "uses" => broker.policy.max_uses_allowed = 1,
                "ttl" => broker.policy.max_ttl_seconds = 60,
                "allow" => broker.policy.allow.clear(),
                _ => unreachable!(),
            }
            assert_eq!(broker.restore(vec![lease.clone()]), 0, "{change}");
        }
    }

    #[test]
    fn removing_or_rotating_a_secret_revokes_existing_leases() {
        for rotated in [false, true] {
            let mut broker = test_broker();
            let lease = restorable_lease();
            assert_eq!(broker.restore(vec![lease.clone()]), 1);
            if rotated {
                broker.register_secret("github_token".into(), "rotated-value".into());
            } else {
                broker.remove_secret("github_token");
            }
            assert!(matches!(
                broker.use_lease(&lease.id),
                Err(SecretError::LeaseRevoked)
            ));
            assert!(broker.get_lease(&lease.id).unwrap().value.is_empty());
        }
    }
    #[test]
    fn restore_preserves_usage_and_original_expiry() {
        let mut broker = test_broker();
        let mut lease = restorable_lease();
        lease.uses = 2;
        lease.created_at -= chrono::Duration::seconds(30);
        lease.expires_at -= chrono::Duration::seconds(30);
        broker.restore(vec![lease.clone()]);
        let restored = broker.get_lease(&lease.id).unwrap();
        assert_eq!(restored.uses, 2);
        assert_eq!(restored.expires_at, lease.expires_at);
        assert_eq!(broker.use_lease(&lease.id).unwrap(), "ghp_test123");
        assert!(matches!(
            broker.use_lease(&lease.id),
            Err(SecretError::LeaseExhausted)
        ));
    }

    #[test]
    fn empty_allow_list_denies_new_secret_requests() {
        let mut broker = test_broker();
        broker.policy.allow.clear();
        let mut caps = CapabilitySet::new(vec![aivm_capability::Capability::new(
            "use",
            "secret",
            "github_token:read",
        )]);
        assert!(matches!(
            broker.request_lease(
                restorable_lease().request,
                &Cube::new("default-deny"),
                &mut caps,
                false,
                None
            ),
            Err(SecretError::PolicyDenied(_))
        ));
        assert!(broker.live_leases().is_empty());
    }
}
