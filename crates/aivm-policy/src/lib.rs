//! Policy engine — กฎหมายของ AI VM (ดูสเปก §13)
//!
//! หลักการ: deny ชนะเสมอ (deny-overrides) ไม่ขึ้นกับลำดับ rule
//! fail-closed ทุกจุด ตัดสินแบบ deterministic และรับรู้ state
//! MVP: allowlist ใน YAML + deny list ที่ระบุชัดเจน

use aivm_capability::CapabilitySet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("fail-closed: evaluation error: {0}")]
    Eval(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FsPolicy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
}

/// rule แบบมีเงื่อนไข (ขั้นสูง ดูสเปก §13.2) MVP ประเมินแค่ชุดย่อย:
/// `when` รองรับ `state == 'X'`, `state in {'A','B'}`, `confidence >= N`
/// เชื่อมด้วย `&&` ถ้า parse ไม่ได้ rule นั้นจะไม่ match
/// (fail-closed ระดับ rule และ deny-by-default ทั้งระบบ)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub scope: String,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub effect: Option<String>, // "allow" | "deny" ค่าเริ่มต้นคือ allow
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default = "default_true")]
    pub deny_overrides: bool,
    #[serde(default)]
    pub filesystem: FsPolicy,
    #[serde(default)]
    pub process: ProcessPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub system: SystemPolicy,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub require_test_before_network: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: "deny-all".into(),
            deny_overrides: true,
            filesystem: FsPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
            system: SystemPolicy::default(),
            rules: vec![],
            require_test_before_network: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub state: String,
    pub confidence: f64,
    pub tests_passed: bool,
}

impl Policy {
    /// โหลดแบบ fail-closed: YAML เสียได้ Err ผู้เรียกต้องปฏิเสธการสตาร์ต
    pub fn from_yaml(text: &str) -> Result<Self, PolicyError> {
        serde_yaml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// ประเมิน action บน filesystem เทียบกับ policy
    /// ลำดับ: deny ที่ระบุชัด (glob) มาก่อนเสมอ (deny-overrides) แล้วค่อยดู
    /// allow list แล้วค่อย rule แบบมีเงื่อนไข ไม่ตรงอะไรเลยคือ Deny
    pub fn evaluate_fs(
        &self,
        action: &str, // "read" | "write"
        canonical_path: &str,
        ctx: &EvalContext,
    ) -> (Decision, Option<String>) {
        // 1. deny list ชนะเสมอ
        for pat in &self.filesystem.deny {
            if match_pattern(pat, canonical_path) {
                return (Decision::Deny, Some(format!("deny-list:{pat}")));
            }
        }
        // 2. rule แบบมีเงื่อนไขที่ effect: deny ก็ชนะ allow เหมือนกัน
        for rule in &self.rules {
            if rule.effect.as_deref() == Some("deny")
                && rule.action == action
                && rule.resource == "filesystem"
                && match_pattern(&rule.scope, canonical_path)
                && rule_matches(rule, ctx)
            {
                return (Decision::Deny, Some(format!("rule:{}", rule.id)));
            }
        }
        // 3. allow list — แต่ allow-rule ที่ระบุ scope พร้อม `when`
        // จะทำหน้าที่เป็น state gate: ถ้ามี rule แบบนี้ตรงกับคำขอ
        // ต้องมีอย่างน้อยหนึ่ง rule ที่ match ไม่เช่นนั้นสิทธิ์ allow
        // พื้นฐานจะถูกระงับ (สเปก §13.2, §14)
        let allows = match action {
            "read" => &self.filesystem.read,
            "write" => &self.filesystem.write,
            _ => return (Decision::Deny, Some("unknown-fs-action".into())),
        };
        for pat in allows {
            if match_pattern(pat, canonical_path) {
                if self.gated(action, "filesystem", canonical_path, ctx) {
                    return (Decision::Allow, Some(format!("allow-list:{pat}")));
                }
                return (Decision::Deny, Some("state-gate".into()));
            }
        }
        // 5. allow-rule แบบมีเงื่อนไข
        for rule in &self.rules {
            let effect = rule.effect.as_deref().unwrap_or("allow");
            if effect == "allow"
                && rule.action == action
                && rule.resource == "filesystem"
                && match_pattern(&rule.scope, canonical_path)
                && rule_matches(rule, ctx)
            {
                return (Decision::Allow, Some(format!("rule:{}", rule.id)));
            }
        }
        (Decision::Deny, Some("default-deny".into()))
    }

    pub fn evaluate_process(&self, executable: &str) -> (Decision, Option<String>) {
        for pat in &self.process.deny {
            if match_pattern(pat, executable) {
                return (Decision::Deny, Some(format!("deny-list:{pat}")));
            }
        }
        for pat in &self.process.allow {
            if match_pattern(pat, executable) {
                return (Decision::Allow, Some(format!("allow-list:{pat}")));
            }
        }
        (Decision::Deny, Some("default-deny".into()))
    }

    pub fn evaluate_network(&self, host: &str, ctx: &EvalContext) -> (Decision, Option<String>) {
        // เครือข่ายส่วนตัว/loopback/metadata ปฏิเสธเสมอ (defense in depth §18)
        if is_blocked_network(host) {
            return (Decision::Deny, Some("blocked-range".into()));
        }
        for pat in &self.network.deny {
            if match_pattern(pat, host) {
                return (Decision::Deny, Some(format!("deny-list:{pat}")));
            }
        }
        // deny-rule แบบมีเงื่อนไข (เช่น deny_network_during_analyze)
        for rule in &self.rules {
            if rule.effect.as_deref() == Some("deny")
                && rule.action == "network"
                && rule.resource == "network"
                && match_pattern(&rule.scope, host)
                && rule_matches(rule, ctx)
            {
                return (Decision::Deny, Some(format!("rule:{}", rule.id)));
            }
        }
        if self.require_test_before_network && !ctx.tests_passed {
            return (Decision::Deny, Some("require-test-before-network".into()));
        }
        for pat in &self.network.allow {
            if match_pattern(pat, host) {
                if self.gated("network", "network", host, ctx) {
                    return (Decision::Allow, Some(format!("allow-list:{pat}")));
                }
                return (Decision::Deny, Some("state-gate".into()));
            }
        }
        (Decision::Deny, Some("default-deny".into()))
    }

    /// จริงเมื่อไม่มี allow-rule ที่ระบุ scope มากั้นคำขอนี้ หรือมีอย่างน้อย
    /// หนึ่ง rule ที่ `when` เป็นจริง หลัก fail-closed: predicate ที่ไม่รู้จัก
    /// จะไม่มีวัน match (ดู `eval_clause`)
    fn gated(&self, action: &str, resource: &str, scope: &str, ctx: &EvalContext) -> bool {
        let mut scoped = false;
        for rule in &self.rules {
            let effect = rule.effect.as_deref().unwrap_or("allow");
            if effect == "allow"
                && rule.action == action
                && rule.resource == resource
                && match_pattern(&rule.scope, scope)
            {
                scoped = true;
                if rule_matches(rule, ctx) {
                    return true;
                }
            }
        }
        !scoped
    }

    /// เช็กครบทั้งสองชั้น: ต้องมี capability และ policy ต้องอนุญาต (I-2, I-3)
    pub fn authorize_with_capability(
        &self,
        caps: &mut CapabilitySet,
        action: &str,
        resource: &str,
        scope: &str,
        ctx: &EvalContext,
    ) -> (Decision, Option<String>) {
        if caps.authorize(action, resource, scope).is_err() {
            return (Decision::Deny, Some("no-capability".into()));
        }
        match resource {
            "filesystem" => self.evaluate_fs(action, scope, ctx),
            "network" => self.evaluate_network(scope, ctx),
            "process" => self.evaluate_process(scope),
            _ => (Decision::Deny, Some("unknown-resource".into())),
        }
    }
}

/// การเทียบแบบ glob สำหรับ MVP: รองรับ `*`, `**`, ตรงกันพอดี และ prefix
/// `**/.env*` จะ match ทุก path ที่มี `/.env`
pub fn match_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }
    // ใช้ความหมายแบบ `glob` crate กับทั้งสตริง ถ้าไม่ได้ผลค่อยถอยมา
    // เช็กแบบ substring/prefix สำหรับ scope สไตล์ workspace
    if pattern.contains('*') {
        if let Ok(pat) = glob::Pattern::new(pattern) {
            if pat.matches(value) {
                return true;
            }
        }
        // `**/x` match ส่วน `x` ที่อยู่ตรงไหนก็ได้ด้วย
        let stripped: String = pattern
            .trim_start_matches("**/")
            .trim_start_matches("*/")
            .to_string();
        let stripped = stripped.trim_end_matches("/**").trim_end_matches("/*");
        let needle = stripped.trim_matches('*');
        if !needle.is_empty() && value.contains(needle) {
            return true;
        }
        return false;
    }
    // path ธรรมดา: ต้องตรงกันพอดีหรือเป็น prefix แบบไดเรกทอรี
    if value == pattern {
        return true;
    }
    value.starts_with(&format!("{}/", pattern.trim_end_matches('/')))
}

fn is_blocked_network(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "127.0.0.1"
        || h == "::1"
        || h == "localhost"
        || h == "169.254.169.254"
        || h.starts_with("10.")
        || h.starts_with("192.168.")
        || h.starts_with("169.254.")
        || h.starts_with("100.64.")
        || h.starts_with("172.16.")
        || h.starts_with("172.17.")
        || h.starts_with("172.18.")
        || (h.starts_with("172.")
            && h.split('.')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .map(|n| (16..=31).contains(&n))
                .unwrap_or(false))
}

fn rule_matches(rule: &Rule, ctx: &EvalContext) -> bool {
    match &rule.when {
        None => true,
        Some(w) => eval_when(w, ctx),
    }
}

/// ตัวประเมิน `&&` อย่างง่ายสำหรับ MVP (อนาคตใช้ CEL เต็ม)
fn eval_when(when: &str, ctx: &EvalContext) -> bool {
    for clause in when.split("&&") {
        let c = clause.trim();
        if c.is_empty() {
            continue;
        }
        if !eval_clause(c, ctx) {
            return false;
        }
    }
    true
}

fn eval_clause(c: &str, ctx: &EvalContext) -> bool {
    // state == 'VALIDATE'
    if let Some(rest) = c.strip_prefix("state ==") {
        let want = rest.trim().trim_matches('\'').trim_matches('"');
        return ctx.state == want;
    }
    // state in {'MODIFY', 'VALIDATE'}
    if let Some(rest) = c.strip_prefix("state in") {
        let rest = rest.trim().trim_start_matches('{').trim_end_matches('}');
        for item in rest.split(',') {
            let want = item.trim().trim_matches('\'').trim_matches('"');
            if ctx.state == want {
                return true;
            }
        }
        return false;
    }
    // confidence >= 0.8
    if let Some(rest) = c.strip_prefix("confidence >=") {
        if let Ok(v) = rest.trim().parse::<f64>() {
            return ctx.confidence >= v;
        }
        return false; // fail-closed: parse ไม่ได้คือไม่ผ่าน
    }
    if let Some(rest) = c.strip_prefix("tests_passed ==") {
        let want = rest.trim() == "true";
        return ctx.tests_passed == want;
    }
    // predicate ที่ไม่รู้จัก = fail-closed (rule นี้ไม่ match)
    false
}

/// Policy Document ที่มี metadata สำหรับ versioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub policy_id: String,
    pub version: u32,
    pub policy: Policy,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub description: String,
}

impl PolicyDocument {
    pub fn new(policy_id: String, version: u32, policy: Policy) -> Self {
        Self {
            policy_id,
            version,
            policy,
            created_at: now_secs(),
            description: String::new(),
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }
}

/// Policy Manager: จัดการหลาย policy version และ validation
/// MVP: in-memory, single active version per policy_id
#[derive(Debug)]
pub struct PolicyManager {
    policies: HashMap<String, Vec<PolicyDocument>>, // policy_id -> versions
    active: HashMap<String, u32>,                   // policy_id -> active version
}

impl PolicyManager {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            active: HashMap::new(),
        }
    }

    /// เพิ่ม policy ใหม่ (validate ก่อนเก็บ)
    /// คืน error ถ้า validation fail
    pub fn add_policy(&mut self, doc: PolicyDocument) -> Result<(), PolicyError> {
        self.validate_policy(&doc.policy)?;
        let versions = self.policies.entry(doc.policy_id.clone()).or_default();
        // ตรวจสอบ version ซ้ำ
        if versions.iter().any(|v| v.version == doc.version) {
            return Err(PolicyError::Parse(format!(
                "policy version {} already exists for {}",
                doc.version, doc.policy_id
            )));
        }
        versions.push(doc.clone());
        versions.sort_by_key(|v| v.version);
        // ถ้ายังไม่มี active version ให้ตั้งเป็น active
        if !self.active.contains_key(&doc.policy_id) {
            self.active.insert(doc.policy_id.clone(), doc.version);
        }
        Ok(())
    }

    /// ตั้ง active version (ต้องมี version นั้นอยู่แล้ว)
    pub fn set_active(&mut self, policy_id: &str, version: u32) -> Result<(), PolicyError> {
        let versions = self
            .policies
            .get(policy_id)
            .ok_or_else(|| PolicyError::Parse(format!("policy {} not found", policy_id)))?;
        if !versions.iter().any(|v| v.version == version) {
            return Err(PolicyError::Parse(format!(
                "version {} not found for policy {}",
                version, policy_id
            )));
        }
        self.active.insert(policy_id.to_string(), version);
        Ok(())
    }

    /// ดึง active policy
    pub fn get_active(&self, policy_id: &str) -> Option<&Policy> {
        let version = self.active.get(policy_id)?;
        self.policies
            .get(policy_id)?
            .iter()
            .find(|v| v.version == *version)
            .map(|v| &v.policy)
    }

    /// ดึง policy ตาม version ที่ระบุ
    pub fn get_version(&self, policy_id: &str, version: u32) -> Option<&Policy> {
        self.policies
            .get(policy_id)?
            .iter()
            .find(|v| v.version == version)
            .map(|v| &v.policy)
    }

    /// รายการ version ทั้งหมดของ policy
    pub fn list_versions(&self, policy_id: &str) -> Option<Vec<u32>> {
        self.policies
            .get(policy_id)
            .map(|vs| vs.iter().map(|v| v.version).collect())
    }

    /// Validate policy structure (fail-closed)
    fn validate_policy(&self, policy: &Policy) -> Result<(), PolicyError> {
        // ต้องมี name
        if policy.name.is_empty() {
            return Err(PolicyError::Parse("policy name is required".into()));
        }
        // deny_overrides ควรเป็น true (security best practice)
        if !policy.deny_overrides {
            return Err(PolicyError::Parse(
                "deny_overrides must be true for security".into(),
            ));
        }
        // ต้องมี deny list ขั้นต่ำสำหรับ filesystem (defense in depth)
        if policy.filesystem.deny.is_empty() {
            return Err(PolicyError::Parse(
                "filesystem deny list must not be empty".into(),
            ));
        }
        // process deny ต้องมี shell ขั้นต่ำ
        let has_shell_deny = policy
            .process
            .deny
            .iter()
            .any(|d| d.contains("sh") || d.contains("bash"));
        if !has_shell_deny {
            return Err(PolicyError::Parse(
                "process deny must include shell (/bin/sh or /bin/bash)".into(),
            ));
        }
        // network deny ต้องมี private ranges
        let has_private_deny =
            policy.network.deny.iter().any(|d| {
                d.starts_with("10.") || d.starts_with("192.168.") || d.starts_with("172.")
            });
        if !has_private_deny {
            return Err(PolicyError::Parse(
                "network deny must include private IP ranges".into(),
            ));
        }
        Ok(())
    }

    /// โหลด policy จาก YAML string พร้อม validate
    pub fn load_from_yaml(
        &mut self,
        policy_id: &str,
        version: u32,
        yaml: &str,
    ) -> Result<(), PolicyError> {
        let policy = Policy::from_yaml(yaml)?;
        let doc = PolicyDocument::new(policy_id.to_string(), version, policy);
        self.add_policy(doc)
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

use std::collections::HashMap;

/// Request struct สำหรับ PolicyEvaluator (แก้ clippy::too_many_arguments)
#[derive(Debug, Clone)]
pub struct EvalRequest<'a> {
    pub agent_id: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub scope: &'a str,
    pub ctx: &'a EvalContext,
    pub request_bytes: Option<u64>,
}

impl<'a> EvalRequest<'a> {
    pub fn new(
        agent_id: &'a str,
        action: &'a str,
        resource: &'a str,
        scope: &'a str,
        ctx: &'a EvalContext,
    ) -> Self {
        Self {
            agent_id,
            action,
            resource,
            scope,
            ctx,
            request_bytes: None,
        }
    }

    pub fn with_request_bytes(mut self, bytes: u64) -> Self {
        self.request_bytes = Some(bytes);
        self
    }
}

/// PolicyEvaluator: จุดตัดสินใจกลางสำหรับทุก Tool
/// รวม: Identity -> Capability -> Policy -> Constraints -> Decision -> Audit
#[derive(Debug)]
pub struct PolicyEvaluator {
    pub manager: PolicyManager,
}

impl PolicyEvaluator {
    pub fn new(manager: PolicyManager) -> Self {
        Self { manager }
    }

    /// ประเมินคำขอแบบเต็มรูปแบบ
    /// คืน (Decision, reason, policy_version)
    pub fn evaluate(
        &self,
        req: EvalRequest<'_>,
        caps: &mut CapabilitySet,
    ) -> (Decision, String, u32) {
        // 1. ตรวจสอบตัวตนของ Agent (placeholder - ขยายได้ในอนาคต)
        if req.agent_id.is_empty() {
            return (Decision::Deny, "empty agent_id".into(), 0);
        }

        // 2. ดึง active policy
        let policy = match self.manager.get_active("default") {
            Some(p) => p,
            None => {
                // fallback: deny-all policy
                return (Decision::Deny, "no active policy".into(), 0);
            }
        };
        let policy_version = self.manager.active.get("default").copied().unwrap_or(0);

        // 3. ตรวจสอบ Capability (fail-closed)
        if caps.authorize(req.action, req.resource, req.scope).is_err() {
            return (Decision::Deny, "no-capability".into(), policy_version);
        }

        // 4. ตรวจสอบ Constraints (max_bytes, max_calls)
        // หา capability ที่ใช้อยู่
        if let Ok(idx) = caps.authorize(req.action, req.resource, req.scope) {
            if let Some(cap) = caps.caps.get(idx) {
                if let Err(e) = cap.check_constraints(req.request_bytes, None) {
                    return (
                        Decision::Deny,
                        format!("constraint-violation: {e}"),
                        policy_version,
                    );
                }
            }
        }

        // 5. ตรวจสอบ Policy (fail-closed)
        let (decision, reason_opt) = match req.resource {
            "filesystem" => policy.evaluate_fs(req.action, req.scope, req.ctx),
            "network" => policy.evaluate_network(req.scope, req.ctx),
            "process" => policy.evaluate_process(req.scope),
            _ => (Decision::Deny, Some("unknown-resource".into())),
        };

        let reason = reason_opt.unwrap_or_else(|| "no-reason".into());
        (decision, reason, policy_version)
    }
}

/// ตรวจสอบ Path Traversal และ Symlink Escape
/// คืน canonical path ถ้าผ่าน, Err ถ้าล้มเหลว
pub fn validate_path_containment(
    workspace: &std::path::Path,
    requested: &str,
) -> Result<std::path::PathBuf, String> {
    use std::path::{Path, PathBuf};

    let ws = std::fs::canonicalize(workspace)
        .map_err(|e| format!("workspace canonicalize failed: {e}"))?;

    let joined = if Path::new(requested).is_absolute() {
        PathBuf::from(requested)
    } else {
        ws.join(requested)
    };

    // Lexical normalization ก่อน
    let normalized = normalize_path(&joined);

    // ตรวจสอบว่าไม่หลุดออกนอก workspace
    if normalized != ws && !normalized.starts_with(&ws) {
        return Err(format!("path traversal outside workspace: {requested}"));
    }

    // ตรวจสอบ symlink escape - canonicalize จริง
    if let Ok(real) = std::fs::canonicalize(&normalized) {
        let real_ws = std::fs::canonicalize(&ws)
            .map_err(|e| format!("workspace canonicalize failed: {e}"))?;
        if real != real_ws && !real.starts_with(&real_ws) {
            return Err(format!("symlink escape outside workspace: {requested}"));
        }
        return Ok(real);
    }

    // Path ยังไม่มีอยู่ (write case) - ตรวจสอบ parent directories
    let mut cur: Option<&Path> = Some(&normalized);
    while let Some(p) = cur {
        if p == ws || p == Path::new("") {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.file_type().is_symlink() {
                let real = std::fs::canonicalize(p)
                    .map_err(|e| format!("symlink canonicalize failed: {e}"))?;
                let real_ws = std::fs::canonicalize(&ws)
                    .map_err(|e| format!("workspace canonicalize failed: {e}"))?;
                if real != real_ws && !real.starts_with(&real_ws) {
                    return Err(format!("symlink escape in parent: {requested}"));
                }
            }
        }
        cur = p.parent();
    }

    Ok(normalized)
}

/// Normalize path แบบ lexical (ตัด . และ ..)
fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_yaml(
            r#"
name: coding-default
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config, "**/.env*", "**/secrets/**"]
process:
  allow: [/usr/bin/cargo, /usr/bin/rustc, /usr/bin/git]
  deny: [/bin/sh, /bin/bash]
network:
  allow: [github.com, crates.io]
  deny: ["10.0.0.0/8", "192.168.0.0/16"]
system:
  allow: []
"#,
        )
        .unwrap()
    }

    #[test]
    fn deny_overrides_allow() {
        let p = policy();
        let ctx = EvalContext::default();
        let (d, _) = p.evaluate_fs("read", "/workspace/.env", &ctx);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn default_deny_outside_workspace() {
        let p = policy();
        let ctx = EvalContext::default();
        let (d, _) = p.evaluate_fs("read", "/etc/passwd", &ctx);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn shell_denied() {
        let p = policy();
        assert_eq!(p.evaluate_process("/bin/sh").0, Decision::Deny);
        assert_eq!(p.evaluate_process("/usr/bin/cargo").0, Decision::Allow);
    }

    #[test]
    fn metadata_blocked() {
        let p = policy();
        let ctx = EvalContext {
            tests_passed: true,
            ..Default::default()
        };
        assert_eq!(
            p.evaluate_network("169.254.169.254", &ctx).0,
            Decision::Deny
        );
        assert_eq!(p.evaluate_network("127.0.0.1", &ctx).0, Decision::Deny);
    }

    #[test]
    fn invalid_yaml_fail_closed() {
        assert!(Policy::from_yaml(":\t: bad: [").is_err());
    }

    fn gated_policy() -> Policy {
        Policy::from_yaml(
            r#"
name: gated
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: []
network:
  allow: [github.com]
  deny: []
rules:
  - id: allow_write_src
    action: write
    resource: filesystem
    scope: /workspace/src/**
    when: "state in {'MODIFY', 'VALIDATE'} && confidence >= 0.8"
  - id: deny_network_during_analyze
    action: network
    resource: network
    scope: "*"
    when: "state == 'ANALYZE'"
    effect: deny
"#,
        )
        .unwrap()
    }

    #[test]
    fn write_suspended_until_modify_state() {
        let p = gated_policy();
        // path อยู่ใน allow-list แต่ไม่มี allow-rule ไหน match ใน state ANALYZE
        let analyze = EvalContext {
            state: "ANALYZE".into(),
            confidence: 0.9,
            ..Default::default()
        };
        let (d, rule) = p.evaluate_fs("write", "/workspace/src/a.rs", &analyze);
        assert_eq!(d, Decision::Deny);
        assert_eq!(rule.as_deref(), Some("state-gate"));
        // ผ่านเงื่อนไข transition แบบมี guard: ประตูเปิด
        let modify = EvalContext {
            state: "MODIFY".into(),
            confidence: 0.9,
            ..Default::default()
        };
        let (d, _) = p.evaluate_fs("write", "/workspace/src/a.rs", &modify);
        assert_eq!(d, Decision::Allow);
        // confidence ต่ำ ประตูก็ยังปิดแม้อยู่ใน state MODIFY
        let unsure = EvalContext {
            state: "MODIFY".into(),
            confidence: 0.1,
            ..Default::default()
        };
        assert_eq!(
            p.evaluate_fs("write", "/workspace/src/a.rs", &unsure).0,
            Decision::Deny
        );
        // read ไม่ถูก gate (ไม่มี allow-rule ไหนครอบคลุม)
        assert_eq!(
            p.evaluate_fs("read", "/workspace/a.rs", &analyze).0,
            Decision::Allow
        );
    }

    #[test]
    fn network_deny_rule_fires_during_analyze() {
        let p = gated_policy();
        let analyze = EvalContext {
            state: "ANALYZE".into(),
            tests_passed: true,
            ..Default::default()
        };
        let (d, rule) = p.evaluate_network("github.com", &analyze);
        assert_eq!(d, Decision::Deny);
        assert_eq!(rule.as_deref(), Some("rule:deny_network_during_analyze"));
        let validate = EvalContext {
            state: "VALIDATE".into(),
            tests_passed: true,
            ..Default::default()
        };
        assert_eq!(
            p.evaluate_network("github.com", &validate).0,
            Decision::Allow
        );
    }

    #[test]
    fn policy_manager_add_and_get_active() {
        let mut mgr = PolicyManager::new();
        let yaml = r#"
name: test-policy
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config, "**/.env*", "**/secrets/**"]
process:
  allow: [/usr/bin/cargo]
  deny: [/bin/sh, /bin/bash]
network:
  allow: [github.com]
  deny: ["10.0.0.0/8", "192.168.0.0/16"]
system:
  allow: []
"#;
        mgr.load_from_yaml("test-policy", 1, yaml).unwrap();
        let active = mgr.get_active("test-policy").unwrap();
        assert_eq!(active.name, "test-policy");
    }

    #[test]
    fn policy_manager_versioning() {
        let mut mgr = PolicyManager::new();
        let yaml_v1 = r#"
name: versioned
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config, "**/.env*"]
process:
  allow: [/usr/bin/cargo]
  deny: [/bin/sh]
network:
  allow: [github.com]
  deny: ["10.0.0.0/8"]
system:
  allow: []
"#;
        let yaml_v2 = r#"
name: versioned
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config, "**/.env*", "**/secrets/**"]
process:
  allow: [/usr/bin/cargo, /usr/bin/rustc]
  deny: [/bin/sh, /bin/bash]
network:
  allow: [github.com, crates.io]
  deny: ["10.0.0.0/8", "192.168.0.0/16"]
system:
  allow: []
"#;
        mgr.load_from_yaml("versioned", 1, yaml_v1).unwrap();
        mgr.load_from_yaml("versioned", 2, yaml_v2).unwrap();

        // version 1 should still be accessible
        let v1 = mgr.get_version("versioned", 1).unwrap();
        assert!(!v1.process.allow.contains(&"/usr/bin/rustc".to_string()));

        // version 2 should have rustc
        let v2 = mgr.get_version("versioned", 2).unwrap();
        assert!(v2.process.allow.contains(&"/usr/bin/rustc".to_string()));

        // active should be v1 (first loaded)
        let active = mgr.get_active("versioned").unwrap();
        assert!(!active.process.allow.contains(&"/usr/bin/rustc".to_string()));

        // switch to v2
        mgr.set_active("versioned", 2).unwrap();
        let active = mgr.get_active("versioned").unwrap();
        assert!(active.process.allow.contains(&"/usr/bin/rustc".to_string()));
    }

    #[test]
    fn policy_manager_validation_rejects_weak_policy() {
        let mut mgr = PolicyManager::new();
        // missing filesystem deny
        let bad_yaml = r#"
name: bad
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: []
process:
  allow: [/usr/bin/cargo]
  deny: [/bin/sh]
network:
  allow: [github.com]
  deny: ["10.0.0.0/8"]
system:
  allow: []
"#;
        let result = mgr.load_from_yaml("bad", 1, bad_yaml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("filesystem deny list must not be empty"));
    }

    #[test]
    fn policy_manager_rejects_duplicate_version() {
        let mut mgr = PolicyManager::new();
        let yaml = r#"
name: dup
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config]
process:
  allow: [/usr/bin/cargo]
  deny: [/bin/sh]
network:
  allow: [github.com]
  deny: ["10.0.0.0/8"]
system:
  allow: []
"#;
        mgr.load_from_yaml("dup", 1, yaml).unwrap();
        let result = mgr.load_from_yaml("dup", 1, yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn policy_manager_set_active_nonexistent() {
        let mut mgr = PolicyManager::new();
        let yaml = r#"
name: test
deny_overrides: true
filesystem:
  read: [/workspace]
  write: [/workspace/src]
  deny: [/workspace/.git/config]
process:
  allow: [/usr/bin/cargo]
  deny: [/bin/sh]
network:
  allow: [github.com]
  deny: ["10.0.0.0/8"]
system:
  allow: []
"#;
        mgr.load_from_yaml("test", 1, yaml).unwrap();
        let result = mgr.set_active("test", 999);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
}
