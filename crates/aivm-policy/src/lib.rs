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
}
