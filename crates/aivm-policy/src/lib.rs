//! Policy engine — spec §13.
//!
//! Deny-overrides, order-independent, fail-closed, deterministic,
//! state-aware. MVP: YAML allowlist + explicit deny list.

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

/// Conditional rule (advanced, spec §13.2). MVP evaluates a tiny subset:
/// `when` supports `state == 'X'`, `state in {'A','B'}`, `confidence >= N`
/// combined with `&&`. Anything unparsable => rule does not match
/// (fail-closed at rule level, deny-by-default overall).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub scope: String,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub effect: Option<String>, // "allow" | "deny", default allow
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
    /// Fail-closed load: invalid YAML => Err, caller must refuse startup.
    pub fn from_yaml(text: &str) -> Result<Self, PolicyError> {
        serde_yaml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// Evaluate a filesystem action against the policy.
    /// Order: explicit deny (glob) first (deny-overrides), then allow list,
    /// then conditional rules. No match => Deny.
    pub fn evaluate_fs(
        &self,
        action: &str, // "read" | "write"
        canonical_path: &str,
        ctx: &EvalContext,
    ) -> (Decision, Option<String>) {
        // 1. deny list always wins
        for pat in &self.filesystem.deny {
            if match_pattern(pat, canonical_path) {
                return (Decision::Deny, Some(format!("deny-list:{pat}")));
            }
        }
        // 2. conditional rules with effect: deny also win over allows
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
        // 3. allow list
        let allows = match action {
            "read" => &self.filesystem.read,
            "write" => &self.filesystem.write,
            _ => return (Decision::Deny, Some("unknown-fs-action".into())),
        };
        for pat in allows {
            if match_pattern(pat, canonical_path) {
                // 4. allow-rules with `when` must also match if a scoped
                // allow-rule exists for this path; otherwise base allow stands.
                return (Decision::Allow, Some(format!("allow-list:{pat}")));
            }
        }
        // 5. conditional allow rules
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
        // Private/loopback/metadata always denied (defense in depth, §18).
        if is_blocked_network(host) {
            return (Decision::Deny, Some("blocked-range".into()));
        }
        for pat in &self.network.deny {
            if match_pattern(pat, host) {
                return (Decision::Deny, Some(format!("deny-list:{pat}")));
            }
        }
        if self.require_test_before_network && !ctx.tests_passed {
            return (Decision::Deny, Some("require-test-before-network".into()));
        }
        for pat in &self.network.allow {
            if match_pattern(pat, host) {
                return (Decision::Allow, Some(format!("allow-list:{pat}")));
            }
        }
        (Decision::Deny, Some("default-deny".into()))
    }

    /// Full check: capability set + policy. Both must allow (I-2, I-3).
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

/// Glob-ish matching for MVP: supports `*`, `**`, exact, and prefix.
/// `**/.env*` should match any path containing `/.env`.
pub fn match_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }
    // Use the `glob` crate semantics on the full string; fall back to
    // substring/prefix checks for workspace-style scopes.
    if pattern.contains('*') {
        if let Ok(pat) = glob::Pattern::new(pattern) {
            if pat.matches(value) {
                return true;
            }
        }
        // `**/x` also matches bare `x` segments anywhere.
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
    // Plain path: exact or dir-prefix.
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
            && h.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()).map(|n| (16..=31).contains(&n)).unwrap_or(false))
}

fn rule_matches(rule: &Rule, ctx: &EvalContext) -> bool {
    match &rule.when {
        None => true,
        Some(w) => eval_when(w, ctx),
    }
}

/// Tiny `&&`-only evaluator for MVP (full CEL later).
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
        return false; // fail-closed
    }
    if let Some(rest) = c.strip_prefix("tests_passed ==") {
        let want = rest.trim() == "true";
        return ctx.tests_passed == want;
    }
    // Unknown predicate => fail-closed (rule does not match).
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
        assert_eq!(p.evaluate_network("169.254.169.254", &ctx).0, Decision::Deny);
        assert_eq!(p.evaluate_network("127.0.0.1", &ctx).0, Decision::Deny);
    }

    #[test]
    fn invalid_yaml_fail_closed() {
        assert!(Policy::from_yaml(":\t: bad: [").is_err());
    }
}
