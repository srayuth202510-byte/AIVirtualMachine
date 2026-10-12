//! Adversarial MVP-A suite — spec §38.
//!
//! Negative-testing-first: every case below MUST deny (or harden).
//! Run: `cargo test -p aivm-adversarial` (integration) or `cargo test`.

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_policy::{Decision, EvalContext, Policy};
use aivm_tools::ToolGateway;

fn test_policy() -> Policy {
    Policy::from_yaml(
        r#"
name: coding-default
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
  deny: ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "169.254.169.254"]
"#,
    )
    .unwrap()
}

fn harness(tag: &str) -> (ToolGateway, Cube) {
    let dir = std::env::temp_dir().join(format!("aivm-adv-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src").join("ok.rs"), "fn ok() {}").unwrap();
    std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
    let ws = dir.canonicalize().unwrap();
    let yaml = format!(
        "name: t\nfilesystem:\n  read: [{}]\n  write: [{}/src]\n  deny: ['**/.env*', '**/secrets/**']\nprocess: {{allow: [], deny: []}}\nnetwork: {{allow: [], deny: []}}\n",
        ws.display(),
        ws.display()
    );
    let policy = Policy::from_yaml(&yaml).unwrap();
    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws.to_string_lossy()),
        Capability::new("write", "filesystem", &format!("{}/src", ws.display())),
        Capability::new("search", "filesystem", &ws.to_string_lossy()),
    ]);
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let gw = ToolGateway::new(dir, policy, caps, audit, "coder", "sess-adv");
    (gw, Cube::new("adv"))
}

#[test]
fn fs_escape_must_deny() {
    let (mut gw, mut cube) = harness("fs");
    for p in [
        "/etc/passwd",
        "../../etc/shadow",
        "/workspace/../../etc/passwd",
    ] {
        assert!(gw.read(&mut cube, p).is_err(), "must deny {p}");
    }
    let (d, _) = test_policy().evaluate_fs("read", "/etc/passwd", &EvalContext::default());
    assert_eq!(d, Decision::Deny);
}

#[test]
fn dotenv_and_secrets_must_deny() {
    let (mut gw, mut cube) = harness("env");
    assert!(gw.read(&mut cube, ".env").is_err());
    let (d, _) = test_policy().evaluate_fs("read", "/workspace/secrets/k", &EvalContext::default());
    assert_eq!(d, Decision::Deny);
}

#[test]
fn symlink_escape_must_deny() {
    let dir = std::env::temp_dir().join(format!("aivm-adv-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc", dir.join("src").join("evil")).unwrap();
    let ws = dir.canonicalize().unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: t\nfilesystem:\n  read: [{}]\n  write: [{}/src]\n  deny: []\n",
        ws.display(),
        ws.display()
    ))
    .unwrap();
    let caps = CapabilitySet::new(vec![Capability::new(
        "read",
        "filesystem",
        &ws.to_string_lossy(),
    )]);
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let mut gw = ToolGateway::new(dir, policy, caps, audit, "coder", "s");
    let mut cube = Cube::new("adv");
    assert!(gw.read(&mut cube, "src/evil/passwd").is_err());
}

#[test]
fn shell_and_unknown_tools_must_deny() {
    let (mut gw, mut cube) = harness("proc");
    let p = test_policy();
    assert_eq!(p.evaluate_process("/bin/sh").0, Decision::Deny);
    for tool in [
        "shell.exec",
        "process.spawn",
        "network.fetch",
        "secret.get",
        "deploy.run",
    ] {
        let r = gw.dispatch(
            &mut cube,
            &aivm_tools::ToolRequest {
                tool: tool.into(),
                path: "x".into(),
                content: None,
            },
        );
        assert!(r.is_err(), "must deny {tool}");
    }
}

#[test]
fn network_must_deny() {
    let p = test_policy();
    let ctx = EvalContext {
        state: "ANALYZE".into(),
        tests_passed: true,
        ..Default::default()
    };
    for h in [
        "10.1.2.3",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "evil.example.com",
    ] {
        assert_eq!(
            p.evaluate_network(h, &ctx).0,
            Decision::Deny,
            "must deny {h}"
        );
    }
}

#[test]
fn expired_and_exhausted_capability_must_deny() {
    let mut cap = Capability::new("read", "filesystem", "/workspace").with_max_uses(1);
    assert!(cap.authorize("read", "filesystem", "/workspace").is_ok());
    assert!(cap.authorize("read", "filesystem", "/workspace").is_err());
    let mut expired = Capability::new("read", "filesystem", "/workspace");
    expired.expiration = Some(1);
    assert!(expired.check_usable().is_err());
}

#[test]
fn state_jump_must_deny() {
    let mut c = Cube::new("t");
    assert!(c
        .transition(AgentState::Deploy, &TransitionGuards::default())
        .is_err());
}

#[test]
fn invalid_config_must_fail_closed() {
    assert!(Policy::from_yaml(":\t: [[[bad").is_err());
    assert!(aivm_runtime::VmConfig::from_yaml(":\t: [[[bad").is_err());
}

#[test]
fn audit_chain_verifies() {
    let dir = std::env::temp_dir().join(format!("aivm-adv-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("a.jsonl");
    let mut w = AuditWriter::open(&p).unwrap();
    w.append(AuditRecord::new(
        0, "coder", "s", "r1", "ANALYZE", "read", "/w/a", "deny", "p",
    ))
    .unwrap();
    w.append(AuditRecord::new(
        0, "coder", "s", "r2", "ANALYZE", "write", "/w/b", "deny", "p",
    ))
    .unwrap();
    assert_eq!(AuditWriter::verify(&p).unwrap(), 2);
}
