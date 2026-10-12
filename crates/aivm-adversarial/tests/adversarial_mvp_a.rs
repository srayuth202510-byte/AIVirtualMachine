//! ชุดเทสต์ adversarial สำหรับ MVP-A — ดูสเปก §38.
//!
//! เน้น negative-testing-first: ทุกเคสด้านล่างต้อง DENY (หรือ harden)
//! รันด้วย `cargo test -p aivm-adversarial` (integration) หรือ `cargo test`

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

fn adv_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("aivm-adv-{tag}-{nanos}"))
}

fn adv_clean(dir: &std::path::Path) {
    aivm_audit::clear_flags(dir);
    let _ = std::fs::remove_dir_all(dir);
}

fn harness(tag: &str) -> (ToolGateway, Cube, std::path::PathBuf) {
    let dir = adv_dir(tag);
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
    let gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess-adv");
    (gw, Cube::new("adv"), dir)
}

#[test]
fn fs_escape_must_deny() {
    let (mut gw, mut cube, dir) = harness("fs");
    for p in [
        "/etc/passwd",
        "../../etc/shadow",
        "/workspace/../../etc/passwd",
    ] {
        assert!(gw.read(&mut cube, p).is_err(), "must deny {p}");
    }
    let (d, _) = test_policy().evaluate_fs("read", "/etc/passwd", &EvalContext::default());
    assert_eq!(d, Decision::Deny);
    adv_clean(&dir);
}

#[test]
fn dotenv_and_secrets_must_deny() {
    let (mut gw, mut cube, dir) = harness("env");
    assert!(gw.read(&mut cube, ".env").is_err());
    let (d, _) = test_policy().evaluate_fs("read", "/workspace/secrets/k", &EvalContext::default());
    assert_eq!(d, Decision::Deny);
    adv_clean(&dir);
}

#[test]
fn symlink_escape_must_deny() {
    let dir = adv_dir("link");
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
    let mut gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "s");
    let mut cube = Cube::new("adv");
    assert!(gw.read(&mut cube, "src/evil/passwd").is_err());
    adv_clean(&dir);
}

#[test]
fn shell_and_unknown_tools_must_deny() {
    let (mut gw, mut cube, dir) = harness("proc");
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
    adv_clean(&dir);
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
    let dir = adv_dir("audit");
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
    adv_clean(&dir);
}

fn dyn_runtime(tag: &str) -> (aivm_runtime::Runtime, std::path::PathBuf) {
    let dir = adv_dir(&format!("dyn-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = aivm_runtime::VmConfig::from_yaml(
        "name: adv\nfilesystem:\n  read: [./workspace]\n  write: [./workspace/src]\nnetwork:\n  allow: [github.com]\ncapabilities:\n  initial: [read:workspace, search:code]\n",
    )
    .unwrap();
    let rt = aivm_runtime::Runtime::init(cfg, dir.clone()).unwrap();
    (rt, dir)
}

fn guards_modify() -> TransitionGuards {
    TransitionGuards {
        confidence: 0.95,
        confidence_threshold: 0.8,
        ..Default::default()
    }
}

#[test]
fn write_before_grant_must_deny() {
    let (mut rt, dir) = dyn_runtime("pre");
    // INIT มีแค่ read/search: เขียนไม่ได้แม้ใน workspace/src
    assert!(rt.gateway.write(&mut rt.cube, "src/early.rs", "x").is_err());
    // state ANALYZE ก็ยังไม่มี write lease
    rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    assert!(rt.gateway.write(&mut rt.cube, "src/early.rs", "x").is_err());
    adv_clean(&dir);
}

#[test]
fn grant_opens_write_and_revoke_closes_it() {
    let (mut rt, dir) = dyn_runtime("cycle");
    rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    let (granted, _) = rt
        .transition_to(AgentState::Modify, &guards_modify())
        .unwrap();
    assert_eq!(granted, 1);
    assert!(rt.gateway.write(&mut rt.cube, "src/ok.rs", "x").is_ok());
    // lease ผูกกับ MODIFY/VALIDATE: นอกนั้นต้องตาย
    assert_eq!(rt.gateway.caps.revoke_stale("ANALYZE"), 1);
    assert!(rt.gateway.write(&mut rt.cube, "src/late.rs", "x").is_err());
    adv_clean(&dir);
}

#[test]
fn failed_transition_grants_nothing() {
    let (mut rt, dir) = dyn_runtime("jump");
    let before = rt.gateway.caps.caps.len();
    assert!(rt
        .transition_to(AgentState::Deploy, &TransitionGuards::default())
        .is_err());
    assert_eq!(rt.cube.current_state(), AgentState::Init);
    assert_eq!(rt.gateway.caps.caps.len(), before);
    assert!(rt.gateway.caps.caps.iter().all(|c| c.action != "write"));
    adv_clean(&dir);
}

#[test]
fn state_gate_holds_despite_capability() {
    // ต่อให้มี write capability แต่ policy ระงับ allow-list ไว้จนกว่า
    // `when` ของ allow-rule ที่ระบุ scope จะเป็นจริง (สเปก §13.2 + §14)
    let dir = adv_dir("gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let ws = dir.canonicalize().unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: gated\nfilesystem:\n  read: [{}]\n  write: [{}/src]\n  deny: []\nrules:\n  - id: allow_write_src\n    action: write\n    resource: filesystem\n    scope: {}/src/**\n    when: \"state in {{'MODIFY', 'VALIDATE'}} && confidence >= 0.8\"\n",
        ws.display(), ws.display(), ws.display()
    ))
    .unwrap();
    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws.to_string_lossy()),
        Capability::new("write", "filesystem", &format!("{}/src", ws.display())),
    ]);
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let mut gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess-gate");
    let mut cube = Cube::new("gate");
    // ใน INIT: มี capability แต่ประตูปิด
    assert!(gw.write(&mut cube, "src/a.rs", "x").is_err());
    // หลัง transition แบบมี guard คำขอเดียวกันได้รับอนุญาต
    cube.transition(AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    cube.transition(AgentState::Modify, &guards_modify())
        .unwrap();
    assert!(gw.write(&mut cube, "src/a.rs", "x").is_ok());
    adv_clean(&dir);
}

/// gateway สำหรับเทสต์ exec: policy/caps ประกอบเองตามเคส
fn exec_harness(
    tag: &str,
    allow: &[String],
    deny: &[String],
    with_execute_cap: bool,
) -> (ToolGateway, Cube, std::path::PathBuf) {
    let dir = adv_dir(&format!("exec-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let allow_list = allow
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let deny_list = deny
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let policy = Policy::from_yaml(&format!(
        "name: t\nprocess:\n  allow: [{allow_list}]\n  deny: [{deny_list}]\n"
    ))
    .unwrap();
    let ws = dir.canonicalize().unwrap();
    let mut caps = vec![Capability::new("read", "filesystem", &ws.to_string_lossy())];
    if with_execute_cap {
        for exe in allow {
            caps.push(Capability::new("execute", "process", exe));
        }
    }
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let gw = ToolGateway::new(
        dir.clone(),
        policy,
        CapabilitySet::new(caps),
        audit,
        "coder",
        "s",
    );
    (gw, Cube::new("adv"), dir)
}

fn exec_req(exe: &str, args: &[&str]) -> aivm_tools::ToolRequest {
    aivm_tools::ToolRequest {
        tool: "process.exec".into(),
        path: exe.into(),
        content: Some(
            serde_json::to_string(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap(),
        ),
    }
}

#[test]
fn exec_shell_chars_stay_literal() {
    // อาร์กิวเมนต์ต้องไม่ถูกตีความโดย shell: สตริงทั้งก้อนส่งตรงเป็น argv
    let echo = std::fs::canonicalize("/bin/echo").unwrap();
    let echo_s = echo.to_string_lossy().to_string();
    let (mut gw, mut cube, dir) = exec_harness("lit", std::slice::from_ref(&echo_s), &[], true);
    let planted = dir.join("pwned");
    let arg = format!("a;touch {}", planted.display());
    let r = gw.dispatch(&mut cube, &exec_req("/bin/echo", &[&arg]));
    let out = r.unwrap();
    // echo พิมพ์สตริงดิบออกมา แต่ไฟล์ต้องไม่ถูกสร้าง (ไม่มี shell มาต่อคำสั่ง)
    assert!(out.output.contains(&arg));
    assert!(!planted.exists());
    adv_clean(&dir);
}

#[test]
fn exec_symlink_to_shell_denied() {
    // symlink ใน workspace ชี้ไป /bin/sh: canonicalize แล้วเจอ dash = interpreter
    let dash = std::fs::canonicalize("/bin/sh").unwrap();
    let dash_s = dash.to_string_lossy().to_string();
    let (mut gw, mut cube, dir) = exec_harness("link", &[dash_s], &[], true);
    #[cfg(unix)]
    std::os::unix::fs::symlink("/bin/sh", dir.join("src").join("sh")).unwrap();
    let link = format!("{}/src/sh", dir.display());
    // ต่อให้ policy/cap ครอบ canonical ปลายทาง ประตู interpreter ต้องปฏิเสธก่อน
    assert!(gw.dispatch(&mut cube, &exec_req(&link, &[])).is_err());
    adv_clean(&dir);
}

#[test]
fn exec_relative_exe_denied() {
    let (mut gw, mut cube, dir) = exec_harness("rel", &["/bin/true".to_string()], &[], true);
    assert!(gw.dispatch(&mut cube, &exec_req("bin/true", &[])).is_err());
    adv_clean(&dir);
}

#[test]
fn exec_without_capability_denied() {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (mut gw, mut cube, dir) = exec_harness("nocap", &[real], &[], false);
    assert!(gw.dispatch(&mut cube, &exec_req("/bin/true", &[])).is_err());
    adv_clean(&dir);
}

#[test]
fn exec_policy_deny_wins() {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let real2 = real.clone();
    let (mut gw, mut cube, dir) = exec_harness("deny", std::slice::from_ref(&real), &[real2], true);
    assert!(gw.dispatch(&mut cube, &exec_req("/bin/true", &[])).is_err());
    adv_clean(&dir);
}

#[test]
fn exec_bad_argv_shape_denied() {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (mut gw, mut cube, dir) = exec_harness("argv", &[real], &[], true);
    let r = gw.dispatch(
        &mut cube,
        &aivm_tools::ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("not json".into()),
        },
    );
    assert!(r.is_err());
    adv_clean(&dir);
}
