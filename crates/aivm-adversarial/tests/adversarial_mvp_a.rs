//! ชุดเทสต์ adversarial สำหรับ MVP-A — ดูสเปก §38.
//!
//! เน้น negative-testing-first: ทุกเคสด้านล่างต้อง DENY (หรือ harden)
//! รันด้วย `cargo test -p aivm-adversarial` (integration) หรือ `cargo test`

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_policy::{Decision, EvalContext, Policy};
use aivm_sandbox::SandboxLevel;
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

// Phase 7: ระดับ MicroVm ต้อง fail-closed เช่นกัน — ไม่มี backend/config
// ที่สมบูรณ์ = DENY พร้อม audit (ห้ามเงียบผ่านเป็น Process)
#[test]
fn exec_microvm_level_must_deny() {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (mut gw, mut cube, dir) = exec_harness("uvm", std::slice::from_ref(&real), &[], true);
    gw.level = SandboxLevel::MicroVm;
    let r = gw.dispatch(&mut cube, &exec_req("/bin/true", &[]));
    assert!(r.is_err(), "MicroVm ที่ยังไม่พร้อมต้อง DENY");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(
        log.contains("level-disabled") || log.contains("level-invalid"),
        "ต้องมี audit decision สำหรับระดับ MicroVm: {log}"
    );
    assert!(log.contains("\"decision\":\"deny\""));
    adv_clean(&dir);
}

// Phase 5: intent ที่โมเดลผลิตต้องเป็น JSON เข้มเท่านั้น ไม่งั้น DENY
#[test]
fn agent_intent_must_be_strict_json_to_execute() {
    use aivm_runtime::agent::{parse_intent, Intent};

    // ไม่ใช่ JSON เลย (ข่มด้วยคำสั่ง shell) -> ปฏิเสธ
    assert!(parse_intent("sure, run rm -rf / now").is_err());
    // JSON พัง -> ปฏิเสธ
    assert!(parse_intent(r#"{"tool": "filesystem.read", "path": }"#).is_err());
    // tool ที่ไม่อยู่ในลิสต์ (ผ่าน gateway) -> ปฏิเสธที่ชั้น intent
    assert!(parse_intent(r#"{"tool":"shell.exec","path":"/bin/sh"}"#).is_err());
    // ขาด path -> ปฏิเสธ
    assert!(parse_intent(r#"{"tool":"filesystem.read"}"#).is_err());
    // tool ไม่ใช่สตริง -> ปฏิเสธ
    assert!(parse_intent(r#"{"tool":7,"path":"x"}"#).is_err());

    // เคสควบคุม: JSON ที่ถูกต้องสกัดได้เป็น Tool
    match parse_intent(r#"{"tool":"filesystem.read","path":"a.rs"}"#).unwrap() {
        Intent::Tool(r) => assert_eq!(r.tool, "filesystem.read"),
        _ => panic!("expected tool intent"),
    }
}

// Phase 5: ข้อความโมเดลที่ไม่ใช่ JSON ต้องไม่ก่อให้เกิดการกระทำใด ๆ
// และต้องมี audit ระดับ intent (fail-closed + I-7)
#[test]
fn agent_loop_denies_non_json_model_output() {
    let dir = adv_dir("agent-deny");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // provider เริ่มต้นคือ echo ซึ่งตอบข้อความธรรมดา (ไม่ใช่ JSON)
    let cfg = aivm_runtime::VmConfig::from_yaml("name: adv-agent\n").unwrap();
    let mut rt = aivm_runtime::Runtime::init(cfg, dir.clone()).unwrap();
    let run = rt.run_agent("do whatever", 1, None).unwrap();
    assert_eq!(run.stopped, "max-steps");
    assert_eq!(run.steps.len(), 1);
    assert!(
        run.steps[0].outcome.starts_with("ERROR invalid intent"),
        "unexpected outcome: {}",
        run.steps[0].outcome
    );
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(
        log.contains("invalid-intent"),
        "must audit intent deny (I-7)"
    );
    adv_clean(&dir);
}

// ---- G4 Secret Abuse (§38 Secret Abuse + §26) ----

fn secret_harness_adv(tag: &str) -> (ToolGateway, Cube, std::path::PathBuf) {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (gw, cube, dir) = exec_harness(tag, std::slice::from_ref(&real), &[], true);
    let mut broker = aivm_secrets::SecretBroker::new(
        aivm_secrets::SecretPolicy {
            allow: vec!["tok:read".into()],
            deny: vec![],
            hitl_required_for: vec![aivm_secrets::RiskLevel::High],
            max_ttl_seconds: 3600,
            max_uses_allowed: 5,
        },
        None,
    );
    broker.register_secret("tok".into(), "ADV-SECRET-VALUE".into());
    let mut gw = gw.with_secret_broker(broker);
    gw.caps.grant(Capability::new("use", "secret", "tok:read"));
    (gw, cube, dir)
}

fn secret_req(body: serde_json::Value) -> aivm_tools::ToolRequest {
    aivm_tools::ToolRequest {
        tool: "secret.request".into(),
        path: "-".into(),
        content: Some(body.to_string()),
    }
}

fn secret_body_adv(resource: &str, scope: &str, risk: &str) -> serde_json::Value {
    serde_json::json!({
        "tool": "process.exec",
        "resource": resource,
        "scope": scope,
        "purpose": "adv",
        "risk": risk,
    })
}

// Secret Abuse: scope escalation (มี read ขอ write) ต้อง DENY
#[test]
fn secret_scope_escalation_must_deny() {
    let (mut gw, mut cube, dir) = secret_harness_adv("scope");
    let r = gw.dispatch(
        &mut cube,
        &secret_req(secret_body_adv("tok", "write", "low")),
    );
    assert!(r.is_err(), "scope escalation ต้อง DENY");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("\"decision\":\"deny\""));
    assert!(!log.contains("ADV-SECRET-VALUE"));
    adv_clean(&dir);
}

// Secret Abuse: resource ที่ไม่รู้จักต้อง DENY (ไม่บอกว่ามีอะไรบ้าง)
// ชั้น policy ปฏิเสธก่อน (secret-policy) ส่วน pattern ที่ policy เปิดแต่
// broker ไม่มีค่า ตายชั้นถัดไปด้วย secret-unknown
#[test]
fn secret_unknown_resource_must_deny() {
    let (mut gw, mut cube, dir) = secret_harness_adv("unknown");
    // grant cap ตรง resource ปลอมเพื่อให้ถึงขั้น broker (พิสูจน์ว่า broker ปฏิเสธเอง)
    gw.caps
        .grant(Capability::new("use", "secret", "ghost:read"));
    let r = gw.dispatch(
        &mut cube,
        &secret_req(secret_body_adv("ghost", "read", "low")),
    );
    assert!(r.is_err(), "resource ปลอมต้อง DENY");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("secret-policy") || log.contains("secret-unknown"));
    assert!(!log.contains("ADV-SECRET-VALUE"));

    // pattern เปิดแต่ไม่มีค่าใน broker → secret-unknown
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (gw, cube, dir2) = exec_harness("unknown2", std::slice::from_ref(&real), &[], true);
    let mut broker = aivm_secrets::SecretBroker::new(
        aivm_secrets::SecretPolicy {
            allow: vec!["ghost:read".into()],
            deny: vec![],
            hitl_required_for: vec![],
            max_ttl_seconds: 3600,
            max_uses_allowed: 5,
        },
        None,
    );
    broker.register_secret("tok".into(), "ADV-SECRET-VALUE".into());
    let mut gw = gw.with_secret_broker(broker);
    gw.caps
        .grant(Capability::new("use", "secret", "ghost:read"));
    let mut cube = cube;
    let r = gw.dispatch(
        &mut cube,
        &secret_req(secret_body_adv("ghost", "read", "low")),
    );
    assert!(r.is_err());
    let log = std::fs::read_to_string(dir2.join("audit.jsonl")).unwrap();
    assert!(log.contains("secret-unknown"));
    adv_clean(&dir);
    adv_clean(&dir2);
}

// Secret Abuse: high-risk ไม่มี approval ต้อง DENY (default require HITL)
// ผ่าน gateway จริง (broker allow write + cap ครบ — เหลือแค่ HITL ที่ขาด)
#[test]
fn secret_high_risk_without_hitl_must_deny() {
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (gw, cube, dir) = exec_harness("hitl", std::slice::from_ref(&real), &[], true);
    let mut broker = aivm_secrets::SecretBroker::new(
        aivm_secrets::SecretPolicy {
            allow: vec!["tok:write".into()],
            deny: vec![],
            hitl_required_for: vec![aivm_secrets::RiskLevel::High],
            max_ttl_seconds: 3600,
            max_uses_allowed: 5,
        },
        None,
    );
    broker.register_secret("tok".into(), "ADV-SECRET-VALUE".into());
    let mut gw = gw.with_secret_broker(broker);
    gw.caps.grant(Capability::new("use", "secret", "tok:write"));
    let mut cube = cube;
    let r = gw.dispatch(
        &mut cube,
        &secret_req(secret_body_adv("tok", "write", "high")),
    );
    assert!(r.is_err(), "high-risk ไม่มี approval ต้อง DENY");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("hitl-required"));
    assert!(!log.contains("ADV-SECRET-VALUE"));
    adv_clean(&dir);
}

// Secret Abuse: lease ใช้แล้วหมดอายุการใช้ซ้ำต้อง DENY (one-time)
#[test]
fn secret_lease_reuse_must_deny() {
    let (mut gw, mut cube, dir) = secret_harness_adv("reuse");
    let r = gw
        .dispatch(
            &mut cube,
            &secret_req(secret_body_adv("tok", "read", "low")),
        )
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
    let lease_id = v["lease_id"].as_str().unwrap().to_string();
    let exec_with = |gw: &mut ToolGateway, cube: &mut Cube, lease: Option<String>| {
        gw.dispatch(
            cube,
            &aivm_tools::ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some(serde_json::json!({"argv": [], "secret": lease}).to_string()),
            },
        )
    };
    assert!(exec_with(&mut gw, &mut cube, Some(lease_id.clone())).is_ok());
    let r = exec_with(&mut gw, &mut cube, Some(lease_id));
    assert!(r.is_err(), "lease ใช้ซ้ำต้อง DENY");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("lease-exhausted"));
    assert!(!log.contains("ADV-SECRET-VALUE"), "value ห้ามหลุดลง audit");
    adv_clean(&dir);
}

// Secret Abuse: schema ผิดรูปต้อง DENY (non-JSON + ฟิลด์เกิน)
#[test]
fn secret_malformed_request_must_deny() {
    let (mut gw, mut cube, dir) = secret_harness_adv("malformed");
    for body in [
        "not json".to_string(),
        serde_json::json!({"tool": "process.exec"}).to_string(),
        serde_json::json!({
            "tool": "process.exec", "resource": "tok", "scope": "read",
            "purpose": "x", "risk": "low", "smuggle": "value",
        })
        .to_string(),
    ] {
        let r = gw.dispatch(
            &mut cube,
            &aivm_tools::ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(body),
            },
        );
        assert!(r.is_err(), "schema ผิดต้อง DENY");
    }
    adv_clean(&dir);
}

// ---- G4b approve flow (operator เท่านั้น) ----

fn approve_harness_adv(tag: &str) -> (aivm_runtime::Runtime, std::path::PathBuf) {
    let dir = adv_dir(&format!("approve-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("secrets.yaml"), "tok: APPROVE-SECRET\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("secrets.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let cfg = aivm_runtime::VmConfig::from_yaml(
        "name: adv-approve\nsecrets:\n  allow: [\"tok:write\"]\n  hitl_required_for: [\"high\"]\n",
    )
    .unwrap();
    let mut rt = aivm_runtime::Runtime::init(cfg, dir.clone()).unwrap();
    rt.gateway
        .caps
        .grant(Capability::new("use", "secret", "tok:write"));
    (rt, dir)
}

fn request_high_risk(rt: &mut aivm_runtime::Runtime) -> String {
    let r = rt
        .gateway
        .secret_request(
            &mut rt.cube,
            Some(
                &serde_json::json!({
                    "tool": "process.exec",
                    "resource": "tok",
                    "scope": "write",
                    "purpose": "adv",
                    "risk": "high",
                })
                .to_string(),
            ),
        )
        .unwrap_err();
    assert!(r.to_string().contains("approval"));
    let log = std::fs::read_to_string(rt.base_dir.join("audit.jsonl")).unwrap();
    let id = log
        .lines()
        .find_map(|l| {
            let p = l.find("pending:lease-")?;
            Some(
                l[p + "pending:".len()..]
                    .split('"')
                    .next()
                    .unwrap()
                    .to_string(),
            )
        })
        .expect("ต้องมี pending lease id");
    id
}

// G4b: pending → approve ด้วย id ตรง → ใช้ได้ (เส้น operator ปกติ)
#[test]
fn secret_approve_flow_allows_use() {
    let (mut rt, dir) = approve_harness_adv("ok");
    let id = request_high_risk(&mut rt);
    let sum = rt.approve_secret_lease(&id, "op").unwrap();
    assert_eq!(sum.resource, "tok");
    // ใช้ lease ที่ approve แล้วได้ (ครั้งเดียวตาม default max_uses=1)
    let out = rt
        .gateway
        .secret_broker_mut()
        .unwrap()
        .use_lease(&id)
        .unwrap();
    assert_eq!(out, "APPROVE-SECRET");
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("secret-approve"));
    adv_clean(&dir);
}

// G4b: approve id มั่ว / ซ้ำ / ไม่ระบุคน ต้องไม่ผ่านทั้งหมด
#[test]
fn secret_approve_abuse_must_deny() {
    let (mut rt, dir) = approve_harness_adv("abuse");
    let id = request_high_risk(&mut rt);
    // เดา id
    assert!(rt.approve_secret_lease("lease-deadbeef", "op").is_err());
    // ไม่ระบุคน
    assert!(rt.approve_secret_lease(&id, "").is_err());
    // approve จริงครั้งแรกผ่าน
    assert!(rt.approve_secret_lease(&id, "op").is_ok());
    // approve ซ้ำต้องไม่ผ่าน (ไม่ pending แล้ว)
    assert!(rt.approve_secret_lease(&id, "op").is_err());
    adv_clean(&dir);
}

// G4b: ใช้ lease ตั้งแต่ยังไม่ approve ต้อง DENY (lease-not-approved + audit)
#[test]
fn secret_use_before_approve_must_deny() {
    let (mut rt, dir) = approve_harness_adv("early");
    let id = request_high_risk(&mut rt);
    let broker = rt.gateway.secret_broker_mut().unwrap();
    let r = broker.use_lease(&id);
    assert!(
        matches!(r, Err(aivm_secrets::SecretError::NotApproved)),
        "pending ต้องใช้ไม่ได้"
    );
    // ผ่าน gateway exec ก็ต้อง DENY พร้อม audit (inject ไม่เกิด)
    let real = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    rt.gateway.policy.process.allow.push(real.clone());
    rt.gateway
        .caps
        .grant(Capability::new("execute", "process", &real));
    let r = rt.gateway.dispatch(
        &mut rt.cube,
        &aivm_tools::ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some(serde_json::json!({"argv": [], "secret": id}).to_string()),
        },
    );
    assert!(r.is_err());
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("lease-not-approved"));
    adv_clean(&dir);
}
