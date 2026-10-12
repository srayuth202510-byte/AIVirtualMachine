//! Security invariant suite — สเปก §35 (I-1..I-10).
//!
//! ต่างจาก adversarial suite (เน้นเคสโจมตีรายตัว) ไฟล์นี้ผูกหนึ่งเทสต์
//! ต่อหนึ่ง invariant: ถ้า invariant ข้อไหนพัง เทสต์ข้อนั้นแดงทันที
//! รันด้วย `cargo test -p aivm-adversarial` หรือ `make test-adv`

use aivm_audit::AuditWriter;
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_policy::{Decision, EvalContext, Policy};
use aivm_tools::{ToolGateway, ToolRequest};

fn inv_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("aivm-inv-{tag}-{nanos}"))
}

fn inv_clean(dir: &std::path::Path) {
    aivm_audit::clear_flags(dir);
    let _ = std::fs::remove_dir_all(dir);
}

/// gateway มาตรฐาน: read ทั้ง ws + write แค่ src + search ทั้ง ws
fn gateway(tag: &str) -> (ToolGateway, Cube, std::path::PathBuf) {
    let dir = inv_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let ws = dir.canonicalize().unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: inv\nfilesystem:\n  read: [{}]\n  write: [{}/src]\n  deny: ['**/.env*', '**/secrets/**']\nprocess: {{allow: [], deny: [/bin/sh]}}\nnetwork: {{allow: [github.com], deny: []}}\n",
        ws.display(),
        ws.display()
    ))
    .unwrap();
    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws.to_string_lossy()),
        Capability::new("write", "filesystem", &format!("{}/src", ws.display())),
        Capability::new("search", "filesystem", &ws.to_string_lossy()),
    ]);
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess-inv");
    (gw, Cube::new("inv"), dir)
}

fn audit_lines(dir: &std::path::Path) -> usize {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

/// I-1: AI แตะ host ตรง ๆ ไม่ได้ ทุก external action ต้องผ่าน gateway
/// (พยายามอ่านไฟล์ host + spawn ตรง ต้องล้มทั้งหมด)
#[test]
fn i1_no_direct_host_access() {
    let (mut gw, mut cube, dir) = gateway("i1");
    for p in [
        "/etc/passwd",
        "/proc/self/mounts",
        "/root/.ssh/id_rsa",
        "/workspace/../../etc/shadow",
    ] {
        assert!(gw.read(&mut cube, p).is_err(), "I-1 violated by {p}");
    }
    // spawn ตรงโดยไม่ผ่าน gateway ถูกปิดตายใน MVP-A
    let sb = aivm_sandbox::Sandbox::new(aivm_sandbox::SandboxLevel::Process, Default::default());
    assert!(sb.spawn("/bin/true", &[]).is_err());
    inv_clean(&dir);
}

/// I-2: ทุก external action ต้องมี capability (ไม่มี = DENY)
#[test]
fn i2_every_action_needs_capability() {
    let (mut gw, mut cube, dir) = gateway("i2");
    gw.caps = CapabilitySet::default();
    assert!(gw.read(&mut cube, "src/a.rs").is_err());
    assert!(gw.write(&mut cube, "src/a.rs", "x").is_err());
    assert!(gw.search(&mut cube, "fn").is_err());
    // ชั้น policy+capability รวมกันก็ต้องปฏิเสธ
    let p = Policy::default();
    let ctx = EvalContext::default();
    let (d, rule) = p.authorize_with_capability(
        &mut CapabilitySet::default(),
        "read",
        "filesystem",
        "/workspace/a.rs",
        &ctx,
    );
    assert_eq!(d, Decision::Deny);
    assert_eq!(rule.as_deref(), Some("no-capability"));
    inv_clean(&dir);
}

/// I-3: ทุก capability ต้องผ่าน policy (deny-overrides + default-deny)
#[test]
fn i3_policy_judges_every_capability() {
    let p = Policy::from_yaml(
        "name: t\nfilesystem:\n  read: [/workspace]\n  write: []\n  deny: [/workspace]\n",
    )
    .unwrap();
    let ctx = EvalContext::default();
    // allow กับ deny ชนกันที่ path เดียว: deny ต้องชนะ
    let (d, rule) = p.evaluate_fs("read", "/workspace/a.rs", &ctx);
    assert_eq!(d, Decision::Deny);
    assert!(rule.unwrap_or_default().starts_with("deny-list"));
    // ไม่ match อะไรเลย = DENY (default-deny ระดับ rule)
    let (d, _) = p.evaluate_fs("write", "/workspace/src/a.rs", &ctx);
    assert_eq!(d, Decision::Deny);
}

/// I-4: ทุก state transition ต้องผ่านการ validate (ห้ามกระโดด + guard)
fn walk_to(target: AgentState) -> Cube {
    let g = TransitionGuards {
        confidence: 0.9,
        confidence_threshold: 0.8,
        tests_passed: true,
        policy_approved: true,
    };
    let mut c = Cube::new("t");
    if target == AgentState::Init {
        return c;
    }
    for s in [
        AgentState::Analyze,
        AgentState::Modify,
        AgentState::Validate,
        AgentState::Deploy,
    ] {
        c.transition(s, &g).unwrap();
        if s == target {
            break;
        }
    }
    assert_eq!(c.current_state(), target);
    c
}

#[test]
fn i4_transitions_validated() {
    let g = TransitionGuards {
        confidence: 0.9,
        confidence_threshold: 0.8,
        tests_passed: true,
        policy_approved: true,
    };
    // เส้นที่ถูกมีแค่ 4 เส้น
    for (from, to) in [
        (AgentState::Init, AgentState::Analyze),
        (AgentState::Analyze, AgentState::Modify),
        (AgentState::Modify, AgentState::Validate),
        (AgentState::Validate, AgentState::Deploy),
    ] {
        let mut c = walk_to(from);
        assert!(c.transition(to, &g).is_ok());
    }
    // นอกนั้นห้ามหมด (รวมกระโดดข้าม + ถอยหลัง)
    for (from, to) in [
        (AgentState::Init, AgentState::Modify),
        (AgentState::Init, AgentState::Validate),
        (AgentState::Init, AgentState::Deploy),
        (AgentState::Analyze, AgentState::Validate),
        (AgentState::Analyze, AgentState::Deploy),
        (AgentState::Modify, AgentState::Deploy),
        (AgentState::Modify, AgentState::Init),
        (AgentState::Deploy, AgentState::Init),
    ] {
        let mut c = walk_to(from);
        assert!(
            c.transition(to, &g).is_err(),
            "I-4 violated: {from} -> {to} allowed"
        );
    }
    // guard ตก = ห้ามแม้เส้นถูก (confidence ต่ำ / เทสต์ไม่ผ่าน)
    let mut c = walk_to(AgentState::Analyze);
    assert!(c
        .transition(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.1,
                confidence_threshold: 0.8,
                ..Default::default()
            }
        )
        .is_err());
    let mut c = walk_to(AgentState::Modify);
    assert!(c
        .transition(AgentState::Validate, &TransitionGuards::default())
        .is_err());
}

/// I-5: AI แก้เส้นขอบเขตตัวเองไม่ได้ (boundary path เขียนไม่เข้า)
#[test]
fn i5_boundary_immutable() {
    let (mut gw, mut cube, dir) = gateway("i5");
    let ws = dir.canonicalize().unwrap();
    // สร้างไฟล์ขอบเขตขึ้นมาก่อน แล้วพยายามเขียนทับผ่าน gateway
    std::fs::create_dir_all(ws.join("policies")).unwrap();
    std::fs::write(ws.join("policies/coding-default.yaml"), "x").unwrap();
    std::fs::write(ws.join("aivm.yaml"), "x").unwrap();
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "x").unwrap();
    for p in [
        "policies/coding-default.yaml",
        "aivm.yaml",
        ".git/config",
        ".env",
        "secrets/token",
    ] {
        assert!(
            gw.write(&mut cube, p, "pwned").is_err(),
            "I-5 violated by {p}"
        );
    }
    inv_clean(&dir);
}

/// I-6: ไม่แน่ใจ = DENY (parse/eval/context พังต้องไม่กลายเป็น allow)
#[test]
fn i6_fail_closed_on_uncertainty() {
    assert!(Policy::from_yaml(":\t: [[[bad").is_err());
    assert!(aivm_runtime::VmConfig::from_yaml(":\t: [[[bad").is_err());
    let (mut gw, mut cube, dir) = gateway("i6");
    // tool ไม่รู้จัก + action ไม่รู้จัก + resource ไม่รู้จัก
    assert!(gw
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "nope".into(),
                path: "x".into(),
                content: None
            }
        )
        .is_err());
    let p = Policy::default();
    let ctx = EvalContext::default();
    assert_eq!(
        p.evaluate_fs("teleport", "/workspace/a.rs", &ctx).0,
        Decision::Deny
    );
    let (d, _) = p.authorize_with_capability(
        &mut CapabilitySet::default(),
        "read",
        "teleporter",
        "/workspace/a.rs",
        &ctx,
    );
    assert_eq!(d, Decision::Deny);
    // predicate แปลกใน when: rule ไม่ match (deny-by-default คุมต่อ)
    let pr = Policy::from_yaml(
        "name: t\nfilesystem:\n  read: [/workspace]\n  write: [/workspace/src]\n  deny: []\nrules:\n  - id: weird\n    action: write\n    resource: filesystem\n    scope: /workspace/src/**\n    when: \"vibes == 'good'\"\n",
    )
    .unwrap();
    assert_eq!(
        pr.evaluate_fs("write", "/workspace/src/a.rs", &EvalContext::default())
            .0,
        Decision::Deny
    );
    inv_clean(&dir);
}

/// I-7: ทุก action ที่ผ่าน authorize ถูก audit (allow/deny อย่างละ 1 record)
#[test]
fn i7_every_decision_audited() {
    let (mut gw, mut cube, dir) = gateway("i7");
    let before = audit_lines(&dir);
    gw.write(&mut cube, "src/a.rs", "x").unwrap(); // allow
    assert!(gw.read(&mut cube, "/etc/passwd").is_err()); // deny
    assert!(gw
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "nope".into(),
                path: "x".into(),
                content: None
            }
        )
        .is_err()); // deny
    assert_eq!(audit_lines(&dir) - before, 3);
    // chain ตรวจผ่าน (ไม่มีใครแก้ระหว่างทาง)
    assert!(AuditWriter::verify(dir.join("audit.jsonl")).is_ok());
    // grant จาก transition ก็ถูก audit ด้วย
    let rt_dir = inv_dir("i7rt");
    let cfg = aivm_runtime::VmConfig::from_yaml(
        "name: inv\nfilesystem:\n  read: [./workspace]\n  write: [./workspace/src]\ncapabilities:\n  initial: [read:workspace, search:code]\n",
    )
    .unwrap();
    let mut rt = aivm_runtime::Runtime::init(cfg, rt_dir.clone()).unwrap();
    let audit_p = rt_dir.join("audit.jsonl");
    let before_rt = std::fs::read_to_string(&audit_p)
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);
    rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    let (granted, _) = rt
        .transition_to(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.95,
                confidence_threshold: 0.8,
                ..Default::default()
            },
        )
        .unwrap();
    let after_rt = std::fs::read_to_string(&audit_p)
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);
    assert_eq!(granted, 1);
    assert_eq!(after_rt - before_rt, granted);
    assert!(AuditWriter::verify(&audit_p).is_ok());
    inv_clean(&dir);
    inv_clean(&rt_dir);
}

/// I-8: least privilege ตลอดเวลา (scope แคบ + ผูกเวลา/จำนวน/state)
#[test]
fn i8_least_privilege_always() {
    // scope กว้างกว่าเดิมนิดเดียวก็ต้องไม่ได้ (/workspace2 ไม่ใช่ลูก /workspace)
    let mut set = CapabilitySet::new(vec![Capability::new("read", "filesystem", "/workspace")]);
    assert!(set
        .authorize("read", "filesystem", "/workspace2/evil")
        .is_err());
    // ขอ escalate เป็น / ทั้งก้อนยิ่งไม่ได้
    assert!(set.authorize("read", "filesystem", "/").is_err());
    // lease หมดอายุ / หมดโควต้า / ผิด state ใช้ต่อไม่ได้
    let mut exp = Capability::new("read", "filesystem", "/workspace");
    exp.expiration = Some(1);
    assert!(exp.check_usable().is_err());
    let mut one = Capability::new("secret", "t", "s").with_max_uses(1);
    one.authorize("secret", "t", "s").unwrap();
    assert!(one.authorize("secret", "t", "s").is_err());
}

/// I-9: เช็กก่อนรันเสมอ (canonicalize ก่อน check + กัน TOCTOU)
#[test]
fn i9_checks_precede_execution() {
    let (mut gw, mut cube, dir) = gateway("i9");
    let ws = dir.canonicalize().unwrap();
    // สลับ parent เป็น symlink หลังโครงสร้างเกิด: เขียนผ่าน symlink ต้องตาย
    let outside = inv_dir("i9out");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("x"), "secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, ws.join("linkdir")).unwrap();
    let r = gw.write(&mut cube, "linkdir/pwned", "x");
    assert!(r.is_err(), "I-9 violated: TOCTOU symlink swap executed");
    // ไฟล์นอกต้องไม่ถูกสร้าง/แตะจริง
    assert!(!outside.join("pwned").exists());
    inv_clean(&dir);
    inv_clean(&outside);
}

/// I-10: ขอบเขตบังคับเชิงโครงสร้าง ไม่ใช่แค่เช็กในโค้ด
/// (mechanism ระดับ OS + file attr + hardening ใน pre_exec)
#[test]
fn i10_structural_enforcement() {
    // probe รายงานความพร้อมจริงของเครื่อง (ห้ามอ้างว่ามีทั้งที่ไม่มี)
    let pr = aivm_sandbox::probe();
    let _ = serde_json::to_string(&pr).unwrap();
    // ทุกการรันแบบมีกรอบต้องติด no-new-privs + rlimit (ตรวจจาก applied)
    let ws = inv_dir("i10");
    std::fs::create_dir_all(&ws).unwrap();
    let real = std::fs::canonicalize("/bin/true").unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: t\nprocess:\n  allow: [\"{}\"]\n  deny: []\n",
        real.display()
    ))
    .unwrap();
    let out = aivm_sandbox::run_checked(
        &aivm_sandbox::ExecSpec {
            exe: std::path::PathBuf::from("/bin/true"),
            args: vec![],
            cwd: ws.clone(),
            workspace: ws.clone(),
            env_extra: vec![],
            limits: Default::default(),
        },
        &policy,
    )
    .unwrap();
    for m in ["no-new-privs", "pdeathsig-sigkill", "env-scrub", "cwd-pin"] {
        assert!(out.applied.contains(&m.to_string()), "I-10: {m} missing");
    }
    // audit ไฟล์ล็อกเฉพาะเจ้าของ (structural ระดับ FS)
    let (mut gw, mut cube, dir) = gateway("i10b");
    gw.write(&mut cube, "src/a.rs", "x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("audit.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    inv_clean(&ws);
    inv_clean(&dir);
}
