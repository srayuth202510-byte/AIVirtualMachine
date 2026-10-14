//! self-test แบบผ่านตัวกลางในครั้งเดียว (`aivm demo`)
//!
//! สร้าง workspace ชั่วคราวใน temp dir แล้วขับ enforcement chain ทั้งเส้น
//! (capability + policy + gateway + state machine + audit) ผ่านเคส
//! ตัวอย่างทั้ง ALLOW และ DENY จากนั้นตรวจ hash chain ของ audit แล้ว
//! ทำความสะอาด fail-closed: การตัดสินที่ผิดคาดจะถูกรายงาน
//! ไม่มีเงียบหาย
//!
//! นี่คือ loop ดีบักที่เร็วที่สุดของเส้นขอบเขตความปลอดภัย:
//! `cargo run -p aivm-cli -- demo`

use super::{absolutize, Runtime, RuntimeError, VmConfig};
use aivm_audit::AuditWriter;
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_policy::Policy;
use aivm_tools::{ToolGateway, ToolRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    Allow,
    Deny,
}

impl Expect {
    pub fn label(&self) -> &'static str {
        match self {
            Expect::Allow => "ALLOW",
            Expect::Deny => "DENY",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DemoCase {
    pub name: String,
    pub expected: Expect,
    /// เกิดอะไรขึ้นจริง: "allow:..." ตอนอนุญาต "deny:<เหตุผล>" ตอนปฏิเสธ
    pub got: String,
    pub pass: bool,
}

#[derive(Debug)]
pub struct DemoReport {
    pub cases: Vec<DemoCase>,
    pub audit_entries: u64,
    pub audit_verified: bool,
    pub workspace: String,
}

impl DemoReport {
    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|c| c.pass).count()
    }

    pub fn failed(&self) -> usize {
        self.cases.len() - self.passed()
    }

    pub fn ok(&self) -> bool {
        self.failed() == 0 && self.audit_verified
    }
}

fn case(cases: &mut Vec<DemoCase>, name: &str, expected: Expect, result: Result<String, String>) {
    let (got, pass) = match (&expected, result) {
        (Expect::Allow, Ok(out)) => (format!("allow:{out}"), true),
        (Expect::Allow, Err(e)) => (format!("deny:{e}"), false),
        (Expect::Deny, Err(e)) => (format!("deny:{e}"), true),
        (Expect::Deny, Ok(out)) => (format!("allow:{out}"), false),
    };
    cases.push(DemoCase {
        name: name.to_string(),
        expected,
        got,
        pass,
    });
}

pub fn mediated_demo() -> Result<DemoReport, RuntimeError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir().join(format!("aivm-demo-{nanos}"));
    let ws = base.join("workspace");
    std::fs::create_dir_all(ws.join("src")).map_err(|e| RuntimeError::Io(e.to_string()))?;
    std::fs::write(ws.join("src").join("seed.rs"), "fn seed() {}\n")
        .map_err(|e| RuntimeError::Io(e.to_string()))?;
    std::fs::write(ws.join(".env"), "SECRET=demo\n")
        .map_err(|e| RuntimeError::Io(e.to_string()))?;

    let ws_abs = absolutize(&ws);
    let ws_str = ws_abs.to_string_lossy().to_string();

    let policy = Policy::from_yaml(&format!(
        "name: demo\nfilesystem:\n  read: [{ws_str}]\n  write: [{ws_str}/src]\n  deny: ['**/.env*', '**/secrets/**']\nprocess: {{allow: [], deny: [/bin/sh]}}\nnetwork: {{allow: [], deny: []}}\n"
    ))
    .map_err(|e| RuntimeError::Policy(e.to_string()))?;

    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws_str),
        Capability::new("write", "filesystem", &format!("{ws_str}/src")),
        Capability::new("search", "filesystem", &ws_str),
    ]);
    let audit_path = base.join("audit.jsonl");
    let audit = AuditWriter::open(&audit_path).map_err(|e| RuntimeError::Io(e.to_string()))?;
    let mut gw = ToolGateway::new(ws_abs.clone(), policy, caps, audit, "demo", "sess-demo");
    let mut cube = Cube::new("demo");
    let mut cases: Vec<DemoCase> = vec![];

    // 1. ทางสุข: เขียนใน src ได้
    case(
        &mut cases,
        "write src/new.rs",
        Expect::Allow,
        gw.write(&mut cube, "src/new.rs", "fn new() {}\n")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 2. อ่านสิ่งที่เขียนกลับมา (เนื้อหาต้องตรงกัน)
    case(
        &mut cases,
        "read src/new.rs",
        Expect::Allow,
        gw.read(&mut cube, "src/new.rs")
            .map(|r| {
                if r.output.contains("fn new") {
                    "content-ok".to_string()
                } else {
                    "content-mismatch".to_string()
                }
            })
            .map_err(|e| e.to_string())
            .and_then(|s| {
                if s == "content-ok" {
                    Ok(s)
                } else {
                    Err("round-trip mismatch".to_string())
                }
            }),
    );

    // 3. path traversal ต้องถูกปฏิเสธ
    case(
        &mut cases,
        "read ../../etc/passwd (traversal)",
        Expect::Deny,
        gw.read(&mut cube, "../../etc/passwd")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 4. หลุดออกนอกด้วย absolute path ต้องถูกปฏิเสธ
    case(
        &mut cases,
        "read /etc/passwd (escape)",
        Expect::Deny,
        gw.read(&mut cube, "/etc/passwd")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 5. ไฟล์ dotenv ต้องถูกปฏิเสธ (deny-list ของ policy)
    case(
        &mut cases,
        "read .env (deny-list)",
        Expect::Deny,
        gw.read(&mut cube, ".env")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 6. เขียนนอก src ต้องถูกปฏิเสธ (scope ของ capability)
    case(
        &mut cases,
        "write README.md (out of scope)",
        Expect::Deny,
        gw.write(&mut cube, "README.md", "hi")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 7. tool ที่ไม่รู้จักต้องถูกปฏิเสธ
    case(
        &mut cases,
        "dispatch shell.exec (unknown tool)",
        Expect::Deny,
        gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "shell.exec".into(),
                path: "x".into(),
                content: None,
            },
        )
        .map(|r| r.output)
        .map_err(|e| e.to_string()),
    );

    // 8. symlink escape ต้องถูกปฏิเสธ (เฉพาะ unix ที่อื่นข้าม)
    #[cfg(unix)]
    case(
        &mut cases,
        "read src/evil/passwd (symlink escape)",
        Expect::Deny,
        {
            let link = ws_abs.join("src").join("evil");
            let _ = std::os::unix::fs::symlink("/etc", &link);
            gw.read(&mut cube, "src/evil/passwd")
                .map(|r| r.output)
                .map_err(|e| e.to_string())
        },
    );
    #[cfg(not(unix))]
    cases.push(DemoCase {
        name: "read src/evil/passwd (symlink escape, skipped non-unix)".into(),
        expected: Expect::Deny,
        got: "skip".into(),
        pass: true,
    });

    // 9. กระโดด state จาก INIT -> DEPLOY ต้องถูกปฏิเสธ
    {
        let mut c = Cube::new("demo-jump");
        let r = c.transition(AgentState::Deploy, &TransitionGuards::default());
        case(
            &mut cases,
            "transition INIT->DEPLOY (jump)",
            Expect::Deny,
            r.map(|_| "transitioned".to_string())
                .map_err(|e| e.to_string()),
        );
    }

    // 10. transition แบบมี guard ที่ถูกต้องทั้งหมดต้องผ่าน
    {
        let mut c = Cube::new("demo-path");
        let r: Result<String, String> = (|| {
            c.transition(AgentState::Analyze, &TransitionGuards::default())
                .map_err(|e| e.to_string())?;
            c.transition(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    confidence_threshold: 0.8,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
            c.transition(
                AgentState::Validate,
                &TransitionGuards {
                    tests_passed: true,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
            c.transition(
                AgentState::Deploy,
                &TransitionGuards {
                    policy_approved: true,
                    tests_passed: true,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
            Ok(c.current_state().to_string())
        })();
        case(
            &mut cases,
            "transitions INIT..DEPLOY (guarded)",
            Expect::Allow,
            r,
        );
    }

    // 11. สิทธิ์แบบ dynamic: ใน INIT เขียนไม่ได้ พอถึง MODIFY เขียนได้
    {
        let cfg = VmConfig::from_yaml(
            "name: demo-dyn\nfilesystem:\n  read: [./workspace]\n  write: [./workspace/src]\nnetwork:\n  allow: [github.com]\ncapabilities:\n  initial: [read:workspace, search:code]\n",
        )
        .map_err(|e| RuntimeError::Config(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, base.join("dyn")).map_err(|e| RuntimeError::Io(e.to_string()))?;
        let r: Result<String, String> = (|| {
            // ใน INIT ไม่มี write lease
            if rt
                .gateway
                .write(&mut rt.cube, "src/dyn.rs", "fn dyn_() {}\n")
                .is_ok()
            {
                return Err("write allowed in INIT".to_string());
            }
            rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
                .map_err(|e| e.to_string())?;
            let (granted, _) = rt
                .transition_to(
                    AgentState::Modify,
                    &TransitionGuards {
                        confidence: 0.95,
                        confidence_threshold: super::CONFIDENCE_THRESHOLD,
                        ..Default::default()
                    },
                )
                .map_err(|e| e.to_string())?;
            if granted != 1 {
                return Err(format!("expected 1 grant, got {granted}"));
            }
            rt.gateway
                .write(&mut rt.cube, "src/dyn.rs", "fn dyn_() {}\n")
                .map(|r| r.output)
                .map_err(|e| e.to_string())?;
            // ออกจาก state ที่ให้สิทธิ์ lease ถูก revoke: ใช้หลัง revoke ต้องถูกปฏิเสธ
            rt.gateway.caps.revoke_stale("ANALYZE");
            match rt.gateway.write(&mut rt.cube, "src/dyn2.rs", "x") {
                Ok(_) => Err("write allowed after revoke".to_string()),
                Err(_) => Ok("revoked".to_string()),
            }
        })();
        case(&mut cases, "dynamic grant + revoke (§14)", Expect::Allow, r);
    }

    // 12. process.exec แบบผ่านตัวกลาง (§12/Phase 4): ใน INIT ไม่มี
    // execute lease พอถึง MODIFY รัน /bin/true ที่ allowlist ได้
    {
        let cfg = VmConfig::from_yaml(
            "name: demo-exec\ntools:\n  allow: [/bin/true]\ncapabilities:\n  initial: [read:workspace, search:code]\n",
        )
        .map_err(|e| RuntimeError::Config(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, base.join("exec")).map_err(|e| RuntimeError::Io(e.to_string()))?;
        let r: Result<String, String> = (|| {
            let exec_req = ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("[]".into()),
            };
            // INIT: ไม่มี execute capability
            if rt.gateway.dispatch(&mut rt.cube, &exec_req).is_ok() {
                return Err("exec allowed in INIT".to_string());
            }
            // argv ไม่ใช่ JSON = DENY (กัน shell interpolation ตั้งแต่รูปคำขอ)
            let bad_req = ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some("not json".into()),
            };
            if rt.gateway.dispatch(&mut rt.cube, &bad_req).is_ok() {
                return Err("bad argv allowed".to_string());
            }
            rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
                .map_err(|e| e.to_string())?;
            rt.transition_to(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    confidence_threshold: super::CONFIDENCE_THRESHOLD,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
            rt.gateway
                .dispatch(&mut rt.cube, &exec_req)
                .map(|r| format!("exit-ok:{}", r.ok))
                .map_err(|e| e.to_string())
        })();
        case(
            &mut cases,
            "process.exec mediated (Phase 4)",
            Expect::Allow,
            r,
        );
        // build profile ค่าเริ่มต้นปิด: แม้ execute cap ครบก็สร้าง artifacts ไม่ได้
        case(
            &mut cases,
            "build outputs without profile",
            Expect::Deny,
            rt.gateway
                .dispatch(
                    &mut rt.cube,
                    &ToolRequest {
                        tool: "process.exec".into(),
                        path: "/bin/true".into(),
                        content: Some(
                            serde_json::json!({"argv": [], "outputs": ["demo.o"]}).to_string(),
                        ),
                    },
                )
                .map(|result| result.output)
                .map_err(|error| error.to_string()),
        );
    }

    // 13. secret.request ไม่มี broker ต้องถูกปฏิเสธ (G4: fail-closed)
    case(
        &mut cases,
        "secret.request without broker",
        Expect::Deny,
        gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(
                    "{\"tool\":\"process.exec\",\"resource\":\"t\",\"scope\":\"r\",\"purpose\":\"d\"}"
                        .into(),
                ),
            },
        )
        .map(|r| r.output)
        .map_err(|e| e.to_string()),
    );

    // 14. hash chain ของ audit ต้องตรวจผ่าน
    let audit_entries =
        AuditWriter::verify(&audit_path).map_err(|e| RuntimeError::Io(e.to_string()))?;
    let audit_verified = audit_entries > 0;

    let report = DemoReport {
        cases,
        audit_entries,
        audit_verified,
        workspace: ws_str,
    };

    // ลบแบบ best-effort ขยะ demo ต้องไม่เลอะ repo (ล้าง flag FS ก่อนลบ)
    aivm_audit::clear_flags(&base);
    let _ = std::fs::remove_dir_all(&base);

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_all_cases_pass() {
        let rep = mediated_demo().expect("demo must run");
        for c in &rep.cases {
            assert!(c.pass, "demo case failed: {} (got {})", c.name, c.got);
        }
        assert!(rep.audit_verified, "audit chain must verify");
    }
}
