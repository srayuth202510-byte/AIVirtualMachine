//! One-shot mediated self-test (`aivm demo`).
//!
//! Spins up a throwaway workspace in the temp dir, drives the full
//! enforcement chain (capability + policy + gateway + state machine +
//! audit) through representative allow AND deny cases, verifies the
//! audit hash chain, and cleans up. Fails closed: any unexpected
//! decision is reported, never silently ignored.
//!
//! This is the fastest debug loop for the security boundary:
//! `cargo run -p aivm-cli -- demo`.

use super::{absolutize, RuntimeError};
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
    /// What actually happened: "allow…" on allow, "deny:<reason>" on deny.
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

    // 1. Happy-path write inside src.
    case(
        &mut cases,
        "write src/new.rs",
        Expect::Allow,
        gw.write(&mut cube, "src/new.rs", "fn new() {}\n")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 2. Read back what was written (content must round-trip).
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

    // 3. Path traversal must deny.
    case(
        &mut cases,
        "read ../../etc/passwd (traversal)",
        Expect::Deny,
        gw.read(&mut cube, "../../etc/passwd")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 4. Absolute escape must deny.
    case(
        &mut cases,
        "read /etc/passwd (escape)",
        Expect::Deny,
        gw.read(&mut cube, "/etc/passwd")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 5. Dotenv must deny (policy deny-list).
    case(
        &mut cases,
        "read .env (deny-list)",
        Expect::Deny,
        gw.read(&mut cube, ".env")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 6. Write outside src must deny (capability scope).
    case(
        &mut cases,
        "write README.md (out of scope)",
        Expect::Deny,
        gw.write(&mut cube, "README.md", "hi")
            .map(|r| r.output)
            .map_err(|e| e.to_string()),
    );

    // 7. Unknown tool must deny.
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

    // 8. Symlink escape must deny (unix only; skipped elsewhere).
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

    // 9. State jump INIT -> DEPLOY must deny.
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

    // 10. Validated guarded transitions must allow.
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

    // 11. Audit chain must verify.
    let audit_entries =
        AuditWriter::verify(&audit_path).map_err(|e| RuntimeError::Io(e.to_string()))?;
    let audit_verified = audit_entries > 0;

    let report = DemoReport {
        cases,
        audit_entries,
        audit_verified,
        workspace: ws_str,
    };

    // Best-effort cleanup; demo artifacts must not pollute the repo.
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
