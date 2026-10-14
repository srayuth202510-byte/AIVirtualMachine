//! Agent loop + compiler/linker/test binary จริง: โมเดลแบบ scripted ทำให้เส้นทาง deterministic
use aivm_audit::AuditWriter;
use aivm_cube::{AgentState, TransitionGuards};
use aivm_model::{Model, ModelError};
use aivm_runtime::{Runtime, VmConfig};
use aivm_tools::{ToolError, ToolRequest};
use serde_json::json;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

const BROKEN: &str = "int add(int a, int b) { return a - b; }\nint main(void) { return add(2, 3) == 5 && add(-1, 1) == 0 ? 0 : 1; }\n";
const FIXED: &str = "int add(int a, int b) { return a + b; }\nint main(void) { return add(2, 3) == 5 && add(-1, 1) == 0 ? 0 : 1; }\n";
struct Script(Mutex<VecDeque<String>>);
impl Model for Script {
    fn reason(&self, _: &str) -> Result<String, ModelError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .expect("script exhausted"))
    }
    fn token_count(&self, text: &str) -> usize {
        text.len()
    }
    fn max_context(&self) -> usize {
        32768
    }
}
struct Fixture {
    runtime: Runtime,
    root: PathBuf,
    cc: String,
    ld: String,
    crt: Vec<String>,
}
impl Fixture {
    fn new(enabled: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aivm-coding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cc = std::fs::canonicalize("/usr/bin/cc")
            .expect("coding tests require GCC/binutils")
            .display()
            .to_string();
        let ld = std::fs::canonicalize("/usr/bin/ld")
            .unwrap()
            .display()
            .to_string();
        let crt = ["crt1.o", "crti.o", "crtn.o"]
            .into_iter()
            .map(|name| {
                let output = std::process::Command::new(&cc)
                    .arg(format!("-print-file-name={name}"))
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let path = String::from_utf8(output.stdout).unwrap().trim().to_owned();
                assert!(
                    std::path::Path::new(&path).is_file(),
                    "C runtime startup file missing: {path}"
                );
                path
            })
            .collect();
        let config = VmConfig::from_yaml(&format!(
            r#"
name: coding
resources: {{cpu: 1, memory: 1GB, storage: 64MB}}
build: {{enabled: {enabled}, max_files: 4, max_bytes: 1048576}}
tools: {{allow: [cc, as, ld, "build:tests"]}}
"#
        ))
        .unwrap();
        let runtime = Runtime::init(config, root.clone()).unwrap();
        std::fs::create_dir_all(runtime.workspace.join("src")).unwrap();
        std::fs::write(runtime.workspace.join("src/main.c"), BROKEN).unwrap();
        Self {
            runtime,
            root,
            cc,
            ld,
            crt,
        }
    }
    fn modify(&mut self) {
        self.runtime
            .transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        self.runtime
            .transition_to(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    confidence_threshold: 0.8,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    fn artifact(&self) -> String {
        "build:tests".into()
    }
    fn build_steps(&self) -> Vec<String> {
        vec![
            intent(&self.cc, &json!({"argv":["-pipe", "-c", "src/main.c", "-o", ".aivm-build/main.o"],"outputs":["main.o"]}).to_string()),
            intent(&self.ld, &json!({"argv":["-o", ".aivm-build/tests", "--dynamic-linker", "/lib64/ld-linux-x86-64.so.2", self.crt[0], self.crt[1], ".aivm-build/main.o", "-lc", self.crt[2]],"outputs":["tests"]}).to_string()),
            intent(&self.artifact(), "[]"),
        ]
    }
    fn execute(&mut self, steps: Vec<String>) -> aivm_runtime::agent::AgentRun {
        self.runtime.model = Box::new(Script(Mutex::new(steps.into())));
        self.runtime
            .run_agent("fix add and run the tests", 10, Some(&self.root))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.root);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn intent(exe: &str, content: &str) -> String {
    json!({"tool":"process.exec","path":exe,"content":content}).to_string()
}
fn done() -> String {
    json!({"done":true,"summary":"completed"}).to_string()
}

#[test]
fn agent_reads_fixes_builds_and_tests_with_audited_limits() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    let mut baseline = fixture.build_steps();
    baseline.push(done());
    let baseline = fixture.execute(baseline);
    assert!(
        baseline.steps[0].outcome.starts_with("OK"),
        "{:?}",
        baseline.steps
    );
    assert!(
        baseline.steps[1].outcome.starts_with("OK"),
        "{:?}",
        baseline.steps
    );
    assert!(
        baseline.steps[2].outcome.starts_with("FAIL"),
        "broken code must fail: {:?}",
        baseline.steps
    );
    assert!(baseline.steps[2].outcome.contains("exit status: 1"));
    let mut steps = vec![
        json!({"tool":"filesystem.read","path":"src/main.c"}).to_string(),
        json!({"tool":"filesystem.write","path":"src/main.c","content":FIXED}).to_string(),
    ];
    steps.extend(fixture.build_steps());
    steps.push(done());
    let run = fixture.execute(steps);
    assert_eq!(run.stopped, "done");
    assert_eq!(run.steps.len(), 5);
    assert!(
        run.steps.iter().all(|step| step.outcome.starts_with("OK")),
        "{:?}",
        run.steps
    );
    assert!(run.steps[4].outcome.contains("exit status: 0"));
    assert_eq!(
        std::fs::read_to_string(fixture.runtime.workspace.join("src/main.c")).unwrap(),
        FIXED
    );
    assert_eq!(fixture.runtime.cube.current_state(), AgentState::Modify);
    assert!(
        !fixture.runtime.cube.tests_passed,
        "agent cannot supply operator guards"
    );
    let artifacts = fixture.runtime.workspace.join(".aivm-build");
    let entries: Vec<_> = std::fs::read_dir(&artifacts).unwrap().collect();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .into_iter()
        .all(|entry| entry.unwrap().metadata().unwrap().len() <= 1048576 / 4));
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap() >= 20);
    let log = std::fs::read_to_string(fixture.root.join("audit.jsonl")).unwrap();
    assert!(log.contains("exit:1"));
    assert!(log.contains("exit:0"));
    // output directory ไม่เข้าบริบทโมเดลผ่าน search/RAG และแก้ผ่าน filesystem tool ไม่ได้
    let files = fixture
        .runtime
        .gateway
        .context_files(&mut fixture.runtime.cube)
        .unwrap();
    assert!(files.iter().all(|(path, _)| !path.contains(".aivm-build")));
    assert!(fixture
        .runtime
        .gateway
        .write(&mut fixture.runtime.cube, ".aivm-build/tests", "tampered")
        .is_err());
}

#[test]
fn build_outputs_require_profile_capability_and_safe_names() {
    let mut fixture = Fixture::new(false);
    fixture.modify();
    let request = |names: Vec<&str>| ToolRequest {
        tool: "process.exec".into(),
        path: fixture.cc.clone(),
        content: Some(json!({"argv":[],"outputs":names}).to_string()),
    };
    let denied = fixture
        .runtime
        .gateway
        .dispatch(&mut fixture.runtime.cube, &request(vec!["new.o"]));
    assert!(matches!(denied, Err(ToolError::Denied(_))));
    assert!(!fixture.runtime.workspace.join(".aivm-build").exists());
    let mut fixture = Fixture::new(true);
    let req = ToolRequest {
        tool: "process.exec".into(),
        path: fixture.cc.clone(),
        content: Some(json!({"argv":[],"outputs":["new.o"]}).to_string()),
    };
    assert!(fixture
        .runtime
        .gateway
        .dispatch(&mut fixture.runtime.cube, &req)
        .is_err());
    assert!(!fixture.runtime.workspace.join(".aivm-build").exists());
    fixture.modify();
    for name in ["../escape", "/tmp/escape", ".env", "secrets.yaml"] {
        let req = ToolRequest {
            tool: "process.exec".into(),
            path: fixture.cc.clone(),
            content: Some(json!({"argv":[],"outputs":[name]}).to_string()),
        };
        assert!(fixture
            .runtime
            .gateway
            .dispatch(&mut fixture.runtime.cube, &req)
            .is_err());
    }
    assert!(!fixture.runtime.workspace.join(".aivm-build").exists());
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).is_ok());
}

#[test]
fn artifact_file_count_and_byte_quotas_are_enforced() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    let source = r#"
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    char bytes[4096] = {0};
    int fd = open(".aivm-build/data", O_WRONLY | O_TRUNC);
    if (fd < 0) return 2;
    for (;;) { if (write(fd, bytes, sizeof(bytes)) < 0) return 3; }
}
"#;
    std::fs::write(fixture.runtime.workspace.join("src/main.c"), source).unwrap();
    let mut steps = fixture.build_steps();
    steps[2] = intent(
        &fixture.artifact(),
        &json!({"argv":[],"outputs":["data"]}).to_string(),
    );
    steps.push(done());
    let run = fixture.execute(steps);
    assert!(run.steps[0].outcome.starts_with("OK"), "{:?}", run.steps);
    assert!(run.steps[1].outcome.starts_with("OK"), "{:?}", run.steps);
    assert!(run.steps[2].outcome.starts_with("FAIL"), "{:?}", run.steps);
    let root = fixture.runtime.workspace.join(".aivm-build");
    assert_eq!(
        std::fs::metadata(root.join("data")).unwrap().len(),
        1048576 / 4
    );
    let req = ToolRequest {
        tool: "process.exec".into(),
        path: fixture.cc.clone(),
        content: Some(json!({"argv":[],"outputs":["extra1", "extra2"]}).to_string()),
    };
    assert!(fixture
        .runtime
        .gateway
        .dispatch(&mut fixture.runtime.cube, &req)
        .is_err());
    assert!(!root.join("extra1").exists());
    assert!(!root.join("extra2").exists());
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).is_ok());
}

#[test]
fn symlink_output_roots_and_secret_builds_fail_closed() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new(true);
    fixture.modify();
    let outside = fixture.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, fixture.runtime.workspace.join(".aivm-build")).unwrap();
    let req = ToolRequest {
        tool: "process.exec".into(),
        path: fixture.cc.clone(),
        content: Some(json!({"argv":[],"outputs":["escaped"]}).to_string()),
    };
    assert!(fixture
        .runtime
        .gateway
        .dispatch(&mut fixture.runtime.cube, &req)
        .is_err());
    assert!(!outside.join("escaped").exists());
    std::fs::remove_file(fixture.runtime.workspace.join(".aivm-build")).unwrap();
    let req = ToolRequest {
        content: Some(
            json!({"argv":[],"outputs":["secret-output"],"secret":"lease-unknown"}).to_string(),
        ),
        ..req
    };
    assert!(fixture
        .runtime
        .gateway
        .dispatch(&mut fixture.runtime.cube, &req)
        .is_err());
    assert!(!fixture.runtime.workspace.join(".aivm-build").exists());
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).is_ok());
}

#[test]
fn compiler_errors_are_failures_with_diagnostics_and_no_state_escalation() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    std::fs::write(
        fixture.runtime.workspace.join("src/main.c"),
        "this is not valid C;",
    )
    .unwrap();
    let mut steps = vec![fixture.build_steps().remove(0)];
    steps.push(done());
    let run = fixture.execute(steps);
    assert!(run.steps[0].outcome.starts_with("FAIL"), "{:?}", run.steps);
    assert!(run.steps[0].outcome.contains("error:"));
    assert!(!fixture.runtime.cube.tests_passed);
}

#[test]
fn generated_tests_cannot_write_sources_create_files_or_read_private_data() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    let private = fixture.root.join("host-private");
    std::fs::write(&private, "PRIVATE").unwrap();
    std::fs::write(fixture.runtime.workspace.join(".env"), "PRIVATE").unwrap();
    let source = format!(
        r#"
#include <fcntl.h>
#include <unistd.h>
int main(void) {{
    if (open("src/main.c", O_WRONLY) >= 0) return 1;
    if (open(".aivm-build/unreserved", O_CREAT | O_WRONLY, 0600) >= 0) return 2;
    if (open("{}", O_RDONLY) >= 0) return 3;
    if (open(".env", O_RDONLY) >= 0) return 4;
    return 0;
}}
"#,
        private.display()
    );
    std::fs::write(fixture.runtime.workspace.join("src/main.c"), &source).unwrap();
    let mut steps = fixture.build_steps();
    steps.push(done());
    let run = fixture.execute(steps);
    assert!(
        run.steps.iter().all(|step| step.outcome.starts_with("OK")),
        "{:?}",
        run.steps
    );
    assert!(run.steps[2].outcome.contains("exit status: 0"));
    assert_eq!(
        std::fs::read_to_string(fixture.runtime.workspace.join("src/main.c")).unwrap(),
        source
    );
    assert!(!fixture
        .runtime
        .workspace
        .join(".aivm-build/unreserved")
        .exists());
    assert_eq!(std::fs::read_to_string(private).unwrap(), "PRIVATE");
}
