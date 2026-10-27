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
    fn semantic(task: &aivm_runtime::semantic::SemanticTask) -> Self {
        Self::semantic_with_model(task, None)
    }
    fn semantic_with_model(
        task: &aivm_runtime::semantic::SemanticTask,
        model: Option<aivm_runtime::ModelBlock>,
    ) -> Self {
        let mut fixture = Self::with_model(true, model);
        fixture.modify();
        std::fs::write(
            fixture
                .runtime
                .workspace
                .join(aivm_runtime::semantic::SOURCE_PATH),
            task.program_source().unwrap(),
        )
        .unwrap();
        let contract = fixture.runtime.gateway.verifier.as_mut().unwrap();
        contract.executable = "build:tests".into();
        // semantic helper มี main ของตัวเองและอยู่เหนือ src ที่ model เขียนได้
        let steps = vec![
            intent(&fixture.cc, &json!({"argv":["-pipe","-std=c11","-c","semantic.c","-o",".aivm-build/main.o"],"outputs":["main.o"]}).to_string()),
            intent(&fixture.ld, &json!({"argv":["-o",".aivm-build/tests","--dynamic-linker","/lib64/ld-linux-x86-64.so.2",fixture.crt[0],fixture.crt[1],".aivm-build/main.o","-lc",fixture.crt[2]],"outputs":["tests"]}).to_string()),
        ];
        fixture.prepare_verifier(&steps);
        fixture
    }
    fn new(enabled: bool) -> Self {
        Self::with_model(enabled, None)
    }
    fn with_model(enabled: bool, model: Option<aivm_runtime::ModelBlock>) -> Self {
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
        let mut config = VmConfig::from_yaml(&format!(
            r#"
name: coding
resources: {{cpu: 1, memory: 1GB, storage: 64MB}}
build: {{enabled: {enabled}, max_files: 4, max_bytes: 1048576}}
{verification}
tools: {{allow: [cc, as, ld, "build:tests"]}}
"#,
            verification = if enabled {
                "verification: {executable: 'build:tests', argv: []}"
            } else {
                ""
            }
        ))
        .unwrap();
        if let Some(model) = model {
            config.model = model;
            config.resources.memory = "4GB".into();
            config.resources.storage = "5GB".into();
            // 8k context ใช้ CPU มากกว่า short probes; คง threads=2 แต่ให้ CPU budget 240 วินาที
            config.resources.cpu = if config
                .model
                .local
                .as_ref()
                .is_some_and(|local| local.ctx_size <= 512)
            {
                2
            } else {
                4
            };
            config.filesystem.write = vec!["./workspace/src".into()];
        }
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
        // กรณีตั้งใจให้ verifier ไม่ผ่านจะถูกปฏิเสธ finish จึงหยุดตาม budget ของ script
        let writes = steps
            .iter()
            .filter(|step| {
                serde_json::from_str::<ToolRequest>(step)
                    .is_ok_and(|request| request.tool == "filesystem.write")
            })
            .count();
        let max_steps = steps.len()
            + writes
                * self
                    .runtime
                    .gateway
                    .verifier
                    .as_ref()
                    .map(|contract| contract.execution_plan().unwrap().len())
                    .unwrap_or(0);
        self.runtime.model = Box::new(Script(Mutex::new(steps.into())));
        self.runtime
            .run_agent("fix add and run the tests", max_steps, Some(&self.root))
            .unwrap()
    }
    fn prepare_verifier(&mut self, commands: &[String]) {
        let prepare = commands
            .iter()
            .map(|command| {
                let request: ToolRequest = serde_json::from_str(command).unwrap();
                let body: aivm_tools::ExecContent =
                    serde_json::from_str(request.content.as_deref().unwrap()).unwrap();
                aivm_tools::verification::VerifierStep {
                    executable: request.path,
                    argv: body.argv,
                    outputs: body.outputs,
                }
            })
            .collect::<Vec<_>>();
        self.runtime.gateway.verifier.as_mut().unwrap().prepare = prepare.clone();
        self.runtime.config.verification.as_mut().unwrap().prepare = prepare;
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
    assert!(matches!(
        run.verification_status,
        aivm_tools::verification::VerificationStatus::Verified
    ));
    let record = run.verification.as_ref().unwrap();
    assert_eq!(record.workspace_sha256.len(), 64);
    assert_eq!(record.executable_sha256.len(), 64);
    assert_eq!(record.audit_id.len(), 64);
    assert_eq!(run.steps.len(), 5);
    assert!(
        run.steps.iter().all(|step| step.outcome.starts_with("OK")),
        "{:?}",
        run.steps
    );
    assert!(run.steps[4].outcome.contains("exit status: 0"));
    assert!(run.steps[2].outcome.contains("Executed request:"));
    assert!(run.steps[2].outcome.contains("main.o"));
    assert!(run.steps[3].outcome.contains("--dynamic-linker"));
    assert_eq!(
        std::fs::read_to_string(fixture.runtime.workspace.join("src/main.c")).unwrap(),
        FIXED
    );
    assert_eq!(fixture.runtime.cube.current_state(), AgentState::Modify);
    assert!(
        !fixture.runtime.cube.tests_passed(),
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
fn operator_verifier_builds_after_edit_and_repairs_a_failed_test_without_model_build_commands() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    fixture.prepare_verifier(&fixture.build_steps()[..2]);
    let run = fixture.execute(vec![
        json!({"tool":"filesystem.write","path":"src/main.c","content":BROKEN}).to_string(),
        json!({"tool":"filesystem.write","path":"src/main.c","content":FIXED}).to_string(),
    ]);
    assert_eq!(run.steps.len(), 8);
    assert!(run.steps[3].outcome.contains("exit status: 1"));
    assert_eq!(run.steps[4].origin, "model");
    for index in [1, 2, 3, 5, 6, 7] {
        assert_eq!(run.steps[index].origin, "operator_verifier");
    }
    assert_eq!(run.stopped, "done");
    assert!(matches!(
        run.verification_status,
        aivm_tools::verification::VerificationStatus::Verified
    ));
    assert!(!fixture.runtime.cube.tests_passed());
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).is_ok());
}

#[test]
fn operator_prepare_cannot_bypass_gateway_authorization() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    fixture.prepare_verifier(&[intent("/bin/sh", r#"{"argv":[]}"#)]);
    fixture.runtime.model = Box::new(Script(Mutex::new(
        vec![json!({"tool":"filesystem.write","path":"src/main.c","content":FIXED}).to_string()]
            .into(),
    )));
    let run = fixture
        .runtime
        .run_agent("Fix the code and run tests", 2, Some(&fixture.root))
        .unwrap();
    assert_eq!(run.steps.len(), 2);
    assert_eq!(run.steps[1].origin, "operator_verifier");
    assert!(run.steps[1].outcome.starts_with("DENY process.exec"));
    assert!(matches!(
        run.verification_status,
        aivm_tools::verification::VerificationStatus::Unverified
    ));
    assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).is_ok());
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
fn gcc_requires_pipe_and_cannot_create_unreserved_temporary_files() {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    let compile = |pipe: bool| {
        let mut argv = vec!["-c", "src/main.c", "-o", ".aivm-build/main.o"];
        if pipe {
            argv.insert(0, "-pipe");
        }
        intent(
            &fixture.cc,
            &json!({"argv":argv,"outputs":["main.o"]}).to_string(),
        )
    };
    let steps = vec![compile(false), compile(true), done()];
    let run = fixture.execute(steps);
    assert!(run.steps[0].outcome.starts_with("FAIL"), "{:?}", run.steps);
    assert!(run.steps[0]
        .outcome
        .contains("Cannot create temporary file"));
    assert!(run.steps[1].outcome.starts_with("OK"), "{:?}", run.steps);
    assert!(
        std::fs::metadata(fixture.runtime.workspace.join(".aivm-build/main.o"))
            .unwrap()
            .len()
            > 0
    );
    assert!(!fixture.runtime.cube.tests_passed());
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
    assert!(!fixture.runtime.cube.tests_passed());
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

/// คุณภาพของ patch จากโมเดลจริงต้องวัดกับ source และ verifier ของ operator แยกจาก summary
#[test]
#[ignore = "requires pinned worker config and quality evidence path"]
fn real_model_repairs_source_checked_by_an_independent_verifier() {
    use sha2::{Digest, Sha256};
    let config_path =
        std::env::var("AIVM_WORKER_HOST_CONFIG").expect("pinned model config required");
    let evidence =
        std::env::var("AIVM_AGENT_QUALITY_EVIDENCE").expect("quality evidence path required");
    let bytes = std::fs::read(config_path).unwrap();
    let mut model_config: aivm_model::ModelConfig = serde_json::from_slice(&bytes).unwrap();
    let local = model_config.local.as_mut().unwrap();
    assert!(!local.model_sha256.is_empty());
    assert!(local
        .worker_sha256
        .as_ref()
        .is_some_and(|pin| !pin.is_empty()));
    local.ctx_size = 8192;
    local.max_tokens = 384;
    let limits = model_config.worker_limits.as_mut().unwrap();
    limits.max_context_tokens = 8192;
    limits.max_output_tokens = 384;
    let model_block = aivm_runtime::ModelBlock {
        provider: model_config.provider.clone(),
        name: model_config.name.clone(),
        local: model_config.local.clone(),
        total_timeout_ms: limits.total_timeout_ms,
        host_resources: limits.host_resources.clone(),
        ..Default::default()
    };
    let boot = std::time::Instant::now();
    let mut fixture = Fixture::with_model(true, Some(model_block));
    let boot_ms = boot.elapsed().as_millis();
    let effective_model_config = fixture.runtime.config.inference_model_config().unwrap();
    fixture.modify();
    let broken = "int add(int a, int b) { return a - b; }\n";
    let verifier="extern int add(int,int);\nint main(void) { for(int a=-8;a<=8;a++) for(int b=-8;b<=8;b++) if(add(a,b)!=a+b) return 1; return 0; }\n";
    let source = fixture.runtime.workspace.join("src/main.c");
    let verifier_path = fixture.runtime.workspace.join("verify.c");
    std::fs::write(&source, broken).unwrap();
    // verify.c อยู่นอก src ซึ่งเป็น write capability ของ agent
    std::fs::write(&verifier_path, verifier).unwrap();
    assert!(
        fixture
            .runtime
            .gateway
            .write(&mut fixture.runtime.cube, "verify.c", verifier)
            .is_err(),
        "operator verifier must be outside agent write authority"
    );
    let commands=vec![
            intent(&fixture.cc,&json!({"argv":["-pipe","-c","src/main.c","-o",".aivm-build/main.o"],"outputs":["main.o"]}).to_string()),
            intent(&fixture.cc,&json!({"argv":["-pipe","-c","verify.c","-o",".aivm-build/verify.o"],"outputs":["verify.o"]}).to_string()),
            intent(&fixture.ld,&json!({"argv":["-o",".aivm-build/tests","--dynamic-linker","/lib64/ld-linux-x86-64.so.2",fixture.crt[0],fixture.crt[1],".aivm-build/main.o",".aivm-build/verify.o","-lc",fixture.crt[2]],"outputs":["tests"]}).to_string()),
            intent("build:tests","[]"),
    ];
    let prepare = commands[..3]
        .iter()
        .map(|command| {
            let request: ToolRequest = serde_json::from_str(command).unwrap();
            let body: aivm_tools::ExecContent =
                serde_json::from_str(request.content.as_deref().unwrap()).unwrap();
            aivm_tools::verification::VerifierStep {
                executable: request.path,
                argv: body.argv,
                outputs: body.outputs,
            }
        })
        .collect::<Vec<_>>();
    fixture.runtime.gateway.verifier.as_mut().unwrap().prepare = prepare.clone();
    fixture
        .runtime
        .config
        .verification
        .as_mut()
        .unwrap()
        .prepare = prepare;
    let verifier_contract = fixture.runtime.gateway.verifier.clone().unwrap();
    let verify = |fixture: &mut Fixture| {
        let mut rows = Vec::new();
        for step in &commands {
            let request: ToolRequest = serde_json::from_str(step).unwrap();
            match fixture
                .runtime
                .gateway
                .dispatch(&mut fixture.runtime.cube, &request)
            {
                Ok(result) => {
                    let ok = result.ok;
                    rows.push(serde_json::to_value(result).unwrap());
                    if !ok {
                        break;
                    }
                }
                Err(error) => {
                    rows.push(json!({"ok":false,"error":error.to_string()}));
                    break;
                }
            }
        }
        rows
    };
    let baseline = verify(&mut fixture);
    assert_eq!(
        baseline.len(),
        4,
        "baseline must compile and execute: {baseline:?}"
    );
    assert!(baseline[..3].iter().all(|row| row["ok"] == true));
    assert_eq!(
        baseline[3]["ok"], false,
        "oracle must reject the known broken implementation"
    );
    let started = std::time::Instant::now();
    let task = "Fix add in src/main.c so it returns the integer sum of its two arguments. Read the source and update only src/main.c through filesystem tools. Do not add a main function. Do not modify verify.c. The runtime will compile and run tests with the operator verifier after your edit, checking 289 input pairs.";
    let max_steps = 8;
    let run = fixture
        .runtime
        .run_agent(task, max_steps, Some(&fixture.root));
    let elapsed_ms = started.elapsed().as_millis();
    let after = std::fs::read(&source).unwrap();
    let results = verify(&mut fixture);
    let task_correct = results.len() == 4 && results.iter().all(|row| row["ok"] == true);
    assert_eq!(
        std::fs::read_to_string(verifier_path).unwrap(),
        verifier,
        "agent modified operator verifier"
    );
    let audit_records = AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap();
    let (agent_run, error) = match run {
        Ok(run) => (Some(run), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let infrastructure_passed = error.is_none();
    let agent_verified = agent_run.as_ref().is_some_and(|run| {
        matches!(
            run.verification_status,
            aivm_tools::verification::VerificationStatus::Verified
        )
    });
    let report = json!({"schema":1,"scope":"One bounded live-model coding task; independent operator verifier checks 289 pairs via the real tool gateway/sandbox. No production success-rate claim.","config_sha256":format!("{:x}",Sha256::digest(&bytes)),"benchmark_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("coding_workflow.rs"))),"effective_model_config":effective_model_config,"max_steps":max_steps,"build_commands":commands,"verifier_contract":verifier_contract,"infrastructure_passed":infrastructure_passed,"baseline_rejected":true,"verifier_unchanged":true,"verifier_write_denied":true,"task_correct":task_correct,"agent_verified":agent_verified,"source_changed":after!=broken.as_bytes(),"source_sha256":format!("{:x}",Sha256::digest(&after)),"client_boot_ms":boot_ms,"agent_elapsed_ms":elapsed_ms,"agent_run":agent_run,"agent_error":error,"verifier_results":results,"audit_records":audit_records});
    std::fs::write(evidence, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    assert!(
        infrastructure_passed,
        "inspect agent quality evidence for infrastructure failure"
    );
    eprintln!("live agent patch quality: {task_correct}; independently verified, not inferred from model summary");
}

#[test]
fn semantic_rejects_known_wrong_answers_and_computes_verified_tool_results() {
    use aivm_runtime::semantic::{SemanticBudget, SemanticTask};
    for (task, wrong, expected) in [
        (
            SemanticTask::Sort {
                values: vec![3, -2, 3, 0],
            },
            "[0,-2,3,3]",
            "[-2,0,3,3]",
        ),
        (SemanticTask::CAdd { left: -8, right: 3 }, "11", "-5"),
    ] {
        let mut fixture = Fixture::semantic(&task);
        fixture.runtime.model = Box::new(Script(Mutex::new(
            vec![wrong.to_string(), wrong.to_string()].into(),
        )));
        let source = std::fs::read(fixture.runtime.workspace.join("semantic.c")).unwrap();
        assert!(fixture
            .runtime
            .gateway
            .write(&mut fixture.runtime.cube, "semantic.c", "tampered")
            .is_err());
        let run = fixture
            .runtime
            .run_semantic(&task, "Return JSON only.", &SemanticBudget::default())
            .unwrap();
        assert_eq!(run.output.as_deref(), Some(expected), "{run:?}");
        assert_eq!(run.origin.as_deref(), Some("tool_solver"));
        assert!(matches!(
            run.status,
            aivm_tools::verification::VerificationStatus::Verified
        ));
        assert_eq!(run.attempts.len(), 2);
        assert!(run
            .attempts
            .iter()
            .all(|a| a.format_valid && a.schema_valid && !a.task_correct));
        assert!(run.attempts.iter().all(|a| matches!(
            a.verification.as_ref().unwrap().status,
            aivm_tools::verification::VerificationStatus::Failed
        )));
        assert_eq!(
            source,
            std::fs::read(fixture.runtime.workspace.join("semantic.c")).unwrap()
        );
        assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap() > 10);
        assert!(!fixture.runtime.cube.tests_passed());
    }
}

#[test]
fn semantic_repairs_with_feedback_and_never_accepts_a_claimed_receipt() {
    use aivm_runtime::semantic::{SemanticBudget, SemanticTask};
    let task = SemanticTask::CAdd { left: -8, right: 3 };
    let mut fixture = Fixture::semantic(&task);
    fixture.runtime.model = Box::new(Script(Mutex::new(
        vec![r#"{"result":-5,"verified":true}"#.into(), "-5".into()].into(),
    )));
    let run = fixture
        .runtime
        .run_semantic(&task, "Return JSON only.", &SemanticBudget::default())
        .unwrap();
    assert!(!run.attempts[0].schema_valid);
    assert!(run.attempts[0].verification.is_none());
    assert_eq!(run.origin.as_deref(), Some("model_repair_with_verifier"));
    assert!(run.attempts[1].prompt.contains("Verifier feedback"));
    assert_eq!(run.output.as_deref(), Some("-5"));
}

#[test]
fn semantic_budget_and_gateway_denials_cannot_produce_verified_results() {
    use aivm_runtime::semantic::{SemanticBudget, SemanticTask};
    let task = SemanticTask::Sort { values: vec![2, 1] };
    let mut fixture = Fixture::semantic(&task);
    let run = fixture
        .runtime
        .run_semantic(
            &task,
            "JSON",
            &SemanticBudget {
                max_actions: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(run.output.is_none());
    assert!(run.verification.is_none());
    assert!(run.termination.contains("budget"));
    let mut fixture = Fixture::semantic(&task);
    fixture.runtime.gateway.verifier.as_mut().unwrap().prepare[0].executable = "/bin/sh".into();
    let run = fixture
        .runtime
        .run_semantic(&task, "JSON", &SemanticBudget::default())
        .unwrap();
    assert!(run.output.is_none());
    assert!(matches!(
        run.status,
        aivm_tools::verification::VerificationStatus::Failed
    ));
    assert!(run.attempts.is_empty());
}

#[test]
fn semantic_refuses_model_writable_or_mismatched_operator_sources() {
    use aivm_runtime::semantic::{SemanticBudget, SemanticTask};
    let task = SemanticTask::CAdd { left: 2, right: 3 };
    let mut fixture = Fixture::semantic(&task);
    fixture
        .runtime
        .gateway
        .caps
        .grant(aivm_capability::Capability::new(
            "write",
            "filesystem",
            &fixture.runtime.workspace.display().to_string(),
        ));
    assert!(fixture
        .runtime
        .run_semantic(&task, "JSON", &SemanticBudget::default())
        .unwrap_err()
        .to_string()
        .contains("write capabilities"));
    let mut fixture = Fixture::semantic(&task);
    std::fs::write(
        fixture.runtime.workspace.join("semantic.c"),
        "int main(void){return 0;}",
    )
    .unwrap();
    let run = fixture
        .runtime
        .run_semantic(&task, "JSON", &SemanticBudget::default())
        .unwrap();
    assert!(run.output.is_none());
    assert!(run.attempts.is_empty());
    assert!(run.termination.contains("does not match"));
}

fn evaluate_semantic_corpus(fresh: bool) {
    use aivm_runtime::semantic::{SemanticBudget, SemanticTask};
    use sha2::{Digest, Sha256};
    let text = include_str!("../../../examples/semantic-quality.json");
    let corpus: serde_json::Value = serde_json::from_str(text).unwrap();
    let output = std::env::var_os("AIVM_SEMANTIC_EVIDENCE").map(PathBuf::from);
    let model_bytes = fresh.then(|| {
        std::fs::read(
            std::env::var("AIVM_WORKER_HOST_CONFIG").expect("pinned worker config required"),
        )
        .unwrap()
    });
    let mut live_fixture = model_bytes.as_ref().map(|bytes| {
        let config: aivm_model::ModelConfig = serde_json::from_slice(bytes).unwrap();
        assert!(!config.local.as_ref().unwrap().model_sha256.is_empty());
        let limits = config.worker_limits.as_ref().unwrap();
        let block = aivm_runtime::ModelBlock {
            provider: config.provider.clone(),
            name: config.name.clone(),
            local: config.local.clone(),
            total_timeout_ms: limits.total_timeout_ms,
            host_resources: limits.host_resources.clone(),
            ..Default::default()
        };
        let task = serde_json::from_value(corpus["cases"][0]["task"].clone()).unwrap();
        Fixture::semantic_with_model(&task, Some(block))
    });
    let mut rows = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let task: SemanticTask = serde_json::from_value(case["task"].clone()).unwrap();
        let mut replay_fixture = if fresh {
            None
        } else {
            Some(Fixture::semantic(&task))
        };
        let fixture = live_fixture.as_mut().or(replay_fixture.as_mut()).unwrap();
        if fresh {
            // operator เปลี่ยนโจทย์/ตัวตรวจระหว่าง runs; โมเดลยังเขียน semantic.c ไม่ได้
            std::fs::write(
                fixture.runtime.workspace.join("semantic.c"),
                task.program_source().unwrap(),
            )
            .unwrap();
        } else {
            let candidate = case["initial_candidate"].as_str().unwrap().to_string();
            fixture.runtime.model = Box::new(Script(Mutex::new(
                vec![candidate.clone(), candidate].into(),
            )));
        }
        let source_before = std::fs::read(fixture.runtime.workspace.join("semantic.c")).unwrap();
        let run = fixture
            .runtime
            .run_semantic(
                &task,
                case["prompt"].as_str().unwrap(),
                &SemanticBudget::default(),
            )
            .unwrap();
        assert_eq!(
            source_before,
            std::fs::read(fixture.runtime.workspace.join("semantic.c")).unwrap()
        );
        if fresh {
            assert!(
                run.attempts
                    .iter()
                    .all(|attempt| attempt.infrastructure_status != "model_error"),
                "fresh model infrastructure failed: {:?}",
                run.attempts
            );
        }
        let first = run
            .attempts
            .first()
            .and_then(|a| a.output.as_deref())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let final_value = run
            .output
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let first_correct = first.as_ref() == Some(&case["expected"]);
        let assisted_correct = run.is_verified() && final_value.as_ref() == Some(&case["expected"]);
        assert!(assisted_correct, "{}: {run:?}", case["id"]);
        assert!(AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap() > 5);
        let audit = std::fs::read(fixture.root.join("audit.jsonl")).unwrap();
        let id = case["id"].as_str().unwrap();
        assert!(id.len() < 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
        let audit_name = format!("{id}.audit.jsonl");
        if let Some(path) = &output {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path.join(&audit_name))
                .unwrap();
            file.write_all(&audit).unwrap();
        }
        eprintln!(
            "semantic case {id}: first={first_correct}, assisted={assisted_correct}, origin={:?}",
            run.origin
        );
        rows.push(json!({"id":id,"task":task,"prompt":case["prompt"],"candidate_origin":if fresh {"fresh_model"}else{case["candidate_origin"].as_str().unwrap()},"first_correct":first_correct,"assisted_correct":assisted_correct,"audit_file":audit_name,"audit_sha256":format!("{:x}",Sha256::digest(&audit)),"run":run}));
    }
    let first_correct = rows.iter().filter(|r| r["first_correct"] == true).count();
    let assisted_correct = rows
        .iter()
        .filter(|r| r["assisted_correct"] == true)
        .count();
    let report = json!({"schema":1,"mode":if fresh {"fresh_model"}else{"replay"},"scope":if fresh {json!("Fresh pinned Qwen inference on two original regressions and six frozen semantic transfer probes; not a general benchmark.")} else {corpus["scope"].clone()},"corpus_sha256":format!("{:x}",Sha256::digest(text.as_bytes())),"model_config_sha256":model_bytes.map(|bytes|format!("{:x}",Sha256::digest(&bytes))),"completed":rows.len(),"total":corpus["cases"].as_array().unwrap().len(),"first_correct":first_correct,"assisted_correct":assisted_correct,"cases":rows});
    if let Some(path) = output {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join("evidence.json"))
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&report).unwrap())
            .unwrap();
    }
    eprintln!(
        "semantic {}: first {first_correct}/{}; assisted {assisted_correct}/{}",
        if fresh {
            "fresh model"
        } else {
            "replayed/probe candidates"
        },
        rows.len(),
        rows.len()
    );
}

#[test]
fn semantic_quality_replay() {
    evaluate_semantic_corpus(false);
}

#[test]
#[ignore = "requires pinned GGUF worker; keep fresh model scores separate from replay/probe evidence"]
fn real_model_semantic_quality() {
    evaluate_semantic_corpus(true);
}
