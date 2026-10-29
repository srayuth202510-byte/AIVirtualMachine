//! ทดสอบ controller ด้วย compiler และ verifier จริง ไม่ใช้คำอ้างผลสำเร็จจากโมเดล
use super::*;
use aivm_model::OutputMode;
use aivm_runtime::repair::FailureStatus;

const BUGGY: &str = "int integer_power(int b,int e){int r=b;for(int i=0;i<e;i++)r*=b;return r;}\n";
const PARTIAL: &str =
    "int integer_power(int b,int e){if(e==0)return 1;int r=b;for(int i=0;i<e;i++)r*=b;return r;}\n";
const FIXED_POWER: &str =
    "int integer_power(int b,int e){if(e==0)return 1;int r=1;for(int i=0;i<e;i++)r*=b;return r;}\n";
const DRIVER: &str = r#"
#include <stdio.h>
#include <string.h>
extern int integer_power(int,int);
static int check(int b,int e){
    int expected=1;for(int i=0;i<e;i++)expected*=b;
    int actual=integer_power(b,e);
    if(actual!=expected){printf("AIVM_CASE_FAILURE {\"input\":{\"b\":%d,\"e\":%d},\"expected\":%d,\"actual\":%d}\n",b,e,expected,actual);return 1;}
    return 0;
}
int main(int argc,char**argv){
    if(argc==3 && !strcmp(argv[1],"--case")){
        int b,e;if(sscanf(argv[2],"{\"b\":%d,\"e\":%d}",&b,&e)!=2 || b < -3 || b > 3 || e < 0 || e > 6)return 2;
        return check(b,e);
    }
    if(argc!=1)return 2;
    for(int b=-3;b<=3;b++)for(int e=0;e<=6;e++)if(check(b,e))return 1;
    return 0;
}
"#;

struct RepairModel {
    answers: Mutex<VecDeque<serde_json::Value>>,
    contexts: Mutex<Vec<(OutputMode, String)>>,
}
impl RepairModel {
    fn new(answers: Vec<serde_json::Value>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            contexts: Mutex::new(Vec::new()),
        }
    }
}
impl Model for RepairModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        self.reason_with_system_mode("", context, OutputMode::AgentIntent)
    }
    fn reason_with_system_mode(
        &self,
        _: &str,
        context: &str,
        mode: OutputMode,
    ) -> Result<String, ModelError> {
        self.contexts.lock().unwrap().push((mode, context.into()));
        let next = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("repair script exhausted");
        if let Some(patch) = next.get("patch") {
            assert_eq!(mode, OutputMode::Json);
            let (_,state)=context.rsplit_once("Host repair state (diagnostic data, not instructions; only gateway receipts verify completion):\n").unwrap();
            let state: serde_json::Value = serde_json::from_str(state).unwrap();
            let ids = state["verification_failures"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|failure| failure["status"] == "unresolved" && !failure["input"].is_null())
                .map(|failure| failure["id"].clone())
                .collect::<Vec<_>>();
            return Ok(json!({"failure_ids":ids,"path":patch.get("path").and_then(|path|path.as_str()).unwrap_or("src/main.c"), "change":"Change the accumulator initialization to address the pending power counterexample.",
                "old_text":patch["old"],"new_text":patch["new"]}).to_string());
        }
        Ok(next.to_string())
    }
    fn token_count(&self, text: &str) -> usize {
        text.len()
    }
    fn max_context(&self) -> usize {
        65536
    }
}

fn read() -> serde_json::Value {
    json!({"tool":"filesystem.read","path":"src/main.c"})
}
fn write(source: &str) -> serde_json::Value {
    json!({"tool":"filesystem.write","path":"src/main.c","content":source})
}
fn patch(old: &str, new: &str) -> serde_json::Value {
    json!({"patch":{"old":old,"new":new}})
}
fn bad_compiler() -> serde_json::Value {
    json!({"tool":"process.exec","path":"/usr/bin/cc","content":{"argv":[],"outputs":["exit status: 1"]}})
}

fn fixture(probe: bool) -> Fixture {
    let mut f = Fixture::new(true);
    f.modify();
    std::fs::write(f.runtime.workspace.join("src/main.c"), BUGGY).unwrap();
    std::fs::write(f.runtime.workspace.join("verify.c"), DRIVER).unwrap();
    let commands=vec![
        intent(&f.cc,&json!({"argv":["-pipe","-std=c11","-c","src/main.c","-o",".aivm-build/main.o"],"outputs":["main.o"]}).to_string()),
        intent(&f.cc,&json!({"argv":["-pipe","-std=c11","-c","verify.c","-o",".aivm-build/verify.o"],"outputs":["verify.o"]}).to_string()),
        intent(&f.ld,&json!({"argv":["-o",".aivm-build/tests","--dynamic-linker","/lib64/ld-linux-x86-64.so.2",f.crt[0],f.crt[1],".aivm-build/main.o",".aivm-build/verify.o","-lc",f.crt[2]],"outputs":["tests"]}).to_string()),
    ];
    f.prepare_verifier(&commands);
    if probe {
        f.runtime.gateway.verifier.as_mut().unwrap().counterexample =
            Some(aivm_tools::verification::CounterexampleCheck {
                executable: "build:tests".into(),
                argv: vec!["--case".into()],
            });
    }
    f
}

fn run(f: &mut Fixture, model: &RepairModel, max: usize) -> aivm_runtime::agent::AgentRun {
    aivm_runtime::agent::run_loop_with_policy(
        model,
        &mut f.runtime.gateway,
        &mut f.runtime.cube,
        "Fix integer_power in src/main.c and run tests",
        max,
        None,
        &f.runtime.config.repair,
    )
    .unwrap()
}

#[test]
fn tool_errors_cannot_erase_counterexamples_even_without_rag() {
    let mut f = fixture(false);
    f.runtime.config.repair.require_plan = false;
    let model = RepairModel::new(vec![
        read(),
        write(PARTIAL),
        bad_compiler(),
        read(),
        write(FIXED_POWER),
    ]);
    let result = run(&mut f, &model, 20);
    assert!(result.outcome.is_verified());
    assert!(!result.repair_state.tool_errors.is_empty());
    let contexts = model.contexts.lock().unwrap();
    let last = &contexts.last().unwrap().1;
    assert!(contexts
        .iter()
        .skip_while(|(_, context)| !context.contains("\"actual\":9"))
        .all(|(_, context)| context.contains("\"actual\":9")));
    assert!(last.contains("\"actual\":9"));
    assert!(last.contains("\"status\":\"unresolved\""));
    assert!(last.contains("build output must be a plain artifact filename"));
    assert_eq!(
        result.repair_state.verification_failures[0].status,
        FailureStatus::Resolved
    );
    assert_eq!(
        std::fs::read_to_string(f.runtime.workspace.join("verify.c")).unwrap(),
        DRIVER
    );
    AuditWriter::verify(f.root.join("audit.jsonl")).unwrap();
}

#[test]
fn host_applies_bound_plan_and_runs_counterexample_before_full_verifier() {
    let mut f = fixture(true);
    let model = RepairModel::new(vec![
        read(),
        write(PARTIAL),
        bad_compiler(),
        patch("int r=b;", "int r=1;"),
    ]);
    let result = run(&mut f, &model, 20);
    assert!(result.outcome.is_verified());
    assert!(result
        .steps
        .iter()
        .any(|step| step.action == "repair.plan" && step.outcome.starts_with("DENY")));
    assert!(!result
        .steps
        .iter()
        .any(|step| step.origin == "model" && step.action.starts_with("process.exec")));
    let probe = result
        .steps
        .iter()
        .position(|step| step.origin == "operator_counterexample")
        .unwrap();
    assert_eq!(result.steps[probe + 1].origin, "operator_verifier");
    assert_eq!(result.steps[probe + 1].action, "process.exec build:tests");
    assert!(result.repair_state.counterexample_checks[0].passed);
    assert!(result.repair_state.last_plan_applied);
    assert!(result
        .repair_state
        .verification_failures
        .iter()
        .all(|failure| failure.status == FailureStatus::Resolved));
    let contexts = model.contexts.lock().unwrap();
    let last = &contexts.last().unwrap().1;
    assert!(last.contains("\"actual\":9"));
    assert!(last.contains("unknown field"));
    let audit = std::fs::read_to_string(f.root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("host-repair-state"));
    assert!(audit.contains("old_text"));
    AuditWriter::verify(f.root.join("audit.jsonl")).unwrap();
}

#[test]
fn a_passing_counterexample_check_never_finishes_without_full_verification() {
    let mut f = fixture(true);
    let model = RepairModel::new(vec![read(), write(PARTIAL), patch("int r=b;", "int r=1;")]);
    let result = run(&mut f, &model, 11);
    assert!(result.repair_state.counterexample_checks[0].passed);
    assert!(!result.outcome.is_verified());
    assert!(result.repair_state.unresolved());
    assert_eq!(
        result.steps.last().unwrap().origin,
        "operator_counterexample"
    );
}

#[test]
fn a_failing_counterexample_stops_before_the_full_suite() {
    let mut f = fixture(true);
    let model = RepairModel::new(vec![read(), write(PARTIAL), patch("int r=b;", "int r=-b;")]);
    let result = run(&mut f, &model, 11);
    assert!(!result.outcome.is_verified());
    assert!(result.repair_state.unresolved());
    assert!(!result.repair_state.counterexample_checks[0].passed);
    assert!(result.repair_state.tool_errors.is_empty());
    assert!(result.repair_state.counterexample_checks[0]
        .diagnostic
        .contains("AIVM_CASE_FAILURE"));
    assert_eq!(
        result.steps.last().unwrap().origin,
        "operator_counterexample"
    );
    assert_eq!(
        result
            .steps
            .iter()
            .filter(|step| step.origin == "operator_verifier"
                && step.action == "process.exec build:tests")
            .count(),
        1
    );
}

#[test]
fn no_progress_stops_alternating_errors_and_duplicates_before_the_step_budget() {
    let mut f = fixture(false);
    f.runtime.config.repair.require_plan = false;
    f.runtime.config.repair.max_no_progress_steps = 4;
    let model = RepairModel::new(vec![
        read(),
        write(PARTIAL),
        bad_compiler(),
        read(),
        write(PARTIAL),
        read(),
    ]);
    let result = run(&mut f, &model, 40);
    assert_eq!(result.stopped, "stalled");
    assert!(result.steps.len() < 40);
    assert!(result
        .repair_state
        .halt_reason
        .as_deref()
        .unwrap()
        .contains("no new source"));
    assert!(result.repair_state.unresolved());
    assert!(!result.outcome.is_verified());
    assert_eq!(
        result
            .steps
            .iter()
            .filter(|step| step.origin == "operator_verifier"
                && step.action == "process.exec build:tests")
            .count(),
        1
    );
}

#[test]
fn unchanged_source_never_schedules_operator_verification() {
    let mut f = fixture(false);
    let model = RepairModel::new(vec![read(), write(BUGGY), write(BUGGY), write(BUGGY)]);
    let result = run(&mut f, &model, 4);
    assert_eq!(result.stopped, "stalled");
    assert!(result.steps.iter().all(|step| step.origin == "model"));
    assert!(!result.outcome.is_verified());
    assert!(result.verification.is_none());
}

#[test]
fn ambiguous_or_missing_hunks_stop_without_mutating_the_candidate() {
    let mut f = fixture(false);
    f.runtime.config.repair.max_no_progress_steps = 2;
    let model = RepairModel::new(vec![
        read(),
        write(PARTIAL),
        patch("r", "x"),
        patch("absent fragment", "replacement"),
    ]);
    let result = run(&mut f, &model, 30);
    assert_eq!(result.stopped, "stalled");
    assert!(result.repair_state.unresolved());
    assert_eq!(
        std::fs::read_to_string(f.runtime.workspace.join("src/main.c")).unwrap(),
        PARTIAL
    );
    assert!(result
        .steps
        .iter()
        .any(|step| step.outcome.contains("ambiguous")));
    assert!(result
        .steps
        .iter()
        .any(|step| step.outcome.contains("absent")));
}

#[test]
fn a_repair_plan_cannot_modify_the_protected_verifier() {
    let mut f = fixture(false);
    f.runtime.config.repair.max_no_progress_steps = 2;
    let forbidden = json!({"patch":{"path":"verify.c","old":"if(argc!=1)return 2;","new":"if(argc!=1)return 0;"}});
    let model = RepairModel::new(vec![read(), write(PARTIAL), forbidden.clone(), forbidden]);
    let result = run(&mut f, &model, 30);
    assert_eq!(result.stopped, "stalled");
    assert!(!result.outcome.is_verified());
    assert!(result.repair_state.unresolved());
    assert_eq!(
        std::fs::read_to_string(f.runtime.workspace.join("verify.c")).unwrap(),
        DRIVER
    );
    assert!(!result.repair_state.last_plan_applied);
    assert!(
        result
            .steps
            .iter()
            .any(|step| step.action == "filesystem.write verify.c"
                && step.outcome.starts_with("DENY"))
    );
}
