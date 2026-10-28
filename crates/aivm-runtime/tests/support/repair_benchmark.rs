//! benchmark งานแก้โค้ด: baseline ต้อง fail และ final outcome มาจาก protected verifier
use super::*;
use aivm_tools::contracts::{Execution, SolutionOrigin};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const CORPUS: &str = include_str!("../../../../examples/repair-benchmark.json");
#[derive(Deserialize)]
struct Corpus {
    schema: u8,
    scope: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    id: String,
    revision: u64,
    category: String,
    description: String,
    buggy: String,
    reference: String,
    verifier: String,
}

#[derive(Default, Serialize)]
struct ModelCost {
    calls: u64,
    usage_reported_calls: u64,
    input_tokens_reported: u64,
    output_tokens_reported: u64,
    input_tokens_estimate: u64,
    observed_output_tokens_estimate: u64,
    failed_calls: u64,
    inference_ms: u128,
}
struct MeteredModel {
    model: Box<dyn Model>,
    cost: Arc<Mutex<ModelCost>>,
}
impl Model for MeteredModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        self.reason_with_system_mode("", context, aivm_model::OutputMode::Text)
    }
    fn reason_with_system_mode(
        &self,
        system: &str,
        context: &str,
        mode: aivm_model::OutputMode,
    ) -> Result<String, ModelError> {
        let start = Instant::now();
        let input = self
            .model
            .token_count(system)
            .saturating_add(self.model.token_count(context));
        let result = self.model.reason_with_system_mode(system, context, mode);
        let usage = self.model.last_usage();
        let mut cost = self.cost.lock().unwrap();
        cost.calls += 1;
        if let Some(usage) = usage {
            cost.usage_reported_calls += 1;
            cost.input_tokens_reported += usage.input_tokens as u64;
            cost.output_tokens_reported += usage.output_tokens as u64;
        }
        cost.input_tokens_estimate += input as u64;
        cost.inference_ms += start.elapsed().as_millis();
        match &result {
            Ok(output) => {
                cost.observed_output_tokens_estimate += self.model.token_count(output) as u64
            }
            Err(_) => cost.failed_calls += 1,
        }
        result
    }
    fn token_count(&self, text: &str) -> usize {
        self.model.token_count(text)
    }
    fn max_context(&self) -> usize {
        self.model.max_context()
    }
}

struct MemorySample {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<u64>>,
}
impl MemorySample {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut peak = 0;
            while !done.load(Ordering::Relaxed) {
                let mut queue = vec![std::process::id()];
                let mut seen = std::collections::HashSet::new();
                let mut rss = 0;
                while let Some(pid) = queue.pop() {
                    if !seen.insert(pid) {
                        continue;
                    }
                    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                        rss += status
                            .lines()
                            .find_map(|line| line.strip_prefix("VmRSS:"))
                            .and_then(|value| value.split_whitespace().next())
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(0)
                            * 1024;
                    }
                    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
                        for task in tasks.flatten() {
                            if let Ok(children) =
                                std::fs::read_to_string(task.path().join("children"))
                            {
                                queue.extend(
                                    children
                                        .split_whitespace()
                                        .filter_map(|value| value.parse::<u32>().ok()),
                                );
                            }
                        }
                    }
                }
                peak = peak.max(rss);
                std::thread::sleep(Duration::from_millis(25));
            }
            peak
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap()
    }
}
impl Drop for MemorySample {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn commands(fixture: &Fixture) -> Vec<String> {
    vec![
        intent(&fixture.cc, &json!({"argv":["-pipe","-std=c11","-c","src/main.c","-o",".aivm-build/main.o"],"outputs":["main.o"]}).to_string()),
        intent(&fixture.cc, &json!({"argv":["-pipe","-std=c11","-c","verify.c","-o",".aivm-build/verify.o"],"outputs":["verify.o"]}).to_string()),
        intent(&fixture.ld, &json!({"argv":["-o",".aivm-build/tests","--dynamic-linker","/lib64/ld-linux-x86-64.so.2",fixture.crt[0],fixture.crt[1],".aivm-build/main.o",".aivm-build/verify.o","-lc",fixture.crt[2]],"outputs":["tests"]}).to_string()),
        intent("build:tests", "[]"),
    ]
}

fn verify(fixture: &mut Fixture, plan: &[String]) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for encoded in plan {
        let request = serde_json::from_str(encoded).unwrap();
        let result = fixture
            .runtime
            .gateway
            .dispatch(&mut fixture.runtime.cube, &request);
        let ok = result.as_ref().is_ok_and(|result| result.ok);
        rows.push(match result {
            Ok(result) => serde_json::to_value(result).unwrap(),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        });
        if !ok {
            break;
        }
    }
    rows
}

fn run_case(
    case: &Case,
    model: Option<aivm_runtime::ModelBlock>,
    out: &std::path::Path,
) -> serde_json::Value {
    let started = Instant::now();
    let sample = MemorySample::start();
    let boot = Instant::now();
    let fresh = model.is_some();
    let mut fixture = Fixture::with_model(true, model);
    let client_initialization_ms = boot.elapsed().as_millis();
    fixture.modify();
    std::fs::write(fixture.runtime.workspace.join("src/main.c"), &case.buggy).unwrap();
    std::fs::write(fixture.runtime.workspace.join("verify.c"), &case.verifier).unwrap();
    std::fs::write(
        fixture.runtime.workspace.join("README.md"),
        &case.description,
    )
    .unwrap();
    // task นี้แก้ไฟล์เดียว เพื่อให้ diff ครบกับ source ที่ verifier ตรวจ
    fixture.runtime.config.filesystem.write = vec!["./workspace/src/main.c".into()];
    fixture.runtime.gateway.policy.filesystem.write = vec![fixture
        .runtime
        .workspace
        .join("src/main.c")
        .display()
        .to_string()];
    fixture.runtime.policy = fixture.runtime.gateway.policy.clone();
    let plan = commands(&fixture);
    fixture.prepare_verifier(&plan[..3]);
    let protected = fixture
        .runtime
        .gateway
        .write(&mut fixture.runtime.cube, "verify.c", "tampered")
        .is_err();
    let baseline = verify(&mut fixture, &plan);
    let reproduced = baseline.len() == 4
        && baseline[..3].iter().all(|row| row["ok"] == true)
        && baseline[3]["ok"] == false
        && baseline[3]["verification"]["exit_code"] == 1;
    assert!(
        reproduced && protected,
        "{}: baseline must compile and fail the protected oracle: {baseline:?}",
        case.id
    );
    let cost = Arc::new(Mutex::new(ModelCost::default()));
    let task = format!("Fix the bug in src/main.c. {} Read the source, repair only src/main.c, and run the tests. Do not add main or modify verify.c. The operator runtime will compile and run the protected verifier after an edit.", case.description);
    let (outcome, task_contract, run, error) = if fresh {
        let inner = std::mem::replace(
            &mut fixture.runtime.model,
            Box::new(aivm_model::EchoModel {
                name: "unused".into(),
            }),
        );
        fixture.runtime.model = Box::new(MeteredModel {
            model: inner,
            cost: cost.clone(),
        });
        match fixture.runtime.run_agent(&task, 16, Some(&fixture.root)) {
            Ok(run) => (
                Some(run.outcome.clone()),
                Some(run.task_contract.clone()),
                Some(run),
                None,
            ),
            Err(error) => (None, None, None, Some(error.to_string())),
        }
    } else {
        // reference patch เป็น operator control; ห้ามนับเป็น model_repair
        let contract = fixture
            .runtime
            .gateway
            .begin_task(&mut fixture.runtime.cube, &task)
            .unwrap();
        fixture
            .runtime
            .gateway
            .write(&mut fixture.runtime.cube, "src/main.c", &case.reference)
            .unwrap();
        let checked = verify(&mut fixture, &plan);
        let receipt =
            serde_json::from_value(checked.last().unwrap()["verification"].clone()).unwrap();
        let outcome = fixture
            .runtime
            .gateway
            .finalize_task(
                &mut fixture.runtime.cube,
                &contract,
                Execution::Completed,
                SolutionOrigin::OperatorPatch,
                Some(&receipt),
            )
            .unwrap();
        (Some(outcome), Some(contract), None, None)
    };
    let final_check = verify(&mut fixture, &plan);
    let oracle_correct = final_check.len() == 4 && final_check.iter().all(|row| row["ok"] == true);
    assert_eq!(
        std::fs::read_to_string(fixture.runtime.workspace.join("verify.c")).unwrap(),
        case.verifier
    );
    let actual = std::fs::read(fixture.runtime.workspace.join("src/main.c")).unwrap();
    let old = fixture.root.join("original.c");
    std::fs::write(&old, &case.buggy).unwrap();
    let patch = std::process::Command::new("diff")
        .args(["-u", "--label", "a/src/main.c", "--label", "b/src/main.c"])
        .arg(&old)
        .arg(fixture.runtime.workspace.join("src/main.c"))
        .output()
        .unwrap();
    assert!(matches!(patch.status.code(), Some(0 | 1)));
    let directory = out.join(&case.id);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("patch.diff"), &patch.stdout).unwrap();
    std::fs::write(directory.join("source.c"), &actual).unwrap();
    let artifact = task_contract
        .as_ref()
        .zip(outcome.as_ref())
        .map(|(contract, outcome)| {
            fixture
                .runtime
                .gateway
                .publish_artifact(
                    &mut fixture.runtime.cube,
                    contract,
                    outcome,
                    1,
                    "patch",
                    &patch.stdout,
                )
                .unwrap()
        });
    let audit = std::fs::read(fixture.root.join("audit.jsonl")).unwrap();
    AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap();
    std::fs::write(directory.join("audit.jsonl"), &audit).unwrap();
    let success = reproduced
        && oracle_correct
        && actual != case.buggy.as_bytes()
        && outcome.as_ref().is_some_and(|outcome| {
            outcome.is_verified()
                && outcome.solution_origin
                    == if fresh {
                        SolutionOrigin::ModelRepair
                    } else {
                        SolutionOrigin::OperatorPatch
                    }
        });
    let patch_retries = run
        .as_ref()
        .map(|run| {
            run.steps
                .iter()
                .filter(|step| step.outcome.starts_with("OK filesystem.write"))
                .count()
                .saturating_sub(1)
        })
        .unwrap_or(0);
    let sampled_tree_peak_rss_bytes = sample.finish();
    let elapsed_ms = started.elapsed().as_millis();
    let infrastructure_failure =
        error.is_some() || run.as_ref().is_some_and(|run| run.error.is_some());
    json!({"id":case.id,"revision":case.revision,"category":case.category,"baseline_reproduced":reproduced,
        "reproduction_test_origin":"operator","protected_verifier":protected,"verifier_unchanged":true,
        "patch_oracle_correct":oracle_correct,"task_success":success,"infrastructure_failure":infrastructure_failure,"outcome":outcome,"task_contract":task_contract,
        "artifact":artifact,"agent_run":run,"error":error,"source_changed":actual!=case.buggy.as_bytes(),
        "source_sha256":format!("{:x}",Sha256::digest(&actual)),"audit_sha256":format!("{:x}",Sha256::digest(&audit)),
        "effective_config":fixture.runtime.config,"baseline":baseline,"independent_final_check":final_check,
        "cost":{"total_elapsed_ms":elapsed_ms,"client_initialization_ms":client_initialization_ms,"model_loading_ms":null,
            "worker_model_loading_included_in_inference_wall_time":true,"patch_retries":patch_retries,
            "model":*cost.lock().unwrap(),"sampled_tree_peak_rss_bytes":sampled_tree_peak_rss_bytes,"rss_sample_interval_ms":25,
            "token_accounting":"pinned_worker_reported_when_available; estimates separate; rejected outputs may be unobserved"}})
}

fn suite(fresh: bool) {
    let corpus: Corpus = serde_json::from_str(CORPUS).unwrap();
    assert_eq!(corpus.schema, 1);
    assert!((20..=30).contains(&corpus.cases.len()));
    let model = if fresh {
        let bytes = std::fs::read(
            std::env::var("AIVM_WORKER_HOST_CONFIG")
                .expect("approved pinned model config required"),
        )
        .unwrap();
        let config: aivm_model::ModelConfig = serde_json::from_slice(&bytes).unwrap();
        let local = config.local.as_ref().unwrap();
        assert_eq!(config.provider, "local");
        assert_eq!(local.model_sha256.len(), 64);
        assert!(local
            .worker_sha256
            .as_ref()
            .is_some_and(|value| value.len() == 64));
        Some((
            aivm_runtime::ModelBlock {
                provider: config.provider.clone(),
                name: config.name.clone(),
                local: config.local.clone(),
                total_timeout_ms: config
                    .worker_limits
                    .as_ref()
                    .and_then(|limits| limits.total_timeout_ms),
                host_resources: config
                    .worker_limits
                    .as_ref()
                    .unwrap()
                    .host_resources
                    .clone(),
                ..Default::default()
            },
            format!("{:x}", Sha256::digest(&bytes)),
        ))
    } else {
        None
    };
    let out = std::env::var("AIVM_REPAIR_BENCHMARK_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("aivm-repair-report-{}", uuid::Uuid::new_v4()))
        });
    std::fs::create_dir_all(&out).unwrap();
    let started = Instant::now();
    let mut rows = Vec::new();
    for case in &corpus.cases {
        let case_started = Instant::now();
        assert!(case
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_case(case, model.as_ref().map(|entry| entry.0.clone()), &out)
        }));
        rows.push(match result { Ok(row) => row, Err(_) => json!({"id":case.id,"revision":case.revision,"task_success":false,"infrastructure_failure":true,"error":"case failed before completion; inspect raw log","cost":{"total_elapsed_ms":case_started.elapsed().as_millis()}}) });
        let success = rows
            .iter()
            .filter(|row| row["task_success"] == true)
            .count();
        let total_cost: u64 = rows
            .iter()
            .filter_map(|row| row["cost"]["total_elapsed_ms"].as_u64())
            .sum();
        let report = json!({"schema":2,"mode":if fresh {"fresh_model"} else {"reference_control"},"scope":corpus.scope,
            "build_profile":if cfg!(debug_assertions) {"debug"} else {"release"},
            "corpus_sha256":format!("{:x}",Sha256::digest(CORPUS.as_bytes())),"model_config_sha256":model.as_ref().map(|entry| &entry.1),
            "source_identity":std::env::var("AIVM_SOURCE_IDENTITY").ok().and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok()),
            "completed":rows.len(),"total":corpus.cases.len(),"task_successes":success,"elapsed_ms":started.elapsed().as_millis(),
            "cost_per_success_ms":if success>0 {Some(total_cost as f64/success as f64)} else {None},"cases":rows});
        std::fs::write(
            out.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    assert!(
        rows.iter().all(|row| row["infrastructure_failure"] != true),
        "infrastructure failures: {}",
        out.display()
    );
    if !fresh {
        assert!(
            rows.iter().all(|row| row["task_success"] == true),
            "reference control failed: {}",
            out.display()
        );
    }
}

#[test]
fn repair_corpus_baselines_and_reference_controls() {
    suite(false);
}

#[test]
#[ignore = "requires approved pinned model config and host worker prerequisites"]
fn fresh_model_repair_benchmark() {
    suite(true);
}
