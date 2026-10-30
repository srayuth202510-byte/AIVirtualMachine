//! ตรวจ failure บน host จริงโดยไม่ใช้ error ทั่วไปแทนหลักฐาน resource limit
use aivm_model::{worker::*, ModelConfig};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn process_identity(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm อาจมีช่องว่างหรือวงเล็บ; starttime คือ field 22 หลังปิด comm
    text.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn descendants(pid: u32, found: &mut BTreeMap<u32, u64>) {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return;
    };
    for task in tasks.flatten() {
        let Ok(children) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for child in children.split_whitespace().filter_map(|v| v.parse().ok()) {
            if let Some(identity) = process_identity(child) {
                found.insert(child, identity);
                descendants(child, found);
            }
        }
    }
}

fn memory_failure(error: &str, serial: &str) -> bool {
    let text = format!("{error}\n{serial}").to_ascii_lowercase();
    let reason = error.to_ascii_lowercase();
    // timeout/ลายเซ็นผิด/ขาด prerequisite ไม่ใช่หลักฐานว่า memory limit ทำงาน
    if [
        "timed out",
        "deadline",
        "timeout",
        "sha256 mismatch",
        "prerequisites",
        "spawn worker:",
    ]
    .iter()
    .any(|word| reason.contains(word))
    {
        return false;
    }
    [
        "cannot allocate memory",
        "memory allocation",
        "failed to allocate",
        "failed to mmap",
        "mmap failed",
        "out of memory",
        "out-of-memory",
        "oom-kill",
        "std::bad_alloc",
        "model snapshot tmpfs capacity exhausted (ram-backed staging)",
    ]
    .iter()
    .any(|word| text.contains(word))
}

fn timeout_failure(error: &str) -> bool {
    [
        "worker deadline exceeded",
        "wall-clock timeout",
        "microvm run timed out",
    ]
    .iter()
    .any(|word| error.contains(word))
}

fn scoped_processes(root: &Path) -> Vec<u32> {
    let marker = root.to_string_lossy();
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            if pid == std::process::id() {
                return None;
            }
            let command = std::fs::read(entry.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&command)
                .contains(marker.as_ref())
                .then_some(pid)
        })
        .collect()
}

fn assert_reaped(observed: &BTreeMap<u32, u64>, root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive: Vec<_> = observed
            .iter()
            .filter(|(pid, start)| process_identity(**pid) == Some(**start))
            .collect();
        let scoped = scoped_processes(root);
        if alive.is_empty() && scoped.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "worker descendants survived cleanup: {alive:?}; scoped={scoped:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn observe<T>(action: impl FnOnce() -> T) -> (T, BTreeMap<u32, u64>) {
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let observer = scope.spawn(|| {
            let mut found = BTreeMap::new();
            while !done.load(Ordering::Relaxed) {
                descendants(std::process::id(), &mut found);
                std::thread::sleep(Duration::from_millis(5));
            }
            descendants(std::process::id(), &mut found);
            found
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        done.store(true, Ordering::Relaxed);
        let found = observer.join().unwrap();
        match result {
            Ok(value) => (value, found),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

fn scratch_logs(root: &Path) -> String {
    let mut result = String::new();
    for entry in std::fs::read_dir(root).unwrap().flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("aivm-uvm-run-")
        {
            if let Ok(log) = std::fs::read_to_string(entry.path().join("serial.log")) {
                result.push_str(&log);
            }
            std::fs::remove_dir_all(entry.path()).unwrap();
        }
    }
    result
}

fn assert_staging_clean(root: &Path, config: &ModelConfig) {
    let remaining: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|v| v.file_name())
        .collect();
    assert!(remaining.is_empty(), "worker staging leaked: {remaining:?}");
    if let WorkerLauncher::Container { config } = &config.local.as_ref().unwrap().worker_launcher {
        let leaked: Vec<_> = std::fs::read_dir(&config.cgroup_root)
            .unwrap()
            .flatten()
            .filter(|v| v.file_name().to_string_lossy().starts_with("aivm-"))
            .map(|v| v.file_name())
            .collect();
        assert!(leaked.is_empty(), "private cgroups leaked: {leaked:?}");
    }
}

#[test]
fn failure_classification_rejects_unrelated_errors() {
    assert!(memory_failure(
        "model load: failed to mmap: Cannot allocate memory",
        ""
    ));
    assert!(memory_failure(
        "sandbox worker exit 137",
        "Out of memory: Killed process 12"
    ));
    assert!(memory_failure(
        "model snapshot tmpfs capacity exhausted (RAM-backed staging)",
        ""
    ));
    assert!(memory_failure(
        "Cannot allocate memory",
        "kernel timeout configuration"
    ));
    for error in [
        "worker returned no response",
        "sandbox worker exit 137",
        "model sha256 mismatch",
        "container prerequisites unavailable",
        "microvm run timed out",
        "model artifact read/copy failed: No space left on device (os error 28)",
    ] {
        assert!(!memory_failure(error, ""), "{error}");
    }
    assert!(timeout_failure("worker failed: worker deadline exceeded"));
    assert!(!timeout_failure("model hash mismatch"));
}

#[test]
fn process_observer_tracks_and_reaps_actual_children() {
    let ((), observed) = observe(|| {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("0.1")
            .spawn()
            .unwrap();
        child.wait().unwrap();
    });
    assert!(!observed.is_empty());
    assert_reaped(&observed, Path::new("/unused-aivm-failure-observer"));
}

#[test]
#[ignore = "requires pinned GGUF, private test TMPDIR, and container/KVM host"]
fn real_isolated_worker_failure_recovery() {
    let path = std::env::var("AIVM_WORKER_HOST_CONFIG").expect("set AIVM_WORKER_HOST_CONFIG");
    let config: ModelConfig = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let local = config.local.as_ref().expect("local model required");
    assert_eq!(config.provider, "local");
    assert!(!local.model_sha256.is_empty());
    assert!(local
        .worker_sha256
        .as_ref()
        .is_some_and(|pin| !pin.is_empty()));
    assert!(!matches!(local.worker_launcher, WorkerLauncher::Process));
    let root = PathBuf::from(
        std::env::var("AIVM_WORKER_HOST_TMPDIR").expect("private host test directory required"),
    );
    assert_eq!(std::env::temp_dir(), root);
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("aivm-worker-failures-"));
    let evidence_path =
        PathBuf::from(std::env::var("AIVM_WORKER_HOST_EVIDENCE").expect("evidence path required"));
    let limits = config.worker_limits.clone().unwrap();
    assert!(limits.memory_mb > 128);
    let client = WorkerClient::from_config(&config).unwrap();
    let request = InferenceRequest {
        protocol_version: PROTOCOL_VERSION,
        output_mode: Default::default(),
        request_id: "failure-recovery".into(),
        model_id: config.name.clone(),
        prompt: "Reply with the word hello.".into(),
        stream: true,
        max_output_tokens: 4,
        timeout_ms: limits.timeout_ms,
        temperature: None,
    };
    let mut evidence = Vec::new();
    for case in ["timeout", "memory"] {
        let mut constrained = limits.clone();
        let mut req = request.clone();
        if case == "timeout" {
            req.timeout_ms = 100;
        } else {
            constrained.memory_mb = 128;
        }
        let started = Instant::now();
        let mut deltas = 0;
        let (result, observed) = observe(|| {
            client.infer_stream(&config, req.clone(), &constrained, &mut |_| {
                deltas += 1;
                Ok(())
            })
        });
        let error = result
            .expect_err("constrained inference must fail")
            .to_string();
        assert!(!observed.is_empty(), "no actual child process was observed");
        assert_reaped(&observed, &root);
        let serial = scratch_logs(&root);
        assert_staging_clean(&root, &config);
        let elapsed_ms = started.elapsed().as_millis();
        assert_eq!(deltas, 0, "failed load must not emit tokens");
        assert!(
            elapsed_ms < 180_000,
            "failure/cleanup exceeded bounded setup allowance: {elapsed_ms}"
        );
        if case == "timeout" {
            assert!(
                timeout_failure(&error),
                "unexpected timeout failure: {error}"
            );
        } else {
            assert!(
                memory_failure(&error, &serial),
                "no memory-pressure evidence: {error}; serial tail: {}",
                serial
                    .chars()
                    .skip(serial.chars().count().saturating_sub(2000))
                    .collect::<String>()
            );
        }
        evidence.push(serde_json::json!({"case":case,"passed":true,"timeout_ms":req.timeout_ms,
            "memory_mb":constrained.memory_mb,"elapsed_ms":elapsed_ms,"error":error,
            "observed_processes":observed,"descendants_reaped":true,"staging_clean":true,
            "stream_deltas":deltas,"guest_oom_diagnostic":serial.to_ascii_lowercase().contains("out of memory")}));
        evidence.last_mut().unwrap()["memory_failure_kind"] =
            serde_json::json!(if case != "memory" {
                "not-applicable"
            } else if error.contains("tmpfs capacity exhausted") {
                "ram-backed-staging-capacity"
            } else if serial.to_ascii_lowercase().contains("out of memory") {
                "guest-oom-diagnostic"
            } else {
                "allocation-failure"
            });
        std::fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();

        // ใช้ client เดิมและ pins เดิมหลังแต่ละ failure; ต้องเกิด inference ใหม่ที่ตรวจผ่านจริง
        let (response, observed) =
            observe(|| client.infer_stream(&config, request.clone(), &limits, &mut |_| Ok(())));
        let response = response.expect("healthy inference after failure must recover");
        assert_eq!(response.verification.status, VerificationStatus::Verified);
        assert!(response
            .output
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty()));
        assert_reaped(&observed, &root);
        scratch_logs(&root);
        assert_staging_clean(&root, &config);
        evidence.push(
            serde_json::json!({"case":format!("recovery-after-{case}"),"passed":true,
            "verification":"verified","descendants_reaped":true,"staging_clean":true,
            "observed_processes":observed}),
        );
        std::fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        eprintln!("failure-recovery: {case} contained; healthy inference verified");
    }
}
