use aivm_model::{worker::*, LocalModelConfig, ModelConfig};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

fn request() -> InferenceRequest {
    InferenceRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: "req-1".into(),
        model_id: "echo".into(),
        prompt: "hello".into(),
        stream: false,
        max_output_tokens: 16,
        timeout_ms: 2000,
    }
}
fn worker() -> WorkerClient {
    WorkerClient::new(env!("CARGO_BIN_EXE_aivm-model-worker"))
}

#[test]
fn actual_worker_stream_matches_final_response() {
    let client = worker();
    let mut output = String::new();
    let response = client
        .infer_stream(
            &ModelConfig::default(),
            request(),
            &InferenceLimits::default(),
            &mut |delta| {
                output.push_str(delta);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(response.output.as_deref(), Some(output.as_str()));
    assert!(output.contains("hello"));
}

struct Script(PathBuf);
impl Script {
    fn new(body: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "aivm-hostile-worker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Script {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn cancellation_kills_a_worker_that_never_reads_input() {
    let script = Script::new("exec /bin/sleep 30");
    let client = WorkerClient::new(&script.0);
    let token = client.cancellation_token();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        token.store(true, Ordering::Relaxed);
    });
    let started = Instant::now();
    let error = client
        .infer(
            &ModelConfig::default(),
            request(),
            &InferenceLimits::default(),
        )
        .unwrap_err();
    cancel.join().unwrap();
    assert!(error.to_string().contains("cancelled"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn response_does_not_allow_worker_to_outlive_deadline() {
    let response = r#"{"protocol_version":1,"request_id":"req-1","output":"ok","usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},"termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null}"#;
    let script = Script::new(&format!(
        "read request\nprintf '%s\\n' '{response}'\nexec /bin/sleep 30"
    ));
    let client = WorkerClient::new(&script.0);
    let mut req = request();
    req.timeout_ms = 150;
    let started = Instant::now();
    assert!(client
        .infer(&ModelConfig::default(), req, &InferenceLimits::default())
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn mismatched_response_is_rejected() {
    let script = Script::new(
        r#"read request
printf '%s\n' '{"protocol_version":1,"request_id":"wrong","output":"ok"}'"#,
    );
    assert!(WorkerClient::new(&script.0)
        .infer(
            &ModelConfig::default(),
            request(),
            &InferenceLimits::default()
        )
        .unwrap_err()
        .to_string()
        .contains("identity"));
}

#[test]
fn unavailable_container_cannot_fall_back_to_process() {
    let config = ModelConfig {
        local: Some(LocalModelConfig {
            worker_launcher: WorkerLauncher::Container {
                config: aivm_sandbox::container::ContainerConfig {
                    bubblewrap: "/nonexistent/bwrap".into(),
                    ..Default::default()
                },
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(worker()
        .infer(&config, request(), &InferenceLimits::default())
        .unwrap_err()
        .to_string()
        .contains("container prerequisites"));
}

#[cfg(feature = "microvm")]
#[test]
fn invalid_microvm_pins_cannot_fall_back_to_process() {
    let file = Script::new("unused artifact");
    let config = ModelConfig {
        local: Some(LocalModelConfig {
            model_path: file.0.to_string_lossy().into_owned(),
            worker_launcher: WorkerLauncher::Microvm {
                config: Box::default(),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(worker()
        .infer(&config, request(), &InferenceLimits::default())
        .is_err());
}

/// Explicit host gate: never silently skip missing configuration/prerequisites.
#[test]
#[ignore = "requires operator-provided pinned model and container/KVM host"]
fn real_isolated_worker_host_validation() {
    let path = std::env::var("AIVM_WORKER_HOST_CONFIG")
        .expect("set AIVM_WORKER_HOST_CONFIG to a ModelConfig JSON file");
    let config: ModelConfig = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let local = config.local.as_ref().expect("local model config required");
    assert_eq!(config.provider, "local");
    assert!(!local.model_sha256.is_empty(), "pin model hash");
    assert!(
        local
            .worker_sha256
            .as_ref()
            .is_some_and(|hash| !hash.is_empty()),
        "pin worker hash"
    );
    assert!(
        !matches!(local.worker_launcher, WorkerLauncher::Process),
        "select container or microvm"
    );
    let limits = config.worker_limits.clone().unwrap_or_default();
    let req = InferenceRequest {
        model_id: config.name.clone(),
        prompt: "Reply with the word hello.".into(),
        timeout_ms: limits.timeout_ms,
        ..request()
    };
    let client = WorkerClient::new(local.worker_path.as_ref().unwrap());
    let mut streamed = String::new();
    let response = client
        .infer_stream(&config, req, &limits, &mut |delta| {
            streamed.push_str(delta);
            Ok(())
        })
        .unwrap();
    assert!(!streamed.trim().is_empty());
    assert_eq!(response.output.as_deref(), Some(streamed.as_str()));
    assert!(matches!(
        response.verification.status,
        VerificationStatus::Verified
    ));
    assert!(
        response
            .applied_limits
            .iter()
            .any(|limit| limit.contains("network")),
        "missing network isolation evidence"
    );
    let mut req = request();
    req.model_id = config.name.clone();
    req.prompt = "Explain operating systems in detail.".into();
    req.timeout_ms = limits.timeout_ms;
    let error = client
        .infer_stream(&config, req, &limits, &mut |_| {
            Err(WorkerError::Failed("host-validation cancellation".into()))
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("host-validation cancellation"),
        "{error}"
    );
}

#[test]
fn cancellation_after_first_delta_does_not_wait_for_final_response() {
    let script = Script::new(
        r#"read request
printf '%s\n' '{"protocol_version":1,"request_id":"req-1","delta":"partial"}'
exec /bin/sleep 30"#,
    );
    let client = WorkerClient::new(&script.0);
    let token = client.cancellation_token();
    let started = Instant::now();
    let mut partial = String::new();
    let error = client
        .infer_stream(
            &ModelConfig::default(),
            request(),
            &InferenceLimits::default(),
            &mut |delta| {
                partial.push_str(delta);
                token.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(partial, "partial");
    assert!(error.to_string().contains("cancelled"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn uncompiled_microvm_tier_is_rejected_instead_of_ignored() {
    #[cfg(not(feature = "microvm"))]
    assert!(serde_json::from_str::<WorkerLauncher>(r#"{"tier":"microvm","config":{}}"#).is_err());
}
