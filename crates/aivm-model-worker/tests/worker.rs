use aivm_model::{worker::*, LocalModelConfig, ModelConfig, OutputMode};
use std::{
    path::PathBuf,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

mod support;
use support::TestResources;

fn request() -> InferenceRequest {
    InferenceRequest {
        protocol_version: PROTOCOL_VERSION,
        output_mode: Default::default(),
        request_id: "req-1".into(),
        model_id: "echo".into(),
        prompt: "hello".into(),
        stream: false,
        max_output_tokens: 16,
        timeout_ms: 2000,
        temperature: None,
    }
}
fn worker() -> WorkerClient {
    WorkerClient::new(env!("CARGO_BIN_EXE_aivm-model-worker"))
}

#[test]
fn actual_worker_stream_matches_final_response() {
    let resources = TestResources::new();
    let client = worker();
    let mut output = String::new();
    let response = client
        .infer_stream(
            &ModelConfig::default(),
            request(),
            &resources.limits(),
            &mut |delta| {
                output.push_str(delta);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(response.output.as_deref(), Some(output.as_str()));
    assert!(output.contains("hello"));
    let usage = response
        .control_plane_usage
        .expect("client timing required");
    assert!(usage.total_ms >= usage.preparation_ms + usage.execution_ms + usage.cleanup_ms);
}

struct Script(PathBuf, TestResources);
impl Script {
    fn new(body: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let resources = TestResources::new();
        let path = resources.root().join("worker");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path, resources)
    }

    fn limits(&self) -> InferenceLimits {
        self.1.limits()
    }
}

#[test]
fn early_worker_exit_reports_status_without_disclosing_stderr() {
    // EOF ต้องเก็บ exit code ของ worker จริง ไม่ใช่ SIGKILL ที่ parent ส่งระหว่าง cleanup
    let script = Script::new("read request\nprintf '%s\\n' 'EXIT_SECRET_SENTINEL' >&2\nexit 73");
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap_err();
    assert_eq!(error.code(), "worker_failed", "{error}");
    assert!(error.to_string().contains("exit_code=73"), "{error}");
    assert!(!error.to_string().contains("EXIT_SECRET_SENTINEL"));
    let exit = error.worker_exit().expect("host exit evidence");
    assert_eq!(exit.exit_code, Some(73));
    assert_eq!(exit.signal, None);
    assert!(exit.observed_before_cleanup);
}

#[test]
fn worker_sigkill_is_reported_without_guessing_a_resource_failure() {
    let script = Script::new("read request\nkill -KILL $$");
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap_err();
    assert_eq!(error.code(), "worker_failed", "{error}");
    assert!(error.to_string().contains("signal=9"), "{error}");
    assert!(!error.to_string().contains("memory allocation"));
    let exit = error.worker_exit().unwrap();
    assert_eq!(exit.exit_code, None);
    assert_eq!(exit.signal, Some(9));
    assert!(exit.observed_before_cleanup);
}

#[test]
fn closed_stdout_does_not_bypass_the_exit_deadline() {
    // worker ปิด stdout ก่อนออกจริง; รอได้เท่างบเดิมและต้องไม่อ้างว่า cleanup SIGKILL คือ crash
    let script = Script::new("read request\nexec 1>&-\nexec /bin/sleep 30");
    let mut req = request();
    req.timeout_ms = 100;
    let started = Instant::now();
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), req, &script.limits())
        .unwrap_err();
    assert_eq!(error.code(), "deadline", "{error}");
    assert!(
        error.to_string().contains("observed_before_cleanup=false"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(2), "{error}");
    assert_eq!(error.worker_exit().unwrap().signal, Some(9));
    assert!(!error.worker_exit().unwrap().observed_before_cleanup);
    assert!(matches!(error.cause(), WorkerError::Deadline(_)));
}

#[test]
fn exit_zero_without_completion_and_nonzero_after_completion_both_fail() {
    // exit 0 ไม่แทน protocol completion; completion ก็ไม่ลบล้าง exit status ที่ล้ม
    let response = r#"{"protocol_version":1,"request_id":"req-1","output":"ok","usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},"termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null}"#;
    for (body, code) in [
        ("read request\nexit 0".to_string(), 0),
        (
            format!("read request\nprintf '%s\\n' '{response}'\nexit 74"),
            74,
        ),
    ] {
        let script = Script::new(&body);
        let error = WorkerClient::new(&script.0)
            .infer(&ModelConfig::default(), request(), &script.limits())
            .unwrap_err();
        assert_eq!(error.code(), "worker_failed", "{error}");
        let exit = error.worker_exit().unwrap();
        assert_eq!(exit.exit_code, Some(code));
        assert!(exit.observed_before_cleanup);
    }
}

#[test]
fn partial_stream_does_not_become_completion_when_worker_exits() {
    let script = Script::new("read request\nprintf '%s\\n' '{\"protocol_version\":1,\"request_id\":\"req-1\",\"delta\":\"ok\"}'\nexit 64");
    let mut output = String::new();
    let error = WorkerClient::new(&script.0)
        .infer_stream(
            &ModelConfig::default(),
            request(),
            &script.limits(),
            &mut |delta| {
                output.push_str(delta);
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(output, "ok");
    assert_eq!(error.code(), "worker_failed", "{error}");
    assert_eq!(error.worker_exit().unwrap().exit_code, Some(64));
}

#[test]
fn protocol_failure_retains_its_cause_and_round_trips_exit_evidence() {
    let script =
        Script::new("read request\nprintf '%s\\n' 'EXIT_SECRET_SENTINEL'\nexec /bin/sleep 30");
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap_err();
    assert_eq!(error.code(), "protocol", "{error}");
    assert!(matches!(error.cause(), WorkerError::Protocol(_)));
    assert!(!error.worker_exit().unwrap().observed_before_cleanup);
    let encoded = serde_json::to_string(&error).unwrap();
    assert!(!encoded.contains("EXIT_SECRET_SENTINEL"));
    let decoded: WorkerError = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.code(), "protocol");
    assert_eq!(decoded.worker_exit(), error.worker_exit());
}

#[test]
fn untrusted_worker_cannot_forge_host_exit_evidence() {
    // error_kind เป็นข้อมูลไม่เชื่อถือ: ต้องทิ้ง exit ที่ worker อ้าง แล้วเก็บจาก wait เท่านั้น
    let frame = r#"{"protocol_version":1,"request_id":"req-1","error":"EXIT_SECRET_SENTINEL","error_kind":{"Exit":{"source":{"Failed":"EXIT_SECRET_SENTINEL"},"exit":{"exit_code":99,"signal":null,"core_dumped":false,"observed_before_cleanup":true}}}}"#;
    let script = Script::new(&format!("read request\nprintf '%s\\n' '{frame}'\nexit 73"));
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap_err();
    assert_eq!(error.code(), "worker_failed", "{error}");
    assert!(!error.to_string().contains("EXIT_SECRET_SENTINEL"));
    assert_ne!(error.worker_exit().unwrap().exit_code, Some(99));
}

#[cfg(target_os = "linux")]
#[test]
fn actual_cpu_limit_kill_still_has_an_unclassified_sigkill_status() {
    // kernel บังคับ hard CPU limit จริง; SIGKILL เดี่ยว ๆ ยังไม่พิสูจน์สาเหตุสำหรับ API ทั่วไป
    let script = Script::new("read request\nwhile :; do :; done");
    let limits = InferenceLimits {
        cpu_seconds: 1,
        total_timeout_ms: Some(6000),
        ..script.limits()
    };
    let mut req = request();
    req.timeout_ms = 5000;
    let error = WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), req, &limits)
        .unwrap_err();
    assert_eq!(error.code(), "worker_failed", "{error}");
    let exit = error.worker_exit().unwrap();
    assert_eq!(exit.signal, Some(9));
    assert!(exit.observed_before_cleanup);
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
        .infer(&ModelConfig::default(), request(), &script.limits())
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
    let error = client
        .infer(&ModelConfig::default(), req, &script.limits())
        .unwrap_err();
    // เก็บ error จริงและเวลาที่ผ่านไปเมื่อ assertion ล้ม เพื่อวิเคราะห์ flake ได้
    let elapsed = started.elapsed();
    assert!(
        error.to_string().contains("deadline"),
        "{error}; elapsed={elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "{error}; elapsed={elapsed:?}"
    );
}

#[test]
fn total_deadline_rejects_a_lingering_worker_without_poisoning_the_client() {
    // total budget ต้องตัดงานแม้ inference timeout ยังเหลือ และ client เดิมใช้ใหม่ได้
    let response = r#"{"protocol_version":1,"request_id":"req-1","output":"ok","usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},"termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null,"control_plane_usage":{"preparation_ms":999999,"execution_ms":999999,"cleanup_ms":999999,"total_ms":999999}}"#;
    let body = format!("read request\nprintf '%s\\n' '{response}'");
    let script = Script::new(&format!("{body}\nexec /bin/sleep 30"));
    let client = WorkerClient::new(&script.0);
    let limits = InferenceLimits {
        total_timeout_ms: Some(50),
        ..script.limits()
    };
    let started = Instant::now();
    let error = client
        .infer(&ModelConfig::default(), request(), &limits)
        .unwrap_err();
    assert!(
        error.to_string().contains("total inference deadline"),
        "{error}"
    );
    assert!(error.to_string().contains("total_ms="), "{error}");
    assert!(started.elapsed() < Duration::from_secs(1), "{error}");
    std::fs::write(&script.0, format!("#!/bin/sh\n{body}\n")).unwrap();
    let response = client
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap();
    assert_eq!(response.output.as_deref(), Some("ok"));
    assert!(
        response.control_plane_usage.unwrap().total_ms < 999999,
        "worker timing must be replaced by control-plane measurements"
    );
}

#[test]
fn mismatched_response_is_rejected() {
    let script = Script::new(
        r#"read request
printf '%s\n' '{"protocol_version":1,"request_id":"wrong","output":"ok"}'"#,
    );
    assert!(WorkerClient::new(&script.0)
        .infer(&ModelConfig::default(), request(), &script.limits())
        .unwrap_err()
        .to_string()
        .contains("identity"));
}

#[test]
fn unavailable_container_cannot_fall_back_to_process() {
    let resources = TestResources::new();
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
        .infer(&config, request(), &resources.limits())
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
    assert!(worker().infer(&config, request(), &file.limits()).is_err());
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
    let client = WorkerClient::from_config(&config).unwrap();
    // งบรวมที่สั้นต้องหยุด preparation โดยไม่ส่ง token และใช้ client เดิมทำงานต่อได้
    let bounded = InferenceLimits {
        total_timeout_ms: Some(50),
        ..limits.clone()
    };
    let mut early_deltas = 0;
    let started = Instant::now();
    let error = client
        .infer_stream(&config, req.clone(), &bounded, &mut |_| {
            early_deltas += 1;
            Ok(())
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("total inference deadline"),
        "{error}"
    );
    assert_eq!(early_deltas, 0, "setup timeout must not release tokens");
    assert!(started.elapsed() < Duration::from_secs(5), "{error}");
    // pin ผิดต้องปฏิเสธทุก tier และห้ามปล่อย token ออกมาก่อนตรวจผ่าน
    let mut wrong_pin = config.clone();
    let hash = &mut wrong_pin.local.as_mut().unwrap().model_sha256;
    hash.replace_range(..1, if hash.starts_with('0') { "1" } else { "0" });
    let mut deltas = 0;
    let error = client
        .infer_stream(&wrong_pin, req.clone(), &limits, &mut |_| {
            deltas += 1;
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("sha256 mismatch"), "{error}");
    assert_eq!(deltas, 0, "unpinned bytes must never produce output");

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
            &script.limits(),
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

fn structured_request(mode: OutputMode) -> InferenceRequest {
    InferenceRequest {
        protocol_version: mode.protocol_version(),
        output_mode: mode,
        ..request()
    }
}

fn structured_response(output: &str, mode: OutputMode) -> serde_json::Value {
    serde_json::json!({
        "protocol_version":mode.protocol_version(), "request_id":"req-1",
        "output":output, "output_mode":mode, "grammar_id":mode.grammar_id(),
        "usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},
        "termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null
    })
}

#[test]
fn structured_protocol_is_explicit_and_old_text_requests_remain_version_one() {
    // ไม่ส่ง field ใหม่ให้ worker เดิมใน text mode; structured ต้องใช้ version 2 เสมอ
    let mut raw = serde_json::to_value(request()).unwrap();
    assert!(raw.get("output_mode").is_none());
    assert_eq!(raw["protocol_version"], 1);
    let legacy: InferenceRequest = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(legacy.output_mode, OutputMode::Text);
    raw["output_mode"] = serde_json::json!("json");
    let invalid: InferenceRequest = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(
        invalid
            .validate(&InferenceLimits::default(), 1)
            .unwrap_err()
            .code(),
        "protocol"
    );
    raw["output_mode"] = serde_json::json!("unknown_mode");
    assert!(serde_json::from_value::<InferenceRequest>(raw).is_err());
}

#[test]
fn structured_worker_requires_matching_version_mode_and_grammar_evidence() {
    let mode = OutputMode::AgentIntent;
    for field in ["protocol_version", "output_mode", "grammar_id"] {
        let mut response = structured_response(r#"{"done":true}"#, mode);
        response[field] = match field {
            "protocol_version" => serde_json::json!(1),
            "output_mode" => serde_json::json!("text"),
            _ => serde_json::Value::Null,
        };
        let script = Script::new(&format!("read request\nprintf '%s\\n' '{response}'"));
        let error = WorkerClient::new(&script.0)
            .infer(
                &ModelConfig::default(),
                structured_request(mode),
                &script.limits(),
            )
            .unwrap_err();
        assert_eq!(error.code(), "protocol", "{field}: {error}");
    }
}

#[test]
fn structured_worker_output_is_validated_independently_of_worker_claims() {
    // worker อ้าง completed หรือ artifact_verified ไม่สามารถข้าม Serde ของ control plane
    for output in [
        r#"{"done":true,"extra":1}"#,
        r#"{"done":true,"done":true}"#,
        r#"{"tool":"shell.exec","path":"sh"}"#,
        "```json\n{}\n```",
        "{",
        "[]",
    ] {
        let response = structured_response(output, OutputMode::AgentIntent);
        let script = Script::new(&format!("read request\nprintf '%s\\n' '{response}'"));
        let error = WorkerClient::new(&script.0)
            .infer(
                &ModelConfig::default(),
                structured_request(OutputMode::AgentIntent),
                &script.limits(),
            )
            .unwrap_err();
        assert_eq!(error.code(), "invalid_output", "{output}: {error}");
    }
    let mut response = structured_response("[]", OutputMode::Json);
    response["termination"] = serde_json::json!("length");
    let script = Script::new(&format!("read request\nprintf '%s\\n' '{response}'"));
    assert_eq!(
        WorkerClient::new(&script.0)
            .infer(
                &ModelConfig::default(),
                structured_request(OutputMode::Json),
                &script.limits()
            )
            .unwrap_err()
            .code(),
        "invalid_output"
    );
}

#[test]
fn structured_stream_releases_one_validated_result_and_no_partial_failures() {
    for final_output in [r#"{"done":true}"#, r#"{"done":false}"#] {
        let response = structured_response(final_output, OutputMode::AgentIntent);
        let prefix =
            serde_json::json!({"protocol_version":2,"request_id":"req-1","delta":"{\"done\":"});
        let suffix = serde_json::json!({"protocol_version":2,"request_id":"req-1","delta":final_output.strip_prefix("{\"done\":").unwrap()});
        let script = Script::new(&format!(
            "read request\nprintf '%s\\n' '{prefix}' '{suffix}' '{response}'"
        ));
        let mut callbacks = Vec::new();
        let result = WorkerClient::new(&script.0).infer_stream(
            &ModelConfig::default(),
            structured_request(OutputMode::AgentIntent),
            &script.limits(),
            &mut |delta| {
                callbacks.push(delta.to_string());
                Ok(())
            },
        );
        if final_output.contains("false") {
            assert_eq!(result.unwrap_err().code(), "invalid_output");
            assert!(callbacks.is_empty());
        } else {
            let response = result.unwrap();
            assert_eq!(callbacks, [final_output]);
            assert!(response
                .verification
                .checks
                .iter()
                .any(|check| check.contains("aivm-agent-intent-v1")));
        }
    }
}

#[test]
fn structured_deadline_and_cancellation_do_not_deliver_partial_json() {
    let script = Script::new("read request\nprintf '%s\\n' '{\"protocol_version\":2,\"request_id\":\"req-1\",\"delta\":\"{\"}'\nexec /bin/sleep 30");
    let client = WorkerClient::new(&script.0);
    let mut req = structured_request(OutputMode::Json);
    req.timeout_ms = 100;
    let limits = InferenceLimits {
        timeout_ms: 100,
        ..script.limits()
    };
    let mut delivered = false;
    let error = client
        .infer_stream(&ModelConfig::default(), req.clone(), &limits, &mut |_| {
            delivered = true;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.code(), "deadline", "{error}");
    assert!(!delivered);
    client.cancellation_token().store(true, Ordering::Relaxed);
    assert_eq!(
        client
            .infer_stream(&ModelConfig::default(), req, &limits, &mut |_| {
                delivered = true;
                Ok(())
            })
            .unwrap_err()
            .code(),
        "cancelled"
    );
    assert!(!delivered);
}

#[test]
#[ignore = "requires pinned GGUF worker; checks real structured streaming and output exhaustion"]
fn real_model_structured_stream_and_incomplete_budget() {
    let config: ModelConfig = serde_json::from_slice(
        &std::fs::read(std::env::var("AIVM_WORKER_HOST_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    let client = WorkerClient::from_config(&config).unwrap();
    let limits = config.worker_limits.clone().unwrap();
    let mut req = structured_request(OutputMode::AgentIntent);
    req.model_id = config.name.clone();
    req.prompt = "Return exactly one JSON object to read src/seed.txt. Use tool filesystem.read and path src/seed.txt. No markdown.".into();
    req.timeout_ms = limits.timeout_ms;
    req.max_output_tokens = 1;
    let mut deltas = Vec::new();
    let error = client
        .infer_stream(&config, req.clone(), &limits, &mut |delta| {
            deltas.push(delta.to_string());
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.code(), "invalid_output", "{error}");
    assert!(deltas.is_empty());
    req.max_output_tokens = config.local.as_ref().unwrap().max_tokens;
    let response = client
        .infer_stream(&config, req, &limits, &mut |delta| {
            deltas.push(delta.to_string());
            Ok(())
        })
        .unwrap();
    assert_eq!(deltas.len(), 1);
    assert_eq!(response.output.as_deref(), Some(deltas[0].as_str()));
    assert_eq!(response.termination, "completed");
    assert_eq!(response.grammar_id.as_deref(), Some("aivm-agent-intent-v1"));
    assert_eq!(response.verification.status, VerificationStatus::Verified);
    OutputMode::AgentIntent.validate(&deltas[0]).unwrap();
}

#[test]
fn structured_rejection_keeps_error_code_without_echoing_worker_diagnostics() {
    let script = Script::new("read request\nprintf '%s\\n' '{\"protocol_version\":2,\"request_id\":\"req-1\",\"error\":\"STRUCTURED_SECRET_SENTINEL\",\"error_kind\":{\"InvalidOutput\":\"STRUCTURED_SECRET_SENTINEL\"}}'");
    let error = WorkerClient::new(&script.0)
        .infer(
            &ModelConfig::default(),
            structured_request(OutputMode::Json),
            &script.limits(),
        )
        .unwrap_err();
    assert_eq!(error.code(), "invalid_output");
    assert!(!error.to_string().contains("STRUCTURED_SECRET_SENTINEL"));
}
