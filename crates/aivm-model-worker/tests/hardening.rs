//! ขอบเขตใหม่ต้องทดสอบด้วย worker/control process จริงและ error ที่ไม่เปิดเผย prompt
use aivm_model::{worker::*, LocalModelConfig, ModelConfig};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

mod support;
use support::TestResources;

struct Fixture {
    root: PathBuf,
    config: ModelConfig,
    resources: TestResources,
}
impl Fixture {
    fn new(script: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let resources = TestResources::new();
        let root = resources.root().to_path_buf();
        let worker = root.join("worker");
        std::fs::write(&worker, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let controller = env!("CARGO_BIN_EXE_aivm-model-worker");
        let pin = format!("{:x}", Sha256::digest(std::fs::read(controller).unwrap()));
        let config = ModelConfig {
            local: Some(LocalModelConfig {
                worker_path: Some(worker.to_string_lossy().into()),
                controller_path: Some(controller.into()),
                controller_sha256: Some(pin),
                ..Default::default()
            }),
            ..Default::default()
        };
        Self {
            root,
            config,
            resources,
        }
    }
    fn limits(&self, total: u64) -> InferenceLimits {
        InferenceLimits {
            total_timeout_ms: Some(total),
            ..self.resources.limits()
        }
    }
    fn client(&self) -> WorkerClient {
        WorkerClient::from_config(&self.config).unwrap()
    }
}
fn request() -> InferenceRequest {
    InferenceRequest {
        protocol_version: 1,
        output_mode: Default::default(),
        request_id: "req-1".into(),
        model_id: "echo".into(),
        prompt: "PROMPT_SECRET_SENTINEL".into(),
        stream: true,
        max_output_tokens: 16,
        timeout_ms: 2000,
    }
}
const RESPONSE: &str = r#"{"protocol_version":1,"request_id":"req-1","output":"ok","usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},"termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null}"#;

#[test]
fn controller_preserves_the_worker_exit_status() {
    // controller ที่มี pin ต้องส่งต่อสถานะจาก kernel แยกจาก error text ของ worker
    let fixture = Fixture::new("read request\nexit 73");
    let error = fixture
        .client()
        .infer(&fixture.config, request(), &fixture.limits(2000))
        .unwrap_err();
    assert_eq!(error.code(), "worker_failed", "{error}");
    assert!(error.to_string().contains("exit_code=73"), "{error}");
    let exit = error.worker_exit().unwrap();
    assert_eq!(exit.exit_code, Some(73));
    assert!(exit.observed_before_cleanup);
}

#[test]
fn cleanup_failure_keeps_the_original_worker_exit_evidence() {
    use std::os::unix::fs::PermissionsExt;
    // primary failure และ wait status ต้องยังอยู่เมื่อ staging cleanup ล้มตามหลัง
    let fixture = Fixture::new(
        r#"read request
printf '{"protocol_version":1,"request_id":"req-1","delta":"%s"}\n' "$2"
exit 73"#,
    );
    let local = fixture.config.local.as_ref().unwrap();
    let client = WorkerClient::new(local.worker_path.as_ref().unwrap());
    let mut config = fixture.config.clone();
    config.local.as_mut().unwrap().controller_path = None;
    config.local.as_mut().unwrap().controller_sha256 = None;
    let mut directory = None;
    let error = client
        .infer_stream(
            &config,
            request(),
            &fixture.limits(2000),
            &mut |config_path| {
                let path = std::path::Path::new(config_path)
                    .parent()
                    .unwrap()
                    .to_path_buf();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
                directory = Some(path);
                Ok(())
            },
        )
        .unwrap_err();
    let path = directory.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(path).unwrap();
    assert_eq!(error.code(), "cleanup_failed", "{error}");
    assert!(matches!(
        error.cause(),
        WorkerError::CleanupAfterFailure { .. }
    ));
    let exit = error.worker_exit().unwrap();
    assert_eq!(exit.exit_code, Some(73));
    assert!(exit.observed_before_cleanup);
}

#[test]
fn event_api_streams_and_completes_through_the_pinned_controller() {
    let fixture=Fixture::new(&format!("read request\nprintf '%s\\n' '{{\"protocol_version\":1,\"request_id\":\"req-1\",\"delta\":\"ok\"}}' '{RESPONSE}'"));
    let client = fixture.client();
    let mut job = client
        .start(&fixture.config, request(), &fixture.limits(2000))
        .unwrap();
    assert!(
        matches!(job.next_event().unwrap(),supervised::WorkerEvent::Delta { text,.. } if text=="ok")
    );
    assert!(
        matches!(job.next_event().unwrap(),supervised::WorkerEvent::Complete { response } if response.output.as_deref()==Some("ok"))
    );
}

#[test]
fn controller_reuses_a_single_slot_fixture_quota_after_completion() {
    // controller ต้องคืน lease ก่อนตอบสำเร็จ เพื่อให้คำขอถัดไปใช้ slot เดิมได้แม้พื้นที่ host น้อย
    let fixture = Fixture::new(&format!("read request\nprintf '%s\\n' '{RESPONSE}'"));
    let client = fixture.client();
    let mut limits = fixture.limits(2000);
    limits.host_resources.max_requests = 1;
    let mut req = request();
    req.stream = false;
    for _ in 0..2 {
        let response = client.infer(&fixture.config, req.clone(), &limits).unwrap();
        assert_eq!(response.output.as_deref(), Some("ok"));
    }
}

#[test]
fn total_deadline_bounds_a_controller_blocked_in_preparation() {
    // pinned controller จำลอง helper/setup ที่ไม่คืนการควบคุมและไม่อ่าน stdin
    use std::os::unix::fs::PermissionsExt;
    let mut fixture = Fixture::new("exec /bin/sleep 30");
    let controller = fixture.root.join("stuck-controller");
    let bytes = b"#!/bin/sh\nexec /bin/sleep 30\n";
    std::fs::write(&controller, bytes).unwrap();
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700)).unwrap();
    let local = fixture.config.local.as_mut().unwrap();
    local.controller_path = Some(controller.to_string_lossy().into());
    local.controller_sha256 = Some(format!("{:x}", Sha256::digest(bytes)));
    let client = fixture.client();
    let started = Instant::now();
    let mut job = client
        .start(&fixture.config, request(), &fixture.limits(150))
        .unwrap();
    let error = job.next_event().unwrap_err();
    assert_eq!(error.code(), "deadline", "{error}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(job.wait_for_cleanup(Duration::from_secs(3)).unwrap());
}

#[test]
fn watchdog_kills_worker_while_the_legacy_callback_is_blocked() {
    let fixture=Fixture::new("read request\nprintf '%s\\n' '{\"protocol_version\":1,\"request_id\":\"req-1\",\"delta\":\"ok\"}'\nexec /bin/sleep 30");
    let client = fixture.client();
    let started = Instant::now();
    let error = client
        .infer_stream(
            &fixture.config,
            request(),
            &fixture.limits(200),
            &mut |_| {
                std::thread::sleep(Duration::from_millis(350));
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), "deadline", "{error}");
    assert!(started.elapsed() < Duration::from_secs(1));
    // callback ที่ค้างยังขวาง caller ได้ แต่ watchdog ไม่ต้องรอมันเพื่อหยุด worker
}

#[test]
fn typed_remote_errors_and_stderr_do_not_disclose_request_data() {
    let mut fixture=Fixture::new("read request\nprintf '%s\\n' 'PROMPT_SECRET_SENTINEL' >&2\nprintf '%s\\n' '{\"protocol_version\":1,\"request_id\":\"req-1\",\"error\":\"PROMPT_SECRET_SENTINEL\",\"error_kind\":{\"LimitExceeded\":\"PROMPT_SECRET_SENTINEL\"}}'");
    let local = fixture.config.local.as_mut().unwrap();
    local.controller_path = None;
    local.controller_sha256 = None;
    let error = WorkerClient::new(local.worker_path.clone().unwrap())
        .infer_stream(
            &fixture.config,
            request(),
            &fixture.limits(1000),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(!error.to_string().contains("PROMPT_SECRET_SENTINEL"));
    assert!(matches!(error.cause(), WorkerError::LimitExceeded(_)));
}

#[test]
fn slow_event_consumer_is_bounded_and_receives_the_failure_reason() {
    // terminal channel แยกจาก delta queue: queue เต็มต้องไม่ทำ error หายไปด้วย
    let fixture=Fixture::new("read request\ni=0\nwhile [ $i -lt 64 ]; do printf '%s\\n' '{\"protocol_version\":1,\"request_id\":\"req-1\",\"delta\":\"ok\"}'; i=$((i+1)); done\nexec /bin/sleep 30");
    let client = fixture.client();
    let mut job = client
        .start(&fixture.config, request(), &fixture.limits(2000))
        .unwrap();
    assert!(job.wait_for_cleanup(Duration::from_secs(3)).unwrap());
    let error = job.next_event().unwrap_err();
    assert_eq!(error.code(), "resources_unavailable", "{error}");
}

#[test]
fn successful_response_cannot_hide_a_cleanup_failure() {
    // จำลอง worker เปลี่ยนสิทธิ์ staging จน parent ลบไม่ได้: completion ต้องไม่ถูกปล่อยว่าผ่าน
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(
        r#"read request
printf '{"protocol_version":1,"request_id":"req-1","delta":"%s"}\n' "$2"
printf '{"protocol_version":1,"request_id":"req-1","output":"%s","usage":{"input_tokens":1,"output_tokens":1,"elapsed_ms":0},"termination":"completed","artifact_verified":false,"applied_limits":[],"audit_id":null}\n' "$2"
"#,
    );
    let mut config = fixture.config.clone();
    let local = config.local.as_mut().unwrap();
    local.controller_path = None;
    local.controller_sha256 = None;
    let client = WorkerClient::new(local.worker_path.clone().unwrap());
    let mut directory = None;
    let error = client
        .infer_stream(
            &config,
            request(),
            &fixture.limits(2000),
            &mut |config_path| {
                let path = std::path::Path::new(config_path)
                    .parent()
                    .unwrap()
                    .to_path_buf();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
                directory = Some(path);
                Ok(())
            },
        )
        .unwrap_err();
    let path = directory.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(path).unwrap();
    assert_eq!(error.code(), "cleanup_failed", "{error}");
    assert!(matches!(error.cause(), WorkerError::Cleanup(_)));
}

#[test]
fn controller_preserves_operator_tool_path_without_inheriting_the_full_environment() {
    use std::os::unix::fs::PermissionsExt;
    let mut fixture = Fixture::new("exit 1");
    let controller = fixture.root.join("path-controller");
    let expected = serde_json::to_string(&std::env::var("PATH").unwrap()).unwrap();
    let script=format!("#!/usr/bin/python3\nimport os,sys,json\nassert os.environ.get('PATH') == {expected}\nassert set(os.environ) <= {{'PATH','TMPDIR','LC_CTYPE'}}\nprint(json.dumps({{'event':'complete','response':json.loads('{RESPONSE}')}}))\n");
    std::fs::write(&controller, &script).unwrap();
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700)).unwrap();
    let local = fixture.config.local.as_mut().unwrap();
    local.controller_path = Some(controller.to_string_lossy().into());
    local.controller_sha256 = Some(format!("{:x}", Sha256::digest(script.as_bytes())));
    let client = fixture.client();
    let mut req = request();
    req.stream = false;
    let mut job = client
        .start(&fixture.config, req, &fixture.limits(2000))
        .unwrap();
    assert!(
        matches!(job.next_event().unwrap(),supervised::WorkerEvent::Complete {response} if response.output.as_deref()==Some("ok"))
    );
}

#[test]
#[ignore = "requires host Linux user/network namespaces"]
fn sealed_worker_executes_after_entering_a_user_namespace() {
    // reproduction ของ host regression: child ต้องใช้ /proc/self/fd ไม่ใช่ descriptor ของ parent
    let mut fixture = Fixture::new("exit 1");
    let local = fixture.config.local.as_mut().unwrap();
    local.worker_path = local.controller_path.clone();
    local.worker_sha256 = local.controller_sha256.clone();
    local.worker_launcher = WorkerLauncher::ProcessNamespace;
    let client = fixture.client();
    let mut req = request();
    req.stream = false;
    let response = client
        .infer(&fixture.config, req, &fixture.limits(10000))
        .unwrap();
    assert!(response
        .output
        .as_deref()
        .unwrap()
        .contains("PROMPT_SECRET_SENTINEL"));
    assert!(response
        .applied_limits
        .iter()
        .any(|item| item == "network-namespace"));
}

#[test]
#[ignore = "requires host Linux user/network namespaces"]
fn sealed_model_cache_descriptor_survives_controller_and_namespace_exec() {
    use std::os::unix::fs::PermissionsExt;
    let mut fixture = Fixture::new("exit 1");
    let worker = fixture.root.join("cache-reader");
    let script = r#"#!/usr/bin/python3
import json,sys,fcntl
cfg=json.load(open(sys.argv[2]))
request=json.loads(sys.stdin.readline())
with open(cfg['local']['model_path'],'rb') as model:
    seals=fcntl.fcntl(model.fileno(),fcntl.F_GET_SEALS)
    assert seals & fcntl.F_SEAL_WRITE
    output=model.read().decode()
print(json.dumps({'protocol_version':1,'request_id':request['request_id'],'output':output,'usage':{'input_tokens':1,'output_tokens':2,'elapsed_ms':0},'termination':'completed','artifact_verified':False,'applied_limits':[],'audit_id':None}))
"#;
    std::fs::write(&worker, script).unwrap();
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
    let model = fixture.root.join("weights");
    std::fs::write(&model, b"approved model").unwrap();
    let local = fixture.config.local.as_mut().unwrap();
    local.worker_path = Some(worker.to_string_lossy().into());
    local.model_path = model.to_string_lossy().into();
    local.model_sha256 = format!("{:x}", Sha256::digest(b"approved model"));
    local.worker_launcher = WorkerLauncher::ProcessNamespace;
    let mut limits = fixture.limits(10000);
    limits.host_resources.cache_mb = 1;
    fixture.config.worker_limits = Some(limits.clone());
    let client = fixture.client();
    std::fs::write(model, b"changed source").unwrap();
    let mut req = request();
    req.stream = false;
    let response = client.infer(&fixture.config, req, &limits).unwrap();
    assert_eq!(response.output.as_deref(), Some("approved model"));
}

#[test]
fn process_tier_worker_spawns_threads_under_default_pids_max() {
    // tier process ต้องแยกตัวนับ RLIMIT_NPROC ด้วย userns best-effort เพื่อไม่ให้เธรดของ host UID ขวาง pids_max=64
    let fixture = Fixture::new(&format!(
        "read request\n( : ) &\nwait\nprintf '%s\\n' '{RESPONSE}'"
    ));
    let mut limits = fixture.limits(2000);
    limits.pids_max = 64;
    let mut req = request();
    req.stream = false;
    let response = fixture
        .client()
        .infer(&fixture.config, req, &limits)
        .unwrap();
    assert_eq!(response.output.as_deref(), Some("ok"));
}
