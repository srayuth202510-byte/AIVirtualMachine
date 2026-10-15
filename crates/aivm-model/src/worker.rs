//! Typed protocol shared by the control plane and inference workers.
//!
//! The protocol is transport agnostic. A worker launcher can use pipes, a
//! Unix socket, a container attach, or a MicroVM channel without changing the
//! request validation and response shape.

use super::ModelConfig;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

mod launcher;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PROMPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerLauncher {
    #[default]
    Process,
    ProcessNamespace,
    Container {
        config: aivm_sandbox::container::ContainerConfig,
    },
    #[cfg(feature = "microvm")]
    Microvm {
        config: Box<aivm_sandbox::microvm::MicroVmConfig>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceLimits {
    pub max_context_tokens: usize,
    pub max_output_tokens: usize,
    pub timeout_ms: u64,
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    #[serde(default = "default_cpu_seconds")]
    pub cpu_seconds: u64,
    #[serde(default = "default_pids_max")]
    pub pids_max: u64,
    #[serde(default = "default_storage_mb")]
    pub storage_mb: u64,
}

fn default_storage_mb() -> u64 {
    5120
}

fn default_memory_mb() -> u64 {
    4096
}

fn default_cpu_seconds() -> u64 {
    120
}

fn default_pids_max() -> u64 {
    64
}

impl Default for InferenceLimits {
    fn default() -> Self {
        Self {
            max_context_tokens: 8192,
            max_output_tokens: 2048,
            timeout_ms: 120_000,
            memory_mb: default_memory_mb(),
            cpu_seconds: default_cpu_seconds(),
            pids_max: default_pids_max(),
            storage_mb: default_storage_mb(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub model_id: String,
    pub prompt: String,
    #[serde(default)]
    pub stream: bool,
    pub max_output_tokens: usize,
    pub timeout_ms: u64,
}

impl InferenceRequest {
    pub fn validate(
        &self,
        limits: &InferenceLimits,
        token_count: usize,
    ) -> Result<(), WorkerError> {
        if limits.memory_mb == 0 || limits.cpu_seconds == 0 || limits.pids_max == 0 {
            return Err(WorkerError::InvalidRequest(
                "resource limits must be positive".into(),
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WorkerError::Protocol(format!(
                "unsupported protocol version {}",
                self.protocol_version
            )));
        }
        if self.request_id.is_empty() || self.request_id.len() > MAX_REQUEST_ID_BYTES {
            return Err(WorkerError::InvalidRequest(
                "request_id length is invalid".into(),
            ));
        }
        if self.model_id.is_empty() {
            return Err(WorkerError::InvalidRequest("model_id is required".into()));
        }
        if self.prompt.len() > MAX_PROMPT_BYTES {
            return Err(WorkerError::LimitExceeded("prompt bytes".into()));
        }
        if token_count > limits.max_context_tokens {
            return Err(WorkerError::LimitExceeded("context tokens".into()));
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > limits.max_output_tokens {
            return Err(WorkerError::LimitExceeded("output tokens".into()));
        }
        if self.timeout_ms == 0 || self.timeout_ms > limits.timeout_ms {
            return Err(WorkerError::LimitExceeded("timeout".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceUsage {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub output: Option<String>,
    pub usage: InferenceUsage,
    pub termination: String,
    pub artifact_verified: bool,
    pub applied_limits: Vec<String>,
    pub audit_id: Option<String>,
    #[serde(default)]
    pub verification: InferenceVerification,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceVerification {
    pub status: VerificationStatus,
    pub checks: Vec<String>,
    pub output_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    #[default]
    Unverified,
}

impl InferenceResponse {
    pub fn validate(&self, request: &InferenceRequest) -> Result<(), WorkerError> {
        if self.protocol_version != PROTOCOL_VERSION || self.request_id != request.request_id {
            return Err(WorkerError::Protocol("response identity mismatch".into()));
        }
        if !matches!(self.termination.as_str(), "completed" | "length") || self.output.is_none() {
            return Err(WorkerError::Protocol("invalid completion".into()));
        }
        if self
            .output
            .as_ref()
            .is_some_and(|output| output.len() > MAX_RESPONSE_BYTES)
            || self.usage.output_tokens > request.max_output_tokens
            || self.usage.elapsed_ms > request.timeout_ms
        {
            return Err(WorkerError::LimitExceeded(
                "response exceeds request limits".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum WorkerError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid inference request: {0}")]
    InvalidRequest(String),
    #[error("inference limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("worker failed: {0}")]
    Failed(String),
}

/// Control-plane client for the standalone worker executable.
///
/// The client owns the worker lifetime for one request. This keeps a crashed
/// or wedged model from becoming a long-lived part of the supervisor process.
pub struct WorkerClient {
    pub executable: PathBuf,
    cancelled: Arc<AtomicBool>,
}

impl WorkerClient {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Clone this token into another thread to cancel an active inference.
    pub fn cancellation_token(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }

    pub fn infer(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
    ) -> Result<InferenceResponse, WorkerError> {
        self.infer_controlled(config, request, limits, &mut |_| Ok(()))
    }

    pub fn infer_stream(
        &self,
        config: &ModelConfig,
        mut request: InferenceRequest,
        limits: &InferenceLimits,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
    ) -> Result<InferenceResponse, WorkerError> {
        request.stream = true;
        self.infer_controlled(config, request, limits, on_delta)
    }

    fn infer_controlled(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
    ) -> Result<InferenceResponse, WorkerError> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(WorkerError::Failed("inference cancelled".into()));
        }
        let token_count = request.prompt.split_whitespace().count();
        request.validate(limits, token_count)?;
        if let Some(local) = config.local.as_ref() {
            if let Some(expected) = local.worker_sha256.as_deref() {
                let path = self
                    .executable
                    .to_str()
                    .ok_or_else(|| WorkerError::Failed("worker path is not UTF-8".into()))?;
                crate::verify_model_file(path, expected)
                    .map_err(|e| WorkerError::Failed(format!("worker verification failed: {e}")))?;
            }
        }
        let mut effective_config = config.clone();
        effective_config.worker_limits = Some(limits.clone());
        let config = &effective_config;
        let config_path = write_ephemeral_config(config)?;
        let launcher = config.local.as_ref().map(|local| &local.worker_launcher);
        let result = match launcher {
            Some(WorkerLauncher::Container { .. }) => {
                self.infer_sandboxed(config, &config_path, &request, limits, on_delta)
            }
            #[cfg(feature = "microvm")]
            Some(WorkerLauncher::Microvm { .. }) => {
                self.infer_sandboxed(config, &config_path, &request, limits, on_delta)
            }
            _ => self.infer_with_config(
                &config_path,
                request.clone(),
                limits,
                matches!(launcher, Some(WorkerLauncher::ProcessNamespace)),
                on_delta,
            ),
        }
        .and_then(|mut response| {
            response.validate(&request)?;
            if matches!(launcher, Some(WorkerLauncher::ProcessNamespace)) {
                response.applied_limits.push("network-namespace".into());
            }
            if let Some(local) = config.local.as_ref() {
                if config.provider == "local"
                    && !local.model_sha256.is_empty()
                    && !response.artifact_verified
                {
                    return Err(WorkerError::Protocol(
                        "worker did not verify pinned model".into(),
                    ));
                }
            }
            use sha2::{Digest, Sha256};
            let pinned = config.local.as_ref().is_some_and(|local| {
                !local.model_sha256.is_empty()
                    && local
                        .worker_sha256
                        .as_ref()
                        .is_some_and(|hash| !hash.is_empty())
            });
            response.verification = InferenceVerification {
                status: if pinned && response.artifact_verified {
                    VerificationStatus::Verified
                } else {
                    VerificationStatus::Unverified
                },
                checks: vec![
                    "protocol-version".into(),
                    "request-id".into(),
                    "termination".into(),
                    "output-budget".into(),
                    "worker-exit".into(),
                ],
                output_sha256: response
                    .output
                    .as_ref()
                    .map(|text| format!("{:x}", Sha256::digest(text.as_bytes()))),
            };
            Ok(response)
        });
        let _ = std::fs::remove_dir_all(config_path.parent().unwrap());
        result
    }

    fn infer_with_config(
        &self,
        config_path: &Path,
        request: InferenceRequest,
        limits: &InferenceLimits,
        network_namespace: bool,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
    ) -> Result<InferenceResponse, WorkerError> {
        let mut command = Command::new(&self.executable);
        command
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let memory_bytes = limits
                .memory_mb
                .checked_mul(1024 * 1024)
                .ok_or_else(|| WorkerError::LimitExceeded("memory bytes overflow".into()))?;
            let parent_pid = unsafe { libc::getpid() };
            let cpu_seconds = limits.cpu_seconds;
            let pids_max = limits.pids_max;
            unsafe {
                command.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if network_namespace {
                        aivm_sandbox::enter_worker_network_namespace()?;
                    }
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    set_limit(libc::RLIMIT_CPU, cpu_seconds, cpu_seconds)?;
                    set_limit(libc::RLIMIT_AS, memory_bytes, memory_bytes)?;
                    set_limit(libc::RLIMIT_NPROC, pids_max, pids_max)?;
                    Ok(())
                });
            }
        }
        let child = command
            .spawn()
            .map_err(|e| WorkerError::Failed(format!("spawn worker: {e}")))?;
        let mut child = ChildGuard {
            child,
            terminated: false,
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerError::Failed("worker stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerError::Failed("worker stdout unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| WorkerError::Failed("worker stderr unavailable".into()))?;
        let payload =
            serde_json::to_vec(&request).map_err(|e| WorkerError::Protocol(e.to_string()))?;
        // Write concurrently so a worker that never reads stdin cannot block the deadline.
        std::thread::spawn(move || {
            let mut stdin = stdin;
            let _ = stdin
                .write_all(&payload)
                .and_then(|_| stdin.write_all(b"\n"));
        });
        let stderr_reader = std::thread::spawn(move || {
            let mut tail = Vec::new();
            let mut reader = BufReader::new(stderr);
            let mut buffer = [0; 4096];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                tail.extend_from_slice(&buffer[..n]);
                if tail.len() > 16384 {
                    tail.drain(..tail.len() - 16384);
                }
            }
            String::from_utf8_lossy(&tail).into_owned()
        });
        let (sender, receiver) = mpsc::sync_channel(8);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut total = 0usize;
            loop {
                let mut line = String::new();
                let result = reader
                    .by_ref()
                    .take((MAX_RESPONSE_BYTES + 1) as u64)
                    .read_line(&mut line)
                    .map_err(|e| WorkerError::Failed(format!("read worker response: {e}")))
                    .and_then(|n| {
                        total = total.saturating_add(n);
                        if n == 0 {
                            return Err(WorkerError::Failed("worker returned no response".into()));
                        }
                        if total > MAX_RESPONSE_BYTES {
                            return Err(WorkerError::LimitExceeded("response bytes".into()));
                        }
                        serde_json::from_str::<serde_json::Value>(&line)
                            .map_err(|e| WorkerError::Protocol(e.to_string()))
                    });
                let done = result
                    .as_ref()
                    .map_or(true, |value| value.get("delta").is_none());
                if sender.send(result).is_err() || done {
                    break;
                }
            }
        });
        let deadline =
            Instant::now() + Duration::from_millis(request.timeout_ms.min(limits.timeout_ms));
        let mut streamed = String::new();
        let response_result: Result<InferenceResponse, WorkerError> = (|| loop {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(WorkerError::Failed("inference cancelled".into()));
            }
            if Instant::now() >= deadline {
                return Err(WorkerError::Failed("worker deadline exceeded".into()));
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(value) => {
                    let value = value?;
                    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
                        return Err(WorkerError::Failed(error.into()));
                    }
                    if value.get("request_id").and_then(serde_json::Value::as_str)
                        != Some(request.request_id.as_str())
                        || value
                            .get("protocol_version")
                            .and_then(serde_json::Value::as_u64)
                            != Some(u64::from(PROTOCOL_VERSION))
                    {
                        return Err(WorkerError::Protocol("response identity mismatch".into()));
                    }
                    if let Some(delta) = value.get("delta").and_then(serde_json::Value::as_str) {
                        if !request.stream {
                            return Err(WorkerError::Protocol("unexpected stream event".into()));
                        }
                        streamed.push_str(delta);
                        on_delta(delta)?;
                        continue;
                    }
                    let response: InferenceResponse = serde_json::from_value(value)
                        .map_err(|e| WorkerError::Protocol(e.to_string()))?;
                    response.validate(&request)?;
                    if request.stream && response.output.as_deref() != Some(streamed.as_str()) {
                        return Err(WorkerError::Protocol(
                            "stream differs from final output".into(),
                        ));
                    }
                    break Ok(response);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => return Err(WorkerError::Failed("worker response channel closed".into())),
            }
        })();
        let response = match response_result {
            Ok(response) => response,
            Err(error) => {
                child.terminate();
                let detail = stderr_reader.join().unwrap_or_default();
                return Err(WorkerError::Failed(format!("{error}; {detail}")));
            }
        };
        let status = loop {
            if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(WorkerError::Failed(
                    "worker cancelled or exit deadline exceeded".into(),
                ));
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| WorkerError::Failed(e.to_string()))?
            {
                break status;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // A descendant cannot hold the response or diagnostics pipe open after exit.
        child.terminate();
        let detail = stderr_reader.join().unwrap_or_default();
        if !status.success() {
            return Err(WorkerError::Failed(format!(
                "worker exited with {status}: {detail}"
            )));
        }
        Ok(response)
    }
}

fn consume_delta(
    line: &str,
    request: &InferenceRequest,
    streamed: &mut String,
    on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
) -> Result<(), WorkerError> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| WorkerError::Protocol(e.to_string()))?;
    if value.get("request_id").and_then(serde_json::Value::as_str)
        != Some(request.request_id.as_str())
        || value
            .get("protocol_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(PROTOCOL_VERSION))
    {
        return Err(WorkerError::Protocol("stream identity mismatch".into()));
    }
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        return Err(WorkerError::Failed(error.into()));
    }
    if let Some(delta) = value.get("delta").and_then(serde_json::Value::as_str) {
        streamed.push_str(delta);
        on_delta(delta)?;
    }
    Ok(())
}

struct ChildGuard {
    child: std::process::Child,
    terminated: bool,
}
impl std::ops::Deref for ChildGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl ChildGuard {
    fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(unix)]
fn set_limit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_ephemeral_config(config: &ModelConfig) -> Result<PathBuf, WorkerError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| WorkerError::Failed(format!("clock: {e}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aivm-model-{}-{nonce}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| WorkerError::Failed(format!("private directory: {e}")))?;
    }
    let path = dir.join("config.json");
    let bytes = serde_json::to_vec(config)
        .map_err(|e| WorkerError::Failed(format!("encode model config: {e}")))?;
    write_private(&path, &bytes)?;
    Ok(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WorkerError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| WorkerError::Failed(format!("private file: {e}")))?;
    file.write_all(bytes)
        .map_err(|e| WorkerError::Failed(format!("write private file: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalModelConfig;

    fn request() -> InferenceRequest {
        InferenceRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: "req-1".into(),
            model_id: "model-1".into(),
            prompt: "hello".into(),
            stream: false,
            max_output_tokens: 16,
            timeout_ms: 1_000,
        }
    }

    #[test]
    fn request_accepts_values_within_limits() {
        let limits = InferenceLimits {
            max_context_tokens: 32,
            max_output_tokens: 32,
            timeout_ms: 2_000,
            ..InferenceLimits::default()
        };
        assert!(request().validate(&limits, 4).is_ok());
    }

    #[test]
    fn request_rejects_limits_and_protocol_mismatch() {
        let limits = InferenceLimits::default();
        let mut oversized = request();
        oversized.max_output_tokens = limits.max_output_tokens + 1;
        assert!(matches!(
            oversized.validate(&limits, 1),
            Err(WorkerError::LimitExceeded(_))
        ));

        let mut incompatible = request();
        incompatible.protocol_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            incompatible.validate(&limits, 1),
            Err(WorkerError::Protocol(_))
        ));
    }

    /// container launcher ต้อง fail-closed ตอน prerequisite ไม่พร้อม:
    /// ปฏิเสธก่อน staging/exec ไม่ fallback ไป Process path
    #[cfg(unix)]
    #[test]
    fn container_launcher_rejects_without_prerequisites() {
        use aivm_sandbox::container::ContainerConfig;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "aivm-worker-container-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("executed");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntouch {}\nread request\nprintf '%s\\n' '{{\"protocol_version\":1,\"request_id\":\"req-1\",\"output\":\"x\",\"usage\":{{\"input_tokens\":1,\"output_tokens\":1,\"elapsed_ms\":0}},\"termination\":\"completed\",\"artifact_verified\":true,\"applied_limits\":[],\"audit_id\":null}}'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let local = LocalModelConfig {
            worker_path: Some(script.to_string_lossy().into_owned()),
            worker_launcher: WorkerLauncher::Container {
                config: ContainerConfig {
                    bubblewrap: dir.join("no-bwrap"),
                    init: dir.join("no-init"),
                    cgroup_root: dir.join("no-cgroup"),
                },
            },
            ..Default::default()
        };
        let config = ModelConfig {
            provider: "local".into(),
            name: "worker-container".into(),
            local: Some(local),
            ..Default::default()
        };
        let client = WorkerClient::new(&script);
        let error = client
            .infer(&config, request(), &InferenceLimits::default())
            .unwrap_err();
        assert!(
            error.to_string().contains("container prerequisites"),
            "must reject on missing prerequisites: {error}"
        );
        assert!(!marker.exists(), "payload must never execute");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// container path ที่ prerequisite เต็มแต่ไม่มี backend จริงอยู่ต้องปฏิเสธ
    /// (ไม่มี silent fallback ไป Process) — ใช้ bwrap path แบบไม่มีสิทธิ์
    #[cfg(unix)]
    #[test]
    fn container_launcher_never_falls_back_to_process() {
        use aivm_sandbox::container::ContainerConfig;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "aivm-worker-fallback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("executed");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntouch {}\nread request\nprintf '%s\\n' '{{\"protocol_version\":1,\"request_id\":\"req-1\",\"output\":\"x\",\"usage\":{{\"input_tokens\":1,\"output_tokens\":1,\"elapsed_ms\":0}},\"termination\":\"completed\",\"artifact_verified\":true,\"applied_limits\":[],\"audit_id\":null}}'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let local = LocalModelConfig {
            worker_path: Some(script.to_string_lossy().into_owned()),
            worker_launcher: WorkerLauncher::Container {
                // bwrap ไม่มีสิทธิ์ (ไม่ผ่าน trusted_executable) → probe ตก
                config: ContainerConfig::default(),
            },
            ..Default::default()
        };
        let config = ModelConfig {
            provider: "local".into(),
            name: "worker-fallback".into(),
            local: Some(local),
            ..Default::default()
        };
        let client = WorkerClient::new(&script);
        assert!(
            client
                .infer(&config, request(), &InferenceLimits::default())
                .is_err(),
            "container launcher must not fall back to process execution"
        );
        assert!(!marker.exists(), "payload must never execute");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
