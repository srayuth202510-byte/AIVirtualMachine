//! Typed protocol shared by the control plane and inference workers.
//!
//! The protocol is transport agnostic. A worker launcher can use pipes, a
//! Unix socket, a container attach, or a MicroVM channel without changing the
//! request validation and response shape.

use super::ModelConfig;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
#[cfg(test)]
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant};
use thiserror::Error;

mod cache;
mod control;
mod launcher;
mod resources;
mod staging;
pub use resources::HostResources;
pub mod supervised;
use control::{RequestControl, StagedConfig};

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
    /// งบเวลารวมตั้งแต่ control plane เริ่มเตรียม request; None ใช้ timeout ราย worker ตามเดิม
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_timeout_ms: Option<u64>,
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    #[serde(default = "default_cpu_seconds")]
    pub cpu_seconds: u64,
    #[serde(default = "default_pids_max")]
    pub pids_max: u64,
    #[serde(default = "default_storage_mb")]
    pub storage_mb: u64,
    /// โควตารวมของ operator สำหรับทุก process ที่ใช้ root เดียวกัน
    #[serde(default)]
    pub host_resources: HostResources,
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
            total_timeout_ms: None,
            memory_mb: default_memory_mb(),
            cpu_seconds: default_cpu_seconds(),
            pids_max: default_pids_max(),
            storage_mb: default_storage_mb(),
            host_resources: HostResources::default(),
        }
    }
}

#[cfg(test)]
impl InferenceLimits {
    // fixture ใช้ shell/ไฟล์เล็ก จึงไม่จองทรัพยากรเท่าโมเดลจริงหรือใช้ quota ร่วมกับ operator
    pub(crate) fn test_fixture(root: PathBuf) -> Self {
        Self {
            memory_mb: 64,
            storage_mb: 1,
            host_resources: HostResources {
                root,
                max_requests: 2,
                memory_mb: 128,
                storage_mb: 16,
                queue_timeout_ms: 1_000,
                cache_mb: 0,
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub model_id: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "crate::OutputMode::is_text")]
    pub output_mode: crate::OutputMode,
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
        if limits.total_timeout_ms == Some(0) {
            return Err(WorkerError::InvalidRequest(
                "total timeout must be positive".into(),
            ));
        }
        if self.protocol_version != self.output_mode.protocol_version() {
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
    #[serde(default, skip_serializing_if = "crate::OutputMode::is_text")]
    pub output_mode: crate::OutputMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grammar_id: Option<String>,
    pub usage: InferenceUsage,
    pub termination: String,
    pub artifact_verified: bool,
    pub applied_limits: Vec<String>,
    pub audit_id: Option<String>,
    #[serde(default)]
    pub verification: InferenceVerification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_usage: Option<ControlPlaneUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneUsage {
    pub preparation_ms: u64,
    pub execution_ms: u64,
    pub cleanup_ms: u64,
    pub total_ms: u64,
}

impl std::fmt::Display for ControlPlaneUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "preparation_ms={}; execution_ms={}; cleanup_ms={}; total_ms={}",
            self.preparation_ms, self.execution_ms, self.cleanup_ms, self.total_ms
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceVerification {
    pub status: VerificationStatus,
    pub checks: Vec<String>,
    pub output_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Failed,
    #[default]
    Unverified,
}

impl InferenceResponse {
    pub fn validate(&self, request: &InferenceRequest) -> Result<(), WorkerError> {
        if self.protocol_version != request.protocol_version
            || self.request_id != request.request_id
        {
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
        self.validate_output(request)
    }

    fn validate_output(&self, request: &InferenceRequest) -> Result<(), WorkerError> {
        // worker เก่าหรือหลักฐานโหมดไม่ตรงต้องไม่ผ่านแม้ JSON บังเอิญถูกต้อง
        if self.output_mode != request.output_mode
            || self.grammar_id.as_deref() != request.output_mode.grammar_id()
        {
            return Err(WorkerError::Protocol(
                "output mode/grammar evidence mismatch".into(),
            ));
        }
        if !request.output_mode.is_text() && self.termination != "completed" {
            return Err(WorkerError::InvalidOutput(
                "incomplete structured output".into(),
            ));
        }
        request
            .output_mode
            .validate(self.output.as_deref().unwrap_or(""))
            .map_err(|e| WorkerError::InvalidOutput(e.to_string()))
    }

    /// ตรวจผล inference ทุกมิติ: output length, termination, usage, artifact
    /// คืน VerificationResult ที่ระบุสถานะ verified / failed / unverified
    pub fn verify(&self, request: &InferenceRequest, pinned: bool) -> VerificationResult {
        use sha2::{Digest, Sha256};
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        // 1. Output length
        match &self.output {
            Some(out) if out.len() <= MAX_RESPONSE_BYTES => {
                checks.push("output-length:ok".into());
            }
            Some(_) => {
                checks.push("output-length:exceeded".into());
                failures.push("output exceeds MAX_RESPONSE_BYTES".into());
            }
            None => {
                checks.push("output-length:missing".into());
                failures.push("output is missing".into());
            }
        }

        // 2. Termination reason
        match self.termination.as_str() {
            "completed" | "length" => {
                checks.push("termination:valid".into());
            }
            other => {
                checks.push(format!("termination:invalid:{other}"));
                failures.push("termination reason is not completed/length".into());
            }
        }

        // 3. Usage
        if self.usage.output_tokens <= request.max_output_tokens {
            checks.push("usage-output-tokens:ok".into());
        } else {
            checks.push("usage-output-tokens:exceeded".into());
            failures.push("output tokens exceed request limit".into());
        }
        if self.usage.elapsed_ms <= request.timeout_ms {
            checks.push("usage-elapsed-ms:ok".into());
        } else {
            checks.push("usage-elapsed-ms:exceeded".into());
            failures.push("elapsed time exceeds request timeout".into());
        }
        checks.push(format!("usage-input-tokens:{}", self.usage.input_tokens));

        // 4. Artifact evidence
        if self.artifact_verified {
            checks.push("artifact-evidence:verified".into());
        } else {
            checks.push("artifact-evidence:unverified".into());
            if pinned {
                failures.push("pinned model artifact not verified".into());
            }
        }

        // 5. Identity
        if self.protocol_version == request.protocol_version
            && self.request_id == request.request_id
        {
            checks.push("identity:match".into());
        } else {
            checks.push("identity:mismatch".into());
            failures.push("response identity mismatch".into());
        }

        if let Err(error) = self.validate_output(request) {
            failures.push(error.to_string());
            checks.push("output-schema:failed".into());
        } else {
            checks.push(format!("output-mode:{:?}", request.output_mode));
            if let Some(grammar) = request.output_mode.grammar_id() {
                checks.push(format!("output-schema:ok;grammar:{grammar}"));
            }
        }

        let status = if !failures.is_empty() {
            VerificationStatus::Failed
        } else if pinned && self.artifact_verified {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Unverified
        };

        VerificationResult {
            status,
            checks,
            failures,
            output_sha256: self
                .output
                .as_ref()
                .map(|text| format!("{:x}", Sha256::digest(text.as_bytes()))),
        }
    }
}

/// ผลการตรวจ inference ทุกมิติ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub checks: Vec<String>,
    pub failures: Vec<String>,
    pub output_sha256: Option<String>,
}

/// สถานะจาก wait ของ host; signal หลัง cleanup อาจเป็น SIGKILL ที่ client ส่งเอง
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerExit {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub core_dumped: bool,
    pub observed_before_cleanup: bool,
}

impl WorkerExit {
    fn from_status(status: ExitStatus, observed_before_cleanup: bool) -> Self {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        Self {
            exit_code: status.code(),
            #[cfg(unix)]
            signal: status.signal(),
            #[cfg(not(unix))]
            signal: None,
            #[cfg(unix)]
            core_dumped: status.core_dumped(),
            #[cfg(not(unix))]
            core_dumped: false,
            observed_before_cleanup,
        }
    }
}

impl std::fmt::Display for WorkerExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit_code={}; signal={}; core_dumped={}; observed_before_cleanup={}",
            self.exit_code
                .map_or_else(|| "none".into(), |code| code.to_string()),
            self.signal
                .map_or_else(|| "none".into(), |signal| signal.to_string()),
            self.core_dumped,
            self.observed_before_cleanup
        )
    }
}

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum WorkerError {
    #[error("invalid structured output: {0}")]
    InvalidOutput(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid inference request: {0}")]
    InvalidRequest(String),
    #[error("inference limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("worker failed: {0}")]
    Failed(String),
    #[error("inference deadline: {0}")]
    Deadline(String),
    #[error("inference cancelled: {0}")]
    Cancelled(String),
    #[error("staging cleanup failed: {0}")]
    Cleanup(String),
    #[error("staging cleanup failed: {cleanup}; previous failure: {source}")]
    CleanupAfterFailure {
        cleanup: String,
        source: Box<WorkerError>,
    },
    #[error("inference resources unavailable: {0}")]
    Resources(String),
    #[error("{source}; worker_exit: {exit}")]
    Exit {
        source: Box<WorkerError>,
        exit: WorkerExit,
    },
    #[error("{source}; phase={phase}; {usage}")]
    Context {
        source: Box<WorkerError>,
        phase: String,
        usage: ControlPlaneUsage,
    },
}

impl WorkerError {
    /// รหัสคงที่สำหรับ operator; ไม่ต้องแยกสาเหตุจากข้อความ stderr
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidOutput(_) => "invalid_output",
            Self::Protocol(_) => "protocol",
            Self::InvalidRequest(_) => "invalid_request",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Failed(_) => "worker_failed",
            Self::Deadline(_) => "deadline",
            Self::Cancelled(_) => "cancelled",
            Self::Cleanup(_) | Self::CleanupAfterFailure { .. } => "cleanup_failed",
            Self::Resources(_) => "resources_unavailable",
            Self::Context { source, .. } | Self::Exit { source, .. } => source.code(),
        }
    }

    pub fn cause(&self) -> &Self {
        match self {
            Self::Context { source, .. } | Self::Exit { source, .. } => source.cause(),
            _ => self,
        }
    }

    /// cleanup/context wrappers ต้องไม่ซ่อนหลักฐานการออกของ worker ที่เก็บไว้แล้ว
    pub fn worker_exit(&self) -> Option<&WorkerExit> {
        match self {
            Self::Exit { exit, .. } => Some(exit),
            Self::Context { source, .. } | Self::CleanupAfterFailure { source, .. } => {
                source.worker_exit()
            }
            _ => None,
        }
    }

    fn with_exit(self, exit: Option<WorkerExit>) -> Self {
        match exit {
            Some(exit) => Self::Exit {
                source: Box::new(self),
                exit,
            },
            None => self,
        }
    }
}

/// Control-plane client for the standalone worker executable.
///
/// The client owns the worker lifetime for one request. This keeps a crashed
/// or wedged model from becoming a long-lived part of the supervisor process.
pub struct WorkerClient {
    pub executable: PathBuf,
    cancelled: Arc<AtomicBool>,
    controller: Option<supervised::SupervisedClient>,
    cache: Option<Arc<cache::CachedModel>>,
}

struct RunContext<'a, 'b> {
    control: &'a RequestControl<'b>,
    image: &'a staging::WorkerImage,
    cache: Option<&'a cache::CachedModel>,
}

impl WorkerClient {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            cancelled: Arc::new(AtomicBool::new(false)),
            controller: None,
            cache: None,
        }
    }

    /// ตรวจ controller ตอน boot และเก็บ snapshot เดิมไว้ตลอดอายุ client
    pub fn from_config(config: &ModelConfig) -> Result<Self, WorkerError> {
        let local = config
            .local
            .as_ref()
            .ok_or_else(|| WorkerError::InvalidRequest("local config required".into()))?;
        let mut client = Self::new(
            local
                .worker_path
                .clone()
                .ok_or_else(|| WorkerError::InvalidRequest("worker_path required".into()))?,
        );
        match (&local.controller_path, &local.controller_sha256) {
            (Some(path), Some(pin)) => {
                let controller = supervised::SupervisedClient::new(Path::new(path), pin)?;
                client.cancelled = controller.cancellation_token();
                client.controller = Some(controller);
            }
            (None, None) => (),
            _ => {
                return Err(WorkerError::InvalidRequest(
                    "controller_path and controller_sha256 must be provided together".into(),
                ))
            }
        }
        client.cache = cache::CachedModel::prepare(config)?.map(Arc::new);
        if let Some(controller) = client.controller.as_mut() {
            controller.keep_cache(client.cache.clone())?;
        }
        Ok(client)
    }

    fn cached_config(&self, config: &ModelConfig) -> ModelConfig {
        let mut config = config.clone();
        if let Some(cache) = &self.cache {
            if let Some(local) = config.local.as_mut() {
                local.model_path = cache.child_path().to_string_lossy().into_owned();
            }
        }
        config
    }

    pub fn start(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
    ) -> Result<supervised::WorkerJob, WorkerError> {
        self.controller
            .as_ref()
            .ok_or_else(|| {
                WorkerError::InvalidRequest("event API requires a pinned controller".into())
            })?
            .start(&self.cached_config(config), request, limits)
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
        if request.output_mode.is_text() {
            return self.infer_controlled(config, request, limits, on_delta);
        }
        // กัก delta จากทุก launcher/controller จนตรวจ final schema และ cleanup เสร็จ
        let mut buffered = String::new();
        let response = self.infer_controlled(config, request, limits, &mut |delta| {
            if buffered.len().saturating_add(delta.len()) > MAX_RESPONSE_BYTES {
                return Err(WorkerError::LimitExceeded("structured stream bytes".into()));
            }
            buffered.push_str(delta);
            Ok(())
        })?;
        if response.output.as_deref() != Some(buffered.as_str()) {
            return Err(WorkerError::Protocol(
                "structured stream differs from final output".into(),
            ));
        }
        on_delta(&buffered)?;
        Ok(response)
    }

    fn infer_controlled(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
    ) -> Result<InferenceResponse, WorkerError> {
        let effective_config = self.cached_config(config);
        let config = &effective_config;
        if let Some(controller) = &self.controller {
            let mut job = controller.start(config, request, limits)?;
            loop {
                let event = match job.next_event() {
                    Ok(event) => event,
                    Err(error) => {
                        job.cancel();
                        if !job.wait_for_cleanup(Duration::from_secs(3))? {
                            return Err(WorkerError::CleanupAfterFailure {
                                cleanup: "controller cleanup still pending after grace period"
                                    .into(),
                                source: Box::new(error),
                            });
                        }
                        return Err(error);
                    }
                };
                match event {
                    supervised::WorkerEvent::Delta { text, .. } => {
                        if let Err(error) = on_delta(&text) {
                            job.cancel();
                            if !job.wait_for_cleanup(Duration::from_secs(3))? {
                                return Err(WorkerError::CleanupAfterFailure {
                                    cleanup: "callback cancellation cleanup pending".into(),
                                    source: Box::new(error),
                                });
                            }
                            return Err(error);
                        }
                    }
                    supervised::WorkerEvent::Complete { response } => return Ok(*response),
                    supervised::WorkerEvent::Error { error } => return Err(error),
                }
            }
        }
        if config
            .local
            .as_ref()
            .is_some_and(|local| local.controller_path.is_some())
        {
            return Err(WorkerError::InvalidRequest(
                "construct this client with WorkerClient::from_config".into(),
            ));
        }
        let control = RequestControl::new(&self.cancelled, limits.total_timeout_ms)?;
        let mut staged = None;
        let mut permit = None;
        let result = (|| {
            control.check("validation")?;
            let token_count = request.prompt.split_whitespace().count();
            request.validate(limits, token_count)?;
            permit = Some(resources::Permit::acquire(limits, &control)?);
            staged = Some(StagedConfig::new()?);
            let stage = staged.as_ref().unwrap();
            let executable = staging::prepare_worker(
                &self.executable,
                config
                    .local
                    .as_ref()
                    .and_then(|local| local.worker_sha256.as_deref()),
                stage.directory(),
                &control,
                config.local.as_ref().is_none_or(|local| {
                    matches!(
                        local.worker_launcher,
                        WorkerLauncher::Process | WorkerLauncher::ProcessNamespace
                    )
                }),
            )?;
            let mut effective_config = config.clone();
            effective_config.worker_limits = Some(limits.clone());
            let config = &effective_config;
            let launcher = config.local.as_ref().map(|local| &local.worker_launcher);
            let stage_process_artifacts = matches!(
                launcher,
                Some(WorkerLauncher::Process | WorkerLauncher::ProcessNamespace)
            );
            write_ephemeral_config(config, limits, stage_process_artifacts, &control, stage)?;
            let config_path = &staged.as_ref().unwrap().path;
            let run = RunContext {
                control: &control,
                image: &executable,
                cache: self.cache.as_deref(),
            };
            match launcher {
                Some(WorkerLauncher::Container { .. }) => {
                    self.infer_sandboxed(config, config_path, &request, limits, on_delta, &run)
                }
                #[cfg(feature = "microvm")]
                Some(WorkerLauncher::Microvm { .. }) => {
                    self.infer_sandboxed(config, config_path, &request, limits, on_delta, &run)
                }
                _ => self.infer_with_config(
                    config_path,
                    request.clone(),
                    limits,
                    matches!(launcher, Some(WorkerLauncher::ProcessNamespace)),
                    on_delta,
                    &run,
                ),
            }
            .and_then(|mut response| {
                control.check("response verification")?;
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
                let pinned = config.local.as_ref().is_some_and(|local| {
                    !local.model_sha256.is_empty()
                        && local
                            .worker_sha256
                            .as_ref()
                            .is_some_and(|hash| !hash.is_empty())
                });
                let result = response.verify(&request, pinned);
                response.verification = InferenceVerification {
                    status: result.status,
                    checks: result.checks,
                    output_sha256: result.output_sha256,
                };
                Ok(response)
            })
        })();
        let cleanup_started = Instant::now();
        let cleanup = staged.as_mut().map_or(Ok(()), StagedConfig::cleanup);
        drop(staged);
        drop(permit);
        // cleanup failure ทำให้ completion ล้มเสมอ และยังเก็บสาเหตุเดิมไว้ใน context
        control.finish(
            match cleanup {
                Ok(()) => result,
                Err(error) => Err(match result {
                    Ok(_) => error,
                    Err(source) => WorkerError::CleanupAfterFailure {
                        cleanup: error.to_string(),
                        source: Box::new(source),
                    },
                }),
            },
            cleanup_started,
        )
    }

    fn infer_with_config(
        &self,
        config_path: &Path,
        request: InferenceRequest,
        limits: &InferenceLimits,
        network_namespace: bool,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
        run: &RunContext<'_, '_>,
    ) -> Result<InferenceResponse, WorkerError> {
        let control = run.control;
        let executable = run.image.child_path();
        control.check("worker launch")?;
        let mut command = Command::new(executable);
        run.image.inherit(&mut command);
        if let Some(cache) = run.cache {
            cache.inherit(&mut command);
        }
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
                    } else {
                        #[cfg(target_os = "linux")]
                        {
                            // แยกตัวนับ RLIMIT_NPROC ออกจากโปรเซสของ host UID แบบ best-effort
                            let _ = aivm_sandbox::enter_worker_user_namespace();
                        }
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
        control.begin_execution()?;
        let deadline = control.execution_deadline(request.timeout_ms.min(limits.timeout_ms))?;
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
        let payload = serde_json::to_vec(&request)
            .map_err(|_| WorkerError::Protocol("invalid worker JSON".into()))?;
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
                            return Ok(None);
                        }
                        if total > MAX_RESPONSE_BYTES {
                            return Err(WorkerError::LimitExceeded("response bytes".into()));
                        }
                        serde_json::from_str::<serde_json::Value>(&line)
                            .map(Some)
                            .map_err(|_| WorkerError::Protocol("invalid worker JSON".into()))
                    });
                let done = result.as_ref().map_or(true, |value| {
                    value
                        .as_ref()
                        .is_none_or(|value| value.get("delta").is_none())
                });
                if sender.send(result).is_err() || done {
                    break;
                }
            }
        });
        let mut streamed = String::new();
        let response_result: Result<InferenceResponse, WorkerError> = (|| {
            let response = loop {
                control.check("worker response")?;
                if Instant::now() >= deadline {
                    return Err(WorkerError::Deadline("worker deadline exceeded".into()));
                }
                match receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(value) => {
                        // งบหรือ cancellation อาจเปลี่ยนระหว่างรอ frame ใน channel
                        control.check("worker response")?;
                        if Instant::now() >= deadline {
                            return Err(WorkerError::Deadline("worker deadline exceeded".into()));
                        }
                        let Some(value) = value? else {
                            // EOF อาจมาก่อน wait status พร้อม: รอออกจริงภายใต้งบเดิมก่อนเริ่ม cleanup
                            wait_for_worker_exit(&mut child, control, deadline)?;
                            return Err(WorkerError::Failed(
                                "worker returned no completion".into(),
                            ));
                        };
                        if value.get("request_id").and_then(serde_json::Value::as_str)
                            != Some(request.request_id.as_str())
                            || value
                                .get("protocol_version")
                                .and_then(serde_json::Value::as_u64)
                                != Some(u64::from(request.protocol_version))
                        {
                            return Err(WorkerError::Protocol("response identity mismatch".into()));
                        }
                        if value.get("error").is_some() {
                            return Err(remote_worker_error(&value));
                        }
                        if let Some(delta) = value.get("delta").and_then(serde_json::Value::as_str)
                        {
                            if !request.stream {
                                return Err(WorkerError::Protocol(
                                    "unexpected stream event".into(),
                                ));
                            }
                            control.check("worker stream")?;
                            streamed.push_str(delta);
                            on_delta(delta)?;
                            continue;
                        }
                        let response: InferenceResponse = serde_json::from_value(value)
                            .map_err(|_| WorkerError::Protocol("invalid worker JSON".into()))?;
                        response.validate(&request)?;
                        if request.stream && response.output.as_deref() != Some(streamed.as_str()) {
                            return Err(WorkerError::Protocol(
                                "stream differs from final output".into(),
                            ));
                        }
                        break response;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(_) => {
                        return Err(WorkerError::Failed("worker response channel closed".into()))
                    }
                }
            };
            let status = wait_for_worker_exit(&mut child, control, deadline)?;
            if !status.success() {
                return Err(WorkerError::Failed("worker exited unsuccessfully".into()));
            }
            Ok(response)
        })();
        // A descendant cannot hold the response or diagnostics pipe open after exit.
        let exit = child.terminate_with_exit();
        let detail = stderr_reader.join().unwrap_or_default();
        response_result.map_err(|error| {
            let summary = safe_worker_diagnostic(&detail);
            let error = if matches!(error, WorkerError::Failed(_))
                && summary != "untrusted worker diagnostics withheld"
            {
                WorkerError::Failed(summary.into())
            } else {
                error
            };
            error.with_exit(exit)
        })
    }
}

fn wait_for_worker_exit(
    child: &mut ChildGuard,
    control: &RequestControl<'_>,
    deadline: Instant,
) -> Result<ExitStatus, WorkerError> {
    loop {
        control.check("worker exit")?;
        if Instant::now() >= deadline {
            return Err(WorkerError::Deadline(
                "worker exit deadline exceeded".into(),
            ));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| WorkerError::Failed("wait worker exit".into()))?
        {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// ข้อความจาก worker ไม่ใช่ operator diagnostics: ป้องกัน prompt/secret เข้า error logs
fn safe_worker_diagnostic(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("sha256 mismatch") {
        "artifact sha256 mismatch"
    } else if [
        "cannot allocate memory",
        "memory allocation",
        "failed to allocate",
        "mmap failed",
        "out of memory",
        "tmpfs capacity exhausted",
    ]
    .iter()
    .any(|part| lower.contains(part))
    {
        if lower.contains("tmpfs capacity exhausted") {
            "model snapshot tmpfs capacity exhausted (RAM-backed staging)"
        } else {
            "model memory allocation failed"
        }
    } else {
        "untrusted worker diagnostics withheld"
    }
}

fn remote_worker_error(value: &serde_json::Value) -> WorkerError {
    let text = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    match value
        .get("error_kind")
        .and_then(|value| serde_json::from_value::<WorkerError>(value.clone()).ok())
    {
        Some(WorkerError::Protocol(_)) => WorkerError::Protocol("worker rejected protocol".into()),
        Some(WorkerError::InvalidOutput(_)) => WorkerError::InvalidOutput(
            "worker rejected incomplete or invalid structured output".into(),
        ),
        Some(WorkerError::InvalidRequest(_)) => {
            WorkerError::InvalidRequest("worker rejected request".into())
        }
        Some(WorkerError::LimitExceeded(_)) => {
            WorkerError::LimitExceeded("worker request limits".into())
        }
        _ => WorkerError::Failed(safe_worker_diagnostic(text).into()),
    }
}

fn consume_delta(
    line: &str,
    request: &InferenceRequest,
    streamed: &mut String,
    on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
    control: &RequestControl<'_>,
) -> Result<(), WorkerError> {
    let value: serde_json::Value = serde_json::from_str(line)
        .map_err(|_| WorkerError::Protocol("invalid worker JSON".into()))?;
    if value.get("request_id").and_then(serde_json::Value::as_str)
        != Some(request.request_id.as_str())
        || value
            .get("protocol_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(request.protocol_version))
    {
        return Err(WorkerError::Protocol("stream identity mismatch".into()));
    }
    if value.get("error").is_some() {
        return Err(remote_worker_error(&value));
    }
    if let Some(delta) = value.get("delta").and_then(serde_json::Value::as_str) {
        // buffer อาจมีหลาย frame: ตรวจใหม่ก่อนส่งแต่ละ delta ให้ผู้เรียก
        control.check("sandbox stream")?;
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
    fn terminate_with_exit(&mut self) -> Option<WorkerExit> {
        // อ่านก่อนส่ง signal เพื่อแยกสถานะที่มีอยู่ก่อน cleanup จากสถานะที่เห็นหลัง cleanup เริ่ม
        let before = self.child.try_wait().ok().flatten();
        let observed_before_cleanup = before.is_some();
        self.terminate();
        before
            .or_else(|| self.child.try_wait().ok().flatten())
            .map(|status| WorkerExit::from_status(status, observed_before_cleanup))
    }

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

fn write_ephemeral_config(
    config: &ModelConfig,
    limits: &InferenceLimits,
    stage_process_artifacts: bool,
    control: &RequestControl<'_>,
    staged: &StagedConfig,
) -> Result<(), WorkerError> {
    control.check("configuration")?;
    let dir = staged.directory();
    let mut staged_config = config.clone();
    if stage_process_artifacts {
        stage_local_artifacts(&mut staged_config, dir, limits, control)?;
    }
    control.check("configuration")?;
    let bytes = serde_json::to_vec(&staged_config)
        .map_err(|e| WorkerError::Failed(format!("encode model config: {e}")))?;
    write_private(&staged.path, &bytes)?;
    control.check("configuration")?;
    Ok(())
}

/// Process workers receive private copies of model inputs. The worker verifies
/// the copies against the configured pins and loads those same private paths,
/// removing the hash-then-reopen race on operator-controlled source paths.
fn stage_local_artifacts(
    config: &mut ModelConfig,
    directory: &Path,
    limits: &InferenceLimits,
    control: &RequestControl<'_>,
) -> Result<(), WorkerError> {
    let Some(local) = config.local.as_mut() else {
        return Ok(());
    };
    if local.model_path.is_empty() {
        return Ok(());
    }
    let mut paths = vec![&mut local.model_path];
    paths.extend(
        [
            &mut local.manifest_path,
            &mut local.tokenizer_path,
            &mut local.config_path,
        ]
        .into_iter()
        .filter_map(Option::as_mut),
    );
    let maximum = limits.storage_mb.saturating_mul(1024 * 1024);
    let mut total = 0u64;
    for (index, path) in paths.into_iter().enumerate() {
        control.check("artifact staging")?;
        #[cfg(target_os = "linux")]
        if path.starts_with("/proc/") && path.contains("/fd/") {
            let file = crate::artifact::open_regular(path)
                .map_err(|_| WorkerError::InvalidRequest("invalid sealed model source".into()))?;
            if !crate::artifact::is_sealed(&file) {
                return Err(WorkerError::InvalidRequest(
                    "model cache must be sealed".into(),
                ));
            }
            let bytes = file
                .metadata()
                .map_err(|_| WorkerError::Failed("stat sealed model".into()))?
                .len();
            if bytes > maximum.saturating_sub(total) {
                return Err(WorkerError::LimitExceeded("staging storage".into()));
            }
            total += bytes;
            continue;
        }
        let source = Path::new(path)
            .canonicalize()
            .map_err(|e| WorkerError::Failed(format!("artifact path: {e}")))?;
        let metadata = source
            .metadata()
            .map_err(|e| WorkerError::Failed(format!("artifact metadata: {e}")))?;
        if !metadata.is_file() {
            return Err(WorkerError::InvalidRequest(
                "model artifact must be a regular file".into(),
            ));
        }
        if metadata.len() > maximum.saturating_sub(total) {
            return Err(WorkerError::LimitExceeded("staging storage".into()));
        }
        let destination = directory.join(format!("process-artifact-{index}"));
        let mut input = control::open_artifact(&source)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&destination)
            .map_err(|e| WorkerError::Failed(format!("stage artifact: {e}")))?;
        total += control.copy(&mut input, &mut output, maximum - total, "artifact staging")?;
        control.check("artifact staging")?;
        output
            .sync_all()
            .map_err(|e| WorkerError::Failed(format!("sync artifact: {e}")))?;
        *path = destination.to_string_lossy().into_owned();
        control.check("artifact staging")?;
    }
    Ok(())
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
            output_mode: Default::default(),
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
            .infer(
                &config,
                request(),
                &InferenceLimits::test_fixture(dir.join("quota")),
            )
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
                .infer(
                    &config,
                    request(),
                    &InferenceLimits::test_fixture(dir.join("quota")),
                )
                .is_err(),
            "container launcher must not fall back to process execution"
        );
        assert!(!marker.exists(), "payload must never execute");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
