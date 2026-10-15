//! Typed protocol shared by the control plane and inference workers.
//!
//! The protocol is transport agnostic. A worker launcher can use pipes, a
//! Unix socket, a container attach, or a MicroVM channel without changing the
//! request validation and response shape.

use super::ModelConfig;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PROMPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REQUEST_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceLimits {
    pub max_context_tokens: usize,
    pub max_output_tokens: usize,
    pub timeout_ms: u64,
}

impl Default for InferenceLimits {
    fn default() -> Self {
        Self {
            max_context_tokens: 8192,
            max_output_tokens: 2048,
            timeout_ms: 120_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub model_id: String,
    pub prompt: String,
    pub max_output_tokens: usize,
    pub timeout_ms: u64,
}

impl InferenceRequest {
    pub fn validate(
        &self,
        limits: &InferenceLimits,
        token_count: usize,
    ) -> Result<(), WorkerError> {
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
}

impl WorkerClient {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    pub fn infer(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
    ) -> Result<InferenceResponse, WorkerError> {
        let token_count = request.prompt.split_whitespace().count();
        request.validate(limits, token_count)?;
        let config_path = write_ephemeral_config(config)?;
        let result = self.infer_with_config(&config_path, request, limits);
        let _ = std::fs::remove_file(&config_path);
        result
    }

    fn infer_with_config(
        &self,
        config_path: &Path,
        request: InferenceRequest,
        limits: &InferenceLimits,
    ) -> Result<InferenceResponse, WorkerError> {
        let mut child = Command::new(&self.executable)
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WorkerError::Failed(format!("spawn worker: {e}")))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerError::Failed("worker stdin unavailable".into()))?;
        let payload = serde_json::to_vec(&request)
            .map_err(|e| WorkerError::Failed(format!("encode request: {e}")))?;
        stdin
            .write_all(&payload)
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|e| WorkerError::Failed(format!("write worker request: {e}")))?;
        drop(stdin);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerError::Failed("worker stdout unavailable".into()))?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout)
                .read_line(&mut line)
                .map_err(|e| WorkerError::Failed(format!("read worker response: {e}")))
                .and_then(|_| {
                    if line.trim().is_empty() {
                        return Err(WorkerError::Failed("worker returned no response".into()));
                    }
                    let value: serde_json::Value = serde_json::from_str(&line)
                        .map_err(|e| WorkerError::Failed(format!("decode worker response: {e}")))?;
                    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
                        return Err(WorkerError::Failed(error.to_string()));
                    }
                    serde_json::from_value(value)
                        .map_err(|e| WorkerError::Failed(format!("invalid worker response: {e}")))
                });
            let _ = sender.send(result);
        });
        let timeout = Duration::from_millis(request.timeout_ms.min(limits.timeout_ms));
        let response = match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WorkerError::Failed("worker deadline exceeded".into()));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(WorkerError::Failed("worker response channel closed".into()))
            }
        }?;
        let status = child
            .wait()
            .map_err(|e| WorkerError::Failed(format!("wait worker: {e}")))?;
        if !status.success() {
            return Err(WorkerError::Failed(format!("worker exited with {status}")));
        }
        Ok(response)
    }
}

fn write_ephemeral_config(config: &ModelConfig) -> Result<PathBuf, WorkerError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| WorkerError::Failed(format!("clock: {e}")))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("aivm-model-{}-{nonce}.json", std::process::id()));
    let bytes = serde_json::to_vec(config)
        .map_err(|e| WorkerError::Failed(format!("encode model config: {e}")))?;
    std::fs::write(&path, bytes)
        .map_err(|e| WorkerError::Failed(format!("write model config: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| WorkerError::Failed(format!("protect model config: {e}")))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InferenceRequest {
        InferenceRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: "req-1".into(),
            model_id: "model-1".into(),
            prompt: "hello".into(),
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
}
