//! Typed protocol shared by the control plane and inference workers.
//!
//! The protocol is transport agnostic. A worker launcher can use pipes, a
//! Unix socket, a container attach, or a MicroVM channel without changing the
//! request validation and response shape.

use serde::{Deserialize, Serialize};
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
            max_output_tokens: 1024,
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
