//! A small, transport-stable inference worker.
//!
//! The worker intentionally speaks JSONL over stdin/stdout so a supervisor can
//! later replace the transport with a Unix socket or a MicroVM channel without
//! changing the request/response contract.

use aivm_model::worker::{
    InferenceLimits, InferenceRequest, InferenceResponse, InferenceUsage, WorkerError,
};
use aivm_model::{create_model, ModelConfig};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    if let Err(error) = run() {
        eprintln!("aivm-model-worker: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), WorkerError> {
    let config_path = config_path()?;
    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| WorkerError::Failed(format!("read model config: {e}")))?;
    let config: ModelConfig = serde_json::from_str(&config_text)
        .map_err(|e| WorkerError::Failed(format!("parse model config JSON: {e}")))?;
    #[cfg(target_os = "linux")]
    aivm_sandbox::install_worker_network_seccomp()
        .map_err(|e| WorkerError::Failed(format!("install worker network filter: {e}")))?;
    // The worker must load the backend inline. Clearing worker_path prevents
    // recursive worker spawning when the control plane configured a worker.
    let mut config = config;
    if let Some(local) = config.local.as_mut() {
        local.worker_path = None;
    }
    let model = create_model(&config).map_err(|e| WorkerError::Failed(e.to_string()))?;
    let limits = InferenceLimits::default();
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| WorkerError::Failed(format!("read request: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: InferenceRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_error(
                    &mut stdout,
                    None,
                    WorkerError::InvalidRequest(error.to_string()),
                )?;
                continue;
            }
        };
        let request_id = request.request_id.clone();
        let token_count = model.token_count(&request.prompt);
        let effective_limits = InferenceLimits {
            max_context_tokens: limits.max_context_tokens.min(model.max_context()),
            ..limits.clone()
        };
        if let Err(error) = request.validate(&effective_limits, token_count) {
            write_error(&mut stdout, Some(&request_id), error)?;
            continue;
        }
        let started = Instant::now();
        let output = match model.reason(&request.prompt) {
            Ok(output) => output,
            Err(error) => {
                write_error(
                    &mut stdout,
                    Some(&request_id),
                    WorkerError::Failed(error.to_string()),
                )?;
                continue;
            }
        };
        let response = InferenceResponse {
            protocol_version: aivm_model::worker::PROTOCOL_VERSION,
            request_id,
            usage: InferenceUsage {
                input_tokens: token_count,
                output_tokens: model.token_count(&output),
                elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            },
            output: Some(output),
            termination: "completed".into(),
            artifact_verified: config.provider != "local"
                || config
                    .local
                    .as_ref()
                    .is_some_and(|local| !local.model_sha256.is_empty()),
            applied_limits: vec![
                "context-tokens".into(),
                "output-tokens".into(),
                "timeout-request-bound".into(),
            ],
            audit_id: None,
        };
        serde_json::to_writer(&mut stdout, &response)
            .map_err(|e| WorkerError::Failed(format!("write response: {e}")))?;
        stdout
            .write_all(b"\n")
            .map_err(|e| WorkerError::Failed(format!("write response: {e}")))?;
        stdout
            .flush()
            .map_err(|e| WorkerError::Failed(format!("flush response: {e}")))?;
    }
    Ok(())
}

fn config_path() -> Result<PathBuf, WorkerError> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            return args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| WorkerError::InvalidRequest("--config requires a path".into()));
        }
    }
    Err(WorkerError::InvalidRequest(
        "usage: aivm-model-worker --config <model-config.json>".into(),
    ))
}

fn write_error(
    stdout: &mut impl Write,
    request_id: Option<&str>,
    error: WorkerError,
) -> Result<(), WorkerError> {
    let value = serde_json::json!({
        "protocol_version": aivm_model::worker::PROTOCOL_VERSION,
        "request_id": request_id,
        "error": error.to_string(),
        "error_kind": error,
    });
    serde_json::to_writer(&mut *stdout, &value)
        .map_err(|e| WorkerError::Failed(format!("write error: {e}")))?;
    stdout
        .write_all(b"\n")
        .map_err(|e| WorkerError::Failed(format!("write error: {e}")))?;
    stdout
        .flush()
        .map_err(|e| WorkerError::Failed(format!("flush error: {e}")))?;
    Ok(())
}
