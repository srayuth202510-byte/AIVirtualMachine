//! Model abstraction — spec §28 (`model:` block).
//!
//! Supports local and remote LLMs behind one trait. MVP ships a
//! deterministic echo model for tests/offline runs.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("backend: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: String, // "local" | "remote" | "echo"
    pub name: String,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self { provider: "echo".into(), name: "echo".into() }
    }
}

pub trait Model: Send + Sync {
    fn reason(&self, context: &str) -> Result<String, ModelError>;
}

/// Deterministic offline model (tests, CI, MVP demos).
pub struct EchoModel {
    pub name: String,
}

impl Model for EchoModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        Ok(format!("[{}] intent from context: {}", self.name, context.lines().next().unwrap_or(""))) 
    }
}
