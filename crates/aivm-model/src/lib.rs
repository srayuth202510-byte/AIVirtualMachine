//! นามธรรมโมเดล — ดูสเปก §28 (บล็อก `model:`)
//!
//! รองรับทั้ง LLM แบบ local และ remote หลัง trait เดียวกัน
//! MVP แถม echo model แบบ deterministic ไว้รันเทสต์/ออฟไลน์

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
        Self {
            provider: "echo".into(),
            name: "echo".into(),
        }
    }
}

pub trait Model: Send + Sync {
    fn reason(&self, context: &str) -> Result<String, ModelError>;
}

/// โมเดลออฟไลน์แบบ deterministic (ไว้ใช้ในเทสต์ CI และเดโม MVP)
pub struct EchoModel {
    pub name: String,
}

impl Model for EchoModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        Ok(format!(
            "[{}] intent from context: {}",
            self.name,
            context.lines().next().unwrap_or("")
        ))
    }
}
