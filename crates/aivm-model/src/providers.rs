//! Cloud LLM providers — OpenAI + Anthropic (HTTP ผ่าน ureq+rustls)
//!
//! ใช้ API ผ่าน HTTPS ตรง ไม่ผ่าน gateway (model call ไม่ใช่ tool call)
//! API key อ่านจาก environment variable (ไม่เก็บใน config file)

use crate::{Model, ModelError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const OPENAI_URL: &str = "https://api.openai.com/v1/chat/completions";
const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const TIMEOUT_SECS: u64 = 60;

// ---------- OpenAI ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIConfig {
    pub api_key_env: String, // ชื่อ env var ที่เก็บ API key
    pub model: String,       // เช่น "gpt-4o-mini"
}

impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            api_key_env: "OPENAI_API_KEY".into(),
            model: "gpt-4o-mini".into(),
        }
    }
}

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    max_tokens: u32,
}

#[derive(Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessageOut,
}

#[derive(Deserialize)]
struct OpenAIMessageOut {
    content: String,
}

pub struct OpenAIProvider {
    config: OpenAIConfig,
    api_key: String,
}

impl OpenAIProvider {
    pub fn new(config: OpenAIConfig) -> Result<Self, ModelError> {
        let api_key = std::env::var(&config.api_key_env)
            .map_err(|_| ModelError::Backend(format!("env {} not set", config.api_key_env)))?;
        Ok(Self { config, api_key })
    }
}

impl Model for OpenAIProvider {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        let body = OpenAIRequest {
            model: self.config.model.clone(),
            messages: vec![OpenAIMessage {
                role: "user".into(),
                content: context.to_string(),
            }],
            max_tokens: 2048,
        };
        let resp: OpenAIResponse = ureq::post(OPENAI_URL)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .send_json(serde_json::to_value(&body).unwrap())
            .map_err(|e| ModelError::Backend(e.to_string()))?
            .into_json()
            .map_err(|e| ModelError::Backend(e.to_string()))?;
        resp.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| ModelError::Backend("no choices in response".into()))
    }

    fn token_count(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn max_context(&self) -> usize {
        128_000
    }
}

// ---------- Anthropic ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicConfig {
    pub api_key_env: String,
    pub model: String, // เช่น "claude-sonnet-4-20250514"
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key_env: "ANTHROPIC_API_KEY".into(),
            model: "claude-sonnet-4-20250514".into(),
        }
    }
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
}

#[derive(Deserialize)]
struct AnthropicContentBlock {
    #[serde(default)]
    text: String,
}

pub struct AnthropicProvider {
    config: AnthropicConfig,
    api_key: String,
}

impl AnthropicProvider {
    pub fn new(config: AnthropicConfig) -> Result<Self, ModelError> {
        let api_key = std::env::var(&config.api_key_env)
            .map_err(|_| ModelError::Backend(format!("env {} not set", config.api_key_env)))?;
        Ok(Self { config, api_key })
    }
}

impl Model for AnthropicProvider {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        let body = AnthropicRequest {
            model: self.config.model.clone(),
            max_tokens: 2048,
            messages: vec![AnthropicMessage {
                role: "user".into(),
                content: context.to_string(),
            }],
        };
        let resp: AnthropicResponse = ureq::post(ANTHROPIC_URL)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .send_json(serde_json::to_value(&body).unwrap())
            .map_err(|e| ModelError::Backend(e.to_string()))?
            .into_json()
            .map_err(|e| ModelError::Backend(e.to_string()))?;
        let text: String = resp.content.into_iter().map(|b| b.text).collect();
        if text.is_empty() {
            return Err(ModelError::Backend("empty response".into()));
        }
        Ok(text)
    }

    fn token_count(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn max_context(&self) -> usize {
        200_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_config_default() {
        let c = OpenAIConfig::default();
        assert_eq!(c.api_key_env, "OPENAI_API_KEY");
        assert!(!c.model.is_empty());
    }

    #[test]
    fn anthropic_config_default() {
        let c = AnthropicConfig::default();
        assert_eq!(c.api_key_env, "ANTHROPIC_API_KEY");
        assert!(!c.model.is_empty());
    }

    #[test]
    fn openai_missing_key_fails() {
        std::env::remove_var("OPENAI_API_KEY");
        let cfg = OpenAIConfig::default();
        assert!(OpenAIProvider::new(cfg).is_err());
    }

    #[test]
    fn anthropic_missing_key_fails() {
        std::env::remove_var("ANTHROPIC_API_KEY");
        let cfg = AnthropicConfig::default();
        assert!(AnthropicProvider::new(cfg).is_err());
    }
}
