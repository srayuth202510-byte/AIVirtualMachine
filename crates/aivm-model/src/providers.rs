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

/// ล้าง API key ออกจากข้อความ error (defense in depth: ureq ไม่ควร echo
/// header อยู่แล้ว แต่กันไว้ไม่ให้ key หลุดเข้า log/audit ผ่าน `ModelError`)
fn sanitize(api_key: &str, msg: String) -> String {
    if api_key.is_empty() {
        return msg;
    }
    msg.replace(api_key, "[REDACTED]")
}

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

// ตั้งใจไม่ derive Debug: กัน key หลุดผ่าน `{:?}` เข้า log/audit โดยเผลอ
// ใครต้องการ debug ให้เห็นแค่ชื่อโมเดลกับชื่อ env var พอ
impl std::fmt::Debug for OpenAIProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAIProvider")
            .field("model", &self.config.model)
            .field("api_key_env", &self.config.api_key_env)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
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
            .map_err(|e| ModelError::Backend(sanitize(&self.api_key, e.to_string())))?
            .into_json()
            .map_err(|e| ModelError::Backend(sanitize(&self.api_key, e.to_string())))?;
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

// เช่นเดียวกับ OpenAI: ห้าม Debug/Serialize ตัว key ตรง ๆ
impl std::fmt::Debug for AnthropicProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicProvider")
            .field("model", &self.config.model)
            .field("api_key_env", &self.config.api_key_env)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
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
            .map_err(|e| ModelError::Backend(sanitize(&self.api_key, e.to_string())))?
            .into_json()
            .map_err(|e| ModelError::Backend(sanitize(&self.api_key, e.to_string())))?;
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
        // ใช้ชื่อ env เฉพาะเทสต์นี้ กัน race กับเทสต์อื่นที่รันขนานกัน
        let env = "AIVM_TEST_MISSING_OPENAI_KEY";
        std::env::remove_var(env);
        let cfg = OpenAIConfig {
            api_key_env: env.into(),
            model: "gpt-4o-mini".into(),
        };
        assert!(OpenAIProvider::new(cfg).is_err());
    }

    #[test]
    fn anthropic_missing_key_fails() {
        let env = "AIVM_TEST_MISSING_ANTHROPIC_KEY";
        std::env::remove_var(env);
        let cfg = AnthropicConfig {
            api_key_env: env.into(),
            model: "claude-sonnet-4-20250514".into(),
        };
        assert!(AnthropicProvider::new(cfg).is_err());
    }

    // Debug ต้องไม่พิมพ์ key จริง (กันหลุดเข้า log/audit)
    #[test]
    fn debug_redacts_api_key() {
        let o_env = "AIVM_TEST_OPENAI_KEY_REDACT";
        let a_env = "AIVM_TEST_ANTHROPIC_KEY_REDACT";
        std::env::set_var(o_env, "sk-test-secret-123");
        std::env::set_var(a_env, "sk-ant-test-secret-456");
        let openai = OpenAIProvider::new(OpenAIConfig {
            api_key_env: o_env.into(),
            model: "gpt-4o-mini".into(),
        })
        .expect("key ถูกตั้งแล้วต้องสร้างได้");
        let anthropic = AnthropicProvider::new(AnthropicConfig {
            api_key_env: a_env.into(),
            model: "claude-sonnet-4-20250514".into(),
        })
        .expect("key ถูกตั้งแล้วต้องสร้างได้");
        let od = format!("{openai:?}");
        let ad = format!("{anthropic:?}");
        assert!(!od.contains("sk-test-secret-123"), "Debug ห้ามมี key: {od}");
        assert!(
            !ad.contains("sk-ant-test-secret-456"),
            "Debug ห้ามมี key: {ad}"
        );
        assert!(od.contains("[REDACTED]"));
        assert!(ad.contains("[REDACTED]"));
        std::env::remove_var(o_env);
        std::env::remove_var(a_env);
    }

    // Config ที่ derive Debug มีแค่ชื่อ env var ไม่มี key ตัวจริง
    #[test]
    fn config_debug_holds_no_secret() {
        let c = OpenAIConfig::default();
        let d = format!("{c:?}");
        assert!(d.contains("OPENAI_API_KEY"));
        // ไม่มีฟิลด์ key ใน config ตั้งแต่โครงสร้าง (ตรวจเชิงโครงสร้าง)
        assert!(!d.contains("sk-"));
    }

    // sanitize ต้องล้าง key ออกจาก error string ก่อนขึ้นไปถึง agent/audit
    #[test]
    fn sanitize_strips_key_from_errors() {
        let raw = "request failed with key sk-test-secret-123 inside".to_string();
        let clean = sanitize("sk-test-secret-123", raw);
        assert!(!clean.contains("sk-test-secret-123"));
        assert!(clean.contains("[REDACTED]"));
        // key ว่างต้องคืนข้อความเดิม (ไม่พัง)
        assert_eq!(sanitize("", "plain error".into()), "plain error");
    }
}
