//! นามธรรมโมเดล — ดูสเปก §28 (บล็อก `model:`)
//!
//! รองรับทั้ง LLM แบบ local และ remote หลัง trait เดียวกัน
//! MVP แถม echo model แบบ deterministic ไว้รันเทสต์/ออฟไลน์
//!
//! แบ็กเอนด์ local (GGUF ผ่าน llama.cpp) ถูกปิดไว้หลังฟีเจอร์ `llama`
//! โดยปริยาย เพราะต้องใช้ cmake + toolchain C++ ในการ build
//! (เปิดด้วย `--features llama`)

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod providers;

#[cfg(feature = "llama")]
use std::num::NonZeroU32;

#[cfg(feature = "llama")]
use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{params::LlamaModelParams, LlamaModel},
    sampling::LlamaSampler,
    token::LlamaToken,
};

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("backend: {0}")]
    Backend(String),
    #[error("model load failed: {0}")]
    LoadFailed(String),
    #[error("inference failed: {0}")]
    InferenceFailed(String),
    #[error("tokenizer: {0}")]
    Tokenizer(String),
    #[error("context overflow: max {max}, got {actual}")]
    ContextOverflow { max: usize, actual: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: String, // "local" | "remote" | "echo" | "openai" | "anthropic"
    pub name: String,
    #[serde(default)]
    pub local: Option<LocalModelConfig>,
    #[serde(default)]
    pub openai: Option<providers::OpenAIConfig>,
    #[serde(default)]
    pub anthropic: Option<providers::AnthropicConfig>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "echo".into(),
            name: "echo".into(),
            local: None,
            openai: None,
            anthropic: None,
        }
    }
}

/// การตั้งค่าซิงสำหรับแบ็กเอนด์ local (GGUF)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModelConfig {
    /// พาธไฟล์โมเดล (.gguf)
    pub model_path: String,
    /// จำนวนชั้นที่ยกไป GPU (-1 = ทั้งหมด)
    #[serde(default)]
    pub gpu_layers: i32,
    /// ขนาดคอนเท็กซ์วินโดว์
    #[serde(default = "default_ctx_size")]
    pub ctx_size: usize,
    /// จำนวนเธรดสำหรับ inference บน CPU (0 = อัตโนมัติ)
    #[serde(default = "default_threads")]
    pub threads: i32,
    /// เมล็ดสุ่มสำหรับการแซมเพิล
    #[serde(default)]
    pub seed: u32,
    /// อุณหภูมิสำหรับการแซมเพิล
    #[serde(default = "default_temp")]
    pub temperature: f32,
    /// Top-p sampling
    #[serde(default = "default_top_p")]
    pub top_p: f32,
    /// Top-k sampling
    #[serde(default = "default_top_k")]
    pub top_k: i32,
    /// จำนวนโทเคนสูงสุดที่จะสร้าง
    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,
    /// ใช้ MMap ในการโหลดโมเดล
    #[serde(default = "default_true")]
    pub use_mmap: bool,
    /// ล็อกโมเดลไว้ในหน่วยความจำ
    #[serde(default)]
    pub use_mlock: bool,
    /// โหมด embedding (เฉพาะ embedding ไม่สร้างข้อความ)
    #[serde(default)]
    pub embedding: bool,
}

fn default_ctx_size() -> usize {
    8192
}
fn default_threads() -> i32 {
    0
}
fn default_temp() -> f32 {
    0.7
}
fn default_top_p() -> f32 {
    0.95
}
fn default_top_k() -> i32 {
    40
}
fn default_max_tokens() -> usize {
    2048
}
fn default_true() -> bool {
    true
}

impl Default for LocalModelConfig {
    fn default() -> Self {
        Self {
            model_path: "".into(),
            gpu_layers: -1,
            ctx_size: default_ctx_size(),
            threads: default_threads(),
            seed: 0,
            temperature: default_temp(),
            top_p: default_top_p(),
            top_k: default_top_k(),
            max_tokens: default_max_tokens(),
            use_mmap: default_true(),
            use_mlock: false,
            embedding: false,
        }
    }
}

pub trait Model: Send + Sync {
    fn reason(&self, context: &str) -> Result<String, ModelError>;
    fn token_count(&self, text: &str) -> usize;
    fn max_context(&self) -> usize;
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
    fn token_count(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }
    fn max_context(&self) -> usize {
        8192
    }
}

/// โมเดล GGUF ในเครื่องผ่าน llama.cpp
///
/// เปิดใช้เฉพาะเมื่อ build ด้วยฟีเจอร์ `llama`
#[cfg(feature = "llama")]
pub struct LocalLlamaModel {
    backend: LlamaBackend,
    model: LlamaModel,
    chat_template: Option<llama_cpp_2::model::LlamaChatTemplate>,
    config: LocalModelConfig,
    name: String,
}

#[cfg(feature = "llama")]
impl LocalLlamaModel {
    pub fn new(config: LocalModelConfig) -> Result<Self, ModelError> {
        if config.model_path.is_empty() {
            return Err(ModelError::LoadFailed("model_path is required".into()));
        }

        let backend = LlamaBackend::init().map_err(|e| ModelError::Backend(e.to_string()))?;

        // gpu_layers เป็น i32 (ติดลบ = ไม่ยกไป GPU) แต่ API รับ u32
        let model_params = LlamaModelParams::default()
            .with_n_gpu_layers(config.gpu_layers.max(0) as u32)
            .with_use_mmap(config.use_mmap)
            .with_use_mlock(config.use_mlock)
            .with_vocab_only(config.embedding);

        let model = LlamaModel::load_from_file(&backend, &config.model_path, &model_params)
            .map_err(|e| ModelError::LoadFailed(e.to_string()))?;
        // Instruct GGUF-үүдийн template model metadata-д бий. Байхгүй
        // base model-д хуучин raw-prompt үйлдлийг хэвээр үлдээнэ.
        let chat_template = match model.chat_template(None) {
            Ok(template) => Some(template),
            Err(llama_cpp_2::ChatTemplateError::MissingTemplate) => None,
            Err(error) => return Err(ModelError::LoadFailed(error.to_string())),
        };

        Ok(Self {
            backend,
            model,
            chat_template,
            name: config.model_path.clone(),
            config,
        })
    }

    pub fn with_model_path(mut self, path: String) -> Self {
        self.config.model_path = path;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(feature = "llama")]
impl Model for LocalLlamaModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        let n_ctx = self.config.ctx_size as u32;
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(n_ctx).or(NonZeroU32::new(512)))
            .with_n_threads(self.config.threads);

        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;

        let prompt = if let Some(template) = &self.chat_template {
            let message =
                llama_cpp_2::model::LlamaChatMessage::new("user".into(), context.to_string())
                    .map_err(|e| ModelError::Tokenizer(e.to_string()))?;
            self.model
                .apply_chat_template(template, &[message], true)
                .map_err(|e| ModelError::Tokenizer(e.to_string()))?
        } else {
            context.to_string()
        };
        let vocab = self.model.vocab();
        let tokens = vocab.tokenize(prompt.as_bytes(), true, true);
        if tokens.is_empty() {
            return Err(ModelError::Tokenizer("input produced no tokens".into()));
        }
        if tokens.len() >= self.config.ctx_size {
            return Err(ModelError::ContextOverflow {
                max: self.config.ctx_size,
                actual: tokens.len(),
            });
        }

        // ป้อนพรอมป์ต์ทั้งก้อน (โทเคนสุดท้ายได้ logits อัตโนมัติ)
        let mut batch = LlamaBatch::new(self.config.ctx_size.max(tokens.len()), 1);
        batch
            .add_sequence(&tokens, 0, false)
            .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;
        ctx.decode(&mut batch)
            .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;

        // ใช้ sampler chain ของ llama.cpp แทนการเขียนแซมเพิลเอง
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::temp(self.config.temperature),
            LlamaSampler::top_k(self.config.top_k),
            LlamaSampler::top_p(self.config.top_p, 1),
            LlamaSampler::dist(self.config.seed),
        ]);

        let mut generated: Vec<LlamaToken> = Vec::new();
        while generated.len() < self.config.max_tokens {
            let token = sampler.sample(&ctx, -1);
            if vocab.is_eog(token) {
                break;
            }
            sampler.accept(token);

            let pos = (tokens.len() + generated.len()) as i32;
            generated.push(token);

            batch.clear();
            batch
                .add(token, pos, &[0], true)
                .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;
            ctx.decode(&mut batch)
                .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;
        }

        let bytes = vocab.detokenize(&generated, true, true);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn token_count(&self, text: &str) -> usize {
        self.model
            .vocab()
            .tokenize(text.as_bytes(), false, true)
            .len()
    }

    fn max_context(&self) -> usize {
        self.config.ctx_size
    }
}

/// สร้างโมเดลจาก config (factory)
///
/// ค่าเริ่มต้นคือ `echo` (ออฟไลน์ deterministic); `local` ต้อง build ด้วย
/// ฟีเจอร์ `llama` ไม่งั้นจะคืน error แบบ fail-closed
pub fn create_model(config: &ModelConfig) -> Result<Box<dyn Model>, ModelError> {
    match config.provider.as_str() {
        "echo" => Ok(Box::new(EchoModel {
            name: config.name.clone(),
        })),
        "local" => create_local_model(config),
        "openai" => Ok(Box::new(providers::OpenAIProvider::new(
            config.openai.clone().unwrap_or_default(),
        )?)),
        "anthropic" => Ok(Box::new(providers::AnthropicProvider::new(
            config.anthropic.clone().unwrap_or_default(),
        )?)),
        other => Err(ModelError::Backend(format!("unknown provider: {other}"))),
    }
}

#[cfg(feature = "llama")]
fn create_local_model(config: &ModelConfig) -> Result<Box<dyn Model>, ModelError> {
    let local = config
        .local
        .clone()
        .ok_or_else(|| ModelError::LoadFailed("local config required".into()))?;
    Ok(Box::new(LocalLlamaModel::new(local)?))
}

#[cfg(not(feature = "llama"))]
fn create_local_model(_config: &ModelConfig) -> Result<Box<dyn Model>, ModelError> {
    Err(ModelError::Backend(
        "local provider requires the `llama` feature".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // echo เป็นค่าเริ่มต้น: ต้องสร้างได้และตอบแบบ deterministic
    #[test]
    fn echo_provider_is_deterministic() {
        let cfg = ModelConfig::default();
        let model = create_model(&cfg).unwrap();
        let a = model.reason("hello world").unwrap();
        let b = model.reason("hello world").unwrap();
        assert_eq!(a, b);
        assert_eq!(model.token_count("a b c"), 3);
        assert_eq!(model.max_context(), 8192);
    }

    // provider ที่ไม่รู้จักต้อง fail-closed ไม่ใช่เงียบ ๆ ตกไปใช้ค่าเริ่มต้น
    #[test]
    fn unknown_provider_fails_closed() {
        let cfg = ModelConfig {
            provider: "definitely-not-real".into(),
            name: "x".into(),
            local: None,
            openai: None,
            anthropic: None,
        };
        assert!(create_model(&cfg).is_err());
    }

    #[test]
    fn local_provider_without_valid_config_fails() {
        let cfg = ModelConfig {
            provider: "local".into(),
            name: "x".into(),
            local: None,
            openai: None,
            anthropic: None,
        };
        assert!(create_model(&cfg).is_err());

        let cfg_empty_path = ModelConfig {
            provider: "local".into(),
            name: "x".into(),
            local: Some(LocalModelConfig::default()),
            openai: None,
            anthropic: None,
        };
        assert!(create_model(&cfg_empty_path).is_err());
    }

    #[test]
    fn openai_provider_missing_key_fails_closed() {
        // ชื่อ env เฉพาะเทสต์ กัน race กับเทสต์ providers ที่รันขนานกัน
        let env = "AIVM_TEST_MISSING_OPENAI_KEY_LIB";
        std::env::remove_var(env);
        let cfg = ModelConfig {
            provider: "openai".into(),
            name: "openai".into(),
            local: None,
            openai: Some(providers::OpenAIConfig {
                api_key_env: env.into(),
                model: "gpt-4o-mini".into(),
            }),
            anthropic: None,
        };
        assert!(create_model(&cfg).is_err());
    }

    #[test]
    fn anthropic_provider_missing_key_fails_closed() {
        let env = "AIVM_TEST_MISSING_ANTHROPIC_KEY_LIB";
        std::env::remove_var(env);
        let cfg = ModelConfig {
            provider: "anthropic".into(),
            name: "anthropic".into(),
            local: None,
            openai: None,
            anthropic: Some(providers::AnthropicConfig {
                api_key_env: env.into(),
                model: "claude-sonnet-4-20250514".into(),
            }),
        };
        assert!(create_model(&cfg).is_err());
    }
}
