//! นามธรรมโมเดล — ดูสเปก §28 (บล็อก `model:`)
//!
//! รองรับทั้ง LLM แบบ local และ remote หลัง trait เดียวกัน
//! MVP แถม echo model แบบ deterministic ไว้รันเทสต์/ออฟไลน์
//!
//! แบ็กเอนด์ local (GGUF ผ่าน llama.cpp) ถูกปิดไว้หลังฟีเจอร์ `llama`
//! โดยปริยาย เพราะต้องใช้ cmake + toolchain C++ ในการ build
//! (เปิดด้วย `--features llama`)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod worker;

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
    #[serde(default)]
    pub worker_limits: Option<worker::InferenceLimits>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "echo".into(),
            name: "echo".into(),
            local: None,
            openai: None,
            anthropic: None,
            worker_limits: None,
        }
    }
}

impl ModelConfig {
    // An explicit shared name wins over provider defaults/overrides. Legacy
    // echo/provider placeholders retain provider-specific model defaults.
    fn cloud_model_name(&self) -> Option<&str> {
        (!self.name.is_empty() && self.name != "echo" && self.name != self.provider)
            .then_some(self.name.as_str())
    }

    fn openai_config(&self) -> providers::OpenAIConfig {
        let mut config = self.openai.clone().unwrap_or_default();
        if let Some(name) = self.cloud_model_name() {
            config.model = name.into();
        }
        config
    }

    fn anthropic_config(&self) -> providers::AnthropicConfig {
        let mut config = self.anthropic.clone().unwrap_or_default();
        if let Some(name) = self.cloud_model_name() {
            config.model = name.into();
        }
        config
    }
}

/// การตั้งค่าซิงสำหรับแบ็กเอนด์ local (GGUF)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModelConfig {
    /// พาธไฟล์โมเดล (.gguf)
    pub model_path: String,
    /// sha256 hex (64 ตัว) ของไฟล์โมเดลที่อนุญาต ("": ไม่ pin — โหลดได้แต่ต้องรายงานใน degraded)
    #[serde(default)]
    pub model_sha256: String,
    /// Optional manifest describing the complete model artifact set.
    #[serde(default)]
    pub manifest_path: Option<String>,
    #[serde(default)]
    pub manifest_sha256: Option<String>,
    /// Optional tokenizer/config files covered by the manifest.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    #[serde(default)]
    pub tokenizer_sha256: Option<String>,
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub config_sha256: Option<String>,
    /// Optional standalone worker executable for isolated inference.
    #[serde(default)]
    pub worker_path: Option<String>,
    /// Optional SHA-256 pin for the worker executable.
    #[serde(default)]
    pub worker_sha256: Option<String>,
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
    0.0
}
fn default_top_p() -> f32 {
    0.1
}
fn default_top_k() -> i32 {
    1
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
            model_sha256: "".into(),
            manifest_path: None,
            manifest_sha256: None,
            tokenizer_path: None,
            tokenizer_sha256: None,
            config_path: None,
            config_sha256: None,
            worker_path: None,
            worker_sha256: None,
            gpu_layers: -1,
            ctx_size: default_ctx_size(),
            threads: default_threads(),
            seed: 42,
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

/// เพดานไฟล์โมเดลที่ verify (70B Q4 ~40GB ยังผ่าน เกินนี้ operator ต้องตั้งใจแบ่งเอง)
pub const MAX_MODEL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// ตรวจ supply chain ของไฟล์โมเดลก่อนโหลด (mirror `aivm_sandbox::verify_artifact`)
/// `expected` ว่าง = ไม่ pin (โหลดได้ แต่ caller ควรรายงานใน degraded)
/// ไม่ตรง/รูปแบบผิด/อ่านไม่ได้ = Err เสมอ ไม่มีการโหลดไฟล์นั้น
pub fn verify_model_file(path: &str, expected_sha256_hex: &str) -> Result<(), ModelError> {
    let bad = |m: &str| ModelError::LoadFailed(m.to_string());
    if expected_sha256_hex.is_empty() {
        return Ok(());
    }
    // hex ต้องยาว 64 ตัว (32 ไบต์) และเป็น [0-9a-fA-F] เท่านั้น
    if expected_sha256_hex.len() != 64
        || !expected_sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(bad("bad model hash (must be 64 hex chars)"));
    }
    let mut expected = [0u8; 32];
    for (i, chunk) in expected_sha256_hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| bad("bad hex"))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| bad("bad hex"))?;
        expected[i] = ((hi << 4) | lo) as u8;
    }
    let expected = expected_sha256_hex.to_ascii_lowercase();
    let actual = model_file_sha256(path)?;
    if actual != expected {
        return Err(bad("model sha256 mismatch (refusing to load)"));
    }
    Ok(())
}

/// Compute the SHA-256 of a model artifact without loading it into memory.
pub fn model_file_sha256(path: &str) -> Result<String, ModelError> {
    let bad = |m: &str| ModelError::LoadFailed(m.to_string());
    let mut file = std::fs::File::open(path).map_err(|_| bad("model not readable"))?;
    let meta = file.metadata().map_err(|_| bad("model not statable"))?;
    if !meta.is_file() {
        return Err(bad("model is not a regular file"));
    }
    if meta.len() > MAX_MODEL_BYTES {
        return Err(bad("model too large"));
    }
    // อ่านแบบ stream กันไฟล์ใหญ่กินหน่วยความจำ
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|_| bad("model not readable"))?;
    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
}

pub trait Model: Send + Sync {
    fn reason(&self, context: &str) -> Result<String, ModelError>;
    /// Generate with a per-request output cap. Backends without native
    /// generation controls retain their compatibility behavior.
    fn reason_with_max_output(
        &self,
        context: &str,
        _max_output_tokens: usize,
    ) -> Result<String, ModelError> {
        self.reason(context)
    }
    /// ส่ง system instruction แยกจาก user/context เมื่อ backend รองรับ
    /// backend ทั่วไปคง compatibility ด้วยการต่อข้อความก่อนเรียก reason()
    fn reason_with_system(&self, system: &str, context: &str) -> Result<String, ModelError> {
        self.reason(&format!("{system}\n\n{context}"))
    }
    fn token_count(&self, text: &str) -> usize;
    fn max_context(&self) -> usize;
}

/// Model adapter that keeps inference in the standalone worker process.
pub struct WorkerModel {
    client: worker::WorkerClient,
    config: ModelConfig,
    limits: worker::InferenceLimits,
}

impl WorkerModel {
    fn new(config: ModelConfig, worker_path: String) -> Result<Self, ModelError> {
        let local = config.local.as_ref().ok_or_else(|| {
            ModelError::LoadFailed("local config required for worker model".into())
        })?;
        Ok(Self {
            client: worker::WorkerClient::new(worker_path),
            limits: config
                .worker_limits
                .clone()
                .unwrap_or_else(|| worker::InferenceLimits {
                    max_context_tokens: local.ctx_size,
                    max_output_tokens: local.max_tokens,
                    timeout_ms: 120_000,
                    ..worker::InferenceLimits::default()
                }),
            config,
        })
    }
}

impl Model for WorkerModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        let request = worker::InferenceRequest {
            protocol_version: worker::PROTOCOL_VERSION,
            request_id: format!("infer-{}", uuid_like_id()),
            model_id: self.config.name.clone(),
            prompt: context.to_string(),
            max_output_tokens: self.limits.max_output_tokens,
            timeout_ms: self.limits.timeout_ms,
        };
        self.client
            .infer(&self.config, request, &self.limits)
            .map_err(|e| ModelError::InferenceFailed(e.to_string()))
            .and_then(|response| {
                response
                    .output
                    .ok_or_else(|| ModelError::InferenceFailed("worker returned no output".into()))
            })
    }

    fn token_count(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn max_context(&self) -> usize {
        self.limits.max_context_tokens
    }
}

fn uuid_like_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos().to_string())
        .unwrap_or_else(|_| "0".into())
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
        // supply chain มาก่อนโหลด: hash ไม่ตรง = ไม่แตะไฟล์นั้นเลย
        verify_model_file(&config.model_path, &config.model_sha256)?;

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

    fn reason_with_messages(&self, messages: &[(&str, &str)]) -> Result<String, ModelError> {
        self.reason_with_messages_limit(messages, self.config.max_tokens)
    }

    fn reason_with_messages_limit(
        &self,
        messages: &[(&str, &str)],
        max_output_tokens: usize,
    ) -> Result<String, ModelError> {
        let prompt = if let Some(template) = &self.chat_template {
            let messages = messages
                .iter()
                .map(|(role, content)| {
                    llama_cpp_2::model::LlamaChatMessage::new(
                        (*role).to_string(),
                        (*content).to_string(),
                    )
                    .map_err(|e| ModelError::Tokenizer(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.model
                .apply_chat_template(template, &messages, true)
                .map_err(|e| ModelError::Tokenizer(e.to_string()))?
        } else {
            messages
                .iter()
                .map(|(_, content)| *content)
                .collect::<Vec<_>>()
                .join("\n\n")
        };
        self.generate(&prompt, max_output_tokens.min(self.config.max_tokens))
    }

    fn generate(&self, prompt: &str, max_output_tokens: usize) -> Result<String, ModelError> {
        let n_ctx = self.config.ctx_size as u32;
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(n_ctx).or(NonZeroU32::new(512)))
            .with_n_threads(self.config.threads);

        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| ModelError::InferenceFailed(e.to_string()))?;

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

        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::temp(self.config.temperature),
            LlamaSampler::top_k(self.config.top_k),
            LlamaSampler::top_p(self.config.top_p, 1),
            LlamaSampler::dist(self.config.seed),
        ]);

        let mut generated: Vec<LlamaToken> = Vec::new();
        while generated.len() < max_output_tokens {
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
}

#[cfg(feature = "llama")]
impl Model for LocalLlamaModel {
    fn reason(&self, context: &str) -> Result<String, ModelError> {
        self.reason_with_messages(&[("user", context)])
    }

    fn reason_with_max_output(
        &self,
        context: &str,
        max_output_tokens: usize,
    ) -> Result<String, ModelError> {
        self.reason_with_messages_limit(&[("user", context)], max_output_tokens)
    }

    fn reason_with_system(&self, system: &str, context: &str) -> Result<String, ModelError> {
        self.reason_with_messages(&[("system", system), ("user", context)])
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
        "local" => {
            if let Some(worker_path) = config
                .local
                .as_ref()
                .and_then(|local| local.worker_path.clone())
            {
                Ok(Box::new(WorkerModel::new(config.clone(), worker_path)?))
            } else {
                create_local_model(config)
            }
        }
        "openai" => Ok(Box::new(providers::OpenAIProvider::new(
            config.openai_config(),
        )?)),
        "anthropic" => Ok(Box::new(providers::AnthropicProvider::new(
            config.anthropic_config(),
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

    #[test]
    fn cloud_model_selection_respects_names_and_provider_overrides() {
        let mut config = ModelConfig {
            provider: "openai".into(),
            name: "chosen-openai-model".into(),
            ..Default::default()
        };
        assert_eq!(config.openai_config().model, "chosen-openai-model");
        config.openai = Some(providers::OpenAIConfig {
            api_key_env: "CUSTOM_OPENAI_KEY".into(),
            model: "nested-model".into(),
        });
        assert_eq!(config.openai_config().model, "chosen-openai-model");
        assert_eq!(config.openai_config().api_key_env, "CUSTOM_OPENAI_KEY");
        config.name = "echo".into();
        assert_eq!(config.openai_config().model, "nested-model");
        config.provider = "anthropic".into();
        config.name = "chosen-anthropic-model".into();
        assert_eq!(config.anthropic_config().model, "chosen-anthropic-model");
        config.anthropic = Some(providers::AnthropicConfig {
            api_key_env: "CUSTOM_ANTHROPIC_KEY".into(),
            model: "nested-anthropic".into(),
        });
        assert_eq!(config.anthropic_config().model, "chosen-anthropic-model");
        assert_eq!(
            config.anthropic_config().api_key_env,
            "CUSTOM_ANTHROPIC_KEY"
        );
        config.name = "echo".into();
        assert_eq!(config.anthropic_config().model, "nested-anthropic");
        config.openai = None;
        config.anthropic = None;
        config.name = "echo".into();
        assert_eq!(
            config.openai_config().model,
            providers::OpenAIConfig::default().model
        );
        assert_eq!(
            config.anthropic_config().model,
            providers::AnthropicConfig::default().model
        );
    }

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
            worker_limits: None,
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
            worker_limits: None,
        };
        assert!(create_model(&cfg).is_err());

        let cfg_empty_path = ModelConfig {
            provider: "local".into(),
            name: "x".into(),
            local: Some(LocalModelConfig::default()),
            openai: None,
            anthropic: None,
            worker_limits: None,
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
            worker_limits: None,
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
            worker_limits: None,
        };
        assert!(create_model(&cfg).is_err());
    }

    // supply chain ของไฟล์โมเดล: ตรงผ่าน ไม่ตรง/รูปแบบผิด/อ่านไม่ได้ = ไม่โหลด
    #[test]
    fn model_file_pin_accepts_match_and_rejects_the_rest() {
        let dir = std::env::temp_dir().join(format!("aivm-model-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("tiny.gguf");
        std::fs::write(&file, b"fake-gguf-bytes").unwrap();
        let path = file.to_string_lossy().into_owned();
        // hash จริงของไฟล์นี้ (คำนวณด้วย sha256 ของ bytes เดียวกัน)
        let mut hasher = Sha256::new();
        hasher.update(b"fake-gguf-bytes");
        let good = format!("{:x}", hasher.finalize());
        assert!(verify_model_file(&path, &good).is_ok());
        // ว่าง = ไม่ pin (โหลดได้ แต่ต้องรายงาน degraded ที่ caller)
        assert!(verify_model_file(&path, "").is_ok());
        // hash ผิด/รูปแบบผิด/ไฟล์หาย = ปฏิเสธทั้งหมด
        assert!(verify_model_file(&path, &"00".repeat(32)).is_err());
        assert!(verify_model_file(&path, "zz").is_err());
        assert!(verify_model_file(&path, "abcd").is_err());
        assert!(verify_model_file(dir.join("missing.gguf").to_str().unwrap(), &good).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn worker_path_routes_inference_through_child_process() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aivm-worker-model-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nread request\nprintf '%s\\n' '{\"protocol_version\":1,\"request_id\":\"test\",\"output\":\"worker-ok\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"elapsed_ms\":0},\"termination\":\"completed\",\"artifact_verified\":true,\"applied_limits\":[],\"audit_id\":null}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let local = LocalModelConfig {
            worker_path: Some(script.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let config = ModelConfig {
            provider: "local".into(),
            name: "worker-test".into(),
            local: Some(local),
            ..Default::default()
        };
        let model = create_model(&config).unwrap();
        assert_eq!(model.reason("hello").unwrap(), "worker-ok");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // pin ผิดต้องตายตั้งแต่ก่อนโหลดโมเดล (ไม่เปลืองเวลา init backend)
    #[cfg(feature = "llama")]
    #[test]
    fn local_model_with_wrong_pin_fails_before_load() {
        let cfg = LocalModelConfig {
            model_path: "/tmp/definitely-not-a-model.gguf".into(),
            model_sha256: "00".repeat(32),
            ..Default::default()
        };
        let err = LocalLlamaModel::new(cfg)
            .err()
            .expect("must fail")
            .to_string();
        assert!(
            err.contains("mismatch") || err.contains("statable"),
            "{err}"
        );
    }
}
