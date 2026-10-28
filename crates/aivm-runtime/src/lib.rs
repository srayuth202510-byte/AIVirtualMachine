//! Runtime — ดูสเปก §5, §22, §23, §28.
//!
//! เจ้าของ agent loop: observe -> retrieve -> reason -> intent ->
//! capability/policy -> execute -> observe เชื่อม Cube + Policy +
//! ToolGateway + Memory + Audit จากไฟล์ `aivm.yaml` ไฟล์เดียว

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::{Capability, CapabilitySet, Condition};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_memory::Memory;
use aivm_model::{create_model, LocalModelConfig, Model, ModelConfig};
use aivm_policy::Policy;
use aivm_sandbox::{ResourceLimits, Sandbox, SandboxLevel};
use aivm_tools::{ToolGateway, ToolRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

pub mod agent;
pub mod demo;
pub mod semantic;
mod transaction;

/// เกณฑ์ confidence สำหรับ ANALYZE -> MODIFY (ตัวอย่างในสเปก §15)
pub const CONFIDENCE_THRESHOLD: f64 = 0.8;
/// lease แบบจำกัดเวลาสำหรับสิทธิ์เน็ตเวิร์กที่ให้ตาม state (สเปก §14.3, แบบ JIT)
pub const NETWORK_LEASE_SECS: u64 = 300;
/// Persisted cube and capability usage counters; grants come from current config.
const STATE_FILE: &str = "state.json";
/// ไฟล์ค่า secrets ของ operator (G4 §26) — values อยู่ที่นี่ที่เดียว
/// ห้ามอยู่ใน `aivm.yaml` เด็ดขาด (ดู `load_secrets_file`)
const SECRETS_FILE: &str = "secrets.yaml";

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("config: {0}")]
    Config(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("io: {0}")]
    Io(String),
    #[error("transition denied: {0}")]
    Transition(String),
    #[error("secret: {0}")]
    Secret(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    pub name: String,
    #[serde(default)]
    pub runtime: RuntimeBlock,
    #[serde(default)]
    pub security: SecurityBlock,
    #[serde(default)]
    pub model: ModelBlock,
    #[serde(default)]
    pub resources: ResourceBlock,
    #[serde(default)]
    pub build: aivm_tools::build::BuildConfig,
    /// สัญญาตรวจผลที่ operator เลือก; ไม่เพิ่มสิทธิ์ execute
    #[serde(default)]
    pub verification: Option<aivm_tools::verification::VerifierConfig>,
    #[serde(default)]
    pub filesystem: FilesystemBlock,
    #[serde(default)]
    pub network: NetworkBlock,
    #[serde(default)]
    pub tools: ToolsBlock,
    #[serde(default)]
    pub capabilities: CapabilitiesBlock,
    #[serde(default)]
    pub policy: PolicyExtra,
    /// นโยบาย secrets (G4 §26): มีแค่ patterns (allow/deny/HITL/quota) —
    /// values อยู่ใน `secrets.yaml` ของ operator เท่านั้น
    #[serde(default)]
    pub secrets: aivm_secrets::SecretPolicy,
    /// บล็อก `microvm:` (kernel/rootfs pin + quota) ใช้เมื่อเปิดฟีเจอร์
    /// `microvm` เท่านั้น — บิลด์ที่ไม่มีฟีเจอร์ปฏิเสธบล็อกนี้ด้วย strict schema
    #[cfg(feature = "microvm")]
    #[serde(default)]
    pub microvm: Option<aivm_sandbox::microvm::MicroVmConfig>,
    /// บล็อก `hardware:` (TEE pins + quota) ใช้เมื่อเปิดฟีเจอร์
    /// `hardware` เท่านั้น — บิลด์ที่ไม่มีฟีเจอร์ปฏิเสธบล็อกนี้ด้วย strict schema
    #[cfg(feature = "hardware")]
    #[serde(default)]
    pub hardware: Option<aivm_sandbox::hardware::HardwareConfig>,
}

/// Deployment posture. Development remains the backward-compatible default;
/// production requires verified hashes for local open-weight model files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityBlock {
    #[serde(default = "default_security_profile")]
    pub profile: String,
}

impl Default for SecurityBlock {
    fn default() -> Self {
        Self {
            profile: default_security_profile(),
        }
    }
}

fn default_security_profile() -> String {
    "development".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBlock {
    #[serde(default = "default_isolation")]
    pub isolation: String,
    #[serde(default)]
    pub container: aivm_sandbox::container::ContainerConfig,
}
// ค่าเริ่มต้นต้องเป็น "sandbox" ไม่ใช่ "" (derive Default ให้ String ว่าง
// ซึ่ง from_str จะปฏิเสธแบบ fail-closed — config ที่ไม่ระบุ isolation
// ต้องบูตได้ด้วยพฤติกรรม MVP-B เดิม)
impl Default for RuntimeBlock {
    fn default() -> Self {
        Self {
            isolation: default_isolation(),
            container: aivm_sandbox::container::ContainerConfig::default(),
        }
    }
}
fn default_isolation() -> String {
    "sandbox".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBlock {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub name: String,
    /// งบเวลารวมต่อ WorkerClient request; ต้องใช้ local worker เท่านั้น
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_timeout_ms: Option<u64>,
    #[serde(default)]
    pub host_resources: aivm_model::worker::HostResources,
    /// การตั้งค่าแบ็กเอนด์ local (ใช้เมื่อ provider = "local")
    #[serde(default)]
    pub local: Option<LocalModelConfig>,
    #[serde(default)]
    pub openai: Option<aivm_model::providers::OpenAIConfig>,
    #[serde(default)]
    pub anthropic: Option<aivm_model::providers::AnthropicConfig>,
}

// default ต้องตรงกับ serde default (echo) ไม่ใช่ค่าว่าง เพื่อให้ผู้ที่สร้าง
// ModelBlock::default() ตรง ๆ ยังได้ provider ที่ใช้ได้ (fail-closed ถ้าไม่รู้จัก)
impl Default for ModelBlock {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            name: default_model(),
            total_timeout_ms: None,
            host_resources: Default::default(),
            local: None,
            openai: None,
            anthropic: None,
        }
    }
}
fn default_provider() -> String {
    "echo".into()
}
fn default_model() -> String {
    "echo".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBlock {
    #[serde(default = "default_cpu")]
    pub cpu: u32,
    #[serde(default = "default_mem")]
    pub memory: String,
    #[serde(default = "default_storage")]
    pub storage: String,
}
impl Default for ResourceBlock {
    fn default() -> Self {
        Self {
            cpu: default_cpu(),
            memory: default_mem(),
            storage: default_storage(),
        }
    }
}
fn default_cpu() -> u32 {
    2
}
fn default_mem() -> String {
    "1GB".into()
}
fn default_storage() -> String {
    "5GB".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBlock {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBlock {
    /// operator ต้องเปิดสิทธิ์เขียนอย่างชัดเจน ค่าเริ่มต้นคืออ่านเท่านั้น
    #[serde(default = "default_network_read_only")]
    pub read_only: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    /// เพดานจำนวนครั้งต่อ lease เน็ตเวิร์ก (None = ไม่จำกัดด้วยจำนวนครั้ง)
    #[serde(default)]
    pub max_calls: Option<u32>,
    /// เพดานไบต์สะสมต่อ lease เน็ตเวิร์ก (None = ไม่จำกัดด้วยยอดรวม)
    #[serde(default)]
    pub max_total_bytes: Option<u64>,
}

fn default_network_read_only() -> bool {
    true
}

impl Default for NetworkBlock {
    fn default() -> Self {
        Self {
            read_only: true,
            allow: vec![],
            max_calls: None,
            max_total_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ToolsBlock {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesBlock {
    #[serde(default)]
    pub initial: Vec<String>, // "read:workspace", "search:code"
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyExtra {
    #[serde(default)]
    pub require_test_before_network: bool,
}

impl VmConfig {
    pub fn from_yaml(text: &str) -> Result<Self, RuntimeError> {
        serde_yaml::from_str(text).map_err(|e| RuntimeError::Config(e.to_string()))
    }

    pub fn from_file(path: &Path) -> Result<Self, RuntimeError> {
        let t = std::fs::read_to_string(path).map_err(|e| RuntimeError::Io(e.to_string()))?;
        Self::from_yaml(&t)
    }
}

impl VmConfig {
    /// Model-only configuration uses the same security gate and quotas as the agent runtime.
    pub fn inference_model_config(&self) -> Result<ModelConfig, RuntimeError> {
        validate_model_security(self)?;
        let resources = resource_limits(&self.resources)?;
        Ok(ModelConfig {
            provider: self.model.provider.clone(),
            name: self.model.name.clone(),
            local: self.model.local.clone(),
            openai: self.model.openai.clone(),
            anthropic: self.model.anthropic.clone(),
            worker_limits: self.model.local.as_ref().map(|local| {
                aivm_model::worker::InferenceLimits {
                    max_context_tokens: local.ctx_size,
                    max_output_tokens: local.max_tokens,
                    timeout_ms: 120_000,
                    total_timeout_ms: self.model.total_timeout_ms,
                    memory_mb: resources.memory_mb,
                    cpu_seconds: u64::from(resources.cpu) * 60,
                    pids_max: resources.pids_max,
                    storage_mb: resources.storage_mb,
                    host_resources: self.model.host_resources.clone(),
                }
            }),
        })
    }
}

pub struct Runtime {
    pub config: VmConfig,
    pub base_dir: PathBuf,
    pub workspace: PathBuf,
    pub cube: Cube,
    pub policy: Policy,
    pub gateway: ToolGateway,
    pub memory: Memory,
    pub sandbox: Sandbox,
    pub model: Box<dyn Model>,
    pub model_cfg: ModelConfig,
    op_seq: u64,
    transaction_failed: bool,
    #[cfg(test)]
    transaction_hook: fn(&str) -> std::io::Result<()>,
}

/// state แบบ dynamic ที่ persist ไว้: cube ที่ผ่าน validate แล้ว + lease ที่ยังใช้ได้
/// policy/config อยู่ใน `aivm.yaml` (ต้นฉบับความจริง) มีแค่ส่วนที่เปลี่ยน
/// แปลงตามเวลาที่อยู่ไฟล์นี้ ตัวนับรอด restart แต่ grant มาจาก config ปัจจุบัน
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    cube: Cube,
    caps: CapabilitySet,
    /// leases ค้าง (G4b): รวม values (ไฟล์ 0600 อยู่แล้ว — ระดับเดียวกับ
    /// secrets.yaml) ฟื้นเฉพาะที่ยังใช้ได้ ที่เหลือทิ้ง (fail-closed ข้าม restart)
    #[serde(default)]
    leases: Vec<aivm_secrets::SecretLease>,
}

/// Restore usage and the original deadline for identical grant identities.
/// Current conditions and limits remain authoritative, while an old expiry can
/// only shorten the freshly rebuilt grant. Restart must never renew a JIT lease.
fn restore_cap_usage(current: &mut CapabilitySet, saved: &CapabilitySet) {
    for cap in &mut current.caps {
        for old in &saved.caps {
            if (
                cap.action.as_str(),
                cap.resource.as_str(),
                cap.scope.as_str(),
            ) == (
                old.action.as_str(),
                old.resource.as_str(),
                old.scope.as_str(),
            ) {
                cap.used_count = cap.used_count.max(old.used_count);
                cap.used_bytes = cap.used_bytes.max(old.used_bytes);
                cap.expiration = match (cap.expiration, old.expiration) {
                    (Some(fresh), Some(saved)) => Some(fresh.min(saved)),
                    (None, Some(saved)) => Some(saved),
                    (fresh, None) => fresh,
                };
            }
        }
    }
}

impl Runtime {
    /// init แบบ fail-closed: config/policy เสียได้ Err VM ปฏิเสธสตาร์ต
    pub fn init(config: VmConfig, base_dir: PathBuf) -> Result<Self, RuntimeError> {
        validate_model_security(&config)?;
        let workspace = base_dir.join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|e| RuntimeError::Io(e.to_string()))?;
        // ทำ workspace ให้เป็น absolute เพื่อให้ scope ของ capability
        // กับ path คำขอที่ canonicalize แล้วเทียบกันในโดเมนเดียวกัน
        // (base_dir แบบ relative จะ join ซ้ำใน gateway แล้ว deny หมด)
        let workspace = absolutize(&workspace);
        let base_dir = absolutize(&base_dir);

        let ws_str = workspace.to_string_lossy().to_string();
        let policy = build_policy(&config, &base_dir, &workspace);

        // สิทธิ์เริ่มต้น (state INIT ตาม §14.2)
        let mut caps = vec![];
        for c in &config.capabilities.initial {
            match c.as_str() {
                "read:workspace" => caps.push(Capability::new("read", "filesystem", &ws_str)),
                "search:code" => caps.push(Capability::new("search", "filesystem", &ws_str)),
                "write:src" => caps.push(Capability::new(
                    "write",
                    "filesystem",
                    &format!("{ws_str}/src"),
                )),
                value if value.starts_with("secret:") => {
                    let scope = value.trim_start_matches("secret:");
                    let Some((resource, requested_scope)) = scope.split_once(':') else {
                        return Err(RuntimeError::Config(format!(
                            "invalid initial secret capability: {value}"
                        )));
                    };
                    if resource.is_empty()
                        || requested_scope.is_empty()
                        || scope.chars().any(|c| {
                            !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
                        })
                    {
                        return Err(RuntimeError::Config(format!(
                            "invalid initial secret capability: {value}"
                        )));
                    }
                    caps.push(Capability::new("use", "secret", scope));
                }
                _ => {
                    return Err(RuntimeError::Config(format!(
                        "unknown initial capability: {c}"
                    )))
                }
            }
        }
        if caps.is_empty() {
            caps.push(Capability::new("read", "filesystem", &ws_str));
            caps.push(Capability::new("search", "filesystem", &ws_str));
        }
        let caps = CapabilitySet::new(caps);

        let mut audit = AuditWriter::open(base_dir.join("audit.jsonl"))
            .map_err(|e| RuntimeError::Io(e.to_string()))?;
        transaction::recover(&base_dir, &mut audit)?;
        let recovered = aivm_tools::recover_workspace_writes(&workspace)
            .map_err(|error| RuntimeError::Io(error.to_string()))?;
        if recovered > 0 {
            let mut record = aivm_audit::AuditRecord::new(
                0,
                &config.name,
                "recovery",
                &format!("workspace-recovery-{}", uuid::Uuid::new_v4()),
                "INIT",
                "recovery",
                "workspace",
                "allow",
                &policy.name,
            );
            record.result = format!("removed {recovered} interrupted atomic writes");
            audit
                .append(record)
                .map_err(|error| RuntimeError::Io(error.to_string()))?;
        }
        let mut gateway = ToolGateway::new(
            workspace.clone(),
            policy.clone(),
            caps,
            audit,
            &config.name,
            &format!("sess_{}", config.name),
        );
        // G4 §26: secret broker (patterns จาก yaml + values จาก secrets.yaml
        // ของ operator) — ไม่มีไฟล์ = broker ว่าง = deny หมด (fail-closed)
        let mut broker = aivm_secrets::SecretBroker::new(config.secrets.clone(), None);
        load_secrets_file(&base_dir.join(SECRETS_FILE), &mut broker)?;
        gateway = gateway.with_secret_broker(broker);
        let mut cube = Cube::new(&format!("task_{}", config.name));
        // กู้ state แบบ dynamic (transition ที่ validate แล้ว + lease ที่ยังใช้ได้)
        // Only a missing state file represents a fresh runtime. Corrupt or
        // unreadable state must never reset consumed quotas or revocations.
        let state_path = base_dir.join(STATE_FILE);
        match std::fs::read_to_string(&state_path) {
            Ok(text) => {
                let saved: PersistedState = serde_json::from_str(&text)
                    .map_err(|e| RuntimeError::Config(format!("invalid persisted state: {e}")))?;
                cube = saved.cube;
                // Rebuild state-specific grants from fresh config, then merge
                // counters only (including legacy state without a fingerprint).
                gateway.caps.revoke_stale(&cube.current_state().to_string());
                for cap in state_grants(
                    cube.current_state(),
                    &workspace,
                    &config.network,
                    &policy.process.allow,
                ) {
                    gateway.caps.grant(cap);
                }
                restore_cap_usage(&mut gateway.caps, &saved.caps);
                // G4b: ฟื้น leases ที่ยังใช้ได้ (หมดอายุ/หมดโควต้า/จบแล้วทิ้ง)
                gateway.restore_secret_leases(&cube, saved.leases);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not a fresh state file.
                match std::fs::symlink_metadata(&state_path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(RuntimeError::Io("persisted state is inaccessible".into())),
                }
            }
            Err(e) => {
                return Err(RuntimeError::Io(format!(
                    "cannot read persisted state: {e}"
                )))
            }
        }
        let memory = Memory::new(base_dir.join("memory"));
        // ผูกระดับ isolation จาก config (Phase 7): ค่าแปลก = บูตไม่ขึ้น
        // (fail-closed ไม่เงียบไปใช้ Process) ระดับที่ยังไม่มี backend จะ
        // DENY ทุก process.exec ที่ gateway พร้อม audit อยู่ดี
        let level = SandboxLevel::from_str(&config.runtime.isolation)
            .map_err(|e| RuntimeError::Config(e.to_string()))?;
        config
            .build
            .validate()
            .map_err(|e| RuntimeError::Config(e.to_string()))?;
        if let Some(verifier) = &config.verification {
            verifier
                .validate()
                .map_err(|e| RuntimeError::Config(e.to_string()))?;
            if verifier.executable.starts_with("build:") && !config.build.enabled {
                return Err(RuntimeError::Config(
                    "build verifier requires build.enabled".into(),
                ));
            }
        }
        gateway.verifier = config.verification.clone();
        gateway.build = config.build.clone();
        gateway.level = level;
        gateway.container_cfg = config.runtime.container.clone();
        gateway.limits = resource_limits(&config.resources)?;
        gateway.state_path = Some(base_dir.join(STATE_FILE));
        // ส่ง config MicroVM ลง gateway (เฉพาะบิลด์ที่เปิดฟีเจอร์)
        // ไม่มีบล็อก `microvm:` ใน yaml (= `None`) gateway จะใช้ค่า default
        // ที่ deny ตั้งแต่ artifact หาย — ไม่มีทางรันโดยไม่ตั้งใจ
        #[cfg(feature = "microvm")]
        {
            gateway.microvm_cfg = config.microvm.clone();
        }
        // ส่ง config Hardware Isolation ลง gateway (เฉพาะบิลด์ที่เปิดฟีเจอร์)
        // ไม่มีบล็อก `hardware:` ใน yaml (= `None`) gateway จะใช้ค่า default
        // ที่ deny ตั้งแต่ artifact หาย — ไม่มีทางรันโดยไม่ตั้งใจ
        #[cfg(feature = "hardware")]
        {
            gateway.hardware_cfg = config.hardware.clone();
        }
        let sandbox = Sandbox::new(level, gateway.limits.clone());
        let model_cfg = config.inference_model_config()?;
        // สร้างโมเดลผ่าน factory — provider ที่ไม่รู้จัก/ไม่มีฟีเจอร์จะ fail-closed
        let model: Box<dyn Model> =
            create_model(&model_cfg).map_err(|e| RuntimeError::Config(e.to_string()))?;

        Ok(Self {
            cube,
            config,
            base_dir,
            workspace,
            policy,
            gateway,
            memory,
            sandbox,
            model,
            model_cfg,
            op_seq: 0,
            transaction_failed: false,
            #[cfg(test)]
            transaction_hook: |_| Ok(()),
        })
    }

    /// เดิน state ไปข้างหน้าแบบ validate พร้อมจัดการ capability แบบ dynamic (§14)
    ///
    /// 1. `Cube::transition` ตรวจ edge + guard (fail-closed)
    /// 2. lease ที่ผูกกับ state และหมดความหมายแล้วถูก revoke (§14.3)
    /// 3. สิทธิ์ของ state ใหม่ออกแบบ idempotent (ให้เมื่อจำเป็น JIT, §14.2)
    /// 4. ทุก grant/revoke ถูก audit ถ้าปฏิเสธ state จะไม่ขยับ
    ///
    /// คืน `(granted, revoked)`
    pub fn transition_to(
        &mut self,
        next: AgentState,
        guards: &TransitionGuards,
    ) -> Result<(usize, usize), RuntimeError> {
        self.ensure_ready()?;
        let mut next_cube = self.cube.clone();
        next_cube
            .transition(next, guards)
            .map_err(|e| RuntimeError::Transition(e.to_string()))?;
        let state = next.to_string();
        let mut next_caps = self.gateway.caps.clone();
        let revoked = next_caps.revoke_stale(&state);
        let mut granted = 0;
        let mut granted_labels = Vec::new();
        for cap in state_grants(
            next,
            &self.workspace,
            &self.config.network,
            &self.policy.process.allow,
        ) {
            let label = format!("{}:{}", cap.action, cap.scope);
            if next_caps.grant(cap) {
                granted_labels.push(label);
                granted += 1;
            }
        }
        let before = self.saved_state();
        let previous_cube = self.cube.clone();
        let previous_caps = self.gateway.caps.clone();
        self.cube = next_cube;
        self.gateway.caps = next_caps;
        let details = format!("granted={granted} revoked={revoked} grants={granted_labels:?}");
        if let Err(error) = self.commit_state_change("transition", &state, &details, before) {
            self.cube = previous_cube;
            self.gateway.caps = previous_caps;
            return Err(error);
        }
        self.gateway.clear_quarantine();
        Ok((granted, revoked))
    }

    /// Approve PENDING secret lease (G4b — operator เท่านั้น ไม่ใช่ agent):
    /// exact lease id + ต้อง pending อยู่ + ระบุผู้ approve + audit ระบุคน
    /// คืนสรุป lease (ไม่มี value) approve แล้วใช้ได้ตาม max_uses/TTL เดิม
    pub fn approve_secret_lease(
        &mut self,
        lease_id: &str,
        approved_by: &str,
    ) -> Result<aivm_secrets::LeaseSummary, RuntimeError> {
        self.ensure_ready()?;
        let before = self.saved_state();
        let broker = self
            .gateway
            .secret_broker_mut()
            .ok_or_else(|| RuntimeError::Secret("secret broker not configured".into()))?;
        let lease = broker
            .approve_lease(lease_id, approved_by)
            .map_err(|e| RuntimeError::Secret(e.to_string()))?;
        let summary = aivm_secrets::LeaseSummary {
            id: lease.id.clone(),
            tool: lease.request.tool.clone(),
            resource: lease.request.resource.clone(),
            scope: lease.request.scope.clone(),
            purpose: lease.request.purpose.clone(),
            status: lease.status,
            uses: lease.uses,
            max_uses: lease.request.max_uses,
            hitl_approved: lease.hitl_approved,
            approved_by: lease.approved_by.clone(),
        };
        if let Err(error) =
            self.commit_state_change("secret-approve", &summary.id, approved_by, before)
        {
            if let Some(broker) = self.gateway.secret_broker_mut() {
                let _ = broker.revoke_lease(&summary.id);
            }
            return Err(error);
        }
        Ok(summary)
    }

    /// persist cube ที่ validate แล้ว + lease ที่ยังใช้ได้ เพื่อให้
    /// `transition_to` รอดข้าม restart supervisor เรียกหลัง run/transition/create
    pub fn persist(&self) -> Result<(), RuntimeError> {
        self.ensure_ready()?;
        let saved = self.saved_state();
        let text =
            serde_json::to_string_pretty(&saved).map_err(|e| RuntimeError::Io(e.to_string()))?;
        let path = self.base_dir.join(STATE_FILE);
        aivm_tools::state_store::write_private(&path, &text)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;
        Ok(())
    }

    fn ensure_ready(&self) -> Result<(), RuntimeError> {
        if self.transaction_failed {
            return Err(RuntimeError::Io(
                "runtime transaction requires restart/recovery".into(),
            ));
        }
        transaction::ensure_clear(&self.base_dir)
    }

    fn saved_state(&self) -> PersistedState {
        PersistedState {
            cube: self.cube.clone(),
            caps: self.gateway.caps.clone(),
            leases: self.gateway.live_secret_leases(),
        }
    }

    /// ล้มเหลวหลัง publish journal ต้อง fence จน restart; ห้ามใช้ state ที่ยังไม่รู้ผล
    fn commit_state_change(
        &mut self,
        action: &str,
        resource: &str,
        details: &str,
        before: PersistedState,
    ) -> Result<(), RuntimeError> {
        let after = self.saved_state();
        #[cfg(test)]
        let mut hook = self.transaction_hook;
        #[cfg(not(test))]
        let mut hook = |_: &str| Ok(());
        let result = transaction::commit(
            &self.base_dir,
            &mut self.gateway.audit,
            &self.config.name,
            &self.policy.name,
            action,
            resource,
            details,
            before,
            after,
            &mut hook,
        );
        if let Err(error) = result {
            self.transaction_failed = true;
            self.gateway.block_operations();
            return Err(RuntimeError::Io(format!(
                "state transaction outcome requires restart/recovery: {error}"
            )));
        }
        Ok(())
    }

    fn audit_op(
        &mut self,
        action: &str,
        resource: &str,
        result: &str,
        state: &str,
    ) -> Result<(), RuntimeError> {
        self.audit_op_decision(action, resource, result, state, "allow")
    }

    fn audit_op_decision(
        &mut self,
        action: &str,
        resource: &str,
        result: &str,
        state: &str,
        decision: &str,
    ) -> Result<(), RuntimeError> {
        self.op_seq += 1;
        let mut rec = AuditRecord::new(
            0,
            &self.config.name,
            &format!("sess_{}", self.config.name),
            &format!("state_{:06}", self.op_seq),
            state,
            action,
            resource,
            decision,
            &self.policy.name,
        );
        rec.capability = resource.to_string();
        rec.result = result.to_string();
        self.gateway
            .audit
            .append(rec)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;
        Ok(())
    }

    /// หนึ่งก้าวของ main loop แบบผ่านตัวกลาง (§23): ให้โมเดลคิดจาก context
    /// แล้วรัน filesystem read ผ่าน gateway คืนข้อความของโมเดล
    pub fn step(&mut self, context: &str) -> Result<String, RuntimeError> {
        self.ensure_ready()?;
        let _mem = self.memory.retrieve(&self.cube);
        let model_name = self.model_cfg.name.clone();
        self.audit_op("inference", &model_name, "started", "step")?;
        let intent = match self.model.reason(context) {
            Ok(intent) => {
                self.audit_op("inference", &model_name, "completed", "step")?;
                intent
            }
            Err(error) => {
                self.audit_op("inference", &model_name, "failed", &error.to_string())?;
                return Err(RuntimeError::Config(format!("inference failed: {error}")));
            }
        };
        // สาธิตการผ่านตัวกลาง: ค้น workspace ด้วย search (ถูก audit ทุกครั้ง)
        let req = ToolRequest {
            tool: "code.search".into(),
            path: intent.clone(),
            content: None,
        };
        match self.gateway.dispatch(&mut self.cube, &req) {
            Ok(_) => Ok(intent),
            Err(e) => Ok(format!("{intent} [tool denied: {e}]")),
        }
    }

    /// Workflow แบบ opt-in ของ operator; model-only reason/agent เดิมไม่เปลี่ยนโดยปริยาย
    pub fn run_semantic(
        &mut self,
        task: &semantic::SemanticTask,
        prompt: &str,
        budget: &semantic::SemanticBudget,
    ) -> Result<semantic::SemanticRun, RuntimeError> {
        self.ensure_ready()?;
        let name = self.model_cfg.name.clone();
        self.audit_op("inference", &name, "started", "semantic")?;
        let result = semantic::run(
            &*self.model,
            &mut self.gateway,
            &mut self.cube,
            task,
            prompt,
            budget,
        )
        .map_err(RuntimeError::Config);
        let outcome = match &result {
            Ok(run)
                if matches!(
                    run.status,
                    aivm_tools::verification::VerificationStatus::Verified
                ) =>
            {
                "verified"
            }
            _ => "failed",
        };
        self.audit_op("inference", &name, outcome, "semantic")?;
        result
    }

    /// Agent loop เต็มรอบ (Phase 5): observe → reason → intent → execute → observe
    /// โมเดลต้องตอบเป็น JSON object เดียว (ดู `agent` module); ทุก intent
    /// วิ่งผ่าน gateway เท่านั้น คืนบันทึกการเดินทางของทั้งรอบ
    ///
    /// ถ้า `workspace` ให้มา จะสร้าง RAG index และผสม context ที่เกี่ยวข้อง
    /// ลงใน prompt ก่อนเรียก model (Phase 6 CubeRAG, state-aware)
    pub fn run_agent(
        &mut self,
        task: &str,
        max_steps: usize,
        workspace: Option<&std::path::Path>,
    ) -> Result<agent::AgentRun, RuntimeError> {
        self.ensure_ready()?;
        let model_name = self.model_cfg.name.clone();
        self.audit_op("inference", &model_name, "started", "agent")?;
        // RAG อ่านจาก gateway workspace ที่ runtime เป็นเจ้าของเท่านั้น
        // loop สร้างและตรวจ snapshot ผ่าน gateway ก่อน inference แต่ละรอบ
        let rag_index = workspace.map(|_| aivm_cube::rag::RagIndex::default());
        let result = agent::run_loop(
            &*self.model,
            &mut self.gateway,
            &mut self.cube,
            task,
            max_steps,
            rag_index.as_ref(),
        );
        match &result {
            Ok(_) => self.audit_op("inference", &model_name, "completed", "agent")?,
            Err(error) => self.audit_op("inference", &model_name, "failed", &error.to_string())?,
        }
        result
    }

    pub fn inspect(&self) -> String {
        // แสดง grants จริงโดยไม่อ้างว่า grant เพียงอย่างเดียวผ่าน policy แล้ว
        let state = self.cube.current_state().to_string();
        let grants: Vec<_> = self.gateway.caps.caps.iter().map(|cap| {
            serde_json::json!({
                "grant": cap,
                "usable_in_state": cap.check_usable().is_ok()
                    && cap.condition.as_ref().is_none_or(|condition| !condition.is_stale_in(&state)),
            })
        }).collect();
        format!(
            "AI VM: {}\nState:\n  {}\nModel:\n  {}\nResources:\n  CPU      {}\n  Memory   {}\nCapabilities (grants; policy and constraints also apply):\n{}\nPolicy:\n{}\nProcesses:\n  not measured\nMemory:\n  {} cells\nDenials:\n  {}\n",
            self.config.name, state, self.model_cfg.name,
            self.config.resources.cpu, self.config.resources.memory,
            serde_json::to_string_pretty(&grants).expect("capabilities serialize"),
            serde_json::to_string_pretty(&self.gateway.policy).expect("policy serializes"),
            self.cube.cells_len(), self.cube.denials(),
        )
    }
}

/// สิทธิ์ที่ให้ตาม state (สเปก §14.2) lease ทุกใบมี scope ผูกกับ state
/// (ออกจาก state แล้ว revoke อัตโนมัติ) และจำกัดเวลาถ้าสิทธิ์สูง (เน็ตเวิร์ก)
/// สิทธิ์พื้นฐาน read/search จาก INIT ไม่มี condition จึงรอดเสมอ
fn state_grants(
    next: AgentState,
    workspace: &Path,
    network: &NetworkBlock,
    process_allow: &[String],
) -> Vec<Capability> {
    let ws = workspace.to_string_lossy().to_string();
    let src = format!("{ws}/src");
    let mut out = vec![];
    // สิทธิ์ write + execute เริ่มที่ MODIFY อยู่ต่อถึง VALIDATE (§14.2)
    if matches!(next, AgentState::Modify | AgentState::Validate) {
        let mut write = Capability::new("write", "filesystem", &src);
        write.condition = Some(Condition {
            protocol: None,
            require_state: None,
            valid_states: vec!["MODIFY".to_string(), "VALIDATE".to_string()],
        });
        out.push(write);
        // execute ผูกกับ exe ที่ allowlist ทีละใบ (least privilege รายใบ)
        for exe in process_allow {
            let mut e = Capability::new("execute", "process", exe);
            e.condition = Some(Condition {
                protocol: None,
                require_state: None,
                valid_states: vec!["MODIFY".to_string(), "VALIDATE".to_string()],
            });
            out.push(e);
        }
    }
    if next == AgentState::Validate {
        for host in &network.allow {
            let scope = if host.contains(':') {
                host.clone()
            } else {
                format!("{host}:443")
            };
            for action in ["network:fetch", "network:connect"] {
                if network.read_only && action == "network:connect" {
                    continue;
                }
                let mut net = Capability::new(action, "network", &scope);
                net.condition = Some(Condition {
                    protocol: Some("https".into()),
                    require_state: None,
                    valid_states: vec!["VALIDATE".into()],
                });
                net.constraints.require_tls = true;
                net.constraints.allowed_ports = vec![scope
                    .rsplit(':')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(443)];
                // เพดานต่อ task จาก config (operator กำหนด ไม่มี = ไม่จำกัดข้อนั้น)
                net.constraints.max_calls = network.max_calls;
                net.constraints.max_total_bytes = network.max_total_bytes;
                net.expiration = Some(aivm_capability::now_secs() + NETWORK_LEASE_SECS);
                out.push(net);
            }
        }
    }
    out
}

fn resource_limits(resources: &ResourceBlock) -> Result<ResourceLimits, RuntimeError> {
    fn megabytes(value: &str) -> Result<u64, RuntimeError> {
        let value = value.trim().to_ascii_uppercase();
        let (digits, factor) = if let Some(v) = value.strip_suffix("GB") {
            (v, 1024)
        } else if let Some(v) = value.strip_suffix("MB") {
            (v, 1)
        } else {
            return Err(RuntimeError::Config(
                "resource size must use MB or GB".into(),
            ));
        };
        digits
            .trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(factor))
            .filter(|n| *n > 0)
            .ok_or_else(|| RuntimeError::Config("invalid resource size".into()))
    }
    if resources.cpu == 0 {
        return Err(RuntimeError::Config("CPU must be positive".into()));
    }
    let memory_mb = megabytes(&resources.memory)?;
    let storage_mb = megabytes(&resources.storage)?;
    Ok(ResourceLimits {
        cpu: resources.cpu,
        memory_mb,
        pids_max: 64,
        storage_mb,
    })
}

/// แปลงรายการ tools.allow ใน config เป็น absolute canonical path
/// ชื่อล้วนค้นแค่ /usr/bin กับ /bin (PATH ที่ runtime คุม) อย่างอื่น
/// ต้อง absolute เท่านั้น หาไม่เจอ/มี `/` ปน = ทิ้ง (fail-closed)
fn resolve_tool(name: &str) -> Option<String> {
    let cand = if Path::new(name).is_absolute() {
        PathBuf::from(name)
    } else {
        if name.contains('/') || name.contains('\0') {
            return None;
        }
        ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(name))
            .find(|p| p.is_file())?
    };
    let real = std::fs::canonicalize(&cand).ok()?;
    if !real.is_file() {
        return None;
    }
    Some(real.to_string_lossy().to_string())
}

fn resolve_runtime_tool(
    name: &str,
    workspace: &Path,
    build: &aivm_tools::build::BuildConfig,
) -> Option<String> {
    if let Some(name) = name.strip_prefix("build:") {
        return build
            .artifact_path(workspace, name)
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
    }
    resolve_tool(name)
}

/// โหลดค่า secrets ของ operator (G4 §26): ไฟล์ `{base}/secrets.yaml` รูป
/// `{resource: value}` — ไม่มีไฟล์ = broker ว่าง (deny หมด) ไม่ใช่ error
/// สิทธิ์ต้อง owner-only (0600) ไม่งั้นปฏิเสธทั้งไฟล์ (fail-closed:
/// secret ที่คนอื่นอ่านได้ = ไม่น่าไว้ใจแล้ว)
fn load_secrets_file(
    path: &Path,
    broker: &mut aivm_secrets::SecretBroker,
) -> Result<(), RuntimeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RuntimeError::Io(e.to_string())),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| RuntimeError::Io(e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(RuntimeError::Config(
                "secrets.yaml must be owner-only (0600)".into(),
            ));
        }
    }
    let map: HashMap<String, String> =
        serde_yaml::from_str(&text).map_err(|e| RuntimeError::Config(e.to_string()))?;
    for (k, v) in map {
        if k.is_empty() || k.len() > 128 || v.is_empty() || v.len() > 8192 {
            return Err(RuntimeError::Config("bad secrets.yaml entry".into()));
        }
        broker.register_secret(k, v);
    }
    Ok(())
}

fn absolutize(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(p)
}

fn resolve_scope(base_dir: &Path, workspace: &Path, scope: &str) -> String {
    if scope.starts_with("./") {
        // เทียบกับ VM home (ที่อยู่ของ aivm.yaml): ./workspace/src
        // หมายถึง <base>/workspace/src
        let rel = scope.trim_start_matches("./");
        if rel == "workspace" {
            return workspace.to_string_lossy().to_string();
        }
        if let Some(rest) = rel.strip_prefix("workspace/") {
            return workspace.join(rest).to_string_lossy().to_string();
        }
        return base_dir.join(rel).to_string_lossy().to_string();
    }
    if scope.starts_with("/workspace") {
        // แปลง /workspace แบบ virtual ในสเปกให้เป็นไดเรกทอรีจริง
        let rel = scope
            .trim_start_matches("/workspace")
            .trim_start_matches('/');
        if rel.is_empty() {
            return workspace.to_string_lossy().to_string();
        }
        return workspace.join(rel).to_string_lossy().to_string();
    }
    if Path::new(scope).is_absolute() {
        return scope.to_string();
    }
    // hostname ล้วน (เน็ตเวิร์ก) ผ่านไปตรง ๆ ไม่แตะ
    if !scope.contains('/') && !scope.contains('.') {
        return scope.to_string();
    }
    if !scope.contains('/') {
        return scope.to_string(); // hostname อย่าง github.com
    }
    workspace.join(scope).to_string_lossy().to_string()
}

/// สร้าง policy จาก context จริงร่วมกันทั้ง runtime และ config API
fn build_policy(config: &VmConfig, base_dir: &Path, workspace: &Path) -> Policy {
    let ws_str = workspace.to_string_lossy().to_string();
    let read_scopes: Vec<String> = if config.filesystem.read.is_empty() {
        vec![ws_str.clone()]
    } else {
        config
            .filesystem
            .read
            .iter()
            .map(|s| resolve_scope(base_dir, workspace, s))
            .collect()
    };
    let write_scopes: Vec<String> = if config.filesystem.write.is_empty() {
        vec![format!("{ws_str}/src")]
    } else {
        config
            .filesystem
            .write
            .iter()
            .map(|s| resolve_scope(base_dir, workspace, s))
            .collect()
    };

    Policy {
        name: format!("{}-default", config.name),
        deny_overrides: true,
        filesystem: aivm_policy::FsPolicy {
            read: read_scopes,
            write: write_scopes,
            deny: vec![
                format!("{ws_str}/.git/config"),
                "**/.env*".into(),
                "**/secrets/**".into(),
                format!("{ws_str}/policies"),
                format!("{ws_str}/audit"),
            ],
        },
        process: aivm_policy::ProcessPolicy {
            // allowlist มาจาก tools.allow ใน config เท่านั้น (ชื่อล้วน
            // ค้นใน /usr/bin:/bin แล้ว canonicalize ซ้ำ กัน PATH hijack)
            allow: config
                .tools
                .allow
                .iter()
                .filter_map(|s| resolve_runtime_tool(s, workspace, &config.build))
                .collect(),
            deny: vec!["/bin/sh".into(), "/bin/bash".into()],
        },
        network: aivm_policy::NetworkPolicy {
            read_only: config.network.read_only,
            allow: config.network.allow.clone(),
            deny: vec![
                "10.0.0.0/8".into(),
                "192.168.0.0/16".into(),
                "172.16.0.0/12".into(),
                "127.0.0.1".into(),
                "::1".into(),
                "169.254.169.254".into(),
            ],
        },
        system: Default::default(),
        rules: vec![],
        require_test_before_network: true,
    }
}

/// Config Loader และ Validator
pub mod config {
    use super::{absolutize, build_policy, validate_model_security, RuntimeError, VmConfig};
    use aivm_policy::PolicyManager;
    use std::path::Path;

    /// Validation result
    #[derive(Debug, Clone)]
    pub struct ValidationResult {
        pub config: VmConfig,
        pub warnings: Vec<String>,
    }

    /// โหลดและ validate config พร้อม policy versioning
    pub fn load_and_validate(
        config_path: &Path,
        policy_manager: &mut PolicyManager,
    ) -> Result<ValidationResult, RuntimeError> {
        load_and_validate_at(
            config_path,
            config_path.parent().unwrap_or(Path::new(".")),
            policy_manager,
        )
    }

    /// ระบุ VM home ชัดเจนเมื่อ config ต้นฉบับอยู่นอก VM home
    pub fn load_and_validate_at(
        config_path: &Path,
        base_dir: &Path,
        policy_manager: &mut PolicyManager,
    ) -> Result<ValidationResult, RuntimeError> {
        let config = VmConfig::from_file(config_path)?;
        let base_dir = absolutize(base_dir);
        let workspace = absolutize(&base_dir.join("workspace"));
        let mut warnings = Vec::new();

        // Validate config structure
        validate_config(&config, &mut warnings)?;

        // ห้ามคืน config ใหม่พร้อม policy เก่าที่มีความหมายต่างกันโดยเงียบ
        let default_policy = build_policy(&config, &base_dir, &workspace);
        if let Some(active) = policy_manager.get_active("default") {
            if serde_json::to_value(active).map_err(|e| RuntimeError::Policy(e.to_string()))?
                != serde_json::to_value(&default_policy)
                    .map_err(|e| RuntimeError::Policy(e.to_string()))?
            {
                return Err(RuntimeError::Policy(
                    "active default policy differs from config and VM home".into(),
                ));
            }
        } else {
            let doc = aivm_policy::PolicyDocument::new("default".into(), 1, default_policy);
            policy_manager
                .add_policy(doc)
                .map_err(|e| RuntimeError::Policy(e.to_string()))?;
        }

        Ok(ValidationResult { config, warnings })
    }

    fn validate_config(config: &VmConfig, warnings: &mut Vec<String>) -> Result<(), RuntimeError> {
        // Name required
        if config.name.is_empty() {
            return Err(RuntimeError::Config("vm name is required".into()));
        }

        validate_model_security(config)?;

        // Resources validation
        if config.resources.cpu == 0 {
            warnings.push("cpu not set, defaulting to 2".into());
        }
        if config.resources.memory.is_empty() {
            warnings.push("memory not set, defaulting to 1GB".into());
        }
        if config.resources.storage.is_empty() {
            warnings.push("storage not set, defaulting to 5GB".into());
        }

        // Filesystem validation
        if config.filesystem.read.is_empty() {
            warnings.push("filesystem.read is empty, will default to workspace".into());
        }
        if config.filesystem.write.is_empty() {
            warnings.push("filesystem.write is empty, will default to workspace/src".into());
        }

        // Tools validation
        if config.tools.allow.is_empty() {
            warnings.push("tools.allow is empty, no process.exec will be allowed".into());
        }

        // Capabilities validation
        if config.capabilities.initial.is_empty() {
            warnings.push("capabilities.initial is empty, will default to read+search".into());
        }

        // Policy validation
        if !config.policy.require_test_before_network {
            warnings.push(
                "require_test_before_network=false is ignored; runtime always requires tests before network access"
                    .into(),
            );
        }

        // Local model ที่ไม่ pin hash = น้ำหนักสลับไม่ได้จับ (I-8 ระดับ supply chain)
        if config.model.provider == "local"
            && config
                .model
                .local
                .as_ref()
                .is_none_or(|m| m.model_sha256.is_empty())
        {
            warnings.push(
                "local model is unpinned (set model.local.model_sha256) - weights can be \
                 swapped without detection"
                    .into(),
            );
        }

        Ok(())
    }
}

fn validate_model_security(config: &VmConfig) -> Result<(), RuntimeError> {
    match config.security.profile.as_str() {
        "development" | "production" => {}
        other => {
            return Err(RuntimeError::Config(format!(
                "unknown security.profile: {other}"
            )))
        }
    }
    if let Some(timeout) = config.model.total_timeout_ms {
        if timeout == 0 {
            return Err(RuntimeError::Config(
                "model.total_timeout_ms must be positive".into(),
            ));
        }
        if config.model.provider != "local"
            || config
                .model
                .local
                .as_ref()
                .is_none_or(|local| local.worker_path.is_none())
        {
            return Err(RuntimeError::Config(
                "model.total_timeout_ms requires a local worker_path".into(),
            ));
        }
    }
    if config.model.provider != "local" {
        return Ok(());
    }
    let local = config.model.local.as_ref().ok_or_else(|| {
        RuntimeError::Config("model.local is required when model.provider is local".into())
    })?;
    if config.security.profile == "production" && local.model_sha256.is_empty() {
        return Err(RuntimeError::Config(
            "security.profile=production requires model.local.model_sha256 for local models".into(),
        ));
    }
    if config.security.profile == "production" && local.worker_path.is_none() {
        return Err(RuntimeError::Config(
            "security.profile=production requires an isolated model.local.worker_path".into(),
        ));
    }
    verify_optional_artifact_pin(
        "controller",
        &local.controller_path,
        &local.controller_sha256,
    )?;
    if local.controller_path.is_some() && config.model.total_timeout_ms.is_none() {
        return Err(RuntimeError::Config(
            "controller_path requires model.total_timeout_ms".into(),
        ));
    }
    verify_artifact_pin("model", &local.model_path, &local.model_sha256)?;
    match (&local.worker_path, &local.worker_sha256) {
        (Some(path), Some(hash)) if !hash.is_empty() => {
            verify_artifact_pin("worker", path, hash)?;
        }
        (Some(_), Some(_)) if config.security.profile == "production" => {
            return Err(RuntimeError::Config(
                "production worker_sha256 must be a non-empty hash".into(),
            ));
        }
        (Some(_), None) if config.security.profile == "production" => {
            return Err(RuntimeError::Config(
                "security.profile=production requires model.local.worker_sha256 when worker_path is set".into(),
            ));
        }
        (Some(_), None) => {}
        (Some(_), Some(_)) => {}
        (None, Some(_)) => {
            return Err(RuntimeError::Config(
                "worker_sha256 requires worker_path".into(),
            ));
        }
        (None, None) => {}
    }
    verify_optional_artifact_pin("tokenizer", &local.tokenizer_path, &local.tokenizer_sha256)?;
    verify_optional_artifact_pin("config", &local.config_path, &local.config_sha256)?;
    match (&local.manifest_path, &local.manifest_sha256) {
        (Some(path), Some(hash)) => {
            verify_artifact_pin("manifest", path, hash)?;
            let text = std::fs::read_to_string(path)
                .map_err(|e| RuntimeError::Config(format!("manifest unreadable: {e}")))?;
            let manifest: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| RuntimeError::Config(format!("manifest is not valid JSON: {e}")))?;
            let declared = manifest
                .get("model_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| RuntimeError::Config("manifest must declare model_sha256".into()))?;
            if !declared.eq_ignore_ascii_case(&local.model_sha256) {
                return Err(RuntimeError::Config(
                    "manifest model_sha256 does not match model.local.model_sha256".into(),
                ));
            }
        }
        (None, None) if config.security.profile == "production" => {
            return Err(RuntimeError::Config(
                "security.profile=production requires model.local.manifest_path and manifest_sha256".into(),
            ));
        }
        (None, None) => {}
        _ => {
            return Err(RuntimeError::Config(
                "manifest_path and manifest_sha256 must be provided together".into(),
            ));
        }
    }
    Ok(())
}

fn verify_artifact_pin(kind: &str, path: &str, hash: &str) -> Result<(), RuntimeError> {
    if hash.is_empty() {
        return Ok(());
    }
    aivm_model::verify_model_file(path, hash)
        .map_err(|e| RuntimeError::Config(format!("{kind} artifact verification failed: {e}")))
}

fn verify_optional_artifact_pin(
    kind: &str,
    path: &Option<String>,
    hash: &Option<String>,
) -> Result<(), RuntimeError> {
    match (path, hash) {
        (None, None) => Ok(()),
        (Some(path), Some(hash)) if !hash.is_empty() => verify_artifact_pin(kind, path, hash),
        _ => Err(RuntimeError::Config(format!(
            "{kind}_path and {kind}_sha256 must be provided together"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> VmConfig {
        VmConfig::from_yaml(
            r#"
name: t
filesystem:
  read: [./workspace]
  write: [./workspace/src]
network:
  allow: [github.com]
capabilities:
  initial: [read:workspace, search:code]
"#,
        )
        .unwrap()
    }

    #[test]
    fn operator_config_rejects_unknown_security_and_isolation_fields() {
        for yaml in [
            "name: typo\nruntime:\n  isolaton: container\n",
            "name: typo\nsecurity:\n  profle: production\n",
            "name: typo\nnetwork:\n  max_call: 1\n",
        ] {
            assert!(VmConfig::from_yaml(yaml).is_err(), "accepted typo: {yaml}");
        }
    }

    #[test]
    fn config_loader_and_runtime_build_the_same_policy_for_the_actual_vm_home() {
        let base =
            std::env::temp_dir().join(format!("aivm-policy-context-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(base.join("workspace")).unwrap();
        let path = base.join("aivm.yaml");
        std::fs::write(&path, "name: policy-context\nfilesystem:\n  read: ['./workspace/src']\n  write: ['/workspace/src']\npolicy:\n  require_test_before_network: false\n").unwrap();
        let mut manager = aivm_policy::PolicyManager::new();
        let loaded = config::load_and_validate_at(&path, &base, &mut manager).unwrap();
        let runtime = Runtime::init(loaded.config.clone(), base.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(manager.get_active("default").unwrap()).unwrap(),
            serde_json::to_value(&runtime.policy).unwrap()
        );
        assert!(runtime.policy.require_test_before_network);
        assert!(loaded
            .warnings
            .iter()
            .any(|warning| warning.contains("always requires tests")));
        let mut from_home = aivm_policy::PolicyManager::new();
        config::load_and_validate(&path, &mut from_home).unwrap();
        assert_eq!(
            serde_json::to_value(manager.get_active("default").unwrap()).unwrap(),
            serde_json::to_value(from_home.get_active("default").unwrap()).unwrap()
        );
        std::fs::write(
            &path,
            "name: policy-context\nfilesystem:\n  read: ['./workspace/other']\n",
        )
        .unwrap();
        assert!(config::load_and_validate_at(&path, &base, &mut manager).is_err());
        aivm_audit::clear_flags(&base);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn inspect_reports_real_grants_and_never_invents_read_or_process_counts() {
        let base =
            std::env::temp_dir().join(format!("aivm-inspect-grants-{}", uuid::Uuid::new_v4()));
        let config = VmConfig::from_yaml("name: inspect\ncapabilities:\n  initial: [search:code]\nnetwork:\n  allow: [example.com]\n").unwrap();
        let mut runtime = Runtime::init(config, base.clone()).unwrap();
        let initial = runtime.inspect();
        assert!(initial.contains("\"action\": \"search\""));
        assert!(!initial.contains("\"action\": \"read\""));
        assert!(initial.contains("Processes:\n  not measured"));
        runtime
            .transition_to(AgentState::Analyze, &Default::default())
            .unwrap();
        runtime
            .transition_to(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    ..Default::default()
                },
            )
            .unwrap();
        runtime
            .transition_to(
                AgentState::Validate,
                &TransitionGuards {
                    tests_passed: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let current = runtime.inspect();
        assert!(current.contains("network:fetch"));
        assert!(current.contains("example.com:443"));
        assert!(current.contains("\"expiration\""));
        assert!(!current.contains("Denied:\n"));
        runtime
            .gateway
            .caps
            .caps
            .iter_mut()
            .for_each(|cap| cap.expiration = Some(0));
        assert!(runtime.inspect().contains("\"usable_in_state\": false"));
        aivm_audit::clear_flags(&base);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn restore_keeps_original_network_lease_expiry() {
        let mut fresh = Capability::new("network:fetch", "network", "example.com:443");
        fresh.expiration = Some(aivm_capability::now_secs() + 300);
        let mut old = fresh.clone();
        old.expiration = Some(aivm_capability::now_secs() + 10);
        old.used_count = 3;
        let mut current = CapabilitySet::new(vec![fresh]);
        let saved = CapabilitySet::new(vec![old.clone()]);
        restore_cap_usage(&mut current, &saved);
        assert_eq!(current.caps[0].expiration, old.expiration);
        assert_eq!(current.caps[0].used_count, 3);
    }

    #[test]
    fn production_local_model_requires_matching_manifest() {
        let dir = std::env::temp_dir().join(format!("aivm-manifest-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let model = dir.join("model.gguf");
        let manifest = dir.join("model.manifest.json");
        let worker = dir.join("model-worker");
        std::fs::write(&model, b"model-bytes").unwrap();
        std::fs::write(&worker, b"worker-bytes").unwrap();
        let model_hash = aivm_model::model_file_sha256(model.to_str().unwrap()).unwrap();
        let worker_hash = aivm_model::model_file_sha256(worker.to_str().unwrap()).unwrap();
        std::fs::write(&manifest, format!("{{\"model_sha256\":\"{model_hash}\"}}")).unwrap();
        let manifest_hash = aivm_model::model_file_sha256(manifest.to_str().unwrap()).unwrap();
        let yaml = format!(
            "name: production\nsecurity:\n  profile: production\nmodel:\n  provider: local\n  local:\n    model_path: {}\n    model_sha256: {}\n    worker_path: {}\n    worker_sha256: {}\n    manifest_path: {}\n    manifest_sha256: {}\n",
            model.display(),
            model_hash,
            worker.display(),
            worker_hash,
            manifest.display(),
            manifest_hash
        );
        let cfg = VmConfig::from_yaml(&yaml).unwrap();
        assert!(validate_model_security(&cfg).is_ok());
        std::fs::write(&manifest, b"{\"model_sha256\":\"bad\"}").unwrap();
        assert!(validate_model_security(&cfg).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn total_inference_budget_is_forwarded_and_cannot_be_silently_ignored() {
        // รับ config จาก YAML จริงและห้ามรับ budget เมื่อ backend ไม่มี worker บังคับใช้
        let mut cfg = VmConfig::from_yaml("name: bounded\nmodel:\n  provider: local\n  total_timeout_ms: 2500\n  local:\n    model_path: unused.gguf\n    worker_path: unused-worker\n").unwrap();
        let model = cfg.inference_model_config().unwrap();
        assert_eq!(model.worker_limits.unwrap().total_timeout_ms, Some(2500));
        cfg.model.total_timeout_ms = Some(0);
        assert!(cfg
            .inference_model_config()
            .unwrap_err()
            .to_string()
            .contains("must be positive"));
        cfg.model.total_timeout_ms = Some(2500);
        cfg.model.local.as_mut().unwrap().worker_path = None;
        assert!(cfg
            .inference_model_config()
            .unwrap_err()
            .to_string()
            .contains("worker_path"));
        cfg.model.provider = "echo".into();
        assert!(cfg
            .inference_model_config()
            .unwrap_err()
            .to_string()
            .contains("worker_path"));
    }

    fn test_runtime(tag: &str) -> (Runtime, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
        let rt = Runtime::init(test_config(), base.clone()).unwrap();
        (rt, base)
    }

    #[test]
    fn cloud_provider_blocks_reach_the_runtime_model_factory() {
        for (provider, key) in [
            ("openai", "AIVM_RUNTIME_TEST_OPENAI_CONFIG_KEY"),
            ("anthropic", "AIVM_RUNTIME_TEST_ANTHROPIC_CONFIG_KEY"),
        ] {
            std::env::set_var(key, "test-only");
            let config = VmConfig::from_yaml(&format!(
                "name: cloud\nmodel:\n  provider: {provider}\n  {provider}:\n    api_key_env: {key}\n    model: selected-model\n"
            )).unwrap();
            let (rt, base) = test_runtime(provider);
            drop(rt);
            let rt = Runtime::init(config, base.clone()).unwrap();
            let (model, env) = if provider == "openai" {
                let config = rt.model_cfg.openai.as_ref().unwrap();
                (&config.model, &config.api_key_env)
            } else {
                let config = rt.model_cfg.anthropic.as_ref().unwrap();
                (&config.model, &config.api_key_env)
            };
            assert_eq!(model, "selected-model");
            assert_eq!(env, key);
            let roundtrip =
                VmConfig::from_yaml(&serde_yaml::to_string(&rt.config).unwrap()).unwrap();
            assert_eq!(roundtrip.model.provider, provider);
            drop(rt);
            std::env::remove_var(key);
            aivm_audit::clear_flags(&base);
            let _ = std::fs::remove_dir_all(base);
        }
    }

    #[test]
    fn write_denied_before_modify_grant() {
        let (mut rt, base) = test_runtime("deny");
        let r = rt.gateway.write(&mut rt.cube, "src/a.rs", "x");
        assert!(r.is_err(), "INIT must not hold write");
        aivm_audit::clear_flags(&base);
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn transition_grants_write_and_persists() {
        let (mut rt, base) = test_runtime("grant");
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        let (g, _) = rt
            .transition_to(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    confidence_threshold: CONFIDENCE_THRESHOLD,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(g, 1);
        assert!(rt.gateway.write(&mut rt.cube, "src/a.rs", "x").is_ok());
        rt.persist().unwrap();
        // บูตใหม่กู้ grant + state เดิม ไม่รีเซ็ตกลับ INIT
        let rt2 = Runtime::init(test_config(), base.clone()).unwrap();
        assert_eq!(rt2.cube.current_state(), AgentState::Modify);
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn transition_grants_execute_for_allowlisted_tool() {
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-exec-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = VmConfig::from_yaml(
            "name: t\ntools:\n  allow: [/bin/true]\ncapabilities:\n  initial: [read:workspace, search:code]\n",
        )
        .unwrap();
        // tools.allow แปลงเป็น process allowlist แบบ canonical
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let mut rt = Runtime::init(cfg, base.clone()).unwrap();
        assert!(rt
            .policy
            .process
            .allow
            .contains(&real.to_string_lossy().to_string()));
        // INIT ไม่มี execute: MODIFY ให้ทีเดียว 2 ใบ (write + execute)
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        let (granted, _) = rt
            .transition_to(
                AgentState::Modify,
                &TransitionGuards {
                    confidence: 0.95,
                    confidence_threshold: CONFIDENCE_THRESHOLD,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(granted, 2);
        let scope = real.to_string_lossy().to_string();
        assert!(rt
            .gateway
            .caps
            .authorize("execute", "process", &scope)
            .is_ok());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn transition_denied_leaves_state_untouched() {
        let (mut rt, base) = test_runtime("jump");
        let r = rt.transition_to(AgentState::Deploy, &TransitionGuards::default());
        assert!(r.is_err());
        assert_eq!(rt.cube.current_state(), AgentState::Init);
        assert!(rt.gateway.caps.caps.iter().all(|c| c.action != "write"));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn failed_transition_persist_fences_runtime_until_recovery() {
        let (mut rt, base) = test_runtime("transition-rollback");
        std::fs::create_dir(base.join(STATE_FILE)).unwrap();
        assert!(rt
            .transition_to(AgentState::Analyze, &TransitionGuards::default())
            .is_err());
        assert_eq!(rt.cube.current_state(), AgentState::Init);
        let log = std::fs::read_to_string(base.join("audit.jsonl")).unwrap();
        assert!(log.contains("transition-prepare"));
        assert!(base.join(transaction::JOURNAL).exists());
        assert!(rt.persist().is_err());
        assert!(rt.gateway.read(&mut rt.cube, "src/seed.txt").is_err());
        assert!(!log.contains("transition-commit"));
        assert!(aivm_audit::AuditWriter::verify(base.join("audit.jsonl")).is_ok());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn corrupt_state_file_prevents_boot_without_resetting_quotas() {
        let (mut rt, base) = test_runtime("corrupt");
        std::fs::write(rt.workspace.join("data.txt"), "data").unwrap();
        rt.gateway.caps = CapabilitySet::new(vec![Capability::new(
            "read",
            "filesystem",
            &rt.workspace.to_string_lossy(),
        )
        .with_max_uses(1)]);
        rt.gateway.read(&mut rt.cube, "data.txt").unwrap();
        rt.persist().unwrap();
        drop(rt);
        let mut restored = Runtime::init(test_config(), base.clone()).unwrap();
        let cap = &restored.gateway.caps.caps[0];
        assert_eq!(cap.used_count, 1);
        assert_eq!(cap.max_uses, None);
        assert!(restored
            .gateway
            .read(&mut restored.cube, "data.txt")
            .is_ok());
        drop(restored);
        std::fs::write(base.join(STATE_FILE), "{not json").unwrap();
        assert!(matches!(
            Runtime::init(test_config(), base.clone()),
            Err(RuntimeError::Config(_))
        ));
        assert_eq!(
            std::fs::read_to_string(base.join(STATE_FILE)).unwrap(),
            "{not json"
        );
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn inaccessible_state_is_not_treated_as_a_new_runtime() {
        let (rt, base) = test_runtime("inaccessible-state");
        drop(rt);
        std::fs::create_dir(base.join(STATE_FILE)).unwrap();
        assert!(matches!(
            Runtime::init(test_config(), base.clone()),
            Err(RuntimeError::Io(_))
        ));
        std::fs::remove_dir(base.join(STATE_FILE)).unwrap();
        std::os::unix::fs::symlink(base.join("missing-state"), base.join(STATE_FILE)).unwrap();
        assert!(matches!(
            Runtime::init(test_config(), base.clone()),
            Err(RuntimeError::Io(_))
        ));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    // Phase 7: `runtime.isolation` แปลกต้องบูตไม่ขึ้น (fail-closed ไม่เงียบ
    // ไปใช้ Process) ค่าเริ่มต้นต้องเป็น Process เหมือนเดิม
    #[test]
    fn unknown_isolation_fails_boot() {
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-iso-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut cfg = test_config();
        cfg.runtime.isolation = "docker".into();
        assert!(Runtime::init(cfg, base.clone()).is_err());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn container_config_reaches_gateway() {
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-container-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut cfg = test_config();
        cfg.runtime.isolation = "container".into();
        cfg.runtime.container.cgroup_root = "/sys/fs/cgroup/custom-delegation".into();
        let rt = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(rt.gateway.level, SandboxLevel::Container);
        assert_eq!(
            rt.gateway.container_cfg.cgroup_root,
            PathBuf::from("/sys/fs/cgroup/custom-delegation")
        );
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn isolation_selects_gateway_level() {
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-lvl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // ค่าเริ่มต้น (sandbox) = Process
        let (rt, _) = test_runtime("lvl-default");
        assert_eq!(rt.gateway.level, SandboxLevel::Process);
        // microvm ผูกถึง gateway (exec จะ DENY แบบมี audit)
        let mut cfg = test_config();
        cfg.runtime.isolation = "microvm".into();
        let rt = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(rt.gateway.level, SandboxLevel::MicroVm);
        assert_eq!(rt.sandbox.level, SandboxLevel::MicroVm);
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    // Phase 7 (ฟีเจอร์ microvm): บล็อก `microvm:` ใน yaml ผูกถึง gateway
    // ไม่มีบล็อก (= `None`) gateway ต้องไม่มี config (deny ตั้งแต่ artifact หาย)
    #[cfg(feature = "microvm")]
    #[test]
    fn microvm_block_reaches_gateway() {
        let cfg = VmConfig::from_yaml(
            r#"
name: t
runtime:
  isolation: microvm
microvm:
  kernel_path: /boot/vmlinux
  kernel_sha256: "aa"
  rootfs_path: /img/rootfs.ext4
  rootfs_sha256: "bb"
  vcpu_count: 2
  mem_mb: 512
"#,
        )
        .unwrap();
        let m = cfg.microvm.clone().expect("ต้อง parse บล็อก microvm ได้");
        assert_eq!(m.vcpu_count, 2);
        assert_eq!(m.mem_mb, 512);
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-ucfg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rt = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(rt.gateway.level, SandboxLevel::MicroVm);
        assert!(rt.gateway.microvm_cfg.is_some());
        // ไม่มีบล็อก = None (deny ตั้งแต่ artifact หาย)
        let (rt2, base2) = test_runtime("ucfg-none");
        assert!(rt2.gateway.microvm_cfg.is_none());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
        aivm_audit::clear_flags(&base2);
        let _ = std::fs::remove_dir_all(&base2);
    }

    // Level 3 (ฟีเจอร์ hardware): บล็อก `hardware:` ใน yaml ผูกถึง gateway
    // ไม่มีบล็อก (= `None`) gateway ต้องไม่มี config (deny ตั้งแต่ artifact หาย)
    #[cfg(feature = "hardware")]
    #[test]
    fn hardware_block_reaches_gateway() {
        let cfg = VmConfig::from_yaml(
            r#"
name: t
runtime:
  isolation: hardware
hardware:
  tee_type: generic
  attestation_mode: none
  kernel_path: /boot/vmlinux
  kernel_sha256: "aa"
  rootfs_path: /img/rootfs.ext4
  rootfs_sha256: "bb"
  vcpu_count: 2
  mem_mb: 2048
"#,
        )
        .unwrap();
        let m = cfg.hardware.clone().expect("ต้อง parse บล็อก hardware ได้");
        assert_eq!(m.vcpu_count, 2);
        assert_eq!(m.mem_mb, 2048);
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-hwcfg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rt = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(rt.gateway.level, SandboxLevel::Hardware);
        assert!(rt.gateway.hardware_cfg.is_some());
        // ไม่มีบล็อก = None (deny ตั้งแต่ artifact หาย)
        let (rt2, base2) = test_runtime("hwcfg-none");
        assert!(rt2.gateway.hardware_cfg.is_none());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
        aivm_audit::clear_flags(&base2);
        let _ = std::fs::remove_dir_all(&base2);
    }

    // Phase 7 (ฟีเจอร์ microvm): e2e ระดับ Runtime — yaml `isolation:
    // microvm` + บล็อก pins จริง → `process.exec` ผ่าน gateway ต้อง ALLOW
    // (สาย config → gateway → boot ครบ ไม่ใช่แค่ unit ระดับล่าง: level เป็น
    // MicroVm แล้ว arm Process จะไปไม่ถึงโดย construction)
    // ข้ามอย่างซื่อสัตย์เมื่อไม่มี AIVM_MICROVM_PINS / KVM / firecracker
    #[cfg(feature = "microvm")]
    #[test]
    fn microvm_real_boot_allow_through_gateway() {
        let pins_path = std::env::var("AIVM_MICROVM_PINS").unwrap_or_default();
        if pins_path.is_empty() {
            eprintln!("skip: ตั้ง AIVM_MICROVM_PINS เพื่อทดสอบ e2e จริง");
            return;
        }
        let has_fc = std::env::var_os("PATH")
            .map(|p| {
                std::env::split_paths(&p)
                    .any(|d| d.join("firecracker").is_file() || d.join("firecracker.exe").is_file())
            })
            .unwrap_or(false);
        if !std::path::Path::new("/dev/kvm").exists() || !has_fc {
            eprintln!("skip: เครื่องนี้ไม่มี KVM/firecracker");
            return;
        }
        let text = std::fs::read_to_string(&pins_path).expect("อ่าน pins.json ได้");
        let v: serde_json::Value = serde_json::from_str(&text).expect("pins.json เป็น JSON");
        let str_of = |ptr: &str| v.pointer(ptr).and_then(|x| x.as_str()).unwrap_or("");
        let cfg = VmConfig::from_yaml(&format!(
            r#"
name: uvm-e2e
runtime:
  isolation: microvm
microvm:
  kernel_path: {kp}
  kernel_sha256: "{ks}"
  rootfs_path: {rp}
  rootfs_sha256: "{rs}"
  fc_sha256: "{fs}"
"#,
            kp = str_of("/kernel/path"),
            ks = str_of("/kernel/sha256"),
            rp = str_of("/rootfs/path"),
            rs = str_of("/rootfs/sha256"),
            fs = str_of("/binary/sha256"),
        ))
        .unwrap();
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-uvm-e2e-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut rt = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(rt.gateway.level, SandboxLevel::MicroVm);
        // อนุญาต exe + ให้ execute cap (แบบเดียวกับ exec_harness ฝั่ง tools)
        for exe in ["/bin/true", "/bin/false"] {
            let real = std::fs::canonicalize(exe)
                .unwrap()
                .to_string_lossy()
                .to_string();
            rt.gateway.policy.process.allow.push(real.clone());
            rt.gateway.caps.grant(aivm_capability::Capability::new(
                "execute", "process", &real,
            ));
        }
        // exit 0 = ok:true, exit 1 = ok:false แต่ decision ต้อง allow ทั้งคู่
        let r = rt.gateway.exec(&mut rt.cube, "/bin/true", &[]).unwrap();
        assert!(r.ok);
        assert_eq!(r.decision, "allow");
        let r = rt.gateway.exec(&mut rt.cube, "/bin/false", &[]).unwrap();
        assert!(!r.ok);
        assert_eq!(r.decision, "allow");
        // G3: run ที่จบบริบูรณ์ต้องลง verdict:clean ใน audit ทั้งสองครั้ง
        // G5: ทุก run ต้องมี dna id ต่อท้าย (s{scheme}-k{0|1}-r{0|1}-…)
        let log = std::fs::read_to_string(base.join("audit.jsonl")).unwrap();
        assert!(log.matches("verdict:clean").count() >= 2);
        assert!(log.matches("dna:s").count() >= 2, "ต้องมี dna id: {log}");
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    // G1: deny burst → quarantine → operator transition ล้าง → กลับมาปกติ
    // (deterministic: threshold default 20, ทุก deny ในเสี้ยววินาทีเดียวกัน)
    #[test]
    fn transition_clears_quarantine() {
        let (mut rt, base) = test_runtime("quar");
        let real = std::fs::canonicalize("/bin/true")
            .unwrap()
            .to_string_lossy()
            .to_string();
        rt.gateway.policy.process.allow.push(real.clone());
        rt.gateway.caps.grant(aivm_capability::Capability::new(
            "execute", "process", &real,
        ));
        let probe = aivm_tools::ToolRequest {
            tool: "filesystem.read".into(),
            path: "../../etc/passwd".into(),
            content: None,
        };
        for _ in 0..20 {
            assert!(rt.gateway.dispatch(&mut rt.cube, &probe).is_err());
        }
        // quarantine แล้ว: exec ที่ควร allow ต้องตาย
        // quarantine แล้ว: exec ที่ควร allow ต้องตาย
        let r = rt.gateway.exec(&mut rt.cube, "/bin/true", &[]);
        assert!(r.is_err(), "quarantine ต้อง deny แม้มีสิทธิ์ครบ");
        // operator transition (INIT → ANALYZE ไม่ต้องใช้ guard) ล้างให้
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        let r = rt.gateway.exec(&mut rt.cube, "/bin/true", &[]);
        assert!(r.is_ok(), "หลัง transition ต้องกลับมาปกติ");
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    // G4: secrets.yaml 0600 โหลดเข้า broker (allow ตาม policy) ส่วน 0644
    // ถูกปฏิเสธทั้งไฟล์ (fail-closed) — ไม่มีไฟล์เลยก็บูตได้ (deny หมด)
    #[test]
    fn secrets_yaml_loads_with_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-secrets-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = VmConfig::from_yaml(
            r#"
name: t
runtime:
  isolation: sandbox
capabilities:
  initial: ["secret:test_tok:read"]
secrets:
  allow: ["test_tok:read"]
  low_risk_allow: ["test_tok:read"]
  hitl_required_for: ["high"]
"#,
        )
        .unwrap();
        // ไม่มีไฟล์ = บูตได้ แต่ secret.request ถูก deny (broker ต่อสายแล้ว
        // แต่ว่าง — resource ไม่รู้จัก ไม่ใช่ unconfigured)
        let mut rt = Runtime::init(cfg.clone(), base.clone()).unwrap();
        let body = serde_json::json!({
            "tool": "process.exec",
            "resource": "test_tok",
            "scope": "read",
            "purpose": "test",
            "risk": "low",
        })
        .to_string();
        let r = rt.gateway.secret_request(&mut rt.cube, Some(body.as_str()));
        assert!(r.is_err());
        let log = std::fs::read_to_string(base.join("audit.jsonl")).unwrap();
        assert!(log.contains("secret-unknown"));
        // 0644 = ปฏิเสธ (fail-closed)
        std::fs::write(base.join("secrets.yaml"), "test_tok: VALUE\n").unwrap();
        std::fs::set_permissions(
            base.join("secrets.yaml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Runtime::init(cfg.clone(), base.clone()).is_err());
        // 0600 = โหลดได้ request ผ่าน
        std::fs::set_permissions(
            base.join("secrets.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let mut rt = Runtime::init(cfg, base.clone()).unwrap();
        let body = serde_json::json!({
            "tool": "process.exec",
            "resource": "test_tok",
            "scope": "read",
            "purpose": "test",
            "risk": "low",
        })
        .to_string();
        let r = rt.gateway.secret_request(&mut rt.cube, Some(body.as_str()));
        let r = r.unwrap();
        assert!(r.ok);
        assert!(!r.output.contains("VALUE"));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    // G4b: request(high) → pending → persist → restart → approve → use ได้
    // (deterministic: Process level ไม่ต้องมี KVM)
    #[test]
    fn approve_persist_rehydrate_use_roundtrip() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "aivm-rt-approve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("secrets.yaml"), "test_tok: ROUNDTRIP-VALUE\n").unwrap();
        std::fs::set_permissions(
            base.join("secrets.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let cfg = VmConfig::from_yaml(
            r#"
name: t
runtime:
  isolation: sandbox
tools:
  allow: [/usr/bin/printenv]
capabilities:
  initial: [read:workspace, search:code, "secret:test_tok:write"]
secrets:
  allow: ["test_tok:write"]
  hitl_required_for: ["high"]
"#,
        )
        .unwrap();
        let printenv = std::fs::canonicalize("/usr/bin/printenv")
            .unwrap()
            .to_string_lossy()
            .to_string();
        let grant_all = |rt: &mut Runtime| {
            rt.gateway.caps.grant(aivm_capability::Capability::new(
                "use",
                "secret",
                "test_tok:write",
            ));
            rt.gateway.caps.grant(aivm_capability::Capability::new(
                "execute", "process", &printenv,
            ));
        };
        let body = serde_json::json!({
            "tool": "process.exec",
            "resource": "test_tok",
            "scope": "write",
            "purpose": "test",
            "risk": "high",
        })
        .to_string();
        // 1. ขอ high-risk → pending (deny + มี lease id ใน audit)
        let mut rt = Runtime::init(cfg.clone(), base.clone()).unwrap();
        grant_all(&mut rt);
        let r = rt.gateway.secret_request(&mut rt.cube, Some(body.as_str()));
        assert!(r.is_err());
        let log = std::fs::read_to_string(base.join("audit.jsonl")).unwrap();
        assert!(log.contains("hitl-required"));
        let pending = log
            .lines()
            .find_map(|l| {
                let p = l.find("pending:lease-")?;
                Some(
                    l[p + "pending:".len()..]
                        .split('"')
                        .next()
                        .unwrap()
                        .to_string(),
                )
            })
            .expect("ต้องมี pending lease id ใน audit");
        // 2. persist + restart (จำลองข้าม process) → approve ได้
        rt.persist().unwrap();
        drop(rt);
        let mut rt = Runtime::init(cfg, base.clone()).unwrap();
        grant_all(&mut rt);
        let sum = rt.approve_secret_lease(&pending, "op").unwrap();
        assert_eq!(sum.resource, "test_tok");
        assert_eq!(sum.approved_by.as_deref(), Some("op"));
        // 3. ใช้ lease ที่ approve แล้วได้ (inject ทำงานหลัง restart)
        let r = rt
            .gateway
            .dispatch(
                &mut rt.cube,
                &aivm_tools::ToolRequest {
                    tool: "process.exec".into(),
                    path: "/usr/bin/printenv".into(),
                    content: Some(
                        serde_json::json!({"argv": ["AIVM_SECRET_TEST_TOK_WRITE"], "secret": pending})
                            .to_string(),
                    ),
                },
            )
            .unwrap();
        assert!(r.ok);
        assert_eq!(r.output, "[REDACTED]");
        // 4. audit มีรอย approve ระบุคน + ไม่มี value หลุด
        let log = std::fs::read_to_string(base.join("audit.jsonl")).unwrap();
        assert!(log.contains("secret-approve"));
        assert!(
            log.lines().any(|line| {
                let record: AuditRecord = serde_json::from_str(line).unwrap();
                record.action == "secret-approve-commit"
                    && serde_json::from_str::<serde_json::Value>(&record.result).unwrap()["details"]
                        == "op"
            }),
            "audit ต้องระบุผู้ approve"
        );
        assert!(!log.contains("ROUNDTRIP-VALUE"));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }
    #[test]
    fn rag_never_reads_vm_secrets_even_when_given_the_vm_root() {
        struct Recorder(std::sync::Arc<std::sync::Mutex<String>>);
        impl aivm_model::Model for Recorder {
            fn reason(&self, context: &str) -> Result<String, aivm_model::ModelError> {
                *self.0.lock().unwrap() = context.into();
                Ok(r#"{"done":true,"summary":"done"}"#.into())
            }
            fn token_count(&self, _: &str) -> usize {
                0
            }
            fn max_context(&self) -> usize {
                4096
            }
        }
        let (mut rt, base) = test_runtime("rag-secret");
        std::fs::create_dir_all(rt.workspace.join("src")).unwrap();
        std::fs::write(
            rt.workspace.join("src/safe.txt"),
            "credential source is safe",
        )
        .unwrap();
        std::fs::write(
            base.join("secrets.yaml"),
            "credential: RAG-VALUE-DO-NOT-SEND\n",
        )
        .unwrap();
        std::fs::write(rt.workspace.join("private.txt"), "credential PRIVATE-VALUE").unwrap();
        rt.gateway
            .policy
            .filesystem
            .deny
            .push(rt.workspace.join("private.txt").display().to_string());
        let prompt = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        rt.model = Box::new(Recorder(prompt.clone()));
        rt.run_agent("credential", 1, Some(&base)).unwrap();
        let prompt = prompt.lock().unwrap();
        assert!(prompt.contains("source is safe"));
        assert!(!prompt.contains("RAG-VALUE-DO-NOT-SEND"));
        assert!(!prompt.contains("PRIVATE-VALUE"));
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn consumed_quota_is_checkpointed_before_restart() {
        use std::os::unix::fs::PermissionsExt;
        let (mut rt, base) = test_runtime("quota-restart");
        std::fs::create_dir_all(rt.workspace.join("src")).unwrap();
        std::fs::write(rt.workspace.join("src/seed.txt"), "seed").unwrap();
        rt.gateway.caps = CapabilitySet::new(vec![Capability::new(
            "read",
            "filesystem",
            &rt.workspace.display().to_string(),
        )
        .with_max_uses(1)]);
        rt.gateway.read(&mut rt.cube, "src/seed.txt").unwrap();
        let mode = std::fs::metadata(base.join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let cfg = rt.config.clone();
        drop(rt);
        let mut restored = Runtime::init(cfg, base.clone()).unwrap();
        assert_eq!(restored.gateway.caps.caps[0].used_count, 1);
        assert_eq!(restored.gateway.caps.caps[0].max_uses, None);
        assert!(restored
            .gateway
            .read(&mut restored.cube, "src/seed.txt")
            .is_ok());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    // บัญชีสะสมต้องรอด restart: restart แล้วต้องเหลือเพดานเท่าเดิม
    // (state.json เสียไม่ได้ทำให้ task budget กลับมาใช้ใหม่ — fail-closed)
    #[test]
    fn consumed_byte_budget_survives_restart() {
        use aivm_capability::AuthorizationContext;
        let (mut rt, base) = test_runtime("budget-restart");
        rt.config.network.allow = vec!["example.com".into()];
        rt.config.network.max_total_bytes = Some(100);
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        rt.transition_to(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.9,
                confidence_threshold: CONFIDENCE_THRESHOLD,
                ..Default::default()
            },
        )
        .unwrap();
        rt.transition_to(
            AgentState::Validate,
            &TransitionGuards {
                tests_passed: true,
                ..Default::default()
            },
        )
        .unwrap();
        std::fs::create_dir_all(rt.workspace.join("src")).unwrap();
        std::fs::write(rt.workspace.join("src/seed.txt"), "seed").unwrap();
        let mut cap = Capability::new("network:fetch", "network", "example.com:443")
            .with_constraints(aivm_capability::Constraints::new().with_max_total_bytes(100));
        cap.account_bytes(60); // ใช้ไป 60 จาก 100 เหลือ 40
        let read = Capability::new("read", "filesystem", &rt.workspace.display().to_string());
        rt.gateway.caps = CapabilitySet::new(vec![read, cap]);
        // อ่านไฟล์ธรรมดาเพื่อให้ persist บัญชีสดใหม่ลง state
        rt.gateway.read(&mut rt.cube, "src/seed.txt").unwrap();
        let cfg = rt.config.clone();
        drop(rt);
        let mut restored = Runtime::init(cfg, base.clone()).unwrap();
        let ctx = AuthorizationContext {
            request_bytes: Some(50),
            protocol: Some("https"),
            port: Some(443),
            ..Default::default()
        };
        // เหลือ 40 ขอ 50 = DENY (งบไม่กลับมาเพราะ restart)
        assert!(matches!(
            restored.gateway.caps.authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &ctx
            ),
            Err(aivm_capability::CapabilityError::BudgetExceeded(_))
        ));
        // เหลือ 40 ขอ 40 = ผ่านพอดี
        assert!(restored
            .gateway
            .caps
            .authorize_with_context(
                "network:fetch",
                "network",
                "example.com:443",
                &AuthorizationContext {
                    request_bytes: Some(40),
                    protocol: Some("https"),
                    port: Some(443),
                    ..Default::default()
                },
            )
            .is_ok());
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn read_only_network_defaults_and_runtime_policy_match() {
        for yaml in [
            "name: default",
            "name: explicit\nnetwork:\n  allow: [registry.invalid]",
        ] {
            let config = VmConfig::from_yaml(yaml).unwrap();
            assert!(config.network.read_only);
        }
        let (rt, base) = test_runtime("readonly-policy");
        assert!(rt.gateway.policy.network.read_only);
        let network = NetworkBlock {
            allow: vec!["registry.invalid".into()],
            ..Default::default()
        };
        let caps = state_grants(AgentState::Validate, Path::new("/workspace"), &network, &[]);
        assert_eq!(caps.iter().filter(|c| c.resource == "network").count(), 1);
        assert!(caps.iter().any(|c| c.action == "network:fetch"));
        assert!(!caps.iter().any(|c| c.action == "network:connect"));
        drop(rt);
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn validate_grants_network_actions_with_tls_and_matching_ports() {
        use crate::NetworkBlock;
        let ws = std::path::Path::new("/workspace");
        let network = NetworkBlock {
            read_only: false,
            allow: vec!["api.example.com".into()],
            max_calls: Some(5),
            max_total_bytes: Some(1024),
        };
        let caps = state_grants(AgentState::Validate, ws, &network, &[]);
        for action in ["network:fetch", "network:connect"] {
            let cap = caps.iter().find(|c| c.action == action).unwrap();
            assert_eq!(cap.scope, "api.example.com:443");
            assert!(cap.constraints.require_tls);
            assert_eq!(cap.constraints.allowed_ports, vec![443]);
            // เพดานต่อ task จาก config ต้องติดไปกับ lease ทุกใบ
            assert_eq!(cap.constraints.max_calls, Some(5));
            assert_eq!(cap.constraints.max_total_bytes, Some(1024));
        }
    }

    #[test]
    fn restart_uses_fresh_grants_and_limits_with_legacy_usage() {
        let (mut rt, base) = test_runtime("fresh-caps");
        rt.config.network.read_only = false;
        rt.config.tools.allow = vec!["/bin/true".into()];
        rt.policy.process.allow = vec![std::fs::canonicalize("/bin/true")
            .unwrap()
            .display()
            .to_string()];
        rt.config.network.allow = vec!["example.com".into(), "removed.example".into()];
        rt.config.network.max_calls = Some(10);
        rt.config.network.max_total_bytes = Some(1000);
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        rt.transition_to(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.9,
                confidence_threshold: CONFIDENCE_THRESHOLD,
                ..Default::default()
            },
        )
        .unwrap();
        rt.transition_to(
            AgentState::Validate,
            &TransitionGuards {
                tests_passed: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(rt.gateway.caps.caps.iter().any(|c| c.action == "execute"));
        for cap in &mut rt.gateway.caps.caps {
            cap.used_count = 4;
            cap.used_bytes = 60;
            cap.constraints = Default::default();
            cap.condition = None;
            cap.expiration = None;
        }
        rt.gateway
            .caps
            .caps
            .push(Capability::new("deploy", "host", "*"));
        // Duplicate identities cannot reset counters with a later zero entry.
        rt.gateway.caps.caps.push(Capability::new(
            "network:fetch",
            "network",
            "example.com:443",
        ));
        rt.persist().unwrap();
        let mut cfg = rt.config.clone();
        cfg.tools.allow.clear();
        cfg.network.allow = vec!["example.com".into()];
        cfg.network.max_calls = Some(3);
        cfg.network.max_total_bytes = Some(50);
        drop(rt);
        // The initial-capability list is unchanged: changing only network/tool
        // config must still replace persisted authority.
        let restored = Runtime::init(cfg.clone(), base.clone()).unwrap();
        assert_eq!(restored.cube.current_state(), AgentState::Validate);
        assert!(!restored
            .gateway
            .caps
            .caps
            .iter()
            .any(|c| c.action == "execute"
                || c.action == "deploy"
                || c.scope == "removed.example:443"));
        assert_eq!(
            restored
                .gateway
                .caps
                .caps
                .iter()
                .filter(|c| c.resource == "network")
                .count(),
            2
        );
        for cap in restored
            .gateway
            .caps
            .caps
            .iter()
            .filter(|c| c.resource == "network")
        {
            assert_eq!(cap.used_count, 4);
            assert_eq!(cap.used_bytes, 60);
            assert_eq!(cap.constraints.max_calls, Some(3));
            assert_eq!(cap.constraints.max_total_bytes, Some(50));
            assert!(cap.constraints.require_tls);
            assert!(cap.condition.is_some());
            assert!(cap.expiration.is_some());
            assert!(cap.check_usable().is_err());
        }
        cfg.capabilities.initial = vec!["read:workspace".into()];
        // เปลี่ยน policy เป็นอ่านเท่านั้นตอน restart ต้องถอดสิทธิ์ connect เก่าด้วย
        cfg.network.read_only = true;
        let reduced = Runtime::init(cfg, base.clone()).unwrap();
        assert!(reduced.gateway.policy.network.read_only);
        assert!(!reduced
            .gateway
            .caps
            .caps
            .iter()
            .any(|c| c.action == "network:connect"));
        assert!(!reduced
            .gateway
            .caps
            .caps
            .iter()
            .any(|c| c.action == "search"));
        assert_eq!(reduced.gateway.caps.caps[0].used_count, 4);
        aivm_audit::clear_flags(&base);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn restart_invalidates_secret_leases_after_operator_revocation() {
        use std::os::unix::fs::PermissionsExt;
        for change in ["capability", "value", "file", "policy", "uses", "ttl"] {
            let (rt, base) = test_runtime(&format!("secret-revoke-{change}"));
            let mut cfg = rt.config.clone();
            drop(rt);
            cfg.capabilities.initial = vec!["secret:credential:read".into()];
            cfg.secrets.allow = vec!["credential:read".into()];
            cfg.secrets.low_risk_allow = vec!["credential:read".into()];
            let path = base.join("secrets.yaml");
            std::fs::write(&path, "credential: CURRENT-VALUE\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut rt = Runtime::init(cfg.clone(), base.clone()).unwrap();
            let result = rt
                .gateway
                .secret_request(
                    &mut rt.cube,
                    Some(
                        &serde_json::json!({
                            "tool": "process.exec", "resource": "credential", "scope": "read",
                            "purpose": "test", "risk": "low", "max_uses": 3, "ttl_seconds": 300
                        })
                        .to_string(),
                    ),
                )
                .unwrap();
            let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
            let id = value["lease_id"].as_str().unwrap();
            drop(rt); // issuance checkpoint is the only persisted state
            let mut unchanged = Runtime::init(cfg.clone(), base.clone()).unwrap();
            assert!(unchanged
                .gateway
                .secret_broker_mut()
                .unwrap()
                .get_lease(id)
                .is_some());
            drop(unchanged);
            match change {
                "capability" => cfg.capabilities.initial = vec!["read:workspace".into()],
                "value" => std::fs::write(&path, "credential: ROTATED-VALUE\n").unwrap(),
                "file" => std::fs::remove_file(&path).unwrap(),
                "policy" => cfg.secrets.allow.clear(),
                "uses" => cfg.secrets.max_uses_allowed = 1,
                "ttl" => cfg.secrets.max_ttl_seconds = 60,
                _ => unreachable!(),
            }
            let mut restored = Runtime::init(cfg, base.clone()).unwrap();
            assert!(
                restored
                    .gateway
                    .secret_broker_mut()
                    .unwrap()
                    .get_lease(id)
                    .is_none(),
                "{change}"
            );
            assert!(restored.approve_secret_lease(id, "operator").is_err());
            aivm_audit::clear_flags(&base);
            std::fs::remove_dir_all(base).unwrap();
        }
    }
}
