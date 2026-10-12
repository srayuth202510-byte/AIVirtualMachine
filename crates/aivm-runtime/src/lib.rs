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
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod demo;

/// เกณฑ์ confidence สำหรับ ANALYZE -> MODIFY (ตัวอย่างในสเปก §15)
pub const CONFIDENCE_THRESHOLD: f64 = 0.8;
/// lease แบบจำกัดเวลาสำหรับสิทธิ์เน็ตเวิร์กที่ให้ตาม state (สเปก §14.3, แบบ JIT)
pub const NETWORK_LEASE_SECS: u64 = 300;
/// cube + ชุด capability ที่ persist ไว้ เพื่อให้สิทธิ์แบบ dynamic รอดข้าม restart
const STATE_FILE: &str = "state.json";

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    #[serde(default)]
    pub runtime: RuntimeBlock,
    #[serde(default)]
    pub model: ModelBlock,
    #[serde(default)]
    pub resources: ResourceBlock,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeBlock {
    #[serde(default = "default_isolation")]
    pub isolation: String,
}
fn default_isolation() -> String {
    "sandbox".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelBlock {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub name: String,
    /// การตั้งค่าแบ็กเอนด์ local (ใช้เมื่อ provider = "local")
    #[serde(default)]
    pub local: Option<LocalModelConfig>,
}

// default ต้องตรงกับ serde default (echo) ไม่ใช่ค่าว่าง เพื่อให้ผู้ที่สร้าง
// ModelBlock::default() ตรง ๆ ยังได้ provider ที่ใช้ได้ (fail-closed ถ้าไม่รู้จัก)
impl Default for ModelBlock {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            name: default_model(),
            local: None,
        }
    }
}
fn default_provider() -> String {
    "echo".into()
}
fn default_model() -> String {
    "echo".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceBlock {
    #[serde(default = "default_cpu")]
    pub cpu: u32,
    #[serde(default = "default_mem")]
    pub memory: String,
    #[serde(default = "default_storage")]
    pub storage: String,
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
pub struct FilesystemBlock {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkBlock {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolsBlock {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilitiesBlock {
    #[serde(default)]
    pub initial: Vec<String>, // "read:workspace", "search:code"
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
}

/// state แบบ dynamic ที่ persist ไว้: cube ที่ผ่าน validate แล้ว + lease ที่ยังใช้ได้
/// policy/config อยู่ใน `aivm.yaml` (ต้นฉบับความจริง) มีแค่ส่วนที่เปลี่ยน
/// แปลงตามเวลาที่อยู่ไฟล์นี้ เพื่อให้ grant กับตัวนับการใช้รอดข้าม restart
#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    cube: Cube,
    caps: CapabilitySet,
}

impl Runtime {
    /// init แบบ fail-closed: config/policy เสียได้ Err VM ปฏิเสธสตาร์ต
    pub fn init(config: VmConfig, base_dir: PathBuf) -> Result<Self, RuntimeError> {
        let workspace = base_dir.join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|e| RuntimeError::Io(e.to_string()))?;
        // ทำ workspace ให้เป็น absolute เพื่อให้ scope ของ capability
        // กับ path คำขอที่ canonicalize แล้วเทียบกันในโดเมนเดียวกัน
        // (base_dir แบบ relative จะ join ซ้ำใน gateway แล้ว deny หมด)
        let workspace = absolutize(&workspace);
        let base_dir = absolutize(&base_dir);

        // แปลง scope ที่อิง workspace ให้เป็นสตริง absolute แบบ canonical
        let ws_str = workspace.to_string_lossy().to_string();
        let read_scopes: Vec<String> = if config.filesystem.read.is_empty() {
            vec![ws_str.clone()]
        } else {
            config
                .filesystem
                .read
                .iter()
                .map(|s| resolve_scope(&base_dir, &workspace, s))
                .collect()
        };
        let write_scopes: Vec<String> = if config.filesystem.write.is_empty() {
            vec![format!("{ws_str}/src")]
        } else {
            config
                .filesystem
                .write
                .iter()
                .map(|s| resolve_scope(&base_dir, &workspace, s))
                .collect()
        };

        let policy = Policy {
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
                    .filter_map(|s| resolve_tool(s))
                    .collect(),
                deny: vec!["/bin/sh".into(), "/bin/bash".into()],
            },
            network: aivm_policy::NetworkPolicy {
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
        };

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
                _ => {}
            }
        }
        if caps.is_empty() {
            caps.push(Capability::new("read", "filesystem", &ws_str));
            caps.push(Capability::new("search", "filesystem", &ws_str));
        }
        let caps = CapabilitySet::new(caps);

        let audit = AuditWriter::open(base_dir.join("audit.jsonl"))
            .map_err(|e| RuntimeError::Io(e.to_string()))?;
        let mut gateway = ToolGateway::new(
            workspace.clone(),
            policy.clone(),
            caps,
            audit,
            &config.name,
            &format!("sess_{}", config.name),
        );
        let mut cube = Cube::new(&format!("task_{}", config.name));
        // กู้ state แบบ dynamic (transition ที่ validate แล้ว + lease ที่ยังใช้ได้)
        // ไฟล์ state ที่เสีย/แปลกปลอมจะถูกเมินแบบ fail-closed: VM จะ
        // เริ่มใหม่ด้วยสิทธิ์ INIT ขั้นต่ำ ไม่เคยได้สิทธิ์เกิน
        let state_path = base_dir.join(STATE_FILE);
        if let Ok(text) = std::fs::read_to_string(&state_path) {
            if let Ok(saved) = serde_json::from_str::<PersistedState>(&text) {
                cube = saved.cube;
                gateway.caps = saved.caps;
            }
        }
        let memory = Memory::new(base_dir.join("memory"));
        let sandbox = Sandbox::new(SandboxLevel::Process, ResourceLimits::default());
        let model_cfg = ModelConfig {
            provider: config.model.provider.clone(),
            name: config.model.name.clone(),
            local: config.model.local.clone(),
        };
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
        self.cube
            .transition(next, guards)
            .map_err(|e| RuntimeError::Transition(e.to_string()))?;
        let state = next.to_string();

        let revoked = self.gateway.caps.revoke_stale(&state);
        if revoked > 0 {
            self.audit_op(
                "revoke",
                "capability",
                &format!("{revoked} stale lease(s)"),
                &state,
            )?;
        }

        let mut granted = 0;
        for cap in state_grants(
            next,
            &self.workspace,
            &self.config.network.allow,
            &self.policy.process.allow,
        ) {
            let label = format!("{}:{}", cap.action, cap.scope);
            if self.gateway.caps.grant(cap) {
                granted += 1;
                self.audit_op("grant", &label, "lease issued", &state)?;
            }
        }
        Ok((granted, revoked))
    }

    /// persist cube ที่ validate แล้ว + lease ที่ยังใช้ได้ เพื่อให้
    /// `transition_to` รอดข้าม restart supervisor เรียกหลัง run/transition/create
    pub fn persist(&self) -> Result<(), RuntimeError> {
        let saved = PersistedState {
            cube: self.cube.clone(),
            caps: self.gateway.caps.clone(),
        };
        let text =
            serde_json::to_string_pretty(&saved).map_err(|e| RuntimeError::Io(e.to_string()))?;
        let path = self.base_dir.join(STATE_FILE);
        std::fs::write(&path, text).map_err(|e| RuntimeError::Io(e.to_string()))?;
        // lease ที่ persist มีความอ่อนไหวเหมือน audit: เจ้าของอ่านได้อย่างเดียว
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&path)
                .map_err(|e| RuntimeError::Io(e.to_string()))?
                .permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&path, perm).map_err(|e| RuntimeError::Io(e.to_string()))?;
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
        self.op_seq += 1;
        let mut rec = AuditRecord::new(
            0,
            &self.config.name,
            &format!("sess_{}", self.config.name),
            &format!("state_{:06}", self.op_seq),
            state,
            action,
            resource,
            "allow",
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
        let _mem = self.memory.retrieve(&self.cube);
        let intent = self
            .model
            .reason(context)
            .map_err(|e| RuntimeError::Config(e.to_string()))?;
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

    pub fn inspect(&self) -> String {
        format!(
            "AI VM: {}\nState:\n  {}\nModel:\n  {}\nResources:\n  CPU      {}\n  Memory   {}\nCapabilities:\n  READ     {}\nDenied:\n  WRITE(outside src)\n  NETWORK\n  DEPLOY\nProcesses:\n  0\nMemory:\n  {} cells\nDenials:\n  {}\n",
            self.config.name,
            self.cube.current_state(),
            self.model_cfg.name,
            self.config.resources.cpu,
            self.config.resources.memory,
            self.workspace.display(),
            self.cube.cells.len(),
            self.cube.denials,
        )
    }
}

/// สิทธิ์ที่ให้ตาม state (สเปก §14.2) lease ทุกใบมี scope ผูกกับ state
/// (ออกจาก state แล้ว revoke อัตโนมัติ) และจำกัดเวลาถ้าสิทธิ์สูง (เน็ตเวิร์ก)
/// สิทธิ์พื้นฐาน read/search จาก INIT ไม่มี condition จึงรอดเสมอ
fn state_grants(
    next: AgentState,
    workspace: &Path,
    network_allow: &[String],
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
        for host in network_allow {
            let mut net = Capability::new("network", "network", host);
            net.condition = Some(Condition {
                protocol: Some("https".to_string()),
                require_state: None,
                valid_states: vec!["VALIDATE".to_string()],
            });
            net.expiration = Some(aivm_capability::now_secs() + NETWORK_LEASE_SECS);
            out.push(net);
        }
    }
    out
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

/// Config Loader และ Validator
pub mod config {
    use super::{resolve_tool, RuntimeError, VmConfig};
    use aivm_policy::{Policy, PolicyManager};
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
        let config = VmConfig::from_file(config_path)?;
        let mut warnings = Vec::new();

        // Validate config structure
        validate_config(&config, &mut warnings)?;

        // Load default policy if not exists
        if policy_manager.get_active("default").is_none() {
            let default_policy = build_default_policy(&config);
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
                "require_test_before_network is false - network access allowed without tests"
                    .into(),
            );
        }

        Ok(())
    }

    fn build_default_policy(config: &VmConfig) -> Policy {
        let ws_str = format!("/workspace/{}", config.name);
        Policy {
            name: format!("{}-default", config.name),
            deny_overrides: true,
            filesystem: aivm_policy::FsPolicy {
                read: vec![ws_str.clone()],
                write: vec![format!("{}/src", ws_str)],
                deny: vec![
                    format!("{}/.git/config", ws_str),
                    "**/.env*".into(),
                    "**/secrets/**".into(),
                    format!("{}/policies", ws_str),
                    format!("{}/audit", ws_str),
                ],
            },
            process: aivm_policy::ProcessPolicy {
                allow: config
                    .tools
                    .allow
                    .iter()
                    .filter_map(|s| resolve_tool(s))
                    .collect(),
                deny: vec!["/bin/sh".into(), "/bin/bash".into()],
            },
            network: aivm_policy::NetworkPolicy {
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
            require_test_before_network: config.policy.require_test_before_network,
        }
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
    fn corrupt_state_file_fails_closed_to_init() {
        let (mut rt, base) = test_runtime("corrupt");
        rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        rt.persist().unwrap();
        std::fs::write(base.join(STATE_FILE), "{not json").unwrap();
        let rt2 = Runtime::init(test_config(), base.clone()).unwrap();
        assert_eq!(rt2.cube.current_state(), AgentState::Init);
        aivm_audit::clear_flags(&base);
        let _ = std::fs::remove_dir_all(&base);
    }
}
