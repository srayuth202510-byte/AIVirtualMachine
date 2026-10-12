//! Runtime — spec §5, §22, §23, §28.
//!
//! Owns the agent loop: observe -> retrieve -> reason -> intent ->
//! capability/policy -> execute -> observe. Wires Cube + Policy +
//! ToolGateway + Memory + Audit from a single `aivm.yaml`.

use aivm_audit::AuditWriter;
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::Cube;
use aivm_memory::Memory;
use aivm_model::{EchoModel, Model, ModelConfig};
use aivm_policy::Policy;
use aivm_sandbox::{ResourceLimits, Sandbox, SandboxLevel};
use aivm_tools::{ToolGateway, ToolRequest};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("config: {0}")]
    Config(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("io: {0}")]
    Io(String),
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelBlock {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub name: String,
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
}

impl Runtime {
    /// Fail-closed init: bad config/policy => Err, VM refuses to start.
    pub fn init(config: VmConfig, base_dir: PathBuf) -> Result<Self, RuntimeError> {
        let workspace = base_dir.join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|e| RuntimeError::Io(e.to_string()))?;
        // Absolutize so capability scopes and canonicalized request paths
        // compare in the same domain (relative base_dirs would otherwise
        // double-join inside the gateway and deny everything).
        let workspace = absolutize(&workspace);
        let base_dir = absolutize(&base_dir);

        // Resolve workspace-relative scopes to absolute canonical strings.
        let ws_str = workspace.to_string_lossy().to_string();
        let read_scopes: Vec<String> = if config.filesystem.read.is_empty() {
            vec![ws_str.clone()]
        } else {
            config.filesystem.read.iter().map(|s| resolve_scope(&base_dir, &workspace, s)).collect()
        };
        let write_scopes: Vec<String> = if config.filesystem.write.is_empty() {
            vec![format!("{ws_str}/src")]
        } else {
            config.filesystem.write.iter().map(|s| resolve_scope(&base_dir, &workspace, s)).collect()
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
                allow: vec![],
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

        // Initial capabilities (§14.2 INIT state).
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
        let gateway = ToolGateway::new(
            workspace.clone(),
            policy.clone(),
            caps,
            audit,
            &config.name,
            &format!("sess_{}", config.name),
        );
        let memory = Memory::new(base_dir.join("memory"));
        let sandbox = Sandbox::new(SandboxLevel::Process, ResourceLimits::default());
        let model_cfg = ModelConfig {
            provider: config.model.provider.clone(),
            name: config.model.name.clone(),
        };
        let model: Box<dyn Model> = Box::new(EchoModel { name: model_cfg.name.clone() });

        Ok(Self {
            cube: Cube::new(&format!("task_{}", config.name)),
            config,
            base_dir,
            workspace,
            policy,
            gateway,
            memory,
            sandbox,
            model,
            model_cfg,
        })
    }

    /// One mediated step of the main loop (§23): reason via model, then
    /// execute a filesystem read through the gateway. Returns model text.
    pub fn step(&mut self, context: &str) -> Result<String, RuntimeError> {
        let _mem = self.memory.retrieve(&self.cube);
        let intent = self
            .model
            .reason(context)
            .map_err(|e| RuntimeError::Config(e.to_string()))?;
        // Demonstrate mediation: list workspace via search (always audited).
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

fn absolutize(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(p)
}

fn resolve_scope(base_dir: &Path, workspace: &Path, scope: &str) -> String {
    if scope.starts_with("./") {
        // Relative to the VM home (where aivm.yaml lives): ./workspace/src
        // means <base>/workspace/src.
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
        // Map the spec's virtual /workspace onto the real dir.
        let rel = scope.trim_start_matches("/workspace").trim_start_matches('/');
        if rel.is_empty() {
            return workspace.to_string_lossy().to_string();
        }
        return workspace.join(rel).to_string_lossy().to_string();
    }
    if Path::new(scope).is_absolute() {
        return scope.to_string();
    }
    // Bare hostnames (network) pass through untouched.
    if !scope.contains('/') && !scope.contains('.') {
        return scope.to_string();
    }
    if !scope.contains('/') {
        return scope.to_string(); // hostname like github.com
    }
    workspace.join(scope).to_string_lossy().to_string()
}
