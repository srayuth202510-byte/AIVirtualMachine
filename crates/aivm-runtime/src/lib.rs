//! Runtime — spec §5, §22, §23, §28.
//!
//! Owns the agent loop: observe -> retrieve -> reason -> intent ->
//! capability/policy -> execute -> observe. Wires Cube + Policy +
//! ToolGateway + Memory + Audit from a single `aivm.yaml`.

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::{Capability, CapabilitySet, Condition};
use aivm_cube::{AgentState, Cube, TransitionGuards};
use aivm_memory::Memory;
use aivm_model::{EchoModel, Model, ModelConfig};
use aivm_policy::Policy;
use aivm_sandbox::{ResourceLimits, Sandbox, SandboxLevel};
use aivm_tools::{ToolGateway, ToolRequest};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod demo;

/// Confidence gate for ANALYZE -> MODIFY (spec §15 example).
pub const CONFIDENCE_THRESHOLD: f64 = 0.8;
/// Time-bounded lease for state-granted network access (spec §14.3, JIT).
pub const NETWORK_LEASE_SECS: u64 = 300;
/// Persisted cube + capability set, so dynamic grants survive restarts.
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
    op_seq: u64,
}

/// Persisted dynamic state: validated cube + live capability leases.
/// Policy/config stay in `aivm.yaml` (ground truth); only the evolving
/// part lives here so grants and use-counts survive restarts.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    cube: Cube,
    caps: CapabilitySet,
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
        let mut gateway = ToolGateway::new(
            workspace.clone(),
            policy.clone(),
            caps,
            audit,
            &config.name,
            &format!("sess_{}", config.name),
        );
        let mut cube = Cube::new(&format!("task_{}", config.name));
        // Resume dynamic state (validated transitions + live leases).
        // Corrupt/foreign state files are ignored fail-closed: the VM
        // restarts with minimal INIT grants, never with extra privilege.
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
        };
        let model: Box<dyn Model> = Box::new(EchoModel {
            name: model_cfg.name.clone(),
        });

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

    /// Validated state advance with dynamic capability management (§14).
    ///
    /// 1. `Cube::transition` validates edge + guards (fail-closed).
    /// 2. State-bound leases that lapsed are revoked (§14.3).
    /// 3. Grants for the new state are issued idempotently (JIT, §14.2).
    /// 4. Every grant/revoke is audited; denial leaves state untouched.
    ///
    /// Returns `(granted, revoked)`.
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
        for cap in state_grants(next, &self.workspace, &self.config.network.allow) {
            let label = format!("{}:{}", cap.action, cap.scope);
            if self.gateway.caps.grant(cap) {
                granted += 1;
                self.audit_op("grant", &label, "lease issued", &state)?;
            }
        }
        Ok((granted, revoked))
    }

    /// Persist validated cube + live leases so `transition_to` survives
    /// restarts. Called by the supervisor after run/transition/create.
    pub fn persist(&self) -> Result<(), RuntimeError> {
        let saved = PersistedState {
            cube: self.cube.clone(),
            caps: self.gateway.caps.clone(),
        };
        let text =
            serde_json::to_string_pretty(&saved).map_err(|e| RuntimeError::Io(e.to_string()))?;
        std::fs::write(self.base_dir.join(STATE_FILE), text)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;
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

/// State-gated capability grants (spec §14.2). Leases are scoped,
/// state-bound (auto-revoked on exit), and time-bounded where the
/// privilege is high (network). Base read/search grants from INIT
/// carry no condition and always survive.
fn state_grants(next: AgentState, workspace: &Path, network_allow: &[String]) -> Vec<Capability> {
    let ws = workspace.to_string_lossy().to_string();
    let src = format!("{ws}/src");
    let mut out = vec![];
    match next {
        AgentState::Modify | AgentState::Validate => {
            let mut write = Capability::new("write", "filesystem", &src);
            write.condition = Some(Condition {
                protocol: None,
                require_state: None,
                valid_states: vec!["MODIFY".to_string(), "VALIDATE".to_string()],
            });
            out.push(write);
        }
        _ => {}
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
    // Bare hostnames (network) pass through untouched.
    if !scope.contains('/') && !scope.contains('.') {
        return scope.to_string();
    }
    if !scope.contains('/') {
        return scope.to_string(); // hostname like github.com
    }
    workspace.join(scope).to_string_lossy().to_string()
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
        let _ = std::fs::remove_dir_all(&base);
        let rt = Runtime::init(test_config(), base.clone()).unwrap();
        (rt, base)
    }

    #[test]
    fn write_denied_before_modify_grant() {
        let (mut rt, _base) = test_runtime("deny");
        let r = rt.gateway.write(&mut rt.cube, "src/a.rs", "x");
        assert!(r.is_err(), "INIT must not hold write");
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
        // Fresh boot resumes grants + state instead of resetting to INIT.
        let rt2 = Runtime::init(test_config(), base.clone()).unwrap();
        assert_eq!(rt2.cube.current_state(), AgentState::Modify);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn transition_denied_leaves_state_untouched() {
        let (mut rt, _base) = test_runtime("jump");
        let r = rt.transition_to(AgentState::Deploy, &TransitionGuards::default());
        assert!(r.is_err());
        assert_eq!(rt.cube.current_state(), AgentState::Init);
        assert!(rt.gateway.caps.caps.iter().all(|c| c.action != "write"));
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
        let _ = std::fs::remove_dir_all(&base);
    }
}
