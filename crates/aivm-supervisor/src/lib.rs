//! Supervisor — spec §7.
//!
//! Trusted component OUTSIDE the AI sandbox. Owns VM lifecycle:
//! create/start/stop/pause/kill/inspect. The agent can never mutate it
//! (invariant I-5).

use aivm_runtime::{Runtime, VmConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("vm '{0}' already exists")]
    Exists(String),
    #[error("vm '{0}' not found")]
    NotFound(String),
    #[error("runtime: {0}")]
    Runtime(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmStatus {
    Created,
    Running,
    Paused,
    Stopped,
    Killed,
}

pub struct Supervisor {
    root: PathBuf,
    vms: HashMap<String, (VmStatus, PathBuf)>,
}

impl Supervisor {
    pub fn new(root: PathBuf) -> Self {
        let mut s = Self { root, vms: HashMap::new() };
        s.discover();
        s
    }

    /// Pick up VMs created by previous CLI invocations (crash-safe,
    /// restart-safe: ground truth is `vms/<name>/aivm.yaml` on disk).
    fn discover(&mut self) {
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let dir = e.path();
            if dir.is_dir() && dir.join("aivm.yaml").is_file() {
                if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
                    self.vms
                        .entry(name.to_string())
                        .or_insert((VmStatus::Stopped, dir));
                }
            }
        }
    }

    /// Resolve a VM dir, falling back to disk if the in-memory map missed it.
    fn resolve(&mut self, name: &str) -> Result<PathBuf, SupervisorError> {
        if let Some((_, dir)) = self.vms.get(name) {
            return Ok(dir.clone());
        }
        let dir = self.vm_dir(name);
        if dir.join("aivm.yaml").is_file() {
            self.vms.insert(name.to_string(), (VmStatus::Stopped, dir.clone()));
            return Ok(dir);
        }
        Err(SupervisorError::NotFound(name.into()))
    }

    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn create(&mut self, name: &str, config: VmConfig) -> Result<(), SupervisorError> {
        if self.vms.contains_key(name) {
            return Err(SupervisorError::Exists(name.into()));
        }
        let dir = self.vm_dir(name);
        std::fs::create_dir_all(dir.join("workspace/src"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let yaml = serde_yaml::to_string(&config).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        std::fs::write(dir.join("aivm.yaml"), yaml)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        // Validate runtime boots fail-closed before registering.
        Runtime::init(config, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        self.vms.insert(name.to_string(), (VmStatus::Created, dir));
        Ok(())
    }

    pub fn run(&mut self, name: &str) -> Result<String, SupervisorError> {
        let dir = self.resolve(name)?;
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml")).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let mut rt = Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        if let Some((st, _)) = self.vms.get_mut(name) {
            *st = VmStatus::Running;
        }
        rt.step("init").map_err(|e| SupervisorError::Runtime(e.to_string()))
    }

    pub fn pause(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self.vms.get_mut(name).ok_or_else(|| SupervisorError::NotFound(name.into()))?;
        *st = VmStatus::Paused;
        let _ = dir;
        Ok(())
    }

    pub fn stop(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self.vms.get_mut(name).ok_or_else(|| SupervisorError::NotFound(name.into()))?;
        *st = VmStatus::Stopped;
        let _ = dir;
        Ok(())
    }

    pub fn kill(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self.vms.get_mut(name).ok_or_else(|| SupervisorError::NotFound(name.into()))?;
        *st = VmStatus::Killed;
        let _ = dir;
        Ok(())
    }

    pub fn inspect(&self, name: &str) -> Result<String, SupervisorError> {
        let dir = self
            .vms
            .get(name)
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| self.vm_dir(name));
        if !dir.join("aivm.yaml").is_file() {
            return Err(SupervisorError::NotFound(name.into()));
        }
        let st = self.vms.get(name).map(|(s, _)| s.clone()).unwrap_or(VmStatus::Stopped);
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml")).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let rt = Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(format!("{:?}\n{}", st, rt.inspect()))
    }

    pub fn status(&self, name: &str) -> Option<VmStatus> {
        self.vms.get(name).map(|(s, _)| s.clone())
    }
}
