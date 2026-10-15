//! Supervisor — ดูสเปก §7.
//!
//! องค์ประกอบที่ไว้ใจได้ อยู่นอก AI sandbox เป็นเจ้าของวงจรชีวิต VM:
//! create/start/stop/pause/kill/inspect agent แตะต้องไม่ได้ (invariant I-5)

use aivm_cube::{AgentState, TransitionGuards};
use aivm_runtime::{Runtime, VmConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
mod lifecycle;

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("vm '{0}' already exists")]
    Exists(String),
    #[error("vm '{0}' not found")]
    NotFound(String),
    #[error("runtime: {0}")]
    Runtime(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        let mut s = Self {
            root,
            vms: HashMap::new(),
        };
        s.discover();
        s
    }

    /// เก็บ VM ที่คำสั่ง CLI ครั้งก่อนสร้างไว้ (ทน crash/restart ได้
    /// ต้นฉบับความจริงคือ `vms/<name>/aivm.yaml` บนดิสก์)
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
                        .or_insert_with(|| (lifecycle::status(&dir), dir));
                }
            }
        }
    }

    /// หาไดเรกทอรี VM ถ้าแผนที่ในหน่วยความจำตกหล่นก็ถอยไปดูดิสก์
    fn resolve(&mut self, name: &str) -> Result<PathBuf, SupervisorError> {
        Self::validate_name(name)?;
        if let Some((_, dir)) = self.vms.get(name) {
            return Ok(dir.clone());
        }
        let dir = self.vm_dir(name);
        if dir.join("aivm.yaml").is_file() {
            self.vms
                .insert(name.to_string(), (VmStatus::Stopped, dir.clone()));
            return Ok(dir);
        }
        Err(SupervisorError::NotFound(name.into()))
    }

    fn validate_name(name: &str) -> Result<(), SupervisorError> {
        if name.is_empty()
            || name.len() > 64
            || name == "."
            || name == ".."
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(SupervisorError::Runtime("invalid VM name".into()));
        }
        Ok(())
    }

    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn create(&mut self, name: &str, mut config: VmConfig) -> Result<(), SupervisorError> {
        Self::validate_name(name)?;
        if self.vms.contains_key(name) || self.vm_dir(name).exists() {
            return Err(SupervisorError::Exists(name.into()));
        }
        let dir = self.vm_dir(name);
        std::fs::create_dir_all(&self.root).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        // Reserve the name atomically. Only this operation owns the new
        // directory, so a failed create cannot delete another creator's VM.
        std::fs::create_dir(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SupervisorError::Exists(name.into())
            } else {
                SupervisorError::Runtime(e.to_string())
            }
        })?;
        let result = (|| {
            let _lease = lifecycle::Lease::acquire(&dir, false)?;
            std::fs::create_dir_all(dir.join("workspace/src"))
                .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
            config.name = name.into();
            let yaml = serde_yaml::to_string(&config)
                .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
            let rt = Runtime::init(config, dir.clone())
                .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
            rt.persist()
                .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
            lifecycle::save_status(&dir, &VmStatus::Created)?;
            // Publish the discovery marker last, after validation and state.
            aivm_tools::state_store::write_private(&dir.join("aivm.yaml"), &yaml)
                .map_err(|e| SupervisorError::Runtime(e.to_string()))
        })();
        if let Err(error) = result {
            aivm_audit::clear_flags(&dir);
            std::fs::remove_dir_all(&dir).map_err(|cleanup| {
                SupervisorError::Runtime(format!("{error}; create cleanup failed: {cleanup}"))
            })?;
            return Err(error);
        }
        self.vms.insert(name.to_string(), (VmStatus::Created, dir));
        Ok(())
    }

    pub fn run(&mut self, name: &str) -> Result<String, SupervisorError> {
        self.run_with_prompt(name, "init")
    }

    /// เหมือน `run` แต่กำหนด context/พรอมป์ต์ได้ (ใช้ทดสอบโมเดล local)
    pub fn run_with_prompt(&mut self, name: &str, prompt: &str) -> Result<String, SupervisorError> {
        let dir = self.resolve(name)?;
        let _lease = lifecycle::Lease::acquire(&dir, true)?;
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        if let Some((st, _)) = self.vms.get_mut(name) {
            *st = VmStatus::Running;
        }
        let out = rt
            .step(prompt)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        rt.persist()
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(out)
    }

    /// Agent loop เต็มรอบ (Phase 5) — โมเดลคิดเป็น intent แล้วผ่าน gateway
    /// ถ้า `workspace` ให้มา จะสร้าง RAG index และผสม context ลง prompt (Phase 6)
    pub fn run_agent(
        &mut self,
        name: &str,
        task: &str,
        max_steps: usize,
        workspace: Option<&std::path::Path>,
    ) -> Result<aivm_runtime::agent::AgentRun, SupervisorError> {
        let dir = self.resolve(name)?;
        let _lease = lifecycle::Lease::acquire(&dir, true)?;
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        if let Some((st, _)) = self.vms.get_mut(name) {
            *st = VmStatus::Running;
        }
        let run = rt
            .run_agent(task, max_steps, workspace)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        rt.persist()
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(run)
    }

    /// เดิน state ไปข้างหน้าแบบ validate พร้อมให้/เพิกถอนสิทธิ์แบบ dynamic (§14)
    /// guard มาจาก operator (confidence ผลเทสต์ ผล policy)
    /// ไม่รับจาก agent คืน `(granted, revoked)`
    pub fn transition(
        &mut self,
        name: &str,
        next: AgentState,
        guards: &TransitionGuards,
    ) -> Result<(usize, usize), SupervisorError> {
        let dir = self.resolve(name)?;
        let _lease = lifecycle::Lease::acquire(&dir, false)?;
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let out = rt
            .transition_to(next, guards)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        rt.persist()
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(out)
    }

    /// Approve PENDING secret lease (G4b — operator เท่านั้น):
    /// exact lease id + audit ระบุผู้ approve + persist ทันที
    /// คืนสรุป lease (ไม่มี value) ไว้แสดงให้ operator ดู
    pub fn approve_secret(
        &mut self,
        name: &str,
        lease_id: &str,
        approved_by: &str,
    ) -> Result<String, SupervisorError> {
        let dir = self.resolve(name)?;
        let _lease = lifecycle::Lease::acquire(&dir, false)?;
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let mut rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let sum = rt
            .approve_secret_lease(lease_id, approved_by)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        rt.persist()
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(format!(
            "approved {} (tool={} resource={} scope={} uses={}/{} by={})",
            sum.id,
            sum.tool,
            sum.resource,
            sum.scope,
            sum.uses,
            sum.max_uses,
            sum.approved_by.unwrap_or_default(),
        ))
    }

    pub fn pause(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        lifecycle::control(&dir, libc::SIGSTOP, VmStatus::Paused)?;
        if let Some((state, _)) = self.vms.get_mut(name) {
            *state = VmStatus::Paused;
        }
        Ok(())
    }

    pub fn stop(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        lifecycle::control(&dir, libc::SIGTERM, VmStatus::Stopped)?;
        if let Some((state, _)) = self.vms.get_mut(name) {
            *state = VmStatus::Stopped;
        }
        Ok(())
    }

    pub fn kill(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        lifecycle::control(&dir, libc::SIGKILL, VmStatus::Killed)?;
        if let Some((state, _)) = self.vms.get_mut(name) {
            *state = VmStatus::Killed;
        }
        Ok(())
    }

    pub fn inspect(&self, name: &str) -> Result<String, SupervisorError> {
        Self::validate_name(name)?;
        let dir = self
            .vms
            .get(name)
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| self.vm_dir(name));
        if !dir.join("aivm.yaml").is_file() {
            return Err(SupervisorError::NotFound(name.into()));
        }
        let st = lifecycle::status(&dir);
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(format!("{:?}\n{}", st, rt.inspect()))
    }

    pub fn status(&self, name: &str) -> Option<VmStatus> {
        self.vms.get(name).map(|(_, dir)| lifecycle::status(dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aivm-create-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn failed_create_removes_partial_vm_and_allows_retry() {
        let root = root("retry");
        let mut supervisor = Supervisor::new(root.clone());
        let config = VmConfig::from_yaml("name: test").unwrap();
        let mut bad = config.clone();
        bad.runtime.isolation = "invalid".into();
        assert!(supervisor.create("vm", bad).is_err());
        assert!(!root.join("vm").exists());
        assert!(Supervisor::new(root.clone()).status("vm").is_none());
        supervisor.create("vm", config.clone()).unwrap();
        assert_eq!(
            Supervisor::new(root.clone()).status("vm"),
            Some(VmStatus::Created)
        );
        assert!(root.join("vm/state.json").is_file());
        assert!(matches!(
            supervisor.create("vm", config),
            Err(SupervisorError::Exists(_))
        ));
        aivm_audit::clear_flags(&root);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_creators_cannot_overwrite_each_other() {
        let root = root("concurrent");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let creators: Vec<_> = (0..2)
            .map(|i| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut supervisor = Supervisor::new(root);
                    let config =
                        VmConfig::from_yaml(&format!("name: test\nresources:\n  cpu: {}", i + 1))
                            .unwrap();
                    barrier.wait();
                    supervisor.create("vm", config).map(|()| i + 1)
                })
            })
            .collect();
        let results: Vec<_> = creators.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(SupervisorError::Exists(_))))
                .count(),
            1
        );
        let winner = results.into_iter().find_map(Result::ok).unwrap();
        let config = VmConfig::from_file(&root.join("vm/aivm.yaml")).unwrap();
        assert_eq!(config.resources.cpu, winner);
        assert!(Runtime::init(config, root.join("vm")).is_ok());
        aivm_audit::clear_flags(&root);
        std::fs::remove_dir_all(root).unwrap();
    }
}
