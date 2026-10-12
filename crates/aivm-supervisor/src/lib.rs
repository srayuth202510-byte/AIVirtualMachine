//! Supervisor — ดูสเปก §7.
//!
//! องค์ประกอบที่ไว้ใจได้ อยู่นอก AI sandbox เป็นเจ้าของวงจรชีวิต VM:
//! create/start/stop/pause/kill/inspect agent แตะต้องไม่ได้ (invariant I-5)

use aivm_cube::{AgentState, TransitionGuards};
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
                        .or_insert((VmStatus::Stopped, dir));
                }
            }
        }
    }

    /// หาไดเรกทอรี VM ถ้าแผนที่ในหน่วยความจำตกหล่นก็ถอยไปดูดิสก์
    fn resolve(&mut self, name: &str) -> Result<PathBuf, SupervisorError> {
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
        let yaml =
            serde_yaml::to_string(&config).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        std::fs::write(dir.join("aivm.yaml"), yaml)
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        // ตรวจว่า runtime บูตแบบ fail-closed ได้ก่อนค่อยลงทะเบียน
        Runtime::init(config, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        self.vms.insert(name.to_string(), (VmStatus::Created, dir));
        Ok(())
    }

    pub fn run(&mut self, name: &str) -> Result<String, SupervisorError> {
        self.run_with_prompt(name, "init")
    }

    /// เหมือน `run` แต่กำหนด context/พรอมป์ต์ได้ (ใช้ทดสอบโมเดล local)
    pub fn run_with_prompt(&mut self, name: &str, prompt: &str) -> Result<String, SupervisorError> {
        let dir = self.resolve(name)?;
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

    pub fn pause(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self
            .vms
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.into()))?;
        *st = VmStatus::Paused;
        let _ = dir;
        Ok(())
    }

    pub fn stop(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self
            .vms
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.into()))?;
        *st = VmStatus::Stopped;
        let _ = dir;
        Ok(())
    }

    pub fn kill(&mut self, name: &str) -> Result<(), SupervisorError> {
        let dir = self.resolve(name)?;
        let (st, _) = self
            .vms
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.into()))?;
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
        let st = self
            .vms
            .get(name)
            .map(|(s, _)| s.clone())
            .unwrap_or(VmStatus::Stopped);
        let cfg = VmConfig::from_file(&dir.join("aivm.yaml"))
            .map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        let rt =
            Runtime::init(cfg, dir.clone()).map_err(|e| SupervisorError::Runtime(e.to_string()))?;
        Ok(format!("{:?}\n{}", st, rt.inspect()))
    }

    pub fn status(&self, name: &str) -> Option<VmStatus> {
        self.vms.get(name).map(|(s, _)| s.clone())
    }
}
