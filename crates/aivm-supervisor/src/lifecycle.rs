//! lock ข้าม CLI และควบคุม process จริงด้วย PID + start time ป้องกัน PID reuse
use crate::{SupervisorError, VmStatus};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn error(e: impl std::fmt::Display) -> SupervisorError {
    SupervisorError::Runtime(e.to_string())
}
#[derive(Serialize, Deserialize)]
struct Process {
    pid: u32,
    start: String,
}
fn identity(pid: u32) -> std::io::Result<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other("invalid process identity"))
}
fn process(dir: &Path) -> Option<Process> {
    let record: Process =
        serde_json::from_slice(&std::fs::read(dir.join("process.json")).ok()?).ok()?;
    (identity(record.pid).ok()? == record.start).then_some(record)
}
pub fn status(dir: &Path) -> VmStatus {
    let saved = std::fs::read(dir.join("status.json"))
        .ok()
        .and_then(|s| serde_json::from_slice(&s).ok())
        .unwrap_or(VmStatus::Stopped);
    if matches!(saved, VmStatus::Running | VmStatus::Paused) && process(dir).is_none() {
        VmStatus::Stopped
    } else {
        saved
    }
}
pub fn save_status(dir: &Path, status: &VmStatus) -> Result<(), SupervisorError> {
    aivm_tools::state_store::write_private(
        &dir.join("status.json"),
        &serde_json::to_string(status).map_err(error)?,
    )
    .map_err(error)
}
pub struct Lease {
    _lock: File,
    dir: PathBuf,
    active: bool,
}
impl Lease {
    pub fn acquire(dir: &Path, active: bool) -> Result<Self, SupervisorError> {
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("runtime.lock"))
            .map_err(error)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(error("VM already has an active operation"));
        }
        if active {
            let pid = std::process::id();
            let record = Process {
                pid,
                start: identity(pid).map_err(error)?,
            };
            aivm_tools::state_store::write_private(
                &dir.join("process.json"),
                &serde_json::to_string(&record).map_err(error)?,
            )
            .map_err(error)?;
            save_status(dir, &VmStatus::Running)?;
        }
        Ok(Self {
            _lock: lock,
            dir: dir.to_path_buf(),
            active,
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.active {
            let previous = status(&self.dir);
            let _ = std::fs::remove_file(self.dir.join("process.json"));
            if previous == VmStatus::Running {
                let _ = save_status(&self.dir, &VmStatus::Stopped);
            }
        }
        // unlock อย่างชัดเจน เพราะ thread อื่นอาจ fork และสืบทอด open description
        unsafe {
            libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn pidfd(pid: u32) -> Result<File, SupervisorError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn signal(fd: &File, sig: i32) -> Result<(), SupervisorError> {
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(error(e));
        }
    }
    Ok(())
}
fn children(parent: u32) -> Vec<u32> {
    let mut children = Vec::new();
    // process が複数 thread から spawn した子も対象にする
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent}/task")) {
        for task in tasks.flatten() {
            if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
                children.extend(
                    text.split_whitespace()
                        .filter_map(|s| s.parse::<u32>().ok()),
                );
            }
        }
    }
    children.sort_unstable();
    children.dedup();
    children
}
fn freeze_children(parent: u32, handles: &mut Vec<File>) -> Result<(), SupervisorError> {
    for child in children(parent) {
        if let Ok(fd) = pidfd(child) {
            signal(&fd, libc::SIGSTOP)?;
            freeze_children(child, handles)?;
            handles.push(fd);
        }
    }
    Ok(())
}
pub fn control(dir: &Path, sig: i32, state: VmStatus) -> Result<(), SupervisorError> {
    if let Some(record) = process(dir) {
        let root = pidfd(record.pid)?;
        if identity(record.pid).map_err(error)? != record.start {
            return Err(error("process identity changed"));
        }
        signal(&root, libc::SIGSTOP)?;
        let mut children = Vec::new();
        freeze_children(record.pid, &mut children)?;
        if sig != libc::SIGSTOP {
            for child in children {
                signal(&child, sig)?;
                if sig == libc::SIGTERM {
                    signal(&child, libc::SIGCONT)?;
                }
            }
            signal(&root, sig)?;
            if sig == libc::SIGTERM {
                signal(&root, libc::SIGCONT)?;
            }
        }
    }
    save_status(dir, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aivm-lifecycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    #[test]
    fn operations_are_exclusive_and_status_survives_restart() {
        let dir = directory();
        let lease = Lease::acquire(&dir, false).unwrap();
        assert!(Lease::acquire(&dir, false).is_err());
        save_status(&dir, &VmStatus::Created).unwrap();
        assert_eq!(status(&dir), VmStatus::Created);
        drop(lease);
        assert!(Lease::acquire(&dir, false).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn pause_and_kill_control_a_real_process() {
        let dir = directory();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let record = Process {
            pid: child.id(),
            start: identity(child.id()).unwrap(),
        };
        aivm_tools::state_store::write_private(
            &dir.join("process.json"),
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
        save_status(&dir, &VmStatus::Running).unwrap();
        control(&dir, libc::SIGSTOP, VmStatus::Paused).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
            if stat
                .rsplit_once(')')
                .unwrap()
                .1
                .trim_start()
                .starts_with('T')
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(status(&dir), VmStatus::Paused);
        control(&dir, libc::SIGKILL, VmStatus::Killed).unwrap();
        assert!(!child.wait().unwrap().success());
        assert_eq!(status(&dir), VmStatus::Killed);
        let _ = std::fs::remove_dir_all(dir);
    }
}
