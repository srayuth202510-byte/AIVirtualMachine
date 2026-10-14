//! Landlock บังคับ filesystem scope กับทั้ง subprocess tree (ต้องมี ABI >= 3)
use crate::SandboxError;
use aivm_policy::{Decision, EvalContext, Policy};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const EXECUTE: u64 = 1;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
#[repr(C)]
struct Ruleset {
    handled: u64,
}
#[repr(C, packed)]
struct PathRule {
    allowed: u64,
    parent_fd: i32,
}
fn error() -> SandboxError {
    SandboxError::Disabled(format!(
        "Landlock required: {}",
        std::io::Error::last_os_error()
    ))
}
fn add(rules: &File, path: &Path, access: u64) -> Result<(), SandboxError> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::Invalid("NUL in Landlock path".into()))?;
    // SAFETY: CString มีอายุครอบคลุม syscall และ fd ทุกตัวมีเจ้าของ
    let raw = unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(error());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    let mut access = access;
    if !file
        .metadata()
        .map_err(|e| SandboxError::Invalid(e.to_string()))?
        .is_dir()
    {
        access &= EXECUTE | READ_FILE | WRITE_FILE | (1 << 14);
    }
    let rule = PathRule {
        allowed: access,
        parent_fd: file.as_raw_fd(),
    };
    if unsafe { libc::syscall(libc::SYS_landlock_add_rule, rules.as_raw_fd(), 1, &rule, 0) } < 0 {
        return Err(error());
    }
    Ok(())
}
pub fn prepare(
    workspace: &Path,
    exe: &Path,
    policy: &Policy,
    budget: u64,
) -> Result<(File, u64), SandboxError> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err(SandboxError::Disabled(
            "process sandbox requires Landlock ABI >= 3".into(),
        ));
    }
    let attributes = Ruleset {
        handled: (1 << 15) - 1,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    } as i32;
    if fd < 0 {
        return Err(error());
    }
    let rules = unsafe { File::from_raw_fd(fd) };
    // libraries/toolchain อ่านได้ แต่ไม่มีสิทธิ์เขียน host directories
    for path in [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/dev/null",
        "/dev/urandom",
    ] {
        let path = Path::new(path);
        if path.exists() {
            add(&rules, path, READ_FILE | READ_DIR | EXECUTE)?;
        }
    }
    // binary ที่ operator อนุญาตเป็นข้อยกเว้นเฉพาะไฟล์ ไม่ใช่ parent directory
    add(&rules, exe, EXECUTE | READ_FILE)?;
    for binary in &policy.process.allow {
        let path = Path::new(binary);
        if path.is_file() && policy.evaluate_process(binary).0 == Decision::Allow {
            add(&rules, path, EXECUTE | READ_FILE)?;
        }
    }
    // เดินรายการไฟล์จริงแล้ว grant เฉพาะที่ policy อนุญาต; ไม่ grant subtree
    // อ่านกว้าง เพราะจะทำให้ deny ของไฟล์ลูกไม่มีผล (Landlock เป็น additive)
    fn walk(
        rules: &File,
        dir: &Path,
        workspace: &Path,
        policy: &Policy,
    ) -> Result<(), SandboxError> {
        if dir != workspace
            && dir
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| matches!(s, "secrets" | "policies" | "audit"))
        {
            return Ok(());
        }
        add(rules, dir, READ_DIR)?;
        for entry in std::fs::read_dir(dir).map_err(|e| SandboxError::Invalid(e.to_string()))? {
            let path = entry
                .map_err(|e| SandboxError::Invalid(e.to_string()))?
                .path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| SandboxError::Invalid(e.to_string()))?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                walk(rules, &path, workspace, policy)?;
            } else if meta.is_file()
                && meta.nlink() == 1
                && policy
                    .evaluate_fs("read", &path.to_string_lossy(), &EvalContext::default())
                    .0
                    == Decision::Allow
            {
                add(rules, &path, READ_FILE)?;
            }
        }
        Ok(())
    }
    use std::os::unix::fs::MetadataExt;
    walk(&rules, workspace, workspace, policy)?;
    let mut writable = std::collections::BTreeMap::<std::path::PathBuf, u64>::new();
    // write subtree จะรวมไฟล์ใหม่ ต้องปฏิเสธเมื่อมี deny ที่ซ้อนอยู่ใน scope
    for scope in &policy.filesystem.write {
        if scope.contains(['*', '?', '[']) {
            return Err(SandboxError::Invalid(
                "process write scopes must be concrete directories".into(),
            ));
        }
        let path = Path::new(scope);
        if !path.starts_with(workspace) || !path.exists() {
            continue;
        }
        if !path.is_dir() {
            let meta = std::fs::symlink_metadata(path)
                .map_err(|e| SandboxError::Invalid(e.to_string()))?;
            if meta.is_file()
                && meta.nlink() == 1
                && policy
                    .evaluate_fs("write", &path.to_string_lossy(), &EvalContext::default())
                    .0
                    == Decision::Allow
            {
                add(&rules, path, WRITE_FILE | (1 << 14))?;
                writable.insert(path.to_path_buf(), meta.len());
            }
            continue;
        }
        let real = path
            .canonicalize()
            .map_err(|e| SandboxError::Invalid(e.to_string()))?;
        if !real.starts_with(workspace) {
            return Err(SandboxError::Invalid(
                "process write scope symlink escape".into(),
            ));
        }
        // deny globs (.env/secrets/...) ไม่สามารถแทนด้วย additive Landlock ได้
        // จึงให้เขียนไฟล์ที่มีอยู่และอนุญาตเท่านั้น; file creation ผ่าน gateway
        fn grant_write(
            rules: &File,
            dir: &Path,
            policy: &Policy,
            writable: &mut std::collections::BTreeMap<std::path::PathBuf, u64>,
        ) -> Result<(), SandboxError> {
            for entry in std::fs::read_dir(dir).map_err(|e| SandboxError::Invalid(e.to_string()))? {
                let path = entry
                    .map_err(|e| SandboxError::Invalid(e.to_string()))?
                    .path();
                let meta = std::fs::symlink_metadata(&path)
                    .map_err(|e| SandboxError::Invalid(e.to_string()))?;
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    grant_write(rules, &path, policy, writable)?;
                } else if meta.is_file()
                    && meta.nlink() == 1
                    && policy
                        .evaluate_fs("write", &path.to_string_lossy(), &EvalContext::default())
                        .0
                        == Decision::Allow
                {
                    add(rules, &path, WRITE_FILE | (1 << 14))?;
                    writable.insert(path, meta.len());
                }
            }
            Ok(())
        }
        grant_write(&rules, &real, policy, &mut writable)?;
    }
    fn usage(dir: &Path) -> Result<u64, SandboxError> {
        let mut bytes = 0u64;
        for entry in std::fs::read_dir(dir).map_err(|e| SandboxError::Invalid(e.to_string()))? {
            let path = entry
                .map_err(|e| SandboxError::Invalid(e.to_string()))?
                .path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| SandboxError::Invalid(e.to_string()))?;
            if meta.is_dir() {
                bytes = bytes.saturating_add(usage(&path)?);
            } else if meta.is_file() {
                bytes = bytes.saturating_add(meta.len());
            }
        }
        Ok(bytes)
    }
    let used = usage(workspace)?;
    if used > budget {
        return Err(SandboxError::Invalid(
            "workspace exceeds storage quota".into(),
        ));
    }
    let readonly = used.saturating_sub(writable.values().copied().sum::<u64>());
    // จำกัดแต่ละไฟล์แบบ conservative เพื่อให้ผลรวมไม่เกิน storage quota
    let per_file = budget.saturating_sub(readonly) / (writable.len() as u64).max(1);
    Ok((rules, per_file.max(1)))
}
