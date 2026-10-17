//! Landlock บังคับ filesystem scope กับทั้ง subprocess tree (ต้องมี ABI >= 3)
use crate::{BuildSpec, SandboxError};
use aivm_policy::{Decision, EvalContext, Policy};
use std::cell::RefCell;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

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
pub(crate) struct MountGrant {
    pub path: PathBuf,
    pub file: File,
    pub access: u64,
    pub directory: bool,
}
struct PreparedRules {
    file: File,
    mounts: RefCell<Option<Vec<MountGrant>>>,
    workspace: Option<(PathBuf, File)>,
}
impl AsRawFd for PreparedRules {
    fn as_raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}
fn add(rules: &PreparedRules, path: &Path, access: u64) -> Result<(), SandboxError> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::Invalid("NUL in Landlock path".into()))?;
    // SAFETY: CString มีอายุครอบคลุม syscall และ fd ทุกตัวมีเจ้าของ
    let raw = if let Some((workspace, root)) = &rules.workspace {
        if let Ok(relative) = path.strip_prefix(workspace) {
            #[repr(C)]
            struct OpenHow {
                flags: u64,
                mode: u64,
                resolve: u64,
            }
            let relative = if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            };
            let relative = CString::new(relative.as_os_str().as_bytes())
                .map_err(|_| SandboxError::Invalid("NUL in relative mount path".into()))?;
            let how = OpenHow {
                flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
                mode: 0,
                resolve: 0x08 | 0x04 | 0x01,
            }; // BENEATH | NO_SYMLINKS | NO_XDEV
            unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    root.as_raw_fd(),
                    relative.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                ) as i32
            }
        } else {
            unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) }
        }
    } else {
        unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) }
    };
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
    if let Some(mounts) = rules.mounts.borrow_mut().as_mut() {
        if mounts.len() >= 1024 {
            return Err(SandboxError::Invalid(
                "container mount plan exceeds 1024 grants".into(),
            ));
        }
        let directory = file
            .metadata()
            .map_err(|e| SandboxError::Invalid(e.to_string()))?
            .is_dir();
        mounts.push(MountGrant {
            path: path.to_path_buf(),
            file,
            access,
            directory,
        });
    }
    Ok(())
}
pub fn prepare(
    workspace: &Path,
    exe: &Path,
    policy: &Policy,
    budget: u64,
    build: Option<&BuildSpec>,
) -> Result<(File, u64), SandboxError> {
    let (file, limit, _) = prepare_inner(workspace, exe, policy, budget, build, false)?;
    Ok((file, limit))
}
pub(crate) fn prepare_mounts(
    workspace: &Path,
    exe: &Path,
    policy: &Policy,
    budget: u64,
    build: Option<&BuildSpec>,
) -> Result<(Vec<MountGrant>, u64), SandboxError> {
    let (_, limit, mounts) = prepare_inner(workspace, exe, policy, budget, build, true)?;
    Ok((mounts, limit))
}
fn prepare_inner(
    workspace: &Path,
    exe: &Path,
    policy: &Policy,
    budget: u64,
    build: Option<&BuildSpec>,
    collect_mounts: bool,
) -> Result<(File, u64, Vec<MountGrant>), SandboxError> {
    let mut rules = new_rules(collect_mounts)?;
    if collect_mounts {
        let name = CString::new(workspace.as_os_str().as_bytes())
            .map_err(|_| SandboxError::Invalid("NUL in workspace".into()))?;
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            return Err(error());
        }
        rules.workspace = Some((workspace.to_path_buf(), unsafe { File::from_raw_fd(fd) }));
    }
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
        if path.is_file()
            && policy.evaluate_process(binary, &EvalContext::default()).0 == Decision::Allow
        {
            add(&rules, path, EXECUTE | READ_FILE)?;
        }
    }
    if build.is_some() {
        for (path, access) in [
            ("/usr/include", READ_FILE | READ_DIR),
            ("/usr/libexec/gcc", READ_FILE | READ_DIR | EXECUTE),
        ] {
            if Path::new(path).is_dir() {
                add(&rules, Path::new(path), access)?;
            }
        }
    }
    // เดินรายการไฟล์จริงแล้ว grant เฉพาะที่ policy อนุญาต; ไม่ grant subtree
    // อ่านกว้าง เพราะจะทำให้ deny ของไฟล์ลูกไม่มีผล (Landlock เป็น additive)
    fn walk(
        rules: &PreparedRules,
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
        if path.starts_with(workspace.join(".aivm-build")) {
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
            rules: &PreparedRules,
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
                    if path.file_name().is_some_and(|name| name == ".aivm-build") {
                        continue;
                    }
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
    if let Some(build) = build {
        let expected = workspace.join(".aivm-build");
        let meta = std::fs::symlink_metadata(&build.root)
            .map_err(|e| SandboxError::Invalid(e.to_string()))?;
        if build.root != expected
            || !meta.is_dir()
            || meta.file_type().is_symlink()
            || build
                .root
                .canonicalize()
                .map_err(|e| SandboxError::Invalid(e.to_string()))?
                != expected
            || build.max_file_bytes == 0
            || build.max_file_bytes > budget
        {
            return Err(SandboxError::Invalid("invalid build output profile".into()));
        }
        add(&rules, &build.root, READ_FILE | READ_DIR)?;
        for path in &build.outputs {
            let meta = std::fs::symlink_metadata(path)
                .map_err(|e| SandboxError::Invalid(e.to_string()))?;
            if path.parent() != Some(build.root.as_path()) || !meta.is_file() || meta.nlink() != 1 {
                return Err(SandboxError::Invalid("unsafe build output slot".into()));
            }
            add(&rules, path, WRITE_FILE | (1 << 14))?;
            writable.insert(path.clone(), meta.len());
        }
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
    let per_file = build
        .map(|profile| per_file.min(profile.max_file_bytes))
        .unwrap_or(per_file);
    Ok((
        rules.file,
        per_file.max(1),
        rules.mounts.into_inner().unwrap_or_default(),
    ))
}

fn new_rules(collect_mounts: bool) -> Result<PreparedRules, SandboxError> {
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
    Ok(PreparedRules {
        file: unsafe { File::from_raw_fd(fd) },
        mounts: RefCell::new(collect_mounts.then(Vec::new)),
        workspace: None,
    })
}

pub(crate) fn restrict_mounts(grants: &[(PathBuf, u64)]) -> Result<(), SandboxError> {
    let rules = new_rules(false)?;
    for (path, access) in grants {
        add(&rules, path, *access)?;
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0) } < 0
    {
        return Err(error());
    }
    Ok(())
}
