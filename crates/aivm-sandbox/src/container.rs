//! Bubblewrap container backend. Setup failures never fall back to Process.
use crate::{ExecOutcome, ExecSpec, SandboxError};
use aivm_policy::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operator-owned host configuration; never supplied by a tool request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContainerConfig {
    pub bubblewrap: PathBuf,
    /// Trusted helper installed from this crate (aivm-container-init).
    pub init: PathBuf,
    /// Existing, delegated cgroup v2 directory with cpu/memory/pids enabled.
    pub cgroup_root: PathBuf,
}
impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            bubblewrap: "/usr/bin/bwrap".into(),
            init: "/usr/libexec/aivm-container-init".into(),
            cgroup_root: "/sys/fs/cgroup/aivm".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerProbe {
    pub bubblewrap: bool,
    pub init: bool,
    /// Can allocate, enforce/read back quotas and clean a private cgroup.
    pub cgroup_v2_quotas: bool,
}
impl ContainerConfig {
    pub fn probe(&self) -> ContainerProbe {
        #[cfg(target_os = "linux")]
        return linux::probe(self);
        #[cfg(not(target_os = "linux"))]
        ContainerProbe::default()
    }
}

pub fn run(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &ContainerConfig,
) -> Result<ExecOutcome, SandboxError> {
    run_cancellable(
        spec,
        policy,
        cfg,
        &std::sync::atomic::AtomicBool::new(false),
    )
}

pub fn run_cancellable(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &ContainerConfig,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<ExecOutcome, SandboxError> {
    run_observed(spec, policy, cfg, cancelled, None)
}

pub fn run_observed(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &ContainerConfig,
    cancelled: &std::sync::atomic::AtomicBool,
    observer: Option<std::sync::mpsc::Sender<Vec<u8>>>,
) -> Result<ExecOutcome, SandboxError> {
    #[cfg(target_os = "linux")]
    return linux::run(spec, policy, cfg, cancelled, observer);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (spec, policy, cfg);
        Err(SandboxError::Disabled(
            "container backend requires Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{
        landlock, revalidate_exe, validate, MAX_OUTPUT, SANDBOX_CPU_SECS, SANDBOX_FS_MB,
        SANDBOX_PATH,
    };
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{fs::MetadataExt, process::CommandExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const READY: &str = "aivm-container-init:ready-v1\n";

    fn disabled(error: impl std::fmt::Display) -> SandboxError {
        SandboxError::Disabled(format!("container prerequisites: {error}"))
    }
    fn spawn_error(error: impl std::fmt::Display) -> SandboxError {
        SandboxError::Spawn(format!("container: {error}"))
    }

    struct Cgroup {
        path: PathBuf,
        procs: File,
        kill: File,
    }
    impl Cgroup {
        fn create(root: &Path, limits: &crate::ResourceLimits) -> Result<Self, SandboxError> {
            if !root.is_absolute() {
                return Err(disabled("cgroup_root must be absolute"));
            }
            let root = root.canonicalize().map_err(disabled)?;
            let dir = File::open(&root).map_err(disabled)?;
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
                || stat.f_type != 0x63677270
            {
                return Err(disabled("cgroup_root must be a cgroup v2 filesystem"));
            }
            let enabled =
                std::fs::read_to_string(root.join("cgroup.subtree_control")).map_err(disabled)?;
            if !["cpu", "memory", "pids"]
                .iter()
                .all(|c| enabled.split_whitespace().any(|v| v == *c))
            {
                return Err(disabled(
                    "cpu/memory/pids must be delegated and enabled by operator",
                ));
            }
            // Kernel creates control files atomically with this exclusive directory.
            let mut path = None;
            for n in 0..100 {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(disabled)?
                    .as_nanos();
                let candidate = root.join(format!("aivm-{}-{stamp}-{n}", std::process::id()));
                match std::fs::create_dir(&candidate) {
                    Ok(()) => {
                        path = Some(candidate);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(disabled(e)),
                }
            }
            let path = path.ok_or_else(|| disabled("cannot allocate private cgroup"))?;
            let setup = || -> Result<Self, SandboxError> {
                let memory = limits
                    .memory_mb
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| disabled("memory quota overflow"))?;
                let values = [
                    (
                        "cpu.max",
                        format!("{} 100000", u64::from(limits.cpu) * 100000),
                    ),
                    ("memory.max", memory.to_string()),
                    ("memory.swap.max", "0".into()),
                    ("memory.oom.group", "1".into()),
                    ("pids.max", limits.pids_max.to_string()),
                ];
                for (knob, value) in values {
                    std::fs::write(path.join(knob), &value).map_err(disabled)?;
                    if std::fs::read_to_string(path.join(knob))
                        .map_err(disabled)?
                        .trim()
                        != value
                    {
                        return Err(disabled(format!("{knob} readback mismatch")));
                    }
                }
                Ok(Self {
                    procs: File::options()
                        .write(true)
                        .open(path.join("cgroup.procs"))
                        .map_err(disabled)?,
                    kill: File::options()
                        .write(true)
                        .open(path.join("cgroup.kill"))
                        .map_err(disabled)?,
                    path: path.clone(),
                })
            };
            match setup() {
                Ok(cg) => Ok(cg),
                Err(e) => {
                    let _ = std::fs::remove_dir(&path);
                    Err(e)
                }
            }
        }
        fn cleanup(&self) -> Result<(), SandboxError> {
            // cgroup.kill reaches descendants regardless of sessions/process groups.
            if unsafe { libc::pwrite(self.kill.as_raw_fd(), b"1".as_ptr().cast(), 1, 0) } != 1 {
                return Err(spawn_error(std::io::Error::last_os_error()));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let events = std::fs::read_to_string(self.path.join("cgroup.events"))
                    .map_err(spawn_error)?;
                if events.lines().any(|line| line == "populated 0") {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(spawn_error("cgroup cleanup timed out"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            std::fs::remove_dir(&self.path).map_err(spawn_error)
        }
    }
    impl Drop for Cgroup {
        fn drop(&mut self) {
            if self.path.exists() {
                let _ = self.cleanup();
            }
        }
    }

    fn memfile(name: &std::ffi::CStr) -> Result<File, SandboxError> {
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if fd < 0 {
            return Err(spawn_error(std::io::Error::last_os_error()));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn seal(file: &mut File) -> Result<(), SandboxError> {
        file.seek(SeekFrom::Start(0)).map_err(spawn_error)?;
        if unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(spawn_error(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    #[derive(Serialize, Deserialize)]
    struct InitPlan {
        exe: PathBuf,
        args: Vec<String>,
        grants: Vec<(PathBuf, u64)>,
        fsize: u64,
    }

    pub(super) fn init_main() -> Result<(), SandboxError> {
        let mut text = String::new();
        let args: Vec<OsString> = std::env::args_os().collect();
        let plan_path = match args.as_slice() {
            [_] => PathBuf::from("/run/aivm-init.json"),
            [_, flag, path] if flag == "--plan" => PathBuf::from(path),
            _ => return Err(spawn_error("invalid init arguments")),
        };
        File::open(plan_path)
            .map_err(spawn_error)?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(spawn_error)?;
        if text.len() > 1024 * 1024 {
            return Err(spawn_error("init plan too large"));
        }
        let plan: InitPlan = serde_json::from_str(&text).map_err(spawn_error)?;
        landlock::restrict_mounts(&plan.grants)?;
        let limit = libc::rlimit {
            rlim_cur: plan.fsize,
            rlim_max: plan.fsize,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) } != 0 {
            return Err(spawn_error(std::io::Error::last_os_error()));
        }
        // Trusted prefix is emitted only after Landlock and file limits succeed.
        // The target cannot run (or spoof readiness) before these gates complete.
        std::io::stdout()
            .write_all(READY.as_bytes())
            .map_err(spawn_error)?;
        // No fork: Landlock/seccomp/cgroup limits stay with the entire target tree.
        Err(spawn_error(Command::new(plan.exe).args(plan.args).exec()))
    }

    /// Shared policy grants become an empty tree plus pinned file mounts.
    /// READ_DIR alone must not expose a directory's contents.
    fn mount_args(grants: &[landlock::MountGrant]) -> Result<Vec<OsString>, SandboxError> {
        let mut paths = BTreeMap::<PathBuf, (usize, u64, bool)>::new();
        for (i, grant) in grants.iter().enumerate() {
            if grant.path.starts_with("/dev") {
                continue;
            } // bwrap supplies a private /dev
            let e = paths
                .entry(grant.path.clone())
                .or_insert((i, 0, grant.directory));
            if grants[e.0].file.metadata().map_err(spawn_error)?.ino()
                != grant.file.metadata().map_err(spawn_error)?.ino()
                || grants[e.0].file.metadata().map_err(spawn_error)?.dev()
                    != grant.file.metadata().map_err(spawn_error)?.dev()
            {
                return Err(spawn_error(
                    "filesystem grant changed during policy preparation",
                ));
            }
            e.1 |= grant.access;
        }
        let mut args = Vec::new();
        for (path, (i, access, directory)) in &paths {
            if *directory && access & 4 == 0 {
                args.extend([OsString::from("--dir"), path.as_os_str().to_owned()]);
            } else {
                args.extend([
                    OsString::from(if access & 2 == 0 {
                        "--ro-bind-fd"
                    } else {
                        "--bind-fd"
                    }),
                    OsString::from(grants[*i].file.as_raw_fd().to_string()),
                    path.as_os_str().to_owned(),
                ]);
            }
        }
        Ok(args)
    }

    fn drain(
        mut pipe: impl Read + Send + 'static,
        observer: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    ) -> std::thread::JoinHandle<std::io::Result<(String, bool)>> {
        std::thread::spawn(move || {
            let mut saved = Vec::new();
            let mut buffer = [0; 8192];
            let mut truncated = false;
            loop {
                let n = pipe.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let keep = n.min((MAX_OUTPUT as usize).saturating_sub(saved.len()));
                if let Some(observer) = &observer {
                    if keep > 0 {
                        let _ = observer.send(buffer[..keep].to_vec());
                    }
                }
                saved.extend_from_slice(&buffer[..keep]);
                truncated |= keep != n;
            }
            Ok((String::from_utf8_lossy(&saved).into_owned(), truncated))
        })
    }

    fn trusted_executable(path: &Path) -> bool {
        if !path.is_absolute() {
            return false;
        }
        path.metadata().is_ok_and(|m| {
            m.is_file() && m.uid() == 0 && m.mode() & 0o6022 == 0 && m.mode() & 0o111 != 0
        })
    }
    pub(super) fn probe(cfg: &ContainerConfig) -> ContainerProbe {
        ContainerProbe {
            bubblewrap: trusted_executable(&cfg.bubblewrap),
            init: trusted_executable(&cfg.init),
            cgroup_v2_quotas: Cgroup::create(&cfg.cgroup_root, &crate::ResourceLimits::default())
                .is_ok_and(|cg| cg.cleanup().is_ok()),
        }
    }

    pub(super) fn run(
        spec: &ExecSpec,
        policy: &Policy,
        cfg: &ContainerConfig,
        cancelled: &std::sync::atomic::AtomicBool,
        observer: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    ) -> Result<ExecOutcome, SandboxError> {
        let exe = validate(spec, policy)?;
        if !cfg.bubblewrap.is_absolute() {
            return Err(disabled("bubblewrap path must be absolute"));
        }
        let bwrap = File::open(&cfg.bubblewrap).map_err(disabled)?;
        let metadata = bwrap.metadata().map_err(disabled)?;
        // A setuid wrapper cannot be used with our no-new-privileges contract.
        if !metadata.is_file()
            || metadata.mode() & 0o6000 != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || metadata.uid() != 0
        {
            return Err(disabled(
                "bubblewrap must be a root-owned, non-setuid executable without group/world write",
            ));
        }
        if !cfg.init.is_absolute() {
            return Err(disabled("init path must be absolute"));
        }
        let init = File::open(&cfg.init).map_err(disabled)?;
        let metadata = init.metadata().map_err(disabled)?;
        if !metadata.is_file()
            || metadata.mode() & 0o6022 != 0
            || metadata.mode() & 0o111 == 0
            || metadata.uid() != 0
        {
            return Err(disabled(
                "init must be a root-owned, non-setuid executable without group/world write",
            ));
        }
        let ws = spec.workspace.canonicalize().map_err(spawn_error)?;
        for reserved in [
            "/usr/lib",
            "/usr/lib64",
            "/lib",
            "/lib64",
            "/usr/include",
            "/usr/libexec",
            "/proc",
            "/dev",
            "/sys",
            "/run/aivm-container-init",
            "/run/aivm-init.json",
        ] {
            let reserved = Path::new(reserved);
            if ws.starts_with(reserved) || reserved.starts_with(&ws) {
                return Err(SandboxError::Invalid(
                    "workspace overlaps container system mounts".into(),
                ));
            }
        }
        let cwd = if spec.cwd.is_absolute() {
            spec.cwd.clone()
        } else {
            ws.join(&spec.cwd)
        }
        .canonicalize()
        .map_err(spawn_error)?;
        let mut filesystem_policy = policy.clone();
        if !spec.env_extra.is_empty() || spec.build.is_some() {
            filesystem_policy.filesystem.write.clear();
        }
        let storage = spec
            .limits
            .storage_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| disabled("storage quota overflow"))?;
        let (grants, file_limit) =
            landlock::prepare_mounts(&ws, &exe, &filesystem_policy, storage, spec.build.as_ref())?;
        let mut plan = memfile(c"aivm-container-init-plan")?;
        serde_json::to_writer(
            &mut plan,
            &InitPlan {
                exe: exe.clone(),
                args: spec.args.clone(),
                fsize: file_limit.min(SANDBOX_FS_MB * 1024 * 1024),
                grants: grants.iter().map(|g| (g.path.clone(), g.access)).collect(),
            },
        )
        .map_err(spawn_error)?;
        if plan.metadata().map_err(spawn_error)?.len() > 1024 * 1024 {
            return Err(spawn_error("init plan too large"));
        }
        seal(&mut plan)?;
        let cgroup = Cgroup::create(&cfg.cgroup_root, &spec.limits)?;
        let mut filter = memfile(c"aivm-container-seccomp")?;
        for instruction in unsafe { crate::build_container_filter() } {
            filter
                .write_all(&instruction.code.to_ne_bytes())
                .map_err(spawn_error)?;
            filter
                .write_all(&[instruction.jt, instruction.jf])
                .map_err(spawn_error)?;
            filter
                .write_all(&instruction.k.to_ne_bytes())
                .map_err(spawn_error)?;
        }
        seal(&mut filter)?;
        let mut status_file = memfile(c"aivm-container-status")?;
        let mut args: Vec<OsString> = [
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            SANDBOX_PATH,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.extend(mount_args(&grants)?);
        args.extend([
            OsString::from("--ro-bind-fd"),
            init.as_raw_fd().to_string().into(),
            OsString::from("/run/aivm-container-init"),
            OsString::from("--ro-bind-data"),
            plan.as_raw_fd().to_string().into(),
            OsString::from("/run/aivm-init.json"),
        ]);
        for (key, value) in &spec.env_extra {
            args.extend([OsString::from("--setenv"), key.into(), value.into()]);
        }
        args.extend([
            OsString::from("--remount-ro"),
            OsString::from("/"),
            OsString::from("--chdir"),
            cwd.into_os_string(),
            OsString::from("--seccomp"),
            filter.as_raw_fd().to_string().into(),
            OsString::from("--json-status-fd"),
            status_file.as_raw_fd().to_string().into(),
        ]);

        // Avoid ARG_MAX, keep injected values out of the launcher's command line.
        let mut arg_file = memfile(c"aivm-container-args")?;
        use std::os::unix::ffi::OsStrExt;
        for arg in args {
            arg_file
                .write_all(arg.as_bytes())
                .and_then(|_| arg_file.write_all(&[0]))
                .map_err(spawn_error)?;
        }
        seal(&mut arg_file)?;
        let mut inherited: Vec<i32> = grants.iter().map(|g| g.file.as_raw_fd()).collect();
        inherited.extend([
            filter.as_raw_fd(),
            status_file.as_raw_fd(),
            arg_file.as_raw_fd(),
            init.as_raw_fd(),
            plan.as_raw_fd(),
        ]);
        let procs = cgroup.procs.as_raw_fd();
        let parent_pid = unsafe { libc::getpid() };
        let memory = spec
            .limits
            .memory_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| disabled("memory quota overflow"))?;
        let fsize = file_limit.min(SANDBOX_FS_MB * 1024 * 1024);
        // Execute the validated inode; a path swap cannot substitute another launcher.
        let mut cmd = Command::new(format!("/proc/self/fd/{}", bwrap.as_raw_fd()));
        // --args expands options only: bubblewrap looks for COMMAND on its
        // original argv. Keep the fixed trusted helper there, while mounts
        // and injected environment values remain in the sealed argument fd.
        cmd.args([
            "--args",
            &arg_file.as_raw_fd().to_string(),
            "--",
            "/run/aivm-container-init",
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                // Attach before exec/fork: no unaccounted execution window.
                if libc::write(procs, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in &inherited {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                for (resource, value) in [
                    (libc::RLIMIT_AS, memory),
                    (libc::RLIMIT_CPU, SANDBOX_CPU_SECS),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        revalidate_exe(&exe, policy)?;
        let mut child = cmd.spawn().map_err(spawn_error)?;
        let stdout = drain(
            child
                .stdout
                .take()
                .ok_or_else(|| spawn_error("stdout pipe missing"))?,
            observer,
        );
        let stderr = drain(
            child
                .stderr
                .take()
                .ok_or_else(|| spawn_error("stderr pipe missing"))?,
            None,
        );
        let deadline = Instant::now() + Duration::from_millis(spec.timeout_ms());
        let result = loop {
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                break Err(spawn_error("inference cancelled"));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => break Err(spawn_error("wall-clock timeout")),
                Err(e) => break Err(spawn_error(e)),
            }
        };
        let cleanup = cgroup.cleanup();
        let _ = child.kill();
        let _ = child.wait();
        let output = |h: std::thread::JoinHandle<std::io::Result<(String, bool)>>| {
            h.join()
                .map_err(|_| spawn_error("output reader panicked"))?
                .map_err(spawn_error)
        };
        let (stdout, out_truncated) = output(stdout)?;
        let (stderr, err_truncated) = output(stderr)?;
        cleanup?;
        let status = result?;
        // Bubblewrap emits exit-code only after mount/capability/seccomp setup and exec succeed.
        status_file.seek(SeekFrom::Start(0)).map_err(spawn_error)?;
        let mut report = String::new();
        status_file
            .take(8192)
            .read_to_string(&mut report)
            .map_err(spawn_error)?;
        let exit = report
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find_map(|v| v.get("exit-code").and_then(|v| v.as_i64()));
        if exit != status.code().map(i64::from) || exit.is_none() || exit == Some(125) {
            return Err(spawn_error(format!(
                "bubblewrap/helper setup or exec failed (status {:?})",
                status.code()
            )));
        }
        let stdout = stdout
            .strip_prefix(READY)
            .ok_or_else(|| spawn_error("container init did not confirm enforcement"))?
            .to_owned();
        let mut degraded = Vec::new();
        if out_truncated || err_truncated {
            degraded.push("output-truncated@1MiB".into());
        }
        Ok(ExecOutcome {
            exe: exe.to_string_lossy().into_owned(),
            argv: spec.args.clone(),
            code: status.code(),
            stdout,
            stderr,
            applied: vec![
                "bubblewrap-container".into(),
                "user-namespace".into(),
                "mount-namespace".into(),
                "pid-namespace".into(),
                "network-namespace".into(),
                "ipc-namespace".into(),
                "uts-namespace".into(),
                "cgroup-namespace".into(),
                "policy-file-mounts".into(),
                "landlock-filesystem".into(),
                "readonly-root".into(),
                "private-dev-no-gpu".into(),
                "capability-drop".into(),
                "seccomp-filter".into(),
                "no-new-privs".into(),
                "pdeathsig-sigkill".into(),
                "cgroup-tree-cleanup".into(),
                "wall-clock-deadline".into(),
                "exe-allowlist".into(),
                "arg-schema".into(),
                "env-scrub".into(),
                "cwd-pin".into(),
                "stdin-null".into(),
                format!(
                    "cgroup-cpu-max={} 100000",
                    u64::from(spec.limits.cpu) * 100000
                ),
                format!("cgroup-memory-max={memory}"),
                "cgroup-memory-swap-max=0".into(),
                format!("cgroup-pids-max={}", spec.limits.pids_max),
                format!("rlimit-fsize={fsize}bytes"),
            ],
            degraded,
            dna: String::new(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn ordinary_directory_cannot_fake_cgroup() {
            assert!(Cgroup::create(Path::new("/tmp"), &crate::ResourceLimits::default()).is_err());
        }
        #[test]
        fn workspace_mounts_are_selective_and_keep_pinned_inodes() {
            let ws = std::env::temp_dir().join(format!(
                "aivm-mount-plan-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&ws).unwrap();
            let allowed = ws.join("allowed");
            let denied = ws.join("denied");
            std::fs::write(&allowed, "original").unwrap();
            std::fs::write(&denied, "hidden").unwrap();
            std::os::unix::fs::symlink(&denied, ws.join("link")).unwrap();
            let exe = std::fs::canonicalize("/usr/bin/true").unwrap();
            let policy = Policy::from_yaml(&format!("name: test\nprocess:\n  allow: [{}]\n  deny: [/bin/sh]\nfilesystem:\n  read: ['{}/**']\n  deny: ['{}']\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n", exe.display(), ws.display(), denied.display())).unwrap();
            let (grants, _) =
                landlock::prepare_mounts(&ws, &exe, &policy, 1024 * 1024, None).unwrap();
            assert!(!grants
                .iter()
                .any(|g| g.path == denied || g.path == ws.join("link")));
            let grant = grants.iter().find(|g| g.path == allowed).unwrap();
            assert_eq!(grant.access & 1, 0, "read grants must not acquire EXECUTE");
            let args = mount_args(&grants).unwrap();
            let pos = args.iter().position(|a| a == ws.as_os_str()).unwrap();
            assert_eq!(
                args[pos - 1],
                "--dir",
                "workspace must not be mounted recursively"
            );
            std::fs::rename(&allowed, ws.join("old")).unwrap();
            std::fs::write(&allowed, "replacement").unwrap();
            let pinned = format!("/proc/self/fd/{}", grant.file.as_raw_fd());
            assert_eq!(std::fs::read_to_string(pinned).unwrap(), "original");
            std::fs::remove_dir_all(ws).unwrap();
        }

        #[test]
        fn writable_only_file_is_mounted_for_landlock_to_restrict() {
            let path = PathBuf::from("/etc/hosts");
            let grants = vec![landlock::MountGrant {
                file: File::open(&path).unwrap(),
                path,
                access: 2,
                directory: false,
            }];
            assert!(mount_args(&grants)
                .unwrap()
                .contains(&OsString::from("--bind-fd")));
        }
    }
}

/// Entry point for the trusted helper; 125 is reserved for setup failure.
pub fn init_main() -> Result<(), SandboxError> {
    #[cfg(target_os = "linux")]
    return linux::init_main();
    #[cfg(not(target_os = "linux"))]
    Err(SandboxError::Disabled(
        "container init requires Linux".into(),
    ))
}
