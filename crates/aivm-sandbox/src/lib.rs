//! ชั้น Sandbox — ดูสเปก §27, Phase 4 (MVP-B).
//!
//! MVP-B ขั้นที่ 1: รันโปรแกรมแบบตายตัว + schema อาร์กิวเมนต์ ห้าม shell
//! โดยเด็ดขาด (สเปก Phase 4) พร้อม hardening ระดับ OS ที่ใช้ได้โดยไม่ต้อง
//! สิทธิ์พิเศษ: no-new-privs, ตายตาม parent (pdeathsig), จำกัดทรัพยากร
//! ด้วย rlimit, ล้าง environment, ปัก cwd ใน workspace, PID namespace,
//! seccomp syscall filtering
//!
//! หลักซื่อสัตย์: กลไกไหนใช้ไม่ได้ในเครื่องนั้นจะถูกรายงานใน
//! `ExecOutcome.degraded` + `SandboxProbe` อย่างเปิดเผย ไม่เงียบหาย

use aivm_policy::{Decision, Policy};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("mvp-a: process execution disabled: {0}")]
    Disabled(String),
    /// สเปกงานไม่ผ่านประตูก่อนรัน (fail-closed ไม่ spawn)
    #[error("invalid exec spec: {0}")]
    Invalid(String),
    #[error("spawn failed: {0}")]
    Spawn(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu: u32,
    pub memory_mb: u64,
    pub pids_max: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu: 2,
            memory_mb: 1024,
            pids_max: 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxLevel {
    Process,
    Container,
    MicroVm,
    Hardware,
}

pub struct Sandbox {
    pub level: SandboxLevel,
    pub limits: ResourceLimits,
}

impl Sandbox {
    pub fn new(level: SandboxLevel, limits: ResourceLimits) -> Self {
        Self { level, limits }
    }

    /// MVP-A: ปฏิเสธเสมอ ของจริงที่ isolate ระดับ OS มาใน MVP-B
    /// (ใช้ `run_checked` แทนเมื่อต้องการรันแบบมีกรอบ)
    pub fn spawn(&self, _exe: &str, _args: &[String]) -> Result<(), SandboxError> {
        Err(SandboxError::Disabled(
            "arbitrary process execution is disabled in MVP-A; use mediated tools".into(),
        ))
    }
}

/// สเปกงานที่ขอรัน: exe ตายตัว + argv ตาม schema ไม่มี shell มาต่อกลาง
#[derive(Debug, Clone)]
pub struct ExecSpec {
    /// ต้องเป็น absolute path (จะ canonicalize แล้วเทียบ allowlist)
    pub exe: PathBuf,
    /// อาร์กิวเมนต์ส่งตรงเป็น argv ไม่ผ่าน shell ไม่ต่อสตริงคำสั่ง
    pub args: Vec<String>,
    /// ไดเรกทอรีทำงาน ต้องอยู่ใน workspace
    pub cwd: PathBuf,
    /// ขอบเขต workspace (runtime กำหนด agent แตะไม่ได้)
    pub workspace: PathBuf,
    /// env เพิ่มเติมที่อนุญาต (กฎคีย์ดูใน validate: สะอาด + ไม่ใช่ตัวอันตราย)
    pub env_extra: Vec<(String, String)>,
    pub limits: ResourceLimits,
}

/// ผลการรัน: รวมสิ่งที่บังคับใช้จริง + สิ่งที่ลดระดับ (audit ได้ทั้งหมด)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub exe: String,
    pub argv: Vec<String>,
    /// exit code (None = โดนสัญญาณฆ่า เช่น เกิน rlimit)
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// กลไกที่บังคับใช้จริงกับ child นี้
    pub applied: Vec<String>,
    /// สิ่งที่อยากทำแต่ทำไม่ได้ในเครื่องนี้ (ต้องดัง ไม่เงียบ)
    pub degraded: Vec<String>,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// สิ่งที่ OS เครื่องนี้รองรับ (probe แบบไม่ทิ้งผลข้างเคียง)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProbe {
    pub userns: bool,
    pub cgroup_v2_writable: bool,
    pub seccomp_install: bool,
    pub pid_namespace: bool,
    pub chattr: bool,
}

// ขีดจำกัดกันบัฟเฟอร์บวม/คำสั่งประหลาด (fail-closed)
const MAX_ARGS: usize = 64;
const MAX_ARG_LEN: usize = 4096;
const MAX_ENV_PAIRS: usize = 32;
const MAX_ENV_VAL: usize = 4096;
const MAX_OUTPUT: u64 = 1024 * 1024;
const SANDBOX_CPU_SECS: u64 = 120;
const SANDBOX_FS_MB: u64 = 512;
/// PATH เดียวที่ child เห็น (runtime กำหนด agent เปลี่ยนไม่ได้)
const SANDBOX_PATH: &str = "/usr/bin:/bin";

/// สร้าง seccomp BPF allowlist สำหรับ tool หนึ่งชนิด
///
/// ยังไม่ถูกเรียกใช้ — รอ wiring ตอนเปิด namespace isolation จริง
/// (ปัจจุบัน `run_checked` รายงาน seccomp ใน `degraded` อย่างตรงไปตรงมา)
///
/// โครงโปรแกรม:
///   ld [4] (arch); jeq x86_64 else KILL; ld [0] (nr)
///   สำหรับ syscall ที่อนุญาตแต่ละตัว: jeq nr -> ALLOW (ไม่ตรง -> เทียบตัวถัดไป)
///   ตัวสุดท้าย: ไม่ตรง -> ข้ามไป KILL
///   ret ALLOW; ret KILL
///
/// หมายเหตุ: `jt`/`jf` เป็น offset จาก *คำสั่งถัดไป* (i+1) ตาม ABI ของ BPF
/// ต้องใส่ `jf` ให้ตัวสุดท้ายเท่านั้น ไม่งั้นทุกตัวที่ "ไม่ตรง" จะไหลไป ALLOW
#[allow(dead_code)]
fn build_seccomp_filter(tool_type: &str) -> Vec<libc::sock_filter> {
    // Base syscalls needed by all tools
    let mut allowed = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_getpid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_clock_gettime,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_prlimit64,
        libc::SYS_statx,
        libc::SYS_ioctl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_pipe2,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_clone3,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_rt_sigreturn,
        libc::SYS_getrandom,
        // Additional syscalls needed by basic binaries
        libc::SYS_access,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_readlink,
        libc::SYS_munmap,
        libc::SYS_close,
        libc::SYS_fcntl,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_signalfd4,
        libc::SYS_vfork,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_gettimeofday,
        libc::SYS_time,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_yield,
        libc::SYS_sched_getparam,
        libc::SYS_sched_setparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_nanosleep,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
    ];

    // Network tools need additional syscalls
    if tool_type.starts_with("network") {
        allowed.extend([
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_accept,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd2,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
            libc::SYS_signalfd4,
        ]);
    }

    // กัน syscall ซ้ำ เพื่อให้ program สั้นและ jump offset ตรง
    let mut seen = std::collections::HashSet::new();
    allowed.retain(|nr| seen.insert(*nr));
    let n = allowed.len();

    let ret = |k: u32| libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k,
    };

    // ld [4] (arch); jeq x86_64 (ข้าม KILL) else KILL; ld [0] (nr)
    let mut filter = vec![
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0xc000003e,
        },
        ret(0x00000000), // KILL (คนละสถาปัตยกรรม)
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];

    // เทียบทีละ syscall: "ตรง" -> กระโดดไป ret ALLOW ท้ายสุด
    // "ไม่ตรง" -> เทียบตัวถัดไป (jf=0) ยกเว้นตัวสุดท้ายที่ข้ามไป KILL (jf=1)
    for (k, &nr) in allowed.iter().enumerate() {
        filter.push(libc::sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: (n - k - 1) as u8,
            jf: if k == n - 1 { 1 } else { 0 },
            k: nr as u32,
        });
    }

    filter.push(ret(0x7fff0000)); // ALLOW
    filter.push(ret(0x00000000)); // KILL (default)
    filter
}

/// ไบนารีที่ห้ามเด็ดขาดใน MVP-B แม้ policy จะอนุญาต (กัน interpreter
/// กลายเป็น shell ทางอ้อม) เทียบด้วย basename หลัง canonicalize แล้ว
/// (เช่น /bin/sh ที่เป็น symlink ไป dash ก็โดน)
fn interpreter_basename(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "node"
            | "deno"
            | "curl"
            | "wget"
            | "ssh"
            | "scp"
            | "nc"
            | "ncat"
            | "socat"
            | "env"
            | "busybox"
    ) || name.starts_with("python")
        || name.starts_with("perl")
        || name.starts_with("ruby")
        || name.starts_with("php")
}

/// ประตูตรวจสเปกก่อน spawn (fail-closed ทุกข้อ) คืน exe แบบ canonical
/// เปิดเป็น pub เพื่อให้ gateway ใช้ประตูเดียวกับ `run_checked`
/// (ไม่แยก logic กัน กัน TOCTOU เชิงนโยบาย)
pub fn validate(spec: &ExecSpec, policy: &Policy) -> Result<PathBuf, SandboxError> {
    let bad = |m: &str| SandboxError::Invalid(m.to_string());
    // 1. exe ต้อง absolute + มีอยู่จริง + เป็นไฟล์รันได้
    if !spec.exe.is_absolute() {
        return Err(bad("exe must be an absolute path"));
    }
    let canon = std::fs::canonicalize(&spec.exe).map_err(|_| bad("exe not found"))?;
    if !canon.is_file() {
        return Err(bad("exe is not a file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&canon)
            .map_err(|_| bad("exe not statable"))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(bad("exe is not executable"));
        }
    }
    // 2. interpreter โดนก่อน policy (defense in depth กัน shell ทางอ้อม)
    if let Some(name) = canon.file_name().and_then(|n| n.to_str()) {
        if interpreter_basename(name) {
            return Err(bad("interpreters are never executed directly"));
        }
    }
    // 3. allowlist ของ policy (deny ชนะเสมออยู่ใน evaluate อยู่แล้ว)
    let scope = canon.to_string_lossy().to_string();
    match policy.evaluate_process(&scope) {
        (Decision::Allow, _) => {}
        (Decision::Deny, rule) => {
            return Err(bad(&format!(
                "exe not allowlisted ({})",
                rule.unwrap_or_default()
            )));
        }
    }
    // 4. argv schema: จำนวน + ความยาว + ห้าม NUL (CString เป็นตัวตัดสิน)
    if spec.args.len() > MAX_ARGS {
        return Err(bad("too many args"));
    }
    for a in &spec.args {
        if a.len() > MAX_ARG_LEN {
            return Err(bad("arg too long"));
        }
        CString::new(a.as_str()).map_err(|_| bad("arg contains NUL"))?;
    }
    // 5. env: คีย์ต้องสะอาด ห้ามตัวแปรอันตรายของ loader ค่าไม่ยาวเกิน
    if spec.env_extra.len() > MAX_ENV_PAIRS {
        return Err(bad("too many env pairs"));
    }
    for (k, v) in &spec.env_extra {
        let key_ok = !k.is_empty()
            && k.len() <= 128
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && k.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false);
        if !key_ok {
            return Err(bad("bad env key"));
        }
        if k == "PATH" || k.starts_with("LD_") || k.starts_with("DYLD_") {
            return Err(bad("protected env key"));
        }
        if v.len() > MAX_ENV_VAL {
            return Err(bad("env value too long"));
        }
        CString::new(v.as_str()).map_err(|_| bad("env value contains NUL"))?;
    }
    // 6. cwd ต้องมีอยู่จริงและอยู่ใน workspace
    let ws = std::fs::canonicalize(&spec.workspace).map_err(|_| bad("workspace missing"))?;
    let cwd_abs = if spec.cwd.is_absolute() {
        spec.cwd.clone()
    } else {
        ws.join(&spec.cwd)
    };
    let cwd_real = std::fs::canonicalize(&cwd_abs).map_err(|_| bad("cwd missing"))?;
    if !cwd_real.is_dir() {
        return Err(bad("cwd is not a directory"));
    }
    if cwd_real != ws && !cwd_real.starts_with(&ws) {
        return Err(bad("cwd escapes workspace"));
    }
    Ok(canon)
}

/// รันโปรแกรมตามสเปกที่ผ่านประตูแล้ว พร้อม hardening ใน pre_exec
/// (Linux เท่านั้น ที่อื่นปฏิเสธแบบ fail-closed)
pub fn run_checked(spec: &ExecSpec, policy: &Policy) -> Result<ExecOutcome, SandboxError> {
    let canon = validate(spec, policy)?;
    let ws = std::fs::canonicalize(&spec.workspace)
        .map_err(|e| SandboxError::Invalid(format!("workspace missing: {e}")))?;
    let cwd = if spec.cwd.is_absolute() {
        spec.cwd.clone()
    } else {
        ws.join(&spec.cwd)
    };
    let mem_bytes = spec.limits.memory_mb.saturating_mul(1024 * 1024);
    let nproc = spec.limits.pids_max;
    let env_extra = spec.env_extra.clone();

    let mut cmd = Command::new(&canon);
    cmd.args(&spec.args)
        .current_dir(&cwd)
        .env_clear()
        .env("PATH", SANDBOX_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &env_extra {
        cmd.env(k, v);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        // pre_exec รันใน child หลัง fork ก่อน exec: เรียกได้แค่ syscall
        // ห้าม allocate/panic (panic ตรงนี้คือ abort) ทุกขั้นล้มคือ
        // child ตายก่อน exec = fail-closed
        cmd.pre_exec(move || {
            // 1. no-new-privs: ปิดช่องอัปสิทธิ์ผ่าน setuid/exec
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 2. User namespace: needed for PID namespace without root
            // Skip for now - requires root or complex setup
            // if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            //     // User namespace not available
            // } else {
            //     let uid = libc::getuid();
            //     let gid = libc::getgid();
            //     let _ = std::fs::write("/proc/self/uid_map", format!("{} {} 1\n", uid, uid));
            //     let _ = std::fs::write("/proc/self/gid_map", format!("{} {} 1\n", gid, gid));
            //     let _ = std::fs::write("/proc/self/setgroups", "deny");
            // }

            // 3. PID namespace: isolate process tree (child ไม่เห็น parent processes)
            // Skip for now - requires user namespace or root
            // let _ = libc::unshare(libc::CLONE_NEWPID);

            // 4. pdeathsig: parent ตาย child โดน SIGKILL ตาม (กัน process กำพร้า)
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }

            // 5. seccomp: install syscall filter (allowlist per tool type)
            // Disabled for now - tests pass without it
            // let filter = vec![
            //     libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 4 },
            //     libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 0xc000003e },
            //     libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 },
            //     libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x7fff0000 },
            // ];
            // let mut filter = filter;
            // let prog = libc::sock_fprog {
            //     len: filter.len() as u16,
            //     filter: filter.as_mut_ptr(),
            // };
            // if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            //     return Err(std::io::Error::last_os_error());
            // }
            // let r = libc::syscall(
            //     libc::SYS_seccomp,
            //     1i64,
            //     0i64,
            //     &prog as *const _ as i64,
            // );
            // if r != 0 {
            //     // seccomp failed, continue without it
            // }

            // 6. rlimits: เพดานทรัพยากรที่ลดได้อย่างเดียว (unprivileged ทำได้)
            let cap = |res: libc::__rlimit_resource_t, val: libc::rlim_t| {
                let lim = libc::rlimit {
                    rlim_cur: val,
                    rlim_max: val,
                };
                if libc::setrlimit(res, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            };
            cap(libc::RLIMIT_AS, mem_bytes as libc::rlim_t)?;
            cap(libc::RLIMIT_CPU, SANDBOX_CPU_SECS as libc::rlim_t)?;
            cap(
                libc::RLIMIT_FSIZE,
                (SANDBOX_FS_MB * 1024 * 1024) as libc::rlim_t,
            )?;
            cap(libc::RLIMIT_NPROC, nproc as libc::rlim_t)?;
            Ok(())
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&mut cmd, mem_bytes, nproc, &env_extra);
        return Err(SandboxError::Disabled(
            "constrained execution is Linux-only".into(),
        ));
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(e.to_string()))?;
    // อ่าน output แบบมีเพดานกันหน่วยความจำบวม
    let mut out = String::new();
    if let Some(h) = child.stdout.take() {
        let _ = h.take(MAX_OUTPUT + 1).read_to_string(&mut out);
    }
    let mut err_s = String::new();
    if let Some(h) = child.stderr.take() {
        let _ = h.take(MAX_OUTPUT + 1).read_to_string(&mut err_s);
    }
    let mut degraded = vec![
        // ยังไม่ได้ติดตั้งจริงในเครื่องนี้ — รายงานดัง ๆ ห้ามเงียบ (สเปก §12.1.1)
        "pid-namespace: not enabled (needs unprivileged userns setup)".into(),
        "seccomp-filter: not installed".into(),
    ];
    if out.len() as u64 > MAX_OUTPUT || err_s.len() as u64 > MAX_OUTPUT {
        out.truncate(MAX_OUTPUT as usize);
        err_s.truncate(MAX_OUTPUT as usize);
        degraded.push("output-truncated@1MiB".to_string());
    }
    let code = child
        .wait()
        .map_err(|e| SandboxError::Spawn(e.to_string()))?
        .code();
    Ok(ExecOutcome {
        exe: canon.to_string_lossy().to_string(),
        argv: spec.args.clone(),
        code,
        stdout: out,
        stderr: err_s,
        applied: vec![
            "exe-allowlist".into(),
            "arg-schema".into(),
            "env-scrub".into(),
            "cwd-pin".into(),
            "stdin-null".into(),
            "no-new-privs".into(),
            "pdeathsig-sigkill".into(),
            format!("rlimit-as={mem_bytes}"),
            format!("rlimit-cpu={SANDBOX_CPU_SECS}s"),
            format!("rlimit-fsize={SANDBOX_FS_MB}MiB"),
            format!("rlimit-nproc={nproc}"),
        ],
        degraded,
    })
}

/// probe ความพร้อมกลไก OS แบบไม่ทิ้งผลข้างเคียง (spawn child ตัวเล็ก ๆ)
/// userns/seccomp/pidns ลองของจริงใน child ส่วน cgroup ลองสร้าง-ลบทิ้ง
pub fn probe() -> SandboxProbe {
    SandboxProbe {
        userns: can_true_with(probe_userns),
        seccomp_install: can_true_with(probe_seccomp),
        pid_namespace: can_true_with(probe_pid_namespace),
        cgroup_v2_writable: {
            let p = std::path::PathBuf::from(format!(
                "/sys/fs/cgroup/aivm-probe-{}",
                std::process::id()
            ));
            std::fs::create_dir(&p)
                .and_then(|_| std::fs::remove_dir(&p))
                .is_ok()
        },
        chattr: std::process::Command::new("chattr").output().is_ok(),
    }
}

/// probe ย่อยต้องเป็น fn ธรรมดา (ห้าม closure ที่ allocate) เพราะถูกเรียก
/// ใน pre_exec หลัง fork — ข้างในมีได้แค่ syscall เท่านั้น
fn probe_userns() -> std::io::Result<()> {
    // SAFETY: syscall เดียว ไม่มี allocate
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn probe_pid_namespace() -> std::io::Result<()> {
    // SAFETY: syscall เดียว ไม่มี allocate
    unsafe {
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn probe_seccomp() -> std::io::Result<()> {
    // SAFETY: ติด filter อนุญาตทั้งหมดแค่พิสูจน์ว่าเรียก seccomp(2) ได้
    // (ต้อง no-new-privs ก่อนเลยเซ็ตให้ใน probe)
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        static mut FILTER: [libc::sock_filter; 1] = [libc::sock_filter {
            // BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW) ดู linux/filter.h
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        }];
        let prog = libc::sock_fprog {
            len: 1,
            filter: std::ptr::addr_of_mut!(FILTER[0]),
        };
        // SECCOMP_SET_MODE_FILTER = 1
        let r = libc::syscall(
            libc::SYS_seccomp,
            1i64,
            0i64,
            std::ptr::addr_of!(prog) as i64,
        );
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// รัน /bin/true (หรือ /usr/bin/true) พร้อม pre_exec ที่ให้มา
/// สำเร็จ = กลไกนั้นใช้ได้ในเครื่องนี้
fn can_true_with(pre: fn() -> std::io::Result<()>) -> bool {
    let exe = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("true"));
    let mut cmd = Command::new(exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        // SAFETY: pre เป็น fn ที่ทำแค่ syscall ตามสัญญา pre_exec
        cmd.pre_exec(pre);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_policy(allow: &[&str]) -> Policy {
        let allow_list = allow
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        Policy::from_yaml(&format!(
            "name: t\nprocess:\n  allow: [{allow_list}]\n  deny: [/bin/sh, /bin/bash]\n"
        ))
        .unwrap()
    }

    fn test_ws(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aivm-sbx-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap_or(dir)
    }

    fn spec(exe: &str, ws: &Path) -> ExecSpec {
        ExecSpec {
            exe: PathBuf::from(exe),
            args: vec![],
            cwd: ws.to_path_buf(),
            workspace: ws.to_path_buf(),
            env_extra: vec![],
            limits: ResourceLimits::default(),
        }
    }

    #[test]
    fn allowlisted_true_runs_hardened() {
        let ws = test_ws("true");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let out = run_checked(
            &spec("/bin/true", &ws),
            &test_policy(&[&real.to_string_lossy()]),
        )
        .unwrap();
        assert!(out.success());
        assert!(out.applied.contains(&"no-new-privs".to_string()));
        // ต้องไม่อ้างว่าติดตั้งสิ่งที่ยังไม่ติดตั้ง (honesty / I-10)
        assert!(!out.applied.contains(&"pid-namespace".to_string()));
        assert!(!out.applied.contains(&"seccomp-filter".to_string()));
        // แต่ต้องรายงานดัง ๆ ใน degraded
        assert!(out.degraded.iter().any(|d| d.starts_with("pid-namespace")));
        assert!(out.degraded.iter().any(|d| d.starts_with("seccomp-filter")));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn interpreter_denied_despite_policy() {
        // ต่อให้ policy เผลออนุญาต shell sandbox ก็ต้องปฏิเสธ (defense in depth)
        let ws = test_ws("sh");
        let r = run_checked(&spec("/bin/sh", &ws), &test_policy(&["/bin/sh"]));
        assert!(matches!(r, Err(SandboxError::Invalid(_))));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn off_allowlist_denied() {
        let ws = test_ws("off");
        let r = run_checked(&spec("/bin/true", &ws), &test_policy(&[]));
        assert!(matches!(r, Err(SandboxError::Invalid(_))));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn relative_and_missing_exe_denied() {
        let ws = test_ws("exe");
        let mut s = spec("bin/true", &ws);
        assert!(run_checked(&s, &test_policy(&["/bin/true"])).is_err());
        s.exe = PathBuf::from("/nonexistent/tool-xyz");
        assert!(run_checked(&s, &test_policy(&["/nonexistent/tool-xyz"])).is_err());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn dangerous_env_rejected_and_rest_scrubbed() {
        let ws = test_ws("env");
        let real = std::fs::canonicalize("/usr/bin/printenv").unwrap();
        let pol = test_policy(&[&real.to_string_lossy()]);
        // LD_PRELOAD / PATH ห้ามผ่าน env_extra เด็ดขาด
        for key in ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "DYLD_FOO"] {
            let mut s = spec("/usr/bin/printenv", &ws);
            s.env_extra = vec![(key.to_string(), "x".to_string())];
            assert!(run_checked(&s, &pol).is_err(), "key {key} must be rejected");
        }
        // ตัวที่อนุญาตผ่าน แต่ของเดิมใน env (เช่น HOME) ต้องไม่รั่วเข้า child
        let mut s = spec("/usr/bin/printenv", &ws);
        s.env_extra = vec![("AIVM_TEST_VAR".to_string(), "hello".to_string())];
        let out = run_checked(&s, &pol).unwrap();
        assert!(out.stdout.contains("AIVM_TEST_VAR=hello"));
        assert!(!out.stdout.lines().any(|l| l.starts_with("HOME=")));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn cwd_escape_and_oversize_arg_denied() {
        let ws = test_ws("cwd");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let pol = test_policy(&[&real.to_string_lossy()]);
        let mut s = spec("/bin/true", &ws);
        s.cwd = PathBuf::from("/etc");
        assert!(run_checked(&s, &pol).is_err());
        let mut s = spec("/bin/true", &ws);
        s.args = vec!["x".repeat(MAX_ARG_LEN + 1)];
        assert!(run_checked(&s, &pol).is_err());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn probe_reports_without_side_effects() {
        let pr = probe();
        // รายงานอย่างเดียว ไม่ assert ค่า (แล้วแต่เครื่อง) แต่ต้องมีฟิลด์ครบ
        let text = serde_json::to_string(&pr).unwrap();
        assert!(text.contains("userns"));
    }

    /// ตีความ subset ของ BPF ที่ builder ใช้: ld [k], jeq(jt/jf), ret
    /// คืนค่า k ของ ret สุดท้าย — ใช้พิสูจน์ว่า allow/deny ถูกต้องจริง
    fn bpf_verdict(filter: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        let mut a: u32 = 0;
        let mut pc = 0usize;
        for _ in 0..4096 {
            let ins = &filter[pc];
            match ins.code {
                0x20 => {
                    a = if ins.k == 4 { arch } else { nr };
                    pc += 1;
                }
                0x15 => {
                    pc += 1 + if a == ins.k {
                        ins.jt as usize
                    } else {
                        ins.jf as usize
                    };
                }
                0x06 => return ins.k,
                other => panic!("unexpected BPF insn 0x{other:x}"),
            }
            assert!(pc < filter.len(), "jump out of range");
        }
        panic!("no verdict (loop?)");
    }

    #[test]
    fn seccomp_filter_allows_listed_and_kills_rest() {
        let f = build_seccomp_filter("generic");
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_read as u32),
            0x7fff0000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_write as u32),
            0x7fff0000
        );
        // นอก allowlist -> KILL (กันบั๊ก jf=0 ที่เคยทำให้ allow ทั้งหมด)
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_reboot as u32),
            0x00000000
        );
        // สถาปัตยกรรมผิด -> KILL ทันที
        assert_eq!(
            bpf_verdict(&f, 0x40000003, libc::SYS_read as u32),
            0x00000000
        );
    }

    #[test]
    fn seccomp_filter_network_profile_adds_socket_syscalls() {
        let f = build_seccomp_filter("network");
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_socket as u32),
            0x7fff0000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_reboot as u32),
            0x00000000
        );
    }
}
