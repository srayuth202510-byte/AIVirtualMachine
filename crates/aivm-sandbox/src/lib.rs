//! ชั้น Sandbox — ดูสเปก §27, Phase 4 (MVP-B).
//!
//! MVP-B ขั้นที่ 1: รันโปรแกรมแบบตายตัว + schema อาร์กิวเมนต์ ห้าม shell
//! โดยเด็ดขาด (สเปก Phase 4) พร้อม hardening ระดับ OS ที่ใช้ได้โดยไม่ต้อง
//! สิทธิ์พิเศษ: no-new-privs, ตายตาม parent (pdeathsig), จำกัดทรัพยากร
//! ด้วย rlimit, ล้าง environment, ปัก cwd ใน workspace
//!
//! หลักซื่อสัตย์: กลไกไหนใช้ไม่ได้ในเครื่องนั้นจะถูกรายงานใน
//! `ExecOutcome.degraded` + `SandboxProbe` อย่างเปิดเผย ไม่เงียบหาย
//! namespace/cgroup แบบเต็มและ seccomp allowlist เฉพาะ tool ยังเป็น
//! งานขั้นถัดไป (ดู `probe()` ว่าพร้อมอะไรบ้าง) gateway ยังไม่เรียก
//! exec tools จนกว่าจะพิสูจน์การกัก subprocess ได้

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
fn validate(spec: &ExecSpec, policy: &Policy) -> Result<PathBuf, SandboxError> {
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
            // 2. pdeathsig: parent ตาย child โดน SIGKILL ตาม (กัน process กำพร้า)
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
            // 3. rlimits: เพดานทรัพยากรที่ลดได้อย่างเดียว (unprivileged ทำได้)
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
    let mut degraded = vec![];
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
/// userns/seccomp ลองของจริงใน child ส่วน cgroup ลองสร้าง-ลบทิ้ง
pub fn probe() -> SandboxProbe {
    SandboxProbe {
        userns: can_true_with(probe_userns),
        seccomp_install: can_true_with(probe_seccomp),
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
        assert!(out.degraded.is_empty());
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
}
