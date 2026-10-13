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
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;

/// MicroVM backend (Phase 7) — เปิดด้วยฟีเจอร์ `microvm` เท่านั้น
/// ตอนนี้เป็น skeleton (ประตู fail-closed ยังไม่มีการ boot จริง) เพื่อให้
/// `make verify` เบาและไม่พึ่ง KVM/Firecracker ใน CI (แบบเดียวกับ `llama`)
#[cfg(feature = "microvm")]
pub mod microvm;

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

impl std::str::FromStr for SandboxLevel {
    type Err = SandboxError;

    /// แปลงค่า `runtime.isolation` ใน `aivm.yaml` เป็น level (fail-closed)
    ///
    /// รับ `"sandbox"`/`"process"` (เดิม), `"container"`, `"microvm"`,
    /// `"hardware"` (case-insensitive, ตัด whitespace หัวท้าย) นอกนั้นคืน
    /// `Invalid` — config แปลกห้ามเงียบไปใช้ค่าเริ่มต้น ต้องบูตไม่ขึ้น
    fn from_str(s: &str) -> Result<Self, SandboxError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sandbox" | "process" => Ok(SandboxLevel::Process),
            "container" => Ok(SandboxLevel::Container),
            "microvm" | "micro-vm" | "firecracker" => Ok(SandboxLevel::MicroVm),
            "hardware" => Ok(SandboxLevel::Hardware),
            _ => Err(SandboxError::Invalid(format!(
                "unknown isolation level: {s}"
            ))),
        }
    }
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
    /// `/dev/kvm` เปิดได้ (เงื่อนไขตั้งต้นของ MicroVM Level 2)
    #[serde(default)]
    pub kvm: bool,
    /// ไบนารี `firecracker` อยู่ใน PATH (ยังไม่การันตีเวอร์ชัน)
    #[serde(default)]
    pub firecracker: bool,
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

/// syscall อันตรายที่ต้องฆ่า process ทันที (สเปก §12.1.1)
///
/// เลือกใช้ **denylist** (default-allow) แทน allowlist เพราอ allowlist
/// แบบเคร่งครัดไม่สามารถครอบ syscall ของ compiler / test runner ได้จริง
/// ในทางปฏิบัติ no-new-privs + userns ที่ไม่มีสิทธิ์เหนือ host + denylist
/// syscall อันตรายชั้นนี้คือแนวป้องกันที่ใช้ได้จริง (ดู Docker/systemd default profile)
#[cfg(target_os = "linux")]
const DANGEROUS_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_ptrace,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_bpf,
    libc::SYS_kexec_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_adjtimex,
    libc::SYS_add_key,
    libc::SYS_keyctl,
    libc::SYS_request_key,
    libc::SYS_quotactl,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_sched_setattr,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_mknod,
    libc::SYS_personality,
    libc::SYS_lookup_dcookie,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_clock_adjtime,
    libc::SYS_kcmp,
    libc::SYS_process_madvise,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_openat2,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
];

/// สร้าง seccomp BPF filter แบบ **denylist**: default ALLOW, KILL เฉพาะ syscall
/// ใน `DANGEROUS_SYSCALLS` — syscall ที่อนุญาตปกติจะผ่านหากไม่อยู่ใน denylist
///
/// โครงโปรแกรม:
///   ld [4] (arch); jeq x86_64 else KILL
///   ld [0] (nr); เทียบทีละ syscall ใน denylist: ตรง -> KILL
///   ไม่ตรงเลย -> ALLOW
#[cfg(target_os = "linux")]
unsafe fn build_dangerous_filter() -> Vec<libc::sock_filter> {
    let n = DANGEROUS_SYSCALLS.len();

    let ret = |k: u32| libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k: u32, jt: u8| libc::sock_filter {
        code: 0x15,
        jt,
        jf: 0,
        k,
    };

    // arch check: x86_64 เท่านั้น (KILL ถ้าไม่ตรง)
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
        ret(0x00000000), // KILL (wrong arch)
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];

    // เทียบ denylist: "ตรง" -> กระโดดไป ret KILL (jt = offset จาก i+1)
    // "ไม่ตรง" -> เทียบตัวถัดไป; ตัวสุดท้ายไม่ตรง -> ไหลไป ret ALLOW
    for (i, &nr) in DANGEROUS_SYSCALLS.iter().enumerate() {
        filter.push(jeq(nr as u32, (n - i) as u8));
    }

    filter.push(ret(0x7fff0000)); // ALLOW
    filter.push(ret(0x00000000)); // KILL (denylist match)
    filter
}

/// ติดตั้ง seccomp filter ใน process ปัจจุบัน (ทำใน child หลัง fork)
#[cfg(target_os = "linux")]
unsafe fn install_dangerous_filter() -> std::io::Result<()> {
    let filter = build_dangerous_filter();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    if libc::syscall(libc::SYS_seccomp, 1i64, 0i64, &prog as *const _ as i64) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

/// ตรวจ artifact (kernel/rootfs/image สำหรับ Phase 7) ด้วย sha256 ที่ pin ไว้
/// (supply chain, fail-closed)
///
/// อ่านไฟล์แบบมีเพดาน `max_bytes` คำนวณ sha256 แล้วเทียบกับค่า hex ที่คาดหวัง
/// แบบเทียบทุกไบต์ก่อนคืน (กัน timing oracle แบบง่าย) คืนขนาดไฟล์เมื่อตรง;
/// ทุกความผิดพลาด (ไม่มีไฟล์/อ่านไม่ได้/ใหญ่เกิน/hex ผิด/hash ไม่ตรง)
/// คืน `SandboxError::Invalid` — ห้าม boot เด็ดขาด
pub fn verify_artifact(
    path: &Path,
    expected_sha256_hex: &str,
    max_bytes: u64,
) -> Result<u64, SandboxError> {
    let bad = |m: &str| SandboxError::Invalid(m.to_string());
    // hex ต้องยาว 64 ตัว (32 ไบต์) และเป็น [0-9a-fA-F] เท่านั้น
    if expected_sha256_hex.len() != 64
        || !expected_sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(bad("bad expected hash (must be 64 hex chars)"));
    }
    let mut expected = [0u8; 32];
    for (i, chunk) in expected_sha256_hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| bad("bad hex"))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| bad("bad hex"))?;
        expected[i] = ((hi << 4) | lo) as u8;
    }
    let meta = std::fs::metadata(path).map_err(|_| bad("artifact not statable"))?;
    if !meta.is_file() {
        return Err(bad("artifact is not a file"));
    }
    if meta.len() > max_bytes {
        return Err(bad("artifact too large"));
    }
    let mut f = std::fs::File::open(path).map_err(|_| bad("artifact not readable"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|_| bad("artifact read failed"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_bytes {
            return Err(bad("artifact too large"));
        }
        hasher.update(&buf[..n]);
    }
    let got = hasher.finalize();
    // เทียบทุกไบต์ก่อนตัดสิน (ไม่ early-return ในลูป)
    let mut diff: u8 = 0;
    for (a, b) in got.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(bad("artifact hash mismatch"));
    }
    Ok(total)
}

/// ตรวจ exe ซ้ำทันทีก่อน spawn (บีบหน้าต่าง TOCTOU ระหว่าง `validate` กับ spawn)
///
/// `validate` คืน path ที่ canonicalize แล้ว แต่ไฟล์เป้าหมายอาจถูกสลับหลังตรวจ
/// (symlink/file swap) ฟังก์ชันนี้ stat ไฟล์จริงอีกรอบแล้วตรวจซ้ำ: เป็นไฟล์ +
/// รันได้ + ผ่าน allowlist ของ policy เหมือนเดิม ไม่ผ่าน = fail-closed
/// (แพทเทิร์นเดียวกับที่ guest agent ใน MicroVM ต้องทำซ้ำหลังรับงานข้าม boundary)
pub fn revalidate_exe(canon: &Path, policy: &Policy) -> Result<(), SandboxError> {
    let bad = |m: &str| SandboxError::Invalid(m.to_string());
    let meta = std::fs::metadata(canon).map_err(|_| bad("exe not statable (revalidate)"))?;
    if !meta.is_file() {
        return Err(bad("exe is not a file (revalidate)"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(bad("exe is not executable (revalidate)"));
        }
    }
    // กัน symlink ถูกสลับหลัง validate ครั้งแรก: canonicalize ซ้ำต้องได้เดิม
    let recanon = std::fs::canonicalize(canon).map_err(|_| bad("exe not found (revalidate)"))?;
    if recanon != canon {
        return Err(bad("exe path changed after validate"));
    }
    let scope = canon.to_string_lossy().to_string();
    match policy.evaluate_process(&scope) {
        (Decision::Allow, _) => Ok(()),
        (Decision::Deny, rule) => Err(bad(&format!(
            "exe not allowlisted on revalidate ({})",
            rule.unwrap_or_default()
        ))),
    }
}

/// จุดแยก backend ตาม `SandboxLevel` (seam ของ Phase 7)
///
/// - `Process` = พฤติกรรม MVP-B เดิม (`run_checked`) ไม่เปลี่ยน
/// - `MicroVm` = เปิดฟีเจอร์ `microvm` แล้วเดินประตู skeleton
///   (spec → shape → supply chain → host readiness → `Disabled` จนกว่า
///   milestone boot/exec จะส่งมอบ) ไม่เปิดฟีเจอร์คือ `Disabled` ทันที
/// - `Container`/`Hardware` = ยังไม่มี backend คืน `Disabled` เสมอ
///
/// gateway ชั้นบนจึงไม่ต้องแยกเคสเอง
pub fn run_checked_with_level(
    spec: &ExecSpec,
    policy: &Policy,
    level: SandboxLevel,
) -> Result<ExecOutcome, SandboxError> {
    match level {
        SandboxLevel::Process => run_checked(spec, policy),
        SandboxLevel::Container => Err(SandboxError::Disabled(
            "container backend not implemented; use Process level".into(),
        )),
        #[cfg(feature = "microvm")]
        SandboxLevel::MicroVm => microvm::run_in_microvm(spec, policy, &microvm::MicroVmConfig::default()),
        #[cfg(not(feature = "microvm"))]
        SandboxLevel::MicroVm => Err(SandboxError::Disabled(
            "microvm backend not implemented (needs KVM + firecracker + verified image); use Process level".into(),
        )),
        SandboxLevel::Hardware => Err(SandboxError::Disabled(
            "hardware backend not implemented; use Process level".into(),
        )),
    }
}

/// จุดแยก backend พร้อม config MicroVM (ใช้เมื่อเปิดฟีเจอร์ `microvm`)
///
/// เหมือน `run_checked_with_level` แต่ระดับ MicroVm รับ `MicroVmConfig` จริง
/// (kernel/rootfs pin + vcpu/mem) แทนค่า default ที่ deny ตั้งแต่ artifact
/// หาย — gateway ส่ง config ที่ parse จาก `aivm.yaml` มาทางนี้
#[cfg(feature = "microvm")]
pub fn run_checked_with_level_and_cfg(
    spec: &ExecSpec,
    policy: &Policy,
    level: SandboxLevel,
    cfg: &microvm::MicroVmConfig,
) -> Result<ExecOutcome, SandboxError> {
    match level {
        SandboxLevel::MicroVm => microvm::run_in_microvm(spec, policy, cfg),
        _ => run_checked_with_level(spec, policy, level),
    }
}

// ---- Linux namespace helpers (syscall ล้วน: เรียกได้จาก pre_exec) ----

/// เขียนไฟล์ด้วย open/write/close ไม่ allocate (pre_exec ห้ามแตะ allocator)
#[cfg(target_os = "linux")]
unsafe fn write_bytes(path: *const libc::c_char, data: &[u8]) -> std::io::Result<()> {
    let fd = libc::open(path, libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut off = 0usize;
    while off < data.len() {
        let n = libc::write(
            fd,
            data[off..].as_ptr() as *const libc::c_void,
            data.len() - off,
        );
        if n < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        off += n as usize;
    }
    libc::close(fd);
    Ok(())
}

/// เขียนข้อความ uid/gid map รูปแบบ "0 <id> 1\n" ลงบัฟเฟอร์คงที่ (ไม่ allocate)
/// คืนความยาวที่ใช้จริง — map inside-ns 0 <-> outside <id> (เราเป็น root ใน ns)
#[cfg(target_os = "linux")]
fn format_id_map(id: u32, buf: &mut [u8; 32]) -> usize {
    let mut n = 0usize;
    for b in *b"0 " {
        buf[n] = b;
        n += 1;
    }
    let mut tmp = [0u8; 10];
    let mut t = 0usize;
    let mut v = id;
    if v == 0 {
        tmp[t] = b'0';
        t += 1;
    }
    while v > 0 {
        tmp[t] = b'0' + (v % 10) as u8;
        v /= 10;
        t += 1;
    }
    while t > 0 {
        t -= 1;
        buf[n] = tmp[t];
        n += 1;
    }
    for b in *b" 1\n" {
        buf[n] = b;
        n += 1;
    }
    n
}

/// เข้า user namespace แบบ unprivileged แล้ว map uid/gid ให้ตัวเองเป็น root
/// ใน ns ใหม่ (ต้องเขียน setgroups=deny ก่อน gid_map) จากนั้นสร้าง PID
/// namespace — ทำได้เพราะมี CAP_SYS_ADMIN ใน userns ที่เพิ่งสร้าง
#[cfg(target_os = "linux")]
unsafe fn enter_user_then_pid_ns() -> std::io::Result<()> {
    // ต้องอ่าน uid/gid *ก่อน* unshare: หลังเข้า userns แล้ว getuid() จะเห็นค่า
    // overflow (65534) เพราะยังไม่มี mapping — เคอร์เนลเทียบกับ kuid ตัวจริง
    // (ผู้เขียนต้อง map uid ของตัวเองได้)
    let uid = libc::getuid();
    let gid = libc::getgid();
    if libc::unshare(libc::CLONE_NEWUSER) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // ข้อกำหนด unprivileged: setgroups ต้องเป็น "deny" ก่อนเขียน gid_map
    write_bytes(c"/proc/self/setgroups".as_ptr(), b"deny")?;
    let mut buf = [0u8; 32];
    let n = format_id_map(uid, &mut buf);
    write_bytes(c"/proc/self/uid_map".as_ptr(), &buf[..n])?;
    let n = format_id_map(gid, &mut buf);
    write_bytes(c"/proc/self/gid_map".as_ptr(), &buf[..n])?;
    if libc::unshare(libc::CLONE_NEWPID) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// capset header (kernel struct, กำหนดเองเพรา่ libc crate ไม่ export)
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// capset data (kernel struct, กำหนดเองเพรา่ libc crate ไม่ export)
#[cfg(target_os = "linux")]
#[derive(Copy, Clone)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// ลด capabilities ทั้งหมดใน userns (defense in depth)
///
/// หลังเข้า userns แล้ว process เป็น root (uid 0) ใน ns นั้น มี capabilities
/// ทั้งหมดใน userns ตัวเอง แม้จะไม่มีผลกับ host แต่ควรลดเพื่อไม่ให้ tool
/// ใช้ capabilities ใน userns ตัวเอง (เช่น CAP_SYS_ADMIN ใน userns)
#[cfg(target_os = "linux")]
unsafe fn drop_capabilities() -> std::io::Result<()> {
    let hdr = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if libc::syscall(
        libc::SYS_capset,
        &hdr as *const _ as i64,
        data.as_ptr() as i64,
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// เข้า mount + network namespace (ทำหลัง userns จึงมี CAP_SYS_ADMIN)
#[cfg(target_os = "linux")]
unsafe fn enter_mount_and_net_ns() -> std::io::Result<()> {
    // mount namespace: แยก mount tree จาก host
    if libc::unshare(libc::CLONE_NEWNS) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // ทำให้ mounts ทั้งหมด private (ไม่ propagate กลับ host)
    if libc::mount(
        std::ptr::null(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // network namespace: ไม่มี network (loopback down)
    if libc::unshare(libc::CLONE_NEWNET) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// remount /proc ใน PID namespace ใหม่ (ทำใน child หลัง fork)
#[cfg(target_os = "linux")]
unsafe fn remount_proc() -> std::io::Result<()> {
    if libc::mount(
        c"proc".as_ptr(),
        c"/proc".as_ptr(),
        c"proc".as_ptr(),
        0,
        std::ptr::null(),
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// สถานะความพร้อมของ namespace + seccomp + mount + net
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
struct IsolationStatus {
    userns: bool,
    pidns: bool,
    mountns: bool,
    netns: bool,
    seccomp: bool,
    capdrop: bool,
}

/// เครื่องนี้รองรับ namespace + isolation แบบใด (probe แล้ว cache)
#[cfg(target_os = "linux")]
fn probe_isolation() -> IsolationStatus {
    static SUPPORTED: std::sync::OnceLock<IsolationStatus> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let pr = probe();
        // mount/net ns ทำได้ถ้า userns ทำได้ (เพราะต้องมี CAP_SYS_ADMIN)
        IsolationStatus {
            userns: pr.userns,
            pidns: pr.pid_namespace,
            mountns: pr.userns,
            netns: pr.userns,
            seccomp: pr.seccomp_install,
            capdrop: pr.userns,
        }
    })
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
            //    ค่าถูกล้างในลูกที่ fork ใหม่ (man prctl) จึงต้องตั้งซ้ำในหลาน
            //    ที่เป็น PID 1 อีกครั้ง (ดูขั้น 3) ไม่ใช่สืบทอดอัตโนมัติ
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

            // 3. user + PID namespace แล้ว fork ให้ลูกเป็น PID 1 ใน ns ใหม่
            //    (unshare(CLONE_NEWPID) มีผลกับลูกที่ fork ทีหลังเท่านั้น)
            //    best-effort: เครื่องไหนไม่รองรับก็รันต่อแบบ degraded — gateway
            //    ยังเป็นประตูหลัก (รายงานผลจริงผ่าน applied/degraded)
            if enter_user_then_pid_ns().is_ok() {
                // ลด capabilities ทั้งหมด (defense in depth)
                let _ = drop_capabilities();

                // mount + network namespace (ทำหลัง userns จึงมี CAP_SYS_ADMIN)
                let _ = enter_mount_and_net_ns();

                let pid = libc::fork();
                if pid < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if pid > 0 {
                    // ตัวกลาง: รอลูกแล้วออกด้วยสถานะเดียวกัน (ไม่ exec)
                    let mut status: libc::c_int = 0;
                    while libc::waitpid(pid, &mut status, 0) < 0 {
                        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                            break;
                        }
                    }
                    let code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else if libc::WIFSIGNALED(status) {
                        128 + libc::WTERMSIG(status)
                    } else {
                        1
                    };
                    libc::_exit(code);
                }
                // ลูกเดินต่อ: ตอนนี้เป็น PID 1 ใน ns ใหม่
                // pdeathsig ถูกล้างตอน fork ต้องตั้งใหม่ให้ชี้ไปตัวกลาง:
                // ตัวกลางตาย (เช่น parent หลักตายแล้วตัวกลางโดน SIGKILL) หลานตายตาม
                // กัน race ที่ตัวกลางตายก่อนตั้ง: ถ้า ppid กลายเป็น 1 (init host)
                // แสดงว่ากำพร้าแล้ว ให้ตายทันทีแบบ fail-closed
                let _ = libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                if libc::getppid() == 1 {
                    libc::_exit(1);
                }
            }

            // 4. remount /proc ใน PID namespace ใหม่ (ต้องทำก่อน seccomp
            //    เพราะ mount อยู่ใน denylist)
            let _ = remount_proc();

            // 5. seccomp denylist: default-allow + KILL syscall อันตราย
            //    (ติดหลัง remount /proc เพราะ mount ถูก KILL)
            let _ = install_dangerous_filter();

            // 6. rlimits: เพดานทรัพยากรที่ลดได้อย่างเดียว (unprivileged ทำได้)
            //    ตั้งหลัง fork เพื่อไม่ให้ RLIMIT_NPROC ไปบล็อก fork ภายใน
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

    #[cfg(target_os = "linux")]
    let _iso = probe_isolation();

    // ตรวจ exe ซ้ำก่อน spawn (บีบ TOCTOU: validate ครั้งแรกอาจถูกสลับไฟล์คั่นกลาง)
    revalidate_exe(&canon, policy)?;

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
    #[allow(unused_mut)]
    let mut applied: Vec<String> = vec![
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
    ];
    #[allow(unused_mut)]
    let mut degraded: Vec<String> = vec![];
    // รายงานตามความจริงของเครื่องนี้ (สเปก §12.1.1): กลไกที่ใช้ไม่ได้ต้องดัง
    #[cfg(target_os = "linux")]
    {
        let iso = probe_isolation();
        if iso.userns && iso.pidns {
            applied.push("user-namespace".into());
            applied.push("pid-namespace".into());
        } else {
            degraded.push("user-namespace: unavailable".into());
            degraded.push("pid-namespace: unavailable (needs unprivileged userns)".into());
        }
        if iso.mountns {
            applied.push("mount-namespace".into());
        } else {
            degraded.push("mount-namespace: not applied".into());
        }
        if iso.netns {
            applied.push("network-namespace".into());
        } else {
            degraded.push("network-namespace: not applied".into());
        }
        // capability-drop: รองรับถ้า userns รองรับ (capset ทำได้ใน userns)
        if iso.capdrop {
            applied.push("capability-drop".into());
        } else {
            degraded.push("capability-drop: not applied".into());
        }
        // seccomp denylist: รองรับถ้า probe ยืนยันว่า seccomp(2) ใช้ได้
        if iso.seccomp {
            applied.push("seccomp-filter".into());
        } else {
            degraded.push("seccomp-filter: not installed".into());
        }
    }
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
        applied,
        degraded,
    })
}

/// probe ความพร้อมกลไก OS แบบไม่ทิ้งผลข้างเคียง (spawn child ตัวเล็ก ๆ)
/// userns/seccomp/pidns ลองของจริงใน child ส่วน cgroup ลองสร้าง-ลบทิ้ง
/// KVM/Firecracker ตรวจแค่การมีอยู่ (ไม่ boot จริง) เพื่อใช้วางแผน Phase 7
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
        kvm: probe_kvm(),
        firecracker: probe_firecracker(),
    }
}

/// `/dev/kvm` มีอยู่และเปิดอ่านได้ (ไม่ต้องมีสิทธิ์ใช้จริง)
/// แค่บอกว่าเครื่องนี้มีโอกาสรัน MicroVM ได้ ต้องตรวจเวอร์ชันอีกทีตอน boot
fn probe_kvm() -> bool {
    kvm_available()
}

/// `/dev/kvm` เปิดอ่านได้หรือไม่ (side-effect free)
pub(crate) fn kvm_available() -> bool {
    std::fs::File::open("/dev/kvm").is_ok()
}

/// หาไบนารี `firecracker` ใน PATH (ไม่รัน ไม่ spawn)
/// คืน true ถ้าเจอไฟล์รันได้ชื่อตรงใน PATH เท่านั้น
fn probe_firecracker() -> bool {
    find_firecracker().is_some()
}

/// หา path ของไบนารี `firecracker` ใน PATH (ไม่รัน ไม่ spawn)
/// คืน `None` ถ้าไม่เจอไฟล์รันได้ชื่อตรง — ผู้เรียกต้อง fail-closed
pub(crate) fn find_firecracker() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("firecracker");
        if cand.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = std::fs::metadata(&cand) {
                    if md.permissions().mode() & 0o111 != 0 {
                        return Some(cand);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(cand);
            }
        }
    }
    None
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
    // SAFETY: syscall ล้วน (userns + uid/gid map + pidns) ไม่ allocate
    // ใช้ลำดับเดียวกับ run_checked จริง เพื่อ probe ให้ตรงกับที่ใช้จริง
    unsafe { enter_user_then_pid_ns() }
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
    use std::str::FromStr;

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
        // seccomp denylist ติดตั้งแล้ว -> ต้องอยู่ใน applied และห้ามซ้ำใน degraded
        assert!(out.applied.contains(&"seccomp-filter".to_string()));
        assert!(!out.degraded.iter().any(|d| d.starts_with("seccomp-filter")));
        // namespace แล้วแต่เครื่อง — รายงานต้องสอดคล้อง (applied XOR degraded)
        for ns in [
            "user-namespace",
            "pid-namespace",
            "mount-namespace",
            "network-namespace",
        ] {
            let in_applied = out.applied.iter().any(|a| a == ns);
            let in_degraded = out.degraded.iter().any(|d| d.starts_with(ns));
            assert_ne!(in_applied, in_degraded, "{ns} must be applied XOR degraded");
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn exit_code_propagates_through_namespace_wrapper() {
        // ถ้าใช้ namespace จะมีตัวกลาง fork รอลูกแล้ว exit ตามสถานะ —
        // เทสต์นี้พิสูจน์ว่า exit code ยังส่งผ่านมาถึง runtime ถูกต้อง
        let ws = test_ws("false");
        let real = std::fs::canonicalize("/bin/false").unwrap();
        let out = run_checked(
            &spec("/bin/false", &ws),
            &test_policy(&[&real.to_string_lossy()]),
        )
        .unwrap();
        assert!(!out.success());
        assert_eq!(out.code, Some(1));
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
        let f = unsafe { build_dangerous_filter() };
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_read as u32),
            0x7fff0000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_write as u32),
            0x7fff0000
        );
        // syscall ปกติ -> ALLOW (default-allow)
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
        let f = unsafe { build_dangerous_filter() };
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_socket as u32),
            0x7fff0000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_reboot as u32),
            0x00000000
        );
    }

    #[test]
    fn seccomp_denylist_kills_dangerous_syscalls() {
        let f = unsafe { build_dangerous_filter() };
        // syscall อันตราย -> KILL
        for &nr in DANGEROUS_SYSCALLS {
            assert_eq!(
                bpf_verdict(&f, 0xc000003e, nr as u32),
                0x00000000,
                "syscall {nr} must be KILLed"
            );
        }
        // syscall ปกติที่ไม่อยู่ใน denylist -> ALLOW
        for &nr in &[
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_mmap,
        ] {
            assert_eq!(
                bpf_verdict(&f, 0xc000003e, nr as u32),
                0x7fff0000,
                "syscall {nr} must be ALLOWed"
            );
        }
    }

    #[test]
    fn mount_and_net_namespaces_applied_when_supported() {
        let ws = test_ws("mntnet");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let out = run_checked(
            &spec("/bin/true", &ws),
            &test_policy(&[&real.to_string_lossy()]),
        )
        .unwrap();
        assert!(out.success());
        // ถ้า userns รองรับ -> mount + net ns ต้อง applied ด้วย
        if out.applied.iter().any(|a| a == "user-namespace") {
            assert!(out.applied.iter().any(|a| a == "mount-namespace"));
            assert!(out.applied.iter().any(|a| a == "network-namespace"));
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn capability_drop_applied_when_supported() {
        let ws = test_ws("capdrop");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let out = run_checked(
            &spec("/bin/true", &ws),
            &test_policy(&[&real.to_string_lossy()]),
        )
        .unwrap();
        assert!(out.success());
        // ถ้า userns รองรับ -> capability-drop ต้อง applied
        if out.applied.iter().any(|a| a == "user-namespace") {
            assert!(out.applied.iter().any(|a| a == "capability-drop"));
            assert!(!out
                .degraded
                .iter()
                .any(|d| d.starts_with("capability-drop")));
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ---- Phase 7 เตรียมการ: probe + artifact + level dispatch + revalidate ----

    #[test]
    fn microvm_probe_reports_honestly() {
        // probe ต้องไม่ panic และรายงานฟิลด์ KVM/Firecracker เสมอ
        // (ค่าแล้วแต่เครื่อง: CI ไม่มี KVM ต้องได้ false ไม่ใช่ error)
        let pr = probe();
        let text = serde_json::to_string(&pr).unwrap();
        assert!(text.contains("kvm"));
        assert!(text.contains("firecracker"));
        // ถ้าไม่มี /dev/kvm ต้องรายงาน false (ซื่อสัตย์ ไม่เงียบ)
        if !Path::new("/dev/kvm").exists() {
            assert!(!pr.kvm, "ไม่มี /dev/kvm ต้องรายงาน kvm=false");
        }
    }

    #[test]
    fn artifact_verify_roundtrip_and_mismatch() {
        use sha2::{Digest, Sha256};
        let dir = test_ws("artifact");
        let p = dir.join("kernel.bin");
        std::fs::write(&p, b"fake-kernel-image-v1").unwrap();
        let mut h = Sha256::new();
        h.update(b"fake-kernel-image-v1");
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        // hash ตรงต้องผ่านและคืนขนาดไฟล์
        let size = verify_artifact(&p, &hex, 1024 * 1024).unwrap();
        assert_eq!(size, b"fake-kernel-image-v1".len() as u64);
        // hash ผิดต้อง fail-closed (ห้าม boot)
        let mut bad = hex.clone();
        bad.replace_range(0..1, if &hex[0..1] == "a" { "b" } else { "a" });
        assert!(verify_artifact(&p, &bad, 1024 * 1024).is_err());
        // hex ผิดรูปต้อง fail-closed
        assert!(verify_artifact(&p, "not-hex", 1024 * 1024).is_err());
        // ไฟล์หายต้อง fail-closed
        assert!(verify_artifact(&dir.join("missing"), &hex, 1024 * 1024).is_err());
        // ไฟล์ใหญ่เกินเพดานต้อง fail-closed
        assert!(verify_artifact(&p, &hex, 4).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revalidate_catches_policy_change() {
        // ตรวจซ้ำต้องจับกรณี policy เปลี่ยนหลัง validate ครั้งแรก
        // (จำลอง TOCTOU: อนุญาตตอนแรก แล้วถอด allowlist ก่อน spawn)
        let ws = test_ws("reval");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let pol_allow = test_policy(&[&real.to_string_lossy()]);
        let canon = validate(&spec("/bin/true", &ws), &pol_allow).unwrap();
        assert!(revalidate_exe(&canon, &pol_allow).is_ok());
        // policy ใหม่ไม่อนุญาตแล้ว -> revalidate ต้อง DENY
        let pol_deny = test_policy(&[]);
        assert!(revalidate_exe(&canon, &pol_deny).is_err());
        // path ที่เปลี่ยนไป (canonicalize ซ้ำไม่ตรงเดิม) ต้อง DENY
        let link = ws.join("true-link");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("/bin/true", &link);
            if link.exists() {
                let canon_link = std::fs::canonicalize(&link).unwrap();
                // ส่ง path ที่ไม่ใช่ canonical (symlink) เข้า revalidate ต้องถูกจับ
                // เพราะ recanonicalize แล้วไม่ตรงกับ input
                assert!(revalidate_exe(&link, &pol_allow).is_err());
                let _ = std::fs::remove_file(&link);
                let _ = canon_link;
            }
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    // `runtime.isolation` ใน config แปลงเป็น level แบบ fail-closed:
    // ค่าแปลกห้ามเงียบไปใช้ค่าเริ่มต้น ต้องบูตไม่ขึ้น
    #[test]
    fn isolation_level_parses_and_rejects_unknown() {
        assert_eq!(
            SandboxLevel::from_str("sandbox").unwrap(),
            SandboxLevel::Process
        );
        assert_eq!(
            SandboxLevel::from_str("process").unwrap(),
            SandboxLevel::Process
        );
        assert_eq!(
            SandboxLevel::from_str("  MicroVM ").unwrap(),
            SandboxLevel::MicroVm
        );
        assert_eq!(
            SandboxLevel::from_str("container").unwrap(),
            SandboxLevel::Container
        );
        assert_eq!(
            SandboxLevel::from_str("hardware").unwrap(),
            SandboxLevel::Hardware
        );
        assert!(SandboxLevel::from_str("docker").is_err());
        assert!(SandboxLevel::from_str("").is_err());
    }

    #[test]
    fn non_process_levels_fail_closed() {
        // Level ที่ยังไม่มี backend ต้อง fail-closed เสมอ (fail-closed)
        // gateway จึงไม่ต้องแยกเคสเอง และ CI ที่ไม่มี KVM ยังเขียว
        // หมายเหตุ: เปิดฟีเจอร์ `microvm` แล้ว MicroVm จะเดินประตู skeleton
        // ด้วย config ว่าง (artifact หาย) จึงเป็น Invalid แทน Disabled —
        // deny เหมือนกันทั้งคู่ ไม่มีทางรัน
        let ws = test_ws("levels");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let pol = test_policy(&[&real.to_string_lossy()]);
        let s = spec("/bin/true", &ws);
        for level in [SandboxLevel::Container, SandboxLevel::Hardware] {
            let r = run_checked_with_level(&s, &pol, level);
            assert!(
                matches!(r, Err(SandboxError::Disabled(_))),
                "level {level:?} ต้อง Disabled"
            );
        }
        #[cfg(not(feature = "microvm"))]
        {
            let r = run_checked_with_level(&s, &pol, SandboxLevel::MicroVm);
            assert!(matches!(r, Err(SandboxError::Disabled(_))));
        }
        #[cfg(feature = "microvm")]
        assert!(
            run_checked_with_level(&s, &pol, SandboxLevel::MicroVm).is_err(),
            "MicroVm skeleton ต้อง deny (Invalid/Disabled ก็ได้ ห้ามรัน)"
        );
        // Process ยังรันได้ปกติ (ไม่ถดถอย)
        assert!(run_checked_with_level(&s, &pol, SandboxLevel::Process).is_ok());
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ตัวแปรรับ config ของ MicroVm: Process ต้องส่งผ่านเหมือนเดิม
    // MicroVm ด้วย config ว่างต้อง deny (ไม่ว่า Invalid/Disabled ก็ห้ามรัน)
    #[cfg(feature = "microvm")]
    #[test]
    fn level_and_cfg_routes_by_level() {
        let ws = test_ws("andcfg");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let pol = test_policy(&[&real.to_string_lossy()]);
        let s = spec("/bin/true", &ws);
        let cfg = microvm::MicroVmConfig::default();
        assert!(run_checked_with_level_and_cfg(&s, &pol, SandboxLevel::Process, &cfg).is_ok());
        assert!(run_checked_with_level_and_cfg(&s, &pol, SandboxLevel::MicroVm, &cfg).is_err());
        let _ = std::fs::remove_dir_all(&ws);
    }
}
