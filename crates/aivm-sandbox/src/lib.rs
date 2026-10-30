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

use aivm_policy::{Decision, EvalContext, Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;
pub mod container;
#[cfg(target_os = "linux")]
mod landlock;

/// MicroVM backend (Phase 7) — เปิดด้วยฟีเจอร์ `microvm` เท่านั้น
/// บูตและรัน guest จริงผ่าน Firecracker/KVM พร้อม pinned artifacts
/// ฟีเจอร์ปิดโดยปริยาย; เทสต์บูตจริงต้องมี host prerequisites และ pins
#[cfg(feature = "microvm")]
pub mod microvm;

/// Hardware Isolation backend (Level 3) — เปิดด้วยฟีเจอร์ `hardware` เท่านั้น
/// Generic QEMU/KVM รัน workload จริงได้; TEE/attestation ยัง experimental
/// measured boot, disk encryption และ GPU ยังไม่ใช่ guarantees ที่ยืนยันแล้ว
#[cfg(feature = "hardware")]
pub mod hardware;

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
    /// จำกัดขนาดไฟล์และการเขียน workspace (MiB)
    #[serde(default = "default_storage_mb")]
    pub storage_mb: u64,
}

fn default_storage_mb() -> u64 {
    5 * 1024
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu: 2,
            memory_mb: 1024,
            pids_max: 64,
            storage_mb: default_storage_mb(),
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

/// ไฟล์ output ที่ trusted gateway เตรียมไว้ ไม่มีสิทธิ์สร้างไฟล์ใน child
#[derive(Debug, Clone)]
pub struct BuildSpec {
    pub root: PathBuf,
    pub outputs: Vec<PathBuf>,
    pub max_file_bytes: u64,
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
    /// เส้นตายจริง (ms) นอกเหนือ CPU rlimit
    pub timeout_ms: u64,
    pub build: Option<BuildSpec>,
}

impl ExecSpec {
    fn timeout_ms(&self) -> u64 {
        self.timeout_ms.clamp(1, 120000)
    }
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
    /// เอกลักษณ์ instance ต่อรัน (G5 DNA — ว่าง = ไม่มี เช่น path Process)
    /// รูป `s{scheme}-k{0|1}-r{0|1}-{vcpu}x{mem}-{tmp}` gateway ลง audit
    pub dna: String,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// สิ่งที่ OS เครื่องนี้รองรับ (probe แบบไม่ทิ้งผลข้างเคียง)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProbe {
    /// Checks default container paths; namespaces are reported separately.
    #[serde(default)]
    pub container: container::ContainerProbe,
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
    /// ไบนารี `qemu-system-x86_64` อยู่ใน PATH (เงื่อนไขตั้งต้น Hardware Level 3)
    #[serde(default)]
    pub qemu: bool,
    /// `/dev/sev` มีอยู่ (AMD SEV-SNP)
    #[serde(default)]
    pub sev_snp: bool,
    /// `/dev/tdx_guest` มีอยู่ (Intel TDX)
    #[serde(default)]
    pub tdx: bool,
    /// ไบนารี `swtpm` อยู่ใน PATH (vTPM สำหรับ Hardware Level 3)
    #[serde(default)]
    pub swtpm: bool,
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
    // process ที่ไม่ไว้วางใจห้ามส่งสัญญาณไปยัง host processes
    // กัน exec ทางอ้อมที่หลบ Landlock file-grant (memfd/procfd)
    libc::SYS_execveat,
    libc::SYS_memfd_create,
    libc::SYS_memfd_secret,
    libc::SYS_fallocate,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    libc::SYS_setpgid,
    libc::SYS_setsid,
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

/// syscall ที่อนุญาตสำหรับ workload ทั่วไป (cargo, rustc, gcc, test runner)
/// hybrid allowlist: ถ้า syscall อยู่ในลิสต์นี้ -> ALLOW ทันที
/// ไม่อยู่ -> ตรวจ denylist -> default KILL (fail-closed)
///
/// ลิสต์นี้ครอบคลุม syscall พื้นฐานของ process, memory, file, sync, time, signal
/// เพิ่ม/ลดได้ผ่าน PR พร้อม justification (audit log จะบอก syscall ที่ขาด)
#[cfg(target_os = "linux")]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[
    // Process lifecycle
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_openat,
    libc::SYS_close,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_gettid,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_futex,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_yield,
    libc::SYS_sched_getparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_getpriority,
    libc::SYS_setpriority,
    libc::SYS_getrlimit,
    libc::SYS_setrlimit,
    libc::SYS_prlimit64,
    libc::SYS_getrusage,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_getcpu,
    libc::SYS_sysinfo,
    // Memory management
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_mincore,
    libc::SYS_msync,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_mlockall,
    libc::SYS_munlockall,
    // File operations
    libc::SYS_statx,
    libc::SYS_stat,
    libc::SYS_fstat,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    libc::SYS_getdents,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_umask,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_getcwd,
    libc::SYS_getdents64,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_lseek,
    libc::SYS_sendfile,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_copy_file_range,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_fadvise64,
    libc::SYS_sync,
    libc::SYS_syncfs,
    libc::SYS_flock,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_poll,
    libc::SYS_pselect6,
    libc::SYS_ppoll,
    // Time
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_gettimeofday,
    // Signal handling
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigsuspend,
    // Eventfd / timerfd / signalfd
    libc::SYS_eventfd2,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_signalfd4,
    // Inotify / fanotify
    libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    // Poll / epoll
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    // Socket (local only - network blocked by policy/namespace)
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
    // Misc
    libc::SYS_uname,
    libc::SYS_getrandom,
    libc::SYS_membarrier,
    libc::SYS_rseq,
];

// BPF jump offset (jt/jf) เป็น 8-bit (0..=255): allowlist+denylist ยาวเกินแล้ว
// offset จะล้นแบบเงียบ ๆ ทำให้ syscall อันตรายหลุด — บังคับ fail ตอน compile
const _: () = assert!(
    ALLOWED_SYSCALLS.len() + DANGEROUS_SYSCALLS.len() <= u8::MAX as usize,
    "seccomp allow+deny list too long for 8-bit BPF jump offset"
);

/// โหมดการทำงานของ seccomp filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// Hybrid: allowlist -> denylist -> KILL (fail-closed production)
    /// syscall ที่ไม่อยู่ใน allowlist = KILL (ไม่ใช่ default ALLOW)
    #[default]
    Hybrid,
    /// Audit: allowlist -> denylist -> TRACE (log unknown, then KILL)
    /// ใช้ร่วมกับ tracer (strace -f -e trace=seccomp) เพื่อสร้าง allowlist
    Audit,
    /// Legacy denylist only (default ALLOW) — ไม่แนะนำ
    DenylistOnly,
}

/// สร้าง seccomp BPF filter แบบ **hybrid**: allowlist -> denylist -> default action
///
/// โครงโปรแกรม:
///   ld [4] (arch); jeq x86_64 else KILL
///   ld [0] (nr); binary search allowlist -> ALLOW
///   ld [0] (nr); linear scan denylist -> KILL
///   default_action (KILL/TRACE)
#[cfg(target_os = "linux")]
unsafe fn build_hybrid_filter(mode: SeccompMode) -> Vec<libc::sock_filter> {
    build_hybrid_filter_with_init(mode, false)
}

#[cfg(target_os = "linux")]
unsafe fn build_container_filter() -> Vec<libc::sock_filter> {
    build_hybrid_filter_with_init(SeccompMode::Hybrid, true)
}

#[cfg(target_os = "linux")]
unsafe fn build_hybrid_filter_with_init(
    mode: SeccompMode,
    container_init: bool,
) -> Vec<libc::sock_filter> {
    let n_allow = ALLOWED_SYSCALLS.len();
    let n_deny = DANGEROUS_SYSCALLS.len();

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
    let _jgt = |k: u32, jt: u8| libc::sock_filter {
        code: 0x25,
        jt,
        jf: 0,
        k,
    };

    // Default action สำหรับ syscall ที่ไม่อยู่ใน allowlist (ตรวจ allowlist/denylist ไม่โดน)
    let default_action = match mode {
        // allowlist จริง: syscall นอกลิสต์ = KILL (fail-closed)
        SeccompMode::Hybrid => 0x80000000,       // KILL_PROCESS
        SeccompMode::Audit => 0x7ff00000,        // TRACE (ENOSYS + notify tracer)
        SeccompMode::DenylistOnly => 0x7fff0000, // legacy denylist defaults to ALLOW
    };

    let mut filter = vec![
        // arch check: x86_64 เท่านั้น (KILL ถ้าไม่ตรง)
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

    // x32 ใช้ audit arch เดียวกับ x86_64 แต่ syscall number มี bit 30
    // ปฏิเสธ ABI นี้เพื่อไม่ให้ใช้ syscall ที่หลุดจาก allowlist/denylist
    filter.push(libc::sock_filter {
        code: 0x35,
        jt: 0,
        jf: 1,
        k: 0x40000000,
    });
    filter.push(ret(0x00000000));

    // helper ต้องติดตั้ง Landlock หลัง bubblewrap ติดตั้ง seccomp แล้ว
    // worker ต้อง stack seccomp ของตัวเองด้วย; ทั้งสองเพิ่มข้อจำกัดได้เท่านั้น
    if container_init {
        for nr in [
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
            libc::SYS_seccomp,
        ] {
            filter.push(libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: nr as u32,
            });
            filter.push(ret(0x7fff0000));
        }
    }

    // ioctl ที่ clone/เปลี่ยน filesystem metadata อาจหลบขอบเขต output/byte quota
    // ยังคงให้ ioctl ปกติ (เช่น isatty) ผ่านเพื่อให้ compiler ทำงานได้
    let blocked_ioctl = [
        0x40049409u32,
        0x4020940d,
        0xc0189436,
        0x40086602,
        0x401c5820,
    ];
    filter.push(libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: (blocked_ioctl.len() + 3) as u8,
        k: libc::SYS_ioctl as u32,
    });
    filter.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 24,
    });
    for (index, command) in blocked_ioctl.into_iter().enumerate() {
        filter.push(jeq(command, (blocked_ioctl.len() - index) as u8));
    }
    filter.push(ret(0x7fff0000));
    filter.push(ret(0x00000000));

    // ============ ALLOWLIST: linear scan ============
    // allowlist[i] อยู่ที่ pc = base + i
    // target = ALLOW ret (base + n_allow + n_deny + 1)
    // jt = target - (pc + 1) = n_allow + n_deny - i
    if n_allow > 0 {
        for (i, &nr) in ALLOWED_SYSCALLS.iter().enumerate() {
            let skip = n_allow + n_deny - i;
            filter.push(jeq(nr as u32, skip as u8));
        }
    }

    // ============ DENYLIST: linear scan ============
    // denylist[i] อยู่ที่ pc = base + n_allow + i
    // target = KILL ret (base + n_allow + n_deny + 2)
    // jt = target - (pc + 1) = n_deny - i + 1
    for (i, &nr) in DANGEROUS_SYSCALLS.iter().enumerate() {
        let skip = n_deny - i + 1;
        filter.push(jeq(nr as u32, skip as u8));
    }

    // ============ VERDICTS ============
    // syscall ที่ไม่โดน allowlist/denylist ตกมาที่นี่ (Hybrid=KILL, Audit=TRACE, DenylistOnly=ALLOW)
    filter.push(ret(default_action));
    // syscall ที่ผ่าน allowlist -> ALLOW ชัดเจน (ไม่ผูกกับ default_action)
    filter.push(ret(0x7fff0000));
    // syscall ที่อยู่ใน denylist + fallback -> KILL
    filter.push(ret(0x00000000));

    filter
}

/// ติดตั้ง seccomp filter ใน process ปัจจุบัน (ทำใน child หลัง fork)
#[cfg(target_os = "linux")]
unsafe fn install_dangerous_filter(filter: &[libc::sock_filter]) -> std::io::Result<()> {
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    if libc::syscall(libc::SYS_seccomp, 1i64, 0i64, &prog as *const _ as i64) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Install a small worker-specific filter that blocks network and socket
/// syscalls while leaving ordinary model runtime syscalls available. The
/// filter is intentionally narrower than the process-exec profile so model
/// backends can evolve their memory/thread syscall usage independently.
///
/// นอกเหนือจาก network: กัน cross-process/inspection ที่ worker ไม่มีทางใช้
/// (regression #16: เดิม denylist ลืม ptrace/process_vm_*/bpf — model worker
/// ที่ถูกบุกรุกอ่านหน่วยความจำ/จับคู่ process อื่น + load BPF ได้)
#[cfg(target_os = "linux")]
pub fn install_worker_network_seccomp() -> std::io::Result<()> {
    let denied: &[libc::c_long] = &[
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_shutdown,
        // cross-process ทั้งคู่ — worker ไม่ได้ spawn/inspect process อื่นเลย
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
    ];
    let kill = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x80000000,
    };
    let allow = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    };
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
        kill,
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    // x32 shares AUDIT_ARCH_X86_64 but uses a different syscall number space.
    filter.push(libc::sock_filter {
        code: 0x35,
        jt: 0,
        jf: 1,
        k: 0x40000000,
    });
    filter.push(kill);
    for (index, syscall) in denied.iter().enumerate() {
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: (denied.len() - index) as u8,
            jf: 0,
            k: *syscall as u32,
        });
    }
    filter.push(allow);
    filter.push(kill);
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        install_dangerous_filter(&filter)
    }
}

/// เข้า user namespace แบบไม่บังคับ network namespace เพื่อแยกตัวนับ RLIMIT_NPROC
/// ของ worker ออกจากจำนวนโปรเซสรวมของ UID บน host
#[cfg(target_os = "linux")]
pub fn enter_worker_user_namespace() -> std::io::Result<()> {
    unsafe {
        enter_user_ns()?;
        drop_capabilities()
    }
}

/// Enter an empty network namespace; failure is fatal to a requested namespace tier.
#[cfg(target_os = "linux")]
pub fn enter_worker_network_namespace() -> std::io::Result<()> {
    unsafe {
        enter_user_ns()?;
        if libc::unshare(libc::CLONE_NEWNET) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        drop_capabilities()
    }
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
            | "aivm-container-init"
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
    if !(1..=120000).contains(&spec.timeout_ms) {
        return Err(bad("exec timeout out of range"));
    }
    if spec.limits.cpu == 0
        || spec.limits.memory_mb == 0
        || spec.limits.storage_mb == 0
        || spec.limits.pids_max == 0
    {
        return Err(bad("resource quotas must be positive"));
    }
    if spec.build.is_some() && !spec.env_extra.is_empty() {
        return Err(bad("build outputs cannot receive injected environment"));
    }
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
    //    ชั้นนี้ไม่ถือ state ของ cube: conditional rules (มี `when`) ถูกตรวจ
    //    ซ้ำที่ gateway ด้วย ctx จริง — ที่นี่ยังคุม unconditional + CEL พัง
    let scope = canon.to_string_lossy().to_string();
    match policy.evaluate_process(&scope, &EvalContext::default()) {
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
    // ไม่มี ctx ที่ชั้น revalidate (เหมือน validate ด้านบน) — conditional
    // rules ถูก gateway คุมไว้แล้วด้วย state จริง
    match policy.evaluate_process(&scope, &EvalContext::default()) {
        (Decision::Allow, _) => Ok(()),
        (Decision::Deny, rule) => Err(bad(&format!(
            "exe not allowlisted on revalidate ({})",
            rule.unwrap_or_default()
        ))),
    }
}

/// คำตัดสินหลังพยายามรัน (G3 — `docs/threat-model.md`): ตอบว่า "มีหลักฐาน
/// ว่า boundary ถูกละเมิดหรือไม่" ไม่ใช่ "รันสำเร็จหรือไม่" ดูเฉพาะ signal
/// ฝั่ง host ไม่เดาเจตนา agent
/// - `Clean`: จบบริบูรณ์ หรือไม่เกิด run (deny ตั้งแต่ประตู / infra ล้มแบบ
///   ไม่มีร่องรอยแทรกแซง)
/// - `Suspect`: ผิดปกติแบบอธิบายได้ (timeout, marker หาย/parse ไม่ได้) — ต้องสืบต่อ
/// - `Compromise`: หลักฐานละเมิด boundary (VMM ตายก่อน marker, ไฟล์ถูกสลับกลางบูต)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunVerdict {
    Clean,
    Suspect(&'static str),
    Compromise(&'static str),
}

impl RunVerdict {
    /// ป้ายสั้นสำหรับ audit (`clean`/`suspect`/`compromise`)
    pub fn label(&self) -> &'static str {
        match self {
            RunVerdict::Clean => "clean",
            RunVerdict::Suspect(_) => "suspect",
            RunVerdict::Compromise(_) => "compromise",
        }
    }
    /// เหตุผลแบบตายตัว (ไว้สืบย้อน ไม่ใช่ข้อความอิสระ)
    pub fn reason(&self) -> &'static str {
        match self {
            RunVerdict::Clean => "no-interference-evidence",
            RunVerdict::Suspect(r) | RunVerdict::Compromise(r) => r,
        }
    }
}

/// จุดแยก backend ตาม `SandboxLevel` (seam ของ Phase 7)
/// คืน verdict คู่กับ error เสมอ (G3): gateway เอาไปลง audit โดยไม่ต้องเดาเอง
/// - `Process` = พฤติกรรม MVP-B เดิม (`run_checked`) ไม่เปลี่ยน
/// - `MicroVm` = pinned artifacts → host readiness → Firecracker boot/exec
///   config ว่างหรือ prerequisites ไม่พร้อม = ปฏิเสธ; ไม่มีฟีเจอร์ = `Disabled`
/// - `Container` = bubblewrap + mandatory delegated cgroup v2
/// - `Hardware` = Generic QEMU/KVM เมื่อเปิดฟีเจอร์และ config พร้อม;
///   TEE/attestation ยังไม่ยืนยัน และไม่มีฟีเจอร์ = `Disabled`
///
/// gateway ชั้นบนจึงไม่ต้องแยกเคสเอง
pub fn run_checked_with_level(
    spec: &ExecSpec,
    policy: &Policy,
    level: SandboxLevel,
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    match level {
        SandboxLevel::Process => run_checked(spec, policy).map_err(|e| (e, RunVerdict::Clean)),
        SandboxLevel::Container => container::run(spec, policy, &container::ContainerConfig::default())
            .map_err(|e| (e, RunVerdict::Clean)),
        #[cfg(feature = "microvm")]
        SandboxLevel::MicroVm => microvm::run_in_microvm(spec, policy, &microvm::MicroVmConfig::default()),
        #[cfg(not(feature = "microvm"))]
        SandboxLevel::MicroVm => Err((
            SandboxError::Disabled(
                "microvm backend not implemented (needs KVM + firecracker + verified image); use Process level".into(),
            ),
            RunVerdict::Clean,
        )),
        #[cfg(feature = "hardware")]
        SandboxLevel::Hardware => hardware::run_in_hardware(spec, policy, &hardware::HardwareConfig::default()),
        #[cfg(not(feature = "hardware"))]
        SandboxLevel::Hardware => Err((
            SandboxError::Disabled("hardware backend not implemented (needs TEE host: SEV-SNP/TDX); use Process level".into()),
            RunVerdict::Clean,
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
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    match level {
        SandboxLevel::MicroVm => microvm::run_in_microvm(spec, policy, cfg),
        _ => run_checked_with_level(spec, policy, level),
    }
}

/// จุดแยก backend พร้อม config Hardware Isolation (ใช้เมื่อเปิดฟีเจอร์ `hardware`)
///
/// ระดับ Hardware รับ `HardwareConfig` จริง (TEE type, attestation policy,
/// GPU/NPU config, disk encryption) — gateway ส่ง config ที่ parse จาก
/// `aivm.yaml` มาทางนี้
#[cfg(feature = "hardware")]
pub fn run_checked_with_level_and_cfg_hardware(
    spec: &ExecSpec,
    policy: &Policy,
    level: SandboxLevel,
    cfg: &hardware::HardwareConfig,
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    match level {
        SandboxLevel::Hardware => hardware::run_in_hardware(spec, policy, cfg),
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
/// ใน ns ใหม่ (ต้องเขียน setgroups=deny ก่อน gid_map)
#[cfg(target_os = "linux")]
unsafe fn enter_user_ns() -> std::io::Result<()> {
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
    let storage_bytes = spec.limits.storage_mb.saturating_mul(1024 * 1024);
    let env_extra = spec.env_extra.clone();
    #[cfg(target_os = "linux")]
    let (filesystem_rules, filesystem_fsize_limit) = {
        let mut filesystem_policy = policy.clone();
        if !env_extra.is_empty() || spec.build.is_some() {
            filesystem_policy.filesystem.write.clear();
        }
        landlock::prepare(
            &ws,
            &canon,
            &filesystem_policy,
            storage_bytes,
            spec.build.as_ref(),
        )?
    };
    #[cfg(target_os = "linux")]
    let dangerous_filter = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
    #[cfg(target_os = "linux")]
    let cpu_mask = unsafe {
        let mut available: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut available) != 0 {
            return Err(SandboxError::Spawn(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut selected: libc::cpu_set_t = std::mem::zeroed();
        let mut count = 0;
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if libc::CPU_ISSET(cpu, &available) && count < spec.limits.cpu {
                libc::CPU_SET(cpu, &mut selected);
                count += 1;
            }
        }
        if count == 0 {
            return Err(SandboxError::Invalid("CPU quota must be positive".into()));
        }
        selected
    };
    #[cfg(target_os = "linux")]
    let (mut isolation_reader, isolation_writer) = {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(SandboxError::Spawn(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        }
    };

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
            if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpu_mask) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
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

            // ไม่ fork ใน pre_exec: mediator จะถือ exec-error pipe ทำให้ spawn ค้าง
            // PID namespace จึงรายงาน degraded; Landlock/seccomp ยังบังคับเสมอ
            // หมายเหตุ: PID namespace จะทำให้ compiler/test runner ที่ spawn
            // subprocess ทำงานผิดปกติ ใช้ MicroVM สำหรับ kernel-level isolation
            let mut isolation = 0u8;
            if enter_user_ns().is_ok() {
                isolation |= 1;
                if enter_mount_and_net_ns().is_ok() {
                    isolation |= 4 | 8;
                }
                if drop_capabilities().is_ok() {
                    isolation |= 16;
                }
            }
            // Landlock ตกทอดถึงลูกทุกตัว; ไม่รองรับหรือ restrict ไม่สำเร็จ = DENY
            if libc::syscall(
                libc::SYS_landlock_restrict_self,
                std::os::fd::AsRawFd::as_raw_fd(&filesystem_rules),
                0,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // 5. seccomp denylist: default-allow + KILL syscall อันตราย
            //    (ติดหลัง remount /proc เพราะ mount ถูก KILL)
            install_dangerous_filter(&dangerous_filter)?;
            isolation |= 32;
            if libc::write(
                std::os::fd::AsRawFd::as_raw_fd(&isolation_writer),
                &isolation as *const u8 as *const libc::c_void,
                1,
            ) != 1
            {
                return Err(std::io::Error::last_os_error());
            }

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
                filesystem_fsize_limit.min(SANDBOX_FS_MB * 1024 * 1024) as libc::rlim_t,
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

    // ตรวจ exe ซ้ำก่อน spawn (บีบ TOCTOU: validate ครั้งแรกอาจถูกสลับไฟล์คั่นกลาง)
    revalidate_exe(&canon, policy)?;

    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(e.to_string()))?;
    #[cfg(target_os = "linux")]
    let isolation = {
        let mut value = [0u8];
        isolation_reader
            .read_exact(&mut value)
            .map_err(|e| SandboxError::Spawn(e.to_string()))?;
        value[0]
    };
    // drain pipe สองเส้นพร้อมกันและมี wall-clock deadline
    fn drain<R: Read + Send + 'static>(
        mut pipe: R,
    ) -> std::thread::JoinHandle<std::io::Result<(String, bool)>> {
        std::thread::spawn(move || {
            let mut saved = Vec::new();
            let mut buffer = [0u8; 8192];
            let mut truncated = false;
            loop {
                let n = pipe.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let keep = n.min((MAX_OUTPUT as usize).saturating_sub(saved.len()));
                saved.extend_from_slice(&buffer[..keep]);
                truncated |= keep < n;
            }
            Ok((String::from_utf8_lossy(&saved).into_owned(), truncated))
        })
    }
    let stdout = drain(
        child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Spawn("stdout pipe missing".into()))?,
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Spawn("stderr pipe missing".into()))?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(spec.timeout_ms());
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Ok(None) => {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(SandboxError::Spawn("process wall-clock timeout".into()));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::Spawn(error.to_string()));
            }
        }
    };
    // ลูกที่ fork แล้วถือ pipe ค้างต้องตายด้วย แม้ process หลักจบก่อน
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let output = |handle: std::thread::JoinHandle<std::io::Result<(String, bool)>>| {
        handle
            .join()
            .map_err(|_| SandboxError::Spawn("output reader panicked".into()))?
            .map_err(|e| SandboxError::Spawn(e.to_string()))
    };
    let (out, out_truncated) = output(stdout)?;
    let (err_s, err_truncated) = output(stderr)?;
    #[allow(unused_mut)]
    let mut applied: Vec<String> = vec![
        "cpu-affinity".into(),
        "landlock-filesystem".into(),
        "process-group-cleanup".into(),
        "wall-clock-deadline".into(),
        "exe-allowlist".into(),
        "arg-schema".into(),
        "env-scrub".into(),
        "cwd-pin".into(),
        "stdin-null".into(),
        "no-new-privs".into(),
        "pdeathsig-sigkill".into(),
        format!("rlimit-as={mem_bytes}"),
        format!("rlimit-cpu={SANDBOX_CPU_SECS}s"),
        format!(
            "rlimit-fsize={}bytes",
            filesystem_fsize_limit.min(SANDBOX_FS_MB * 1024 * 1024)
        ),
        format!("rlimit-nproc={nproc}"),
    ];
    #[allow(unused_mut)]
    let mut degraded: Vec<String> = vec![];
    // รายงานตามความจริงของเครื่องนี้ (สเปก §12.1.1): กลไกที่ใช้ไม่ได้ต้องดัง
    #[cfg(target_os = "linux")]
    {
        for (bit, label) in [
            (1, "user-namespace"),
            (2, "pid-namespace"),
            (4, "mount-namespace"),
            (8, "network-namespace"),
            (16, "capability-drop"),
            (32, "seccomp-filter"),
        ] {
            if isolation & bit != 0 {
                applied.push(label.into());
            } else {
                degraded.push(format!("{label}: not applied"));
            }
        }
    }
    if out_truncated || err_truncated {
        degraded.push("output-truncated@1MiB".into());
    }
    let code = status.code();
    Ok(ExecOutcome {
        exe: canon.to_string_lossy().to_string(),
        argv: spec.args.clone(),
        code,
        stdout: out,
        stderr: err_s,
        applied,
        degraded,
        // path Process ไม่มี DNA ต่อ instance (task วิ่งบน host ตรง ๆ)
        dna: String::new(),
    })
}

/// probe ความพร้อมกลไก OS แบบไม่ทิ้งผลข้างเคียง (spawn child ตัวเล็ก ๆ)
/// userns/seccomp/pidns ลองของจริงใน child ส่วน cgroup ลองสร้าง-ลบทิ้ง
/// KVM/Firecracker ตรวจแค่การมีอยู่ (ไม่ boot จริง) เพื่อใช้วางแผน Phase 7
pub fn probe() -> SandboxProbe {
    SandboxProbe {
        container: container::ContainerConfig::default().probe(),
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
        qemu: find_qemu().is_some(),
        sev_snp: std::path::Path::new("/dev/sev").exists(),
        tdx: std::path::Path::new("/dev/tdx_guest").exists(),
        swtpm: probe_binary_in_path("swtpm"),
    }
}

/// ไบนารีชื่อตรงอยู่ใน PATH และรันได้หรือไม่ (ไม่รัน ไม่ spawn —
/// ตรวจแค่การมีอยู่แบบ side-effect free เหมือน `find_firecracker`)
fn probe_binary_in_path(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if !cand.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(&cand) {
                if md.permissions().mode() & 0o111 != 0 {
                    return true;
                }
            }
        }
        #[cfg(not(unix))]
        {
            return true;
        }
    }
    false
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

/// หา path ของไบนารี `qemu-system-x86_64` ใน PATH (ไม่รัน ไม่ spawn)
/// คืน `None` ถ้าไม่เจอไฟล์รันได้ชื่อตรง — ผู้เรียกต้อง fail-closed
#[allow(dead_code)]
pub(crate) fn find_qemu() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("qemu-system-x86_64");
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
    // ตรวจทั้ง namespace และ UID/GID mapping เหมือน runtime:
    // unshare สำเร็จอย่างเดียวไม่ได้แปลว่า /proc อนุญาตให้เขียน mapping
    // SAFETY: syscall ล้วน ไม่มี allocate; เรียกใน child ของ probe เท่านั้น
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        enter_user_ns()
    }
}

fn probe_pid_namespace() -> std::io::Result<()> {
    // SAFETY: syscall ล้วน (userns + uid/gid map + pidns) ไม่ allocate
    // ใช้ลำดับเดียวกับ run_checked จริง เพื่อ probe ให้ตรงกับที่ใช้จริง
    unsafe {
        probe_userns()?;
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
    use std::str::FromStr;

    fn test_policy(allow: &[&str]) -> Policy {
        let allow_list = allow
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        Policy::from_yaml(&format!(
            "name: t\nfilesystem: {{deny: ['**/.env*']}}\nprocess:\n  allow: [{allow_list}]\n  deny: [/bin/sh, /bin/bash]\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n"
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
            timeout_ms: 30000,
            build: None,
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

    #[test]
    fn userns_probe_requires_mapped_identity() {
        fn check_mapped_identity() -> std::io::Result<()> {
            // ตรวจผลและ identity จาก child เดียวกัน ไม่เทียบ probe สองครั้ง:
            // namespace quota อาจเปลี่ยนระหว่างครั้งเมื่อเทสต์รันพร้อมกัน
            if probe_userns().is_err() {
                return Ok(()); // เครื่องที่ใช้ userns ไม่ได้ต้องรายงาน false ได้ตามปกติ
            }
            // kernel ต้องเห็นตัวเราเป็น uid/gid 0 ใน namespace ใหม่จริง
            // หาก probe ตรวจแค่ unshare จะเห็น overflow IDs แทน
            if unsafe { libc::getuid() != 0 || libc::getgid() != 0 } {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        }
        assert!(
            can_true_with(check_mapped_identity),
            "a successful userns probe requires mapped UID/GID"
        );
    }

    /// ตีความ subset ของ BPF ที่ builder ใช้: ld [k], jeq(jt/jf), ret
    /// คืนค่า k ของ ret สุดท้าย — ใช้พิสูจน์ว่า allow/deny ถูกต้องจริง
    fn bpf_verdict(filter: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        bpf_verdict_with_ioctl(filter, arch, nr, 0)
    }
    fn bpf_verdict_with_ioctl(
        filter: &[libc::sock_filter],
        arch: u32,
        nr: u32,
        command: u32,
    ) -> u32 {
        let mut a: u32 = 0;
        let mut pc = 0usize;
        for _ in 0..4096 {
            let ins = &filter[pc];
            match ins.code {
                0x20 => {
                    a = match ins.k {
                        4 => arch,
                        24 => command,
                        _ => nr,
                    };
                    pc += 1;
                }
                0x15 => {
                    pc += 1 + if a == ins.k {
                        ins.jt as usize
                    } else {
                        ins.jf as usize
                    };
                }
                0x35 => {
                    pc += 1 + if a >= ins.k {
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
    fn seccomp_filter_debug() {
        let f = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        eprintln!("Filter len: {}", f.len());
        for (i, ins) in f.iter().enumerate() {
            eprintln!(
                "{:3}: code=0x{:02x} jt={} jf={} k={}",
                i, ins.code, ins.jt, ins.jf, ins.k
            );
        }
        // Test SYS_read
        let verdict = bpf_verdict(&f, 0xc000003e, libc::SYS_read as u32);
        eprintln!("SYS_read verdict: {:#x}", verdict);
    }

    #[test]
    fn seccomp_filter_allows_listed_and_kills_rest() {
        let f = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_read as u32),
            0x7fff0000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_write as u32),
            0x7fff0000
        );
        // Explicitly dangerous syscall -> KILL.
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_reboot as u32),
            0x00000000
        );
        // ห้ามส่งสัญญาณพร้อมข้อมูลไปยัง process ของ host ที่ใช้ UID เดียวกัน
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_rt_sigqueueinfo as u32),
            0x00000000
        );
        // สถาปัตยกรรมผิด -> KILL ทันที
        assert_eq!(
            bpf_verdict(&f, 0x40000003, libc::SYS_read as u32),
            0x00000000
        );
    }

    #[test]
    fn seccomp_hybrid_kills_unlisted_syscall() {
        // allowlist จริง: syscall ที่ไม่อยู่ทั้ง allowlist และ denylist ต้อง KILL
        // (regression: เดิม default เป็น ALLOW ทำให้ syscall นอกลิสต์หลุด)
        let f = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_getpgid));
        assert!(!DANGEROUS_SYSCALLS.contains(&libc::SYS_getpgid));
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_getpgid as u32),
            0x80000000,
            "unlisted syscall must be KILLed under Hybrid (fail-closed allowlist)"
        );
        // อีกหนึ่ง syscall นอกลิสต์ (benign เช่นกัน) ต้อง KILL
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_sethostname as u32),
            0x80000000,
            "unlisted syscall must be KILLed under Hybrid (fail-closed allowlist)"
        );
        // DenylistOnly ยังคง default ALLOW สำหรับ syscall นอกลิสต์ (legacy)
        let legacy = unsafe { build_hybrid_filter(SeccompMode::DenylistOnly) };
        assert_eq!(
            bpf_verdict(&legacy, 0xc000003e, libc::SYS_getpgid as u32),
            0x7fff0000
        );
    }

    #[test]
    fn container_filter_allows_security_setup_without_weakening_other_verdicts() {
        let container = unsafe { build_container_filter() };
        let process = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        let setup = [
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
            libc::SYS_seccomp,
        ];
        // เปรียบเทียบทุก syscall ในช่วงนี้: เปลี่ยนผลเฉพาะ setup สี่ตัว
        for nr in 0..=1024 {
            let expected = if setup.contains(&(nr as libc::c_long)) {
                0x7fff0000
            } else {
                bpf_verdict(&process, 0xc000003e, nr)
            };
            assert_eq!(
                bpf_verdict(&container, 0xc000003e, nr),
                expected,
                "syscall {nr}"
            );
            assert_eq!(bpf_verdict(&container, 0xc000003e, nr | 0x40000000), 0);
            assert_eq!(bpf_verdict(&container, 0x40000003, nr), 0);
        }
        for command in [0x40049409, 0x4020940d, 0xc0189436, 0x40086602, 0x401c5820] {
            assert_eq!(
                bpf_verdict_with_ioctl(&container, 0xc000003e, libc::SYS_ioctl as u32, command),
                0
            );
        }
    }

    #[test]
    fn seccomp_filter_network_profile_adds_socket_syscalls() {
        let f = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_socket as u32),
            0x00000000
        );
        assert_eq!(
            bpf_verdict(&f, 0xc000003e, libc::SYS_reboot as u32),
            0x00000000
        );
    }

    #[test]
    fn seccomp_denylist_kills_dangerous_syscalls() {
        let f = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
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
        for label in ["mount-namespace", "network-namespace"] {
            assert_ne!(
                out.applied.iter().any(|s| s == label),
                out.degraded.iter().any(|s| s.starts_with(label))
            );
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
        // Level 3: probe ต้องรายงานฟิลด์ hardware ด้วย (qemu/sev/tdx/swtpm)
        for f in ["qemu", "sev_snp", "tdx", "swtpm"] {
            assert!(text.contains(f), "probe ต้องมีฟิลด์ {f}");
        }
        // ถ้าไม่มี /dev/kvm ต้องรายงาน false (ซื่อสัตย์ ไม่เงียบ)
        if !Path::new("/dev/kvm").exists() {
            assert!(!pr.kvm, "ไม่มี /dev/kvm ต้องรายงาน kvm=false");
        }
        // TEE device ไม่มี = false (ไม่ใช่ error) — CI ทั่วไปต้องได้แบบนี้
        if !Path::new("/dev/sev").exists() {
            assert!(!pr.sev_snp, "ไม่มี /dev/sev ต้องรายงาน sev_snp=false");
        }
        if !Path::new("/dev/tdx_guest").exists() {
            assert!(!pr.tdx, "ไม่มี /dev/tdx_guest ต้องรายงาน tdx=false");
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
        // Level ที่ config/prerequisites ไม่พร้อมต้อง fail-closed เสมอ
        // gateway จึงไม่ต้องแยกเคสเอง และ CI ที่ไม่มี KVM ยังเขียว
        // หมายเหตุ: เปิดฟีเจอร์ `microvm` แล้ว MicroVm จะตรวจ artifact pins
        // ด้วย config ว่าง (artifact หาย) จึงเป็น Invalid แทน Disabled —
        // deny เหมือนกันทั้งคู่ ไม่มีทางรัน
        let ws = test_ws("levels");
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let pol = test_policy(&[&real.to_string_lossy()]);
        let s = spec("/bin/true", &ws);
        {
            let level = SandboxLevel::Hardware;
            let r = run_checked_with_level(&s, &pol, level);
            #[cfg(not(feature = "hardware"))]
            assert!(
                matches!(r, Err((SandboxError::Disabled(_), _))),
                "level {level:?} ต้อง Disabled"
            );
            #[cfg(feature = "hardware")]
            assert!(
                r.is_err(),
                "Hardware ที่ไม่มี config ต้อง deny (Invalid/Disabled ก็ได้ ห้ามรัน)"
            );
        }
        #[cfg(not(feature = "microvm"))]
        {
            let r = run_checked_with_level(&s, &pol, SandboxLevel::MicroVm);
            assert!(matches!(r, Err((SandboxError::Disabled(_), _))));
        }
        #[cfg(feature = "microvm")]
        assert!(
            run_checked_with_level(&s, &pol, SandboxLevel::MicroVm).is_err(),
            "MicroVm ที่ไม่มี config ต้อง deny (Invalid/Disabled ก็ได้ ห้ามรัน)"
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

    #[test]
    fn process_cannot_read_host_or_policy_denied_files() {
        let ws = test_ws("landlock");
        let outside = test_ws("landlock-outside").join("private.txt");
        std::fs::write(&outside, "HOST-PRIVATE").unwrap();
        std::fs::write(ws.join("allowed.txt"), "ALLOWED").unwrap();
        std::fs::write(ws.join("private.txt"), "DENIED").unwrap();
        let exe = std::fs::canonicalize("/bin/cat").unwrap();
        let mut policy = test_policy(&[&exe.to_string_lossy()]);
        policy.filesystem.read = vec![ws.display().to_string()];
        policy.filesystem.deny = vec![ws.join("private.txt").display().to_string()];
        for path in [&outside, &ws.join("private.txt"), &ws.join("allowed.txt")] {
            let mut job = spec("/bin/cat", &ws);
            job.args = vec![path.display().to_string()];
            let out = run_checked(&job, &policy).unwrap();
            assert!(!out.stdout.contains("HOST-PRIVATE"));
            assert!(!out.stdout.contains("DENIED"));
            if path.ends_with("allowed.txt") {
                assert!(out.stdout.contains("ALLOWED"));
            } else {
                assert!(!out.success());
            }
        }
        let _ = std::fs::remove_dir_all(ws);
        let _ = std::fs::remove_dir_all(outside.parent().unwrap());
    }

    #[test]
    fn stderr_flood_does_not_deadlock_and_sleep_has_deadline() {
        let ws = test_ws("pipes");
        let cat = std::fs::canonicalize("/bin/cat").unwrap();
        let mut job = spec("/bin/cat", &ws);
        job.args = vec![format!("/missing-{}", "x".repeat(900)); MAX_ARGS];
        job.timeout_ms = 3000;
        let out = run_checked(&job, &test_policy(&[&cat.to_string_lossy()])).unwrap();
        assert!(!out.success());
        assert!(out.stderr.len() > 8192);
        let sleep = std::fs::canonicalize("/bin/sleep").unwrap();
        let mut job = spec("/bin/sleep", &ws);
        job.args = vec!["10".into()];
        job.timeout_ms = 50;
        let start = std::time::Instant::now();
        assert!(matches!(
            run_checked(&job, &test_policy(&[&sleep.to_string_lossy()])),
            Err(SandboxError::Spawn(_))
        ));
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(ws);
    }
    #[test]
    fn x32_syscalls_cannot_bypass_seccomp() {
        let filter = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        assert_eq!(
            bpf_verdict(&filter, 0xc000003e, 0x40000000 | libc::SYS_socket as u32),
            0
        );
        assert_eq!(
            bpf_verdict(&filter, 0xc000003e, 0x40000000 | libc::SYS_read as u32),
            0
        );
    }
    #[test]
    fn filesystem_ioctl_cannot_bypass_artifact_quota_or_source_readonly() {
        let filter = unsafe { build_hybrid_filter(SeccompMode::Hybrid) };
        for command in [0x40049409, 0x4020940d, 0xc0189436, 0x40086602, 0x401c5820] {
            assert_eq!(
                bpf_verdict_with_ioctl(&filter, 0xc000003e, libc::SYS_ioctl as u32, command),
                0
            );
        }
        assert_eq!(
            bpf_verdict_with_ioctl(&filter, 0xc000003e, libc::SYS_ioctl as u32, 0x5401),
            0x7fff0000
        );
    }
}
