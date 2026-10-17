//! MicroVM backend — Phase 7 Level 2 (สเปก §Level 2: KVM + Firecracker).
//!
//! วิธีรัน: **drive-stuffing** — บูต rootfs ที่ verify แล้ว (สำเนาชั่วคราว
//! ห้ามแตะไฟล์ pin ต้นฉบับ) ด้วย `init=` ที่ฉีดเข้าไป รัน exe ผ่าน data drive
//! ที่สร้างจาก exe + ldd closure บน host แล้วจับผลทาง serial console
//! (guest ไม่มีเน็ตเวิร์กเลยตั้งแต่เกิด — ไม่ได้ config ไว้)
//!
//! ลำดับประตู (ตั้งใจเรียงแบบนี้ ห้ามสลับ):
//! 1. `validate` สเปกงาน (exe/policy/arg/env/cwd — ประตูเดียวกับ Process)
//! 2. shape ของ config + `verify_artifact` kernel/rootfs (+ alt ทุกชุด
//!    ถ้ามี) — supply chain ต้องมาก่อนตรวจ host: image ปลอมต้องตายก่อน
//!    ไม่ว่าเครื่องจะพร้อมหรือไม่ (test Deterministic ทุกเครื่องแม้ไม่มี KVM)
//! 3. host readiness: Linux + `/dev/kvm` + ไบนารี `firecracker` (+ pin
//!    hash ของไบนารีถ้า operator ตั้ง `fc_sha256` ไว้)
//! 4. boot จริงพร้อมเส้นตาย (timeout) ฆ่าทิ้งแบบ fail-closed เมื่อเกินเวลา
//!    rootfs สำเนาถูก verify ซ้ำหลังก็อป (กันไฟล์ถูกสลับ/ก็อปเสีย)
//! 5. ขนาด guest = ค่าน้อยสุดระหว่าง quota ระดับ VM (cfg) กับ quota ระดับ
//!    task (`spec.limits`) — task ไม่มีทางได้เกินโควตาตัวเอง
//!
//! ข้อจำกัดที่รู้ตัว: `env_extra` ถูกเมิน (gateway ไม่เคยส่งอยู่แล้ว)
//! cwd ใน guest คือ `/`, stdout/stderr แยกด้วย marker บน serial, output
//! ต้องเป็น UTF-8 (เหมือน path เดิม), `pids_max` ไม่ถูก enforce ใน guest,
//! vcpu/mem ถูก clamp ด้วย quota ระดับ task แล้ว, ไบนารี VMM ถูก pin ก็ต่อ
//! เมื่อตั้ง `fc_sha256` — ทุกข้อรายงานผ่าน `applied`/`degraded`

use super::{verify_artifact, ExecOutcome, ExecSpec, SandboxError};
use aivm_policy::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// เพดานขนาด artifact ตั้งต้น (kernel + rootfs ไม่ควรเกินนี้)
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
/// เส้นตายบูต+รันตั้งต้น (boot ปกติใช้ไม่กี่วินาที)
const BOOT_TIMEOUT_DEFAULT_SECS: u64 = 60;
/// ขอบเขตเส้นตายที่อนุญาต (กัน operator ตั้ง 0 = ฆ่าทันที หรือค้างเป็นชั่วโมง)
const BOOT_TIMEOUT_MIN_SECS: u64 = 5;
const BOOT_TIMEOUT_MAX_SECS: u64 = 600;

/// ภาพที่ต้องใช้บูต MicroVM หนึ่งครั้ง (pin ทุกไฟล์ด้วย sha256)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroVmConfig {
    /// path ไฟล์ kernel (vmlinux bzImage)
    #[serde(default)]
    pub kernel_path: PathBuf,
    /// sha256 hex (64 ตัว) ของ kernel ที่อนุญาต
    #[serde(default)]
    pub kernel_sha256: String,
    /// path ไฟล์ rootfs (ext4 image)
    #[serde(default)]
    pub rootfs_path: PathBuf,
    /// sha256 hex (64 ตัว) ของ rootfs ที่อนุญาต
    #[serde(default)]
    pub rootfs_sha256: String,
    /// จำนวน vCPU (1..=32)
    #[serde(default = "default_vcpu")]
    pub vcpu_count: u8,
    /// หน่วยความจำ MiB (64..=32768)
    #[serde(default = "default_mem_mb")]
    pub mem_mb: u32,
    /// เพดานขนาดไฟล์ artifact แต่ละไฟล์
    #[serde(default = "default_max_bytes")]
    pub max_artifact_bytes: u64,
    /// sha256 hex ของไบนารี firecracker ที่อนุญาต (ว่าง = ไม่ pin,
    /// รายงานใน `degraded` ให้ operator รู้ว่ายังไม่ pin)
    #[serde(default)]
    pub fc_sha256: String,
    /// เส้นตายบูต+รันต่อครั้ง หน่วยวินาที (5..=600)
    #[serde(default = "default_boot_timeout")]
    pub boot_timeout_secs: u64,
    /// Optional Jailer configuration (requires root)
    /// เมื่อตั้งค่า จะใช้ jailer รวม firecracker แทนการเรียก firecracker ตรง ๆ
    /// เพิ่ม isolation: chroot, cgroups, namespaces, no-new-privs, drop caps
    #[serde(default)]
    pub jailer: Option<JailerConfig>,
    /// ชุด image สำรอง (G5 DNA): ถ้าตั้งไว้ จะ verify ทุกชุดตั้งแต่ประตู
    /// แล้วสุ่มเลือกหนึ่งชุดต่อบูต — exploit ที่ผูกกับ image เดียวใช้ไม่ได้ทุกครั้ง
    #[serde(default)]
    pub alt_kernel: Option<ArtifactPin>,
    /// rootfs สำรอง (คู่กับ alt_kernel ก็ได้ ไม่บังคับ)
    #[serde(default)]
    pub alt_rootfs: Option<ArtifactPin>,
    /// สุ่มขนาด guest ต่อบูต (G5 DNA, default ปิด): เปิดแล้ว vcpu/mem ถูก
    /// jitter ลงไม่เกิน 25% จากค่าที่ clamp แล้ว (ไม่มีทางเกิน quota และ
    /// ไม่ต่ำกว่า floor 1 vcpu / 64 MiB) — operator ยอมแลก headroom กับ diversity
    #[serde(default)]
    pub dna_jitter: bool,
}

/// image หนึ่งชุดที่ pin ด้วย sha256 (primary ใช้ฟิลด์เดิม, alt ใช้ struct นี้)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPin {
    /// path ไฟล์ image
    pub path: PathBuf,
    /// sha256 hex (64 ตัว) ที่อนุญาต
    pub sha256: String,
}

fn default_vcpu() -> u8 {
    1
}
fn default_mem_mb() -> u32 {
    256
}
fn default_max_bytes() -> u64 {
    DEFAULT_MAX_ARTIFACT_BYTES
}
fn default_boot_timeout() -> u64 {
    BOOT_TIMEOUT_DEFAULT_SECS
}

/// Jailer configuration for additional isolation (requires root)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JailerConfig {
    /// Path to jailer binary (default: "jailer" in PATH)
    #[serde(default)]
    pub jailer_path: PathBuf,
    /// Jailer ID (unique identifier for the microVM instance)
    #[serde(default)]
    pub jailer_id: String,
    /// Enable chroot isolation
    #[serde(default = "default_true")]
    pub chroot: bool,
    /// Enable cgroup v2 isolation
    #[serde(default = "default_true")]
    pub cgroup: bool,
    /// Enable namespace isolation (pid, net, mnt, ipc, uts)
    #[serde(default = "default_true")]
    pub namespace: bool,
    /// Drop all capabilities
    #[serde(default = "default_true")]
    pub drop_caps: bool,
    /// No new privileges
    #[serde(default = "default_true")]
    pub no_new_privs: bool,
}

fn default_true() -> bool {
    true
}

impl Default for MicroVmConfig {
    fn default() -> Self {
        Self {
            kernel_path: PathBuf::new(),
            kernel_sha256: String::new(),
            rootfs_path: PathBuf::new(),
            rootfs_sha256: String::new(),
            vcpu_count: default_vcpu(),
            mem_mb: default_mem_mb(),
            max_artifact_bytes: default_max_bytes(),
            fc_sha256: String::new(),
            boot_timeout_secs: default_boot_timeout(),
            jailer: None,
            alt_kernel: None,
            alt_rootfs: None,
            dna_jitter: false,
        }
    }
}

impl MicroVmConfig {
    /// ตรวจความสมเหตุสมผลของตัวเลข (fail-closed ก่อนแตะไฟล์/boot)
    fn validate_shape(&self) -> Result<(), SandboxError> {
        let bad = |m: &str| SandboxError::Invalid(m.to_string());
        if !(1..=32).contains(&self.vcpu_count) {
            return Err(bad("microvm vcpu_count out of range 1..=32"));
        }
        if !(64..=32768).contains(&self.mem_mb) {
            return Err(bad("microvm mem_mb out of range 64..=32768"));
        }
        if self.max_artifact_bytes == 0 {
            return Err(bad("microvm max_artifact_bytes must be > 0"));
        }
        if !(BOOT_TIMEOUT_MIN_SECS..=BOOT_TIMEOUT_MAX_SECS).contains(&self.boot_timeout_secs) {
            return Err(bad("microvm boot_timeout_secs out of range 5..=600"));
        }
        Ok(())
    }
}

/// รันงานใน MicroVM (boot จริง + จับผลทาง serial)
///
/// ทุกขั้นไม่ผ่านคือไม่คืนผลสำเร็จเด็ดขาด (`Invalid` สำหรับ spec/artifact/
/// shape ปลอม, `Disabled` สำหรับ host ไม่พร้อม, `Spawn` สำหรับ boot ล้ม
/// หรือเกินเส้นตาย) gateway แปลงเป็น DENY ทั้งหมด
///
/// คืน verdict คู่กับ error เสมอ (G3): ประตู spec/shape/supply-chain/host
/// (ยังไม่เกิด run) = `Clean` ส่วนขั้น boot แนบ verdict ตามหลักฐานที่เจอ
pub fn run_in_microvm(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &MicroVmConfig,
) -> Result<ExecOutcome, (SandboxError, super::RunVerdict)> {
    run_in_microvm_cancellable(
        spec,
        policy,
        cfg,
        &std::sync::atomic::AtomicBool::new(false),
    )
}

pub fn run_in_microvm_cancellable(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &MicroVmConfig,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<ExecOutcome, (SandboxError, super::RunVerdict)> {
    run_in_microvm_observed(spec, policy, cfg, cancelled, None)
}

pub fn run_in_microvm_observed(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &MicroVmConfig,
    cancelled: &std::sync::atomic::AtomicBool,
    observer: Option<std::sync::mpsc::Sender<Vec<u8>>>,
) -> Result<ExecOutcome, (SandboxError, super::RunVerdict)> {
    use super::RunVerdict;
    // 1. ประตูสเปกเดียวกับ Process (exe/policy/arg/env/cwd)
    if spec.build.is_some() {
        return Err((
            SandboxError::Invalid("build output profiles are process-only".into()),
            RunVerdict::Clean,
        ));
    }
    let canon = super::validate(spec, policy).map_err(|e| (e, RunVerdict::Clean))?;
    // 2. ตัวเลข config ต้องสมเหตุก่อน (ถูกกว่าแตะไฟล์)
    cfg.validate_shape().map_err(|e| (e, RunVerdict::Clean))?;
    // 3. supply chain: kernel + rootfs ต้องตรง hash ที่ pin ไว้
    verify_artifact(&cfg.kernel_path, &cfg.kernel_sha256, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Clean))?;
    verify_artifact(&cfg.rootfs_path, &cfg.rootfs_sha256, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Clean))?;
    // 3b. alt images (G5 DNA, ถ้ามี): verify ทุกชุดตั้งแต่ประตู (supply chain
    // มาก่อน host readiness เหมือนชุดหลัก) แล้วค่อยสุ่มเลือกในขั้น boot
    if let Some(alt) = &cfg.alt_kernel {
        verify_artifact(&alt.path, &alt.sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }
    if let Some(alt) = &cfg.alt_rootfs {
        verify_artifact(&alt.path, &alt.sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }
    // 4. host readiness (Linux + KVM + binary) — ไม่พร้อมคือ Disabled
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (spec, policy, cfg);
        return Err((
            SandboxError::Disabled("microvm backend is Linux-only".into()),
            RunVerdict::Clean,
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if !super::kvm_available() {
            return Err((
                SandboxError::Disabled(
                    "microvm needs /dev/kvm (KVM not available on this host)".into(),
                ),
                RunVerdict::Clean,
            ));
        }
        let fc = super::find_firecracker().ok_or_else(|| {
            (
                SandboxError::Disabled("microvm needs the firecracker binary in PATH".into()),
                RunVerdict::Clean,
            )
        })?;
        // supply chain ของ VMM เอง: pin ไว้ก็ต้องตรง (ไม่ pin = ยอมรับตาม
        // PATH ของ operator แล้วรายงานใน `degraded` ให้รู้ตัว)
        if !cfg.fc_sha256.is_empty() {
            verify_artifact(&fc, &cfg.fc_sha256, cfg.max_artifact_bytes)
                .map_err(|e| (e, RunVerdict::Clean))?;
        }
        boot::boot_and_run(spec, &canon, cfg, &fc, policy, cancelled, observer)
    }
}

#[cfg(target_os = "linux")]
mod boot;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceLimits, RunVerdict, SandboxError};
    use sha2::{Digest, Sha256};

    fn test_ws(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aivm-uvm-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap_or(dir)
    }

    fn hex_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture(tag: &str) -> (ExecSpec, Policy, MicroVmConfig, PathBuf) {
        let ws = test_ws(tag);
        let kernel = ws.join("vmlinux");
        let rootfs = ws.join("rootfs.ext4");
        std::fs::write(&kernel, b"fake-kernel").unwrap();
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let policy = Policy::from_yaml(&format!(
            "name: t\nfilesystem: {{deny: ['**/.env*']}}\nprocess:\n  allow: [\"{}\"]\n  deny: [/bin/sh]\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n",
            real.display()
        ))
        .unwrap();
        let spec = ExecSpec {
            exe: PathBuf::from("/bin/true"),
            args: vec![],
            cwd: ws.clone(),
            workspace: ws.clone(),
            env_extra: vec![],
            timeout_ms: 30000,
            build: None,
            limits: ResourceLimits::default(),
        };
        let cfg = MicroVmConfig {
            kernel_path: kernel,
            kernel_sha256: hex_of(b"fake-kernel"),
            rootfs_path: rootfs,
            rootfs_sha256: hex_of(b"fake-rootfs"),
            ..MicroVmConfig::default()
        };
        (spec, policy, cfg, ws)
    }

    // shape ผิดต้องตายก่อนแตะ supply chain/host (Invalid ไม่ใช่ Disabled)
    #[test]
    fn bad_shape_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("shape");
        cfg.vcpu_count = 0;
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // เส้นตายประหลาด (0 = ฆ่าทันที, เกินเพดาน = ค้างนาน) ต้องตายตั้งแต่ shape
    #[test]
    fn bad_boot_timeout_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("timeout");
        cfg.boot_timeout_secs = 0;
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        cfg.boot_timeout_secs = 601;
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // pin ของไบนารี VMM ไม่ตรงต้องตายด้วย Invalid (supply chain ของ VMM เอง)
    // ข้ามเมื่อเครื่องไม่มี firecracker (ยังไม่ถึงขั้นตรวจ pin = Disabled)
    #[test]
    fn wrong_fc_pin_fails_closed_as_invalid() {
        if !super::super::kvm_available() || super::super::find_firecracker().is_none() {
            eprintln!("skip: เครื่องนี้ไม่มี firecracker");
            return;
        }
        let (spec, policy, mut cfg, ws) = fixture("fcpin");
        cfg.fc_sha256 = "00".repeat(32);
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // deny ตั้งแต่ประตู (ยังไม่เกิด run) verdict ต้อง Clean — verdict ตอบแค่
    // "มีหลักฐานละเมิด boundary หรือไม่" ไม่ใช่ "รันสำเร็จหรือไม่"
    #[test]
    fn preboot_denial_carries_clean_verdict() {
        let (spec, policy, mut cfg, ws) = fixture("vcode");
        cfg.kernel_sha256 = hex_of(b"something-else");
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // alt image ปลอมต้องตายตั้งแต่ประตู (verify ทุกชุดก่อนสุ่ม — primary
    // ถูกไม่ช่วยถ้า alt ปลอม) deterministic ทุกเครื่อง
    #[test]
    fn tampered_alt_artifact_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("alt");
        let bad_kernel = ws.join("vmlinux-alt");
        std::fs::write(&bad_kernel, b"fake-alt").unwrap();
        cfg.alt_kernel = Some(ArtifactPin {
            path: bad_kernel,
            sha256: hex_of(b"something-else"),
        });
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // image ปลอมต้องตายด้วย Invalid (supply chain มาก่อน host readiness)
    #[test]
    fn tampered_artifact_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("tamper");
        cfg.kernel_sha256 = hex_of(b"something-else");
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // artifact หายต้อง Invalid (fail-closed ไม่ใช่ unwrap/panic)
    #[test]
    fn missing_artifact_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("missing");
        cfg.rootfs_path = ws.join("no-such-file");
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // kernel ปลอม (hash ตรงแต่บูตไม่ได้) ต้องล้มแบบ fail-closed
    // (Deterministic ทุกเครื่อง: host พร้อม = boot ล้ม, ไม่พร้อม = Disabled)
    #[test]
    fn garbage_kernel_fails_closed() {
        let (spec, policy, cfg, ws) = fixture("garbage");
        let r = run_in_microvm(&spec, &policy, &cfg);
        assert!(r.is_err(), "kernel ปลอมต้องไม่รันสำเร็จ");
        let _ = std::fs::remove_dir_all(&ws);
    }

    // บูตจริงแบบ end-to-end (ต้องมี KVM + binary + ไฟล์ pins)
    // ข้าม (แต่ยังเขียว) เมื่อรันใน CI ที่ไม่มีของพวกนี้: ตั้ง
    // `AIVM_MICROVM_PINS=/path/pins.json` เพื่อเปิดเทสต์นี้
    #[test]
    fn real_boot_runs_true_and_false() {
        let pins_path = std::env::var("AIVM_MICROVM_PINS").unwrap_or_default();
        if pins_path.is_empty() {
            eprintln!("skip: ตั้ง AIVM_MICROVM_PINS เพื่อทดสอบบูตจริง");
            return;
        }
        if !super::super::kvm_available() || super::super::find_firecracker().is_none() {
            eprintln!("skip: เครื่องนี้ไม่มี KVM/firecracker");
            return;
        }
        let text = std::fs::read_to_string(&pins_path).expect("อ่าน pins.json ได้");
        let v: serde_json::Value = serde_json::from_str(&text).expect("pins.json เป็น JSON");
        let kernel = v["kernel"]["path"].as_str().expect("มี kernel.path");
        let ksha = v["kernel"]["sha256"].as_str().expect("มี kernel.sha256");
        let rootfs = v["rootfs"]["path"].as_str().expect("มี rootfs.path");
        let rsha = v["rootfs"]["sha256"].as_str().expect("มี rootfs.sha256");
        for (exe, want) in [("/bin/true", 0), ("/bin/false", 1)] {
            let ws = test_ws("realboot");
            let real = std::fs::canonicalize(exe).unwrap();
            let policy = Policy::from_yaml(&format!(
                "name: t\nfilesystem: {{deny: ['**/.env*']}}\nprocess:\n  allow: [\"{}\"]\n  deny: [/bin/sh]\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n",
                real.display()
            ))
            .unwrap();
            let spec = ExecSpec {
                exe: PathBuf::from(exe),
                args: vec![],
                cwd: ws.clone(),
                workspace: ws.clone(),
                env_extra: vec![],
                timeout_ms: 30000,
                build: None,
                limits: crate::ResourceLimits::default(),
            };
            let cfg = MicroVmConfig {
                kernel_path: PathBuf::from(kernel),
                kernel_sha256: ksha.into(),
                rootfs_path: PathBuf::from(rootfs),
                rootfs_sha256: rsha.into(),
                ..MicroVmConfig::default()
            };
            let out = run_in_microvm(&spec, &policy, &cfg)
                .unwrap_or_else(|e| panic!("บูตจริงต้องผ่าน {exe}: {e:?}"));
            assert_eq!(out.code, Some(want), "{exe} ต้อง exit {want}");
            assert!(out.applied.contains(&"microvm-boot".to_string()));
            let _ = std::fs::remove_dir_all(&ws);
        }
    }
}
