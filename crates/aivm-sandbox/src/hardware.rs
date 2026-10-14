//! Hardware Isolation backend — Level 3 (สเปก §Level 3: TEE/Confidential Computing).
//!
//! รองรับ:
//! - AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
//! - Intel TDX (Trust Domain Extensions)
//! - Remote Attestation (ผ่าน AMD KDS / Intel TDX Quote Verification)
//! - Secure Boot + Measured Boot (PCR measurements)
//! - GPU/NPU Isolation (MIG, SR-IOV, vGPU — ต้องการ host driver)
//! - Disk Encryption + Secure Key Storage (vTPM / TPM 2.0)
//!
//! ลำดับประตู (fail-closed, ห้ามสลับ):
//! 1. validate สเปกงาน (exe/policy/arg/env/cwd — เหมือน Process/MicroVM)
//! 2. ตรวจ HardwareConfig shape + verify artifact hash (kernel/initrd/image)
//! 3. ตรวจ host readiness: Linux + KVM + TEE device (sev/tdx) + ไบนารี VMM (qemu/kvmtool)
//! 4. Remote Attestation: request quote/report → verify against endorsement keys
//! 5. Secure/Measured Boot: verify PCR measurements match policy
//! 6. Launch guest (QEMU/KVM with TEE) → จับผลทาง serial/virtio console
//! 7. Disk encryption: unlock with vTPM-sealed key (policy-bound)
//!
//! ข้อจำกัด: ต้องการ host ที่รองรับ SEV-SNP (AMD Zen 3+/Genoa) หรือ TDX (Intel Sapphire Rapids+)
//! และสิทธิ์ root สำหรับบาง operation (KVM, TEE device, vTPM)

use super::{verify_artifact, ExecOutcome, ExecSpec, RunVerdict, SandboxError};
use aivm_policy::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// เพดานขนาด artifact ตั้งต้น (kernel + initrd + image ไม่ควรเกินนี้)
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
/// เส้นตาย launch+run ตั้งต้น
const LAUNCH_TIMEOUT_DEFAULT_SECS: u64 = 120;
/// ขอบเขตเส้นตายที่อนุญาต
const LAUNCH_TIMEOUT_MIN_SECS: u64 = 10;
const LAUNCH_TIMEOUT_MAX_SECS: u64 = 1800;

/// ประเภท TEE ที่รองรับ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeeType {
    /// AMD SEV-SNP
    Sevsnp,
    /// Intel TDX
    Tdx,
    /// Generic TEE (fallback, attestation จะข้าม)
    Generic,
}

impl Default for TeeType {
    fn default() -> Self {
        TeeType::Generic
    }
}

/// โหมดการตรวจสอบ Remote Attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// ต้องการ attestation ผ่าน (fail-closed)
    Strict,
    /// พยายาม attestation แต่ไม่บล็อกถ้า host ไม่รองรับ (degraded)
    BestEffort,
    /// ข้าม attestation (เฉพาะ dev/test)
    None,
}

impl Default for AttestationMode {
    fn default() -> Self {
        AttestationMode::Strict
    }
}

/// การตั้งค่า GPU/NPU isolation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuConfig {
    /// เปิด MIG (Multi-Instance GPU) — ต้องการ NVIDIA A100/H100 + driver
    #[serde(default)]
    pub mig_enabled: bool,
    /// MIG profile (เช่น "1g.5gb", "2g.10gb", "3g.20gb", "7g.40gb")
    #[serde(default)]
    pub mig_profile: String,
    /// เปิด SR-IOV (Virtual Functions) — ต้องการ hardware support
    #[serde(default)]
    pub sriov_enabled: bool,
    /// จำนวน VFs ที่สร้าง
    #[serde(default)]
    pub sriov_num_vfs: u32,
    /// vGPU (mediated device) — ต้องการ NVIDIA vGPU license + driver
    #[serde(default)]
    pub vgpu_enabled: bool,
    /// vGPU type (เช่น "nvidia-222", "nvidia-223")
    #[serde(default)]
    pub vgpu_type: String,
}

/// การตั้งค่า Disk Encryption
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskEncryptionConfig {
    /// เปิด disk encryption (LUKS2 + vTPM-sealed key)
    #[serde(default)]
    pub enabled: bool,
    /// คีย์เข้ารหัส: "vtpm" (seal ไว้ใน vTPM), "tpm2" (TPM 2.0 physical), "passphrase" (dev only)
    #[serde(default = "default_key_source")]
    pub key_source: String,
    /// PCR policy สำหรับ unseal (comma-separated PCR indices, เช่น "0,1,2,3,4,7")
    #[serde(default = "default_pcr_policy")]
    pub pcr_policy: String,
    /// Cipher (default aes-xts-plain64)
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Key size (default 512 for XTS = 256-bit data key)
    #[serde(default = "default_key_size")]
    pub key_size: u32,
}

fn default_key_source() -> String {
    "vtpm".into()
}
fn default_pcr_policy() -> String {
    "0,1,2,3,4,7".into()
}
fn default_cipher() -> String {
    "aes-xts-plain64".into()
}
fn default_key_size() -> u32 {
    512
}

/// การตั้งค่า Secure/Measured Boot
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeasuredBootConfig {
    /// เปิด measured boot (PCR measurements)
    #[serde(default)]
    pub enabled: bool,
    /// Expected PCR values (sha256 hex, index -> value) — verify ตอน boot
    #[serde(default)]
    pub expected_pcrs: std::collections::HashMap<u32, String>,
    /// Firmware type: "ovmf" (UEFI), "sev-firmware" (AMD SEV firmware)
    #[serde(default = "default_firmware")]
    pub firmware: String,
    /// Secure boot: verify kernel/initrd signature
    #[serde(default)]
    pub secure_boot: bool,
    /// Path to DB/DBX/KEK certificates for secure boot verification
    #[serde(default)]
    pub cert_paths: Vec<PathBuf>,
}

fn default_firmware() -> String {
    "ovmf".into()
}

/// การตั้งค่า vTPM
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtpmConfig {
    /// เปิด vTPM (ผ่าน swtpm + QEMU)
    #[serde(default)]
    pub enabled: bool,
    /// Path to swtpm binary (default: "swtpm" ใน PATH)
    #[serde(default)]
    pub swtpm_path: PathBuf,
    /// Path to TPM state directory
    #[serde(default)]
    pub tpm_state_dir: PathBuf,
    /// TPM 2.0 spec compliance
    #[serde(default = "default_true")]
    pub tpm2: bool,
}

fn default_true() -> bool {
    true
}

/// Image artifact ที่ pin ด้วย sha256
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPin {
    /// path ไฟล์ image (kernel/initrd/rootfs)
    pub path: PathBuf,
    /// sha256 hex (64 ตัว) ที่อนุญาต
    pub sha256: String,
}

/// Hardware Isolation configuration (Level 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareConfig {
    /// ประเภท TEE: sevsnp | tdx | generic
    #[serde(default)]
    pub tee_type: TeeType,
    /// โหมด attestation: strict | best_effort | none
    #[serde(default)]
    pub attestation_mode: AttestationMode,
    /// Path ไฟล์ kernel (vmlinux/bzImage)
    #[serde(default)]
    pub kernel_path: PathBuf,
    /// sha256 hex ของ kernel ที่อนุญาต
    #[serde(default)]
    pub kernel_sha256: String,
    /// Path ไฟล์ initrd (optional, สำหรับ measured boot)
    #[serde(default)]
    pub initrd_path: PathBuf,
    /// sha256 hex ของ initrd ที่อนุญาต
    #[serde(default)]
    pub initrd_sha256: String,
    /// Path ไฟล์ rootfs/disk image
    #[serde(default)]
    pub rootfs_path: PathBuf,
    /// sha256 hex ของ rootfs ที่อนุญาต
    #[serde(default)]
    pub rootfs_sha256: String,
    /// จำนวน vCPU (1..=256)
    #[serde(default = "default_vcpu")]
    pub vcpu_count: u32,
    /// หน่วยความจำ MiB (1024..=1048576 = 1GiB..=1TiB)
    #[serde(default = "default_mem_mb")]
    pub mem_mb: u64,
    /// เพดานขนาดไฟล์ artifact แต่ละไฟล์
    #[serde(default = "default_max_bytes")]
    pub max_artifact_bytes: u64,
    /// เส้นตาย launch+run ต่อครั้ง หน่วยวินาที (10..=1800)
    #[serde(default = "default_launch_timeout")]
    pub launch_timeout_secs: u64,
    /// SHA256 ของไบนารี QEMU/KVM ที่อนุญาต (ว่าง = ไม่ pin, รายงานใน degraded)
    #[serde(default)]
    pub qemu_sha256: String,
    /// GPU/NPU isolation config
    #[serde(default)]
    pub gpu: GpuConfig,
    /// Disk encryption config
    #[serde(default)]
    pub disk_encryption: DiskEncryptionConfig,
    /// Measured/Secure boot config
    #[serde(default)]
    pub measured_boot: MeasuredBootConfig,
    /// vTPM config
    #[serde(default)]
    pub vtpm: VtpmConfig,
    /// ชุด image สำรอง (G5 DNA): verify ทุกชุด สุ่มเลือกต่อบูต
    #[serde(default)]
    pub alt_kernel: Option<ArtifactPin>,
    #[serde(default)]
    pub alt_initrd: Option<ArtifactPin>,
    #[serde(default)]
    pub alt_rootfs: Option<ArtifactPin>,
    /// สุ่มขนาด guest ต่อบูต (G5 DNA): ลดไม่เกิน 25% จากค่าที่ clamp แล้ว
    #[serde(default)]
    pub dna_jitter: bool,
    /// เส้นทางโครงสร้างแฟ้มของ host (สำหรับ sev/tdx device)
    #[serde(default = "default_tee_dev_path")]
    pub tee_device_path: PathBuf,
    /// KDS/Certificate cache directory (สำหรับ AMD SEV-SNP attestation)
    #[serde(default)]
    pub kds_cache_dir: PathBuf,
    /// QEMU binary path (default: "qemu-system-x86_64" ใน PATH)
    #[serde(default)]
    pub qemu_path: PathBuf,
}

fn default_vcpu() -> u32 {
    2
}
fn default_mem_mb() -> u64 {
    2048
}
fn default_max_bytes() -> u64 {
    DEFAULT_MAX_ARTIFACT_BYTES
}
fn default_launch_timeout() -> u64 {
    LAUNCH_TIMEOUT_DEFAULT_SECS
}
fn default_tee_dev_path() -> PathBuf {
    "/dev/sev".into() // default สำหรับ SEV-SNP; TDX ใช้ /dev/tdx_guest
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            tee_type: TeeType::default(),
            attestation_mode: AttestationMode::default(),
            kernel_path: PathBuf::new(),
            kernel_sha256: String::new(),
            initrd_path: PathBuf::new(),
            initrd_sha256: String::new(),
            rootfs_path: PathBuf::new(),
            rootfs_sha256: String::new(),
            vcpu_count: default_vcpu(),
            mem_mb: default_mem_mb(),
            max_artifact_bytes: default_max_bytes(),
            launch_timeout_secs: default_launch_timeout(),
            qemu_sha256: String::new(),
            gpu: GpuConfig::default(),
            disk_encryption: DiskEncryptionConfig::default(),
            measured_boot: MeasuredBootConfig::default(),
            vtpm: VtpmConfig::default(),
            alt_kernel: None,
            alt_initrd: None,
            alt_rootfs: None,
            dna_jitter: false,
            tee_device_path: default_tee_dev_path(),
            kds_cache_dir: PathBuf::new(),
            qemu_path: PathBuf::new(),
        }
    }
}

impl HardwareConfig {
    /// ตรวจความสมเหตุสมผลของตัวเลข (fail-closed ก่อนแตะไฟล์/launch)
    fn validate_shape(&self) -> Result<(), SandboxError> {
        let bad = |m: &str| SandboxError::Invalid(m.to_string());
        if !(1..=256).contains(&self.vcpu_count) {
            return Err(bad("hardware vcpu_count out of range 1..=256"));
        }
        if !(1024..=1048576).contains(&self.mem_mb) {
            return Err(bad("hardware mem_mb out of range 1024..=1048576"));
        }
        if self.max_artifact_bytes == 0 {
            return Err(bad("hardware max_artifact_bytes must be > 0"));
        }
        if !(LAUNCH_TIMEOUT_MIN_SECS..=LAUNCH_TIMEOUT_MAX_SECS).contains(&self.launch_timeout_secs)
        {
            return Err(bad("hardware launch_timeout_secs out of range 10..=1800"));
        }
        // Disk encryption PCR policy format validation
        if self.disk_encryption.enabled {
            for pcr in self.disk_encryption.pcr_policy.split(',') {
                if pcr.trim().parse::<u32>().is_err() {
                    return Err(bad(
                        "hardware disk_encryption.pcr_policy must be comma-separated PCR indices",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// รันงานใน Hardware-isolated VM (TEE + Attestation + Measured Boot)
///
/// ทุกขั้นไม่ผ่านคือไม่คืนผลสำเร็จเด็ดขัด (`Invalid` สำหรับ spec/artifact/shape ปลอม,
/// `Disabled` สำหรับ host ไม่พร้อม, `Spawn` สำหรับ launch ล้มหรือเกินเส้นตาย)
/// gateway แปลงเป็น DENY ทั้งหมด
///
/// คืน verdict คู่กับ error เสมอ (G3): ประตู spec/shape/supply-chain/host
/// (ยังไม่เกิด run) = `Clean` ส่วนขั้น launch/attestation แนบ verdict ตามหลักฐานที่เจอ
pub fn run_in_hardware(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &HardwareConfig,
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    use super::RunVerdict;

    // 1. ประตูสเปกเดียวกับ Process/MicroVM (exe/policy/arg/env/cwd)
    if spec.build.is_some() {
        return Err((
            SandboxError::Invalid("build output profiles are process-only".into()),
            RunVerdict::Clean,
        ));
    }
    let canon = super::validate(spec, policy).map_err(|e| (e, RunVerdict::Clean))?;

    // 2. ตัวเลข config ต้องสมเหตุก่อน (ถูกกว่าแตะไฟล์)
    cfg.validate_shape().map_err(|e| (e, RunVerdict::Clean))?;

    // 3. supply chain: kernel + initrd (ถ้ามี) + rootfs ต้องตรง hash ที่ pin ไว้
    verify_artifact(&cfg.kernel_path, &cfg.kernel_sha256, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Clean))?;

    if !cfg.initrd_path.as_os_str().is_empty() {
        verify_artifact(&cfg.initrd_path, &cfg.initrd_sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }

    verify_artifact(&cfg.rootfs_path, &cfg.rootfs_sha256, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Clean))?;

    // 3b. alt images (G5 DNA): verify ทุกชุดตั้งแต่ประตู แล้วสุ่มเลือกในขั้น launch
    if let Some(alt) = &cfg.alt_kernel {
        verify_artifact(&alt.path, &alt.sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }
    if let Some(alt) = &cfg.alt_initrd {
        verify_artifact(&alt.path, &alt.sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }
    if let Some(alt) = &cfg.alt_rootfs {
        verify_artifact(&alt.path, &alt.sha256, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Clean))?;
    }

    // 4. host readiness (Linux + KVM + TEE device + QEMU)
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (spec, policy, cfg);
        return Err((
            SandboxError::Disabled("hardware backend is Linux-only".into()),
            RunVerdict::Clean,
        ));
    }

    #[cfg(target_os = "linux")]
    {
        // ตรวจ KVM
        if !super::kvm_available() {
            return Err((
                SandboxError::Disabled(
                    "hardware needs /dev/kvm (KVM not available on this host)".into(),
                ),
                RunVerdict::Clean,
            ));
        }

        // ตรวจ TEE device ตามประเภท
        let tee_dev = match cfg.tee_type {
            TeeType::Sevsnp => "/dev/sev",
            TeeType::Tdx => "/dev/tdx_guest",
            TeeType::Generic => {
                // Generic ไม่บังคับ device
                ""
            }
        };

        if !tee_dev.is_empty() && !std::path::Path::new(tee_dev).exists() {
            return Err((
                SandboxError::Disabled(format!(
                    "hardware needs {tee_dev} (TEE device not available on this host)"
                )),
                RunVerdict::Clean,
            ));
        }

        // หา QEMU binary
        let qemu_bin = if cfg.qemu_path.as_os_str().is_empty() {
            which::which("qemu-system-x86_64").or_else(|_| {
                Err((
                    SandboxError::Disabled("hardware needs qemu-system-x86_64 in PATH".into()),
                    RunVerdict::Clean,
                ))
            })?
        } else {
            cfg.qemu_path.clone()
        };

        // supply chain ของ VMM เอง: pin ไว้ก็ต้องตรง
        if !cfg.qemu_sha256.is_empty() {
            verify_artifact(&qemu_bin, &cfg.qemu_sha256, cfg.max_artifact_bytes)
                .map_err(|e| (e, RunVerdict::Clean))?;
        }

        // 5. Launch จริงพร้อม TEE + Attestation + Measured Boot
        launch::launch_and_run(spec, &canon, cfg, &qemu_bin)
    }
}

#[cfg(target_os = "linux")]
mod launch;

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
        let dir = std::env::temp_dir().join(format!("aivm-hw-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap_or(dir)
    }

    fn hex_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture(tag: &str) -> (ExecSpec, Policy, HardwareConfig, PathBuf) {
        let ws = test_ws(tag);
        let kernel = ws.join("vmlinux");
        let rootfs = ws.join("rootfs.ext4");
        std::fs::write(&kernel, b"fake-kernel").unwrap();
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();
        let real = std::fs::canonicalize("/bin/true").unwrap();
        let policy = Policy::from_yaml(&format!(
            "name: t\nprocess:\n  allow: [\"{}\"]\n  deny: []\n",
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
        let cfg = HardwareConfig {
            kernel_path: kernel,
            kernel_sha256: hex_of(b"fake-kernel"),
            rootfs_path: rootfs,
            rootfs_sha256: hex_of(b"fake-rootfs"),
            tee_type: TeeType::Generic, // test ไม่ต้องการ TEE device จริง
            attestation_mode: AttestationMode::None,
            ..HardwareConfig::default()
        };
        (spec, policy, cfg, ws)
    }

    // shape ผิดต้องตายก่อนแตะ supply chain/host (Invalid ไม่ใช่ Disabled)
    #[test]
    fn bad_shape_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("shape");
        cfg.vcpu_count = 0;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // เส้นตายประหลาด ต้องตายตั้งแต่ shape
    #[test]
    fn bad_launch_timeout_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("timeout");
        cfg.launch_timeout_secs = 0;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        cfg.launch_timeout_secs = 1801;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // pin ของ QEMU ไม่ตรงต้องตายด้วย Invalid
    #[test]
    fn wrong_qemu_pin_fails_closed_as_invalid() {
        // ข้ามถ้าไม่มี QEMU (ยังไม่ถึงขั้นตรวจ pin = Disabled)
        if which::which("qemu-system-x86_64").is_err() {
            eprintln!("skip: เครื่องนี้ไม่มี qemu-system-x86_64");
            return;
        }
        let (spec, policy, mut cfg, ws) = fixture("qemupin");
        cfg.qemu_sha256 = "00".repeat(32);
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // deny ตั้งแต่ประตู (ยังไม่เกิด run) verdict ต้อง Clean
    #[test]
    fn prelaunch_denial_carries_clean_verdict() {
        let (spec, policy, mut cfg, ws) = fixture("vcode");
        cfg.kernel_sha256 = hex_of(b"something-else");
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // alt image ปลอมต้องตายตั้งแต่ประตู
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
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // image ปลอมต้องตายด้วย Invalid
    #[test]
    fn tampered_artifact_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("tamper");
        cfg.kernel_sha256 = hex_of(b"something-else");
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // artifact หายต้อง Invalid
    #[test]
    fn missing_artifact_fails_closed_as_invalid() {
        let (spec, policy, mut cfg, ws) = fixture("missing");
        cfg.rootfs_path = ws.join("no-such-file");
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // Disk encryption PCR policy validation
    #[test]
    fn bad_pcr_policy_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("pcr");
        cfg.disk_encryption.enabled = true;
        cfg.disk_encryption.pcr_policy = "0,1,invalid,3".into();
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), _))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // TEE type validation: device ต้องมี (ถ้าไม่ใช่ generic)
    #[test]
    fn missing_tee_device_fails_closed_as_disabled() {
        let (spec, policy, mut cfg, ws) = fixture("teedev");
        cfg.tee_type = TeeType::Sevsnp;
        cfg.attestation_mode = AttestationMode::Strict;
        // /dev/sev ไม่มีบนเครื่อง test ทั่วไป → Disabled
        let r = run_in_hardware(&spec, &policy, &cfg);
        assert!(r.is_err());
        if let Err((e, _)) = r {
            assert!(matches!(e, SandboxError::Disabled(_)));
        }
        let _ = std::fs::remove_dir_all(&ws);
    }
}
