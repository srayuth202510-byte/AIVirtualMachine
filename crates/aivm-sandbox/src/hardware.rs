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
use std::path::Path;
use std::path::PathBuf;

/// เพดานขนาด artifact ตั้งต้น (kernel + initrd + image ไม่ควรเกินนี้)
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
/// เพดานขนาดไฟล์ certificate ที่ใช้อ่านตอน secure boot (กันไฟล์ยักษ์)
const MAX_CERT_BYTES: u64 = 1024 * 1024; // 1 MiB
/// เส้นตาย launch+run ตั้งต้น
const LAUNCH_TIMEOUT_DEFAULT_SECS: u64 = 120;
/// ขอบเขตเส้นตายที่อนุญาต
const LAUNCH_TIMEOUT_MIN_SECS: u64 = 10;
const LAUNCH_TIMEOUT_MAX_SECS: u64 = 1800;

/// ตรวจสอบและค้นหา swtpm binary
///
/// ถ้า operator ชี้ `vtpm.swtpm_path` → ตรวจ file มีจริง หรือ fail-closed
/// ถาง → `which::which("swtpm")` เพื่อหาใน PATH (สำหรับ host readiness คืน Disabled ถ้าไม่เจอ)
/// สำหรับ launch สปาเนอร์อีกชั้นจะ package-wrap ไปเป็น Spawn error ตามเดิม
pub(crate) fn resolve_swtpm(cfg: &HardwareConfig) -> Option<PathBuf> {
    if !cfg.vtpm.swtpm_path.as_os_str().is_empty() {
        (cfg.vtpm.swtpm_path.is_file()).then_some(cfg.vtpm.swtpm_path.clone())
    } else {
        which::which("swtpm").ok()
    }
}

/// ตรวจสอบว่า measured boot firmware พร้อมใช้งานบน host
///
/// เมื่อ measured_boot.enabled=True แต่ไฟล์ OVMF ไม่มี → fail-closed ด้วยข้อความชัดเจน
pub(crate) fn check_measured_boot_host(
    cfg: &HardwareConfig,
    firmware: &Path,
) -> Result<(), SandboxError> {
    if cfg.measured_boot.enabled && !firmware.is_file() {
        return Err(SandboxError::Disabled(format!(
            "measured boot enabled but OVMF firmware not found at {} (fail-closed: guest ไม่ได้บูต)",
            firmware.display()
        )));
    }
    Ok(())
}

/// เส้นทางไบนารี OVMF ที่ใช้เมื่อ measured_boot.enabled (เพียงตัวเลือกที่รองรับ)
pub(crate) const OVMF_CODE_PATH: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";

/// ประเภท TEE ที่รองรับ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeeType {
    /// AMD SEV-SNP
    Sevsnp,
    /// Intel TDX
    Tdx,
    /// Generic TEE (fallback, attestation จะข้าม)
    #[default]
    Generic,
}

/// โหมดการตรวจสอบ Remote Attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// ต้องการ attestation ผ่าน (fail-closed)
    #[default]
    Strict,
    /// พยายาม attestation แต่ไม่บล็อกถ้า host ไม่รองรับ (degraded)
    BestEffort,
    /// ข้าม attestation (เฉพาะ dev/test)
    None,
}

/// การตั้งค่า GPU/NPU isolation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GpuConfig {
    /// เปิด MIG (Multi-Instance GPU) — ต้องการ NVIDIA A100/H100 + driver
    #[serde(default)]
    pub mig_enabled: bool,
    /// MIG profile (เช่น "1g.5gb", "2g.10gb", "3g.20gb", "7g.40gb")
    #[serde(default)]
    pub mig_profile: String,
    /// เปิด SR-IOV (Virtual Functions) — บูตด้วย VF ที่ operator เตรียมผ่าน
    /// vfio-pci (AIVM ไม่สร้าง VFs เอง)
    #[serde(default)]
    pub sriov_enabled: bool,
    /// PCI BDF ของ VF ที่จะ pass ผ่าน (เช่น "0000:41:10.0")
    #[serde(default)]
    pub sriov_pci: String,
    /// จำนวน VFs ที่ operator สร้างแล้ว (ต้องเป็น 0 เสมอ — AIVM ไม่สร้าง VFs
    /// เอง, operator เตรียมผ่าน vfio-pci แล้วส่ง BDF ตัวเดียวที่ `sriov_pci`;
    /// ค่าอื่น = `Invalid` ตั้งแต่ shape)
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Path to `sbverify` (sbsigntool) — default = PATH
    #[serde(default)]
    pub sbverify_path: PathBuf,
}

fn default_firmware() -> String {
    "ovmf".into()
}

/// การตั้งค่า vTPM
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ArtifactPin {
    /// path ไฟล์ image (kernel/initrd/rootfs)
    pub path: PathBuf,
    /// sha256 hex (64 ตัว) ที่อนุญาต
    pub sha256: String,
}

/// Hardware Isolation configuration (Level 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// ตรวจแปลง PCI BDF ตามรูป sysfs: `DDDD:BB:SS.F` (hex ล้วน ยาว 12 ตัวอักษร
/// separator ตายตัว func 0..=7) — คืนค่า normalized แบบ lowercase
///
/// BDF ถูกใช้ประกอบทั้ง sysfs path และ QEMU argv จึงต้องกันอักขระพิเศษ
/// (ช่องว่าง/`/`/`;`/`$()`) ตั้งแต่ประเมิน config ไม่ปล่อยให้ไปถึงประตู spawn
pub(super) fn parse_pci_address(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() != 12 {
        return None;
    }
    if chars[4] != ':' || chars[7] != ':' || chars[10] != '.' {
        return None;
    }
    for (i, c) in chars.iter().enumerate() {
        match i {
            4 | 7 | 10 => {}
            11 => {
                if !c.is_ascii_digit() || (*c as u8 - b'0') > 7 {
                    return None;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return None;
                }
            }
        }
    }
    Some(s.to_ascii_lowercase())
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
            // คีย์ผูก vTPM แต่ปิด vTPM = config เป็นไปไม่ได้ (fail-closed
            // ตั้งแต่ shape ไม่ใช่ไปตายตอน guest บูตไม่ขึ้น)
            if self.disk_encryption.key_source == "vtpm" && !self.vtpm.enabled {
                return Err(bad(
                    "hardware disk_encryption.key_source=vtpm needs vtpm.enabled",
                ));
            }
        }
        // Measured boot อ่าน PCR ผ่าน vTPM — ไม่มี vTPM คือ config เป็นไปไม่ได้
        if self.measured_boot.enabled && !self.vtpm.enabled {
            return Err(bad("hardware measured_boot.enabled needs vtpm.enabled"));
        }
        // expected_pcrs ยังเทียบกับ PCR จริงไม่ได้ (ไม่มี quote verification)
        // — ปฏิเสธแทนการรันแล้วรายงาน degraded เพื่อไม่ให้ operator เข้าใจผิด
        // ว่าค่าที่คาดหวังถูกตรวจแล้ว
        if !self.measured_boot.expected_pcrs.is_empty() {
            return Err(bad(
                "hardware measured_boot.expected_pcrs is not implemented (no PCR quote verification); refusing to accept unverified expectations",
            ));
        }
        // ฟิลด์ของ measured boot มีความหมายเฉพาะเมื่อเปิด measured boot —
        // ตั้งไว้แบบปิดคือ config ที่สื่อเจตนาไม่ครบ ให้ตายตั้งแต่ shape
        if (self.measured_boot.secure_boot || !self.measured_boot.cert_paths.is_empty())
            && !self.measured_boot.enabled
        {
            return Err(bad(
                "hardware measured_boot.secure_boot/cert_paths needs measured_boot.enabled",
            ));
        }
        if !self.measured_boot.cert_paths.is_empty() && !self.measured_boot.secure_boot {
            return Err(bad(
                "hardware measured_boot.cert_paths needs secure_boot=true (unused otherwise)",
            ));
        }
        if self.measured_boot.enabled {
            // ใช้ OVMF ตัวเดียวเท่านั้น — ค่าอื่นคืออ้าง firmware ที่เราไม่ได้ใช้
            if self.measured_boot.firmware != "ovmf" {
                return Err(bad(
                    "hardware measured_boot.firmware must be \"ovmf\" (only supported measured-boot firmware)",
                ));
            }
        }
        if self.measured_boot.secure_boot {
            // secure boot ตรวจ signature ของ kernel/initrd จาก cert ที่ operator ให้
            // — ไม่มี cert = ตรวจไม่ได้ ห้ามผ่านแบบเงียบ
            if self.measured_boot.cert_paths.is_empty() {
                return Err(bad(
                    "hardware measured_boot.secure_boot needs cert_paths for signature verification",
                ));
            }
            for cert in &self.measured_boot.cert_paths {
                if cert.as_os_str().is_empty() {
                    return Err(bad(
                        "hardware measured_boot.cert_paths contains an empty path",
                    ));
                }
            }
        }
        // GPU passthrough: ทางเดียวที่เปิดได้คือ SR-IOV VF ที่ operator เตรียม
        // ผ่าน vfio-pci — MIG/vGPU ยังไม่ implement (ตายตั้งแต่ shape กันรัน
        // แบบขาด GPU/ชุดประสิทธิภาพที่ operator คาดโดยไม่มีใครรู้)
        if self.gpu.mig_enabled || self.gpu.vgpu_enabled {
            return Err(bad(
                "hardware gpu MIG/vGPU not implemented yet (mig/vgpu must stay off)",
            ));
        }
        if self.gpu.sriov_enabled && self.gpu.sriov_pci.is_empty() {
            return Err(bad(
                "hardware gpu sriov_enabled needs sriov_pci (operator-prepared VF BDF e.g. 0000:41:10.0)",
            ));
        }
        if !self.gpu.sriov_pci.is_empty() {
            if !self.gpu.sriov_enabled {
                return Err(bad("hardware gpu sriov_pci needs sriov_enabled=true"));
            }
            // BDF ผิดรูปห้ามไปถึง sysfs path/QEMU argv — hex ล้วนตายตัว
            if parse_pci_address(&self.gpu.sriov_pci).is_none() {
                return Err(bad(
                    "hardware gpu sriov_pci must be a PCI BDF like 0000:41:10.0 (hex DDDD:BB:SS.F, func 0..=7)",
                ));
            }
        }
        if self.gpu.sriov_enabled && self.gpu.sriov_num_vfs != 0 {
            return Err(bad(
                "hardware gpu sriov_num_vfs must stay 0 (AIVM does not create VFs; the operator prepares the VF and passes its BDF via sriov_pci)",
            ));
        }
        Ok(())
    }
}

/// ตรวจความพร้อมของ GPU pass-through (SR-IOV VF) บน host (Linux)
///
/// ทุกข้อแม้ต้องผ่านก่อน spawn — ข้อใดขาดคือ fail-closed แบบบอกเหตุผล:
/// device ต้องมีจริงตาม BDF, ต้องอยู่ใน IOMMU group (กัน DMA หลุดจาก guest),
/// และต้อง bound ด้วย vfio-pci (driver อื่นถือ device อยู่ จึงผ่านให้ QEMU ไม่ได้)
fn probe_gpu_passthrough(cfg: &HardwareConfig) -> Result<(), SandboxError> {
    // shape ตรวจ BDF มาแล้ว — แปลงซ้ำเพื่อได้ BDF ที่ normalized (จาก sysfs)
    let addr = parse_pci_address(&cfg.gpu.sriov_pci).ok_or_else(|| {
        SandboxError::Invalid(format!(
            "hardware gpu sriov_pci is not a valid PCI BDF: {}",
            cfg.gpu.sriov_pci
        ))
    })?;
    let dev = std::path::Path::new("/sys/bus/pci/devices").join(&addr);
    if !dev.exists() {
        return Err(SandboxError::Disabled(format!(
            "gpu passthrough needs PCI device {addr} on host (operator prepares the VF first)"
        )));
    }
    if !dev.join("iommu_group").exists() {
        return Err(SandboxError::Disabled(format!(
            "gpu passthrough needs {addr} in an IOMMU group (enable IOMMU on host first)"
        )));
    }
    let driver_name = std::fs::read_link(dev.join("driver"))
        .ok()
        .and_then(|l| l.file_name().map(|f| f.to_string_lossy().into_owned()));
    match driver_name {
        Some(name) if name == "vfio-pci" => Ok(()),
        Some(name) => Err(SandboxError::Disabled(format!(
            "gpu passthrough needs {addr} bound to vfio-pci (currently {name}; unbind and rebind the VF)"
        ))),
        None => Err(SandboxError::Disabled(format!(
            "gpu passthrough needs {addr} bound to vfio-pci (no driver is currently bound)"
        ))),
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

    // 3c. secure boot: certificate ต้องมีจริงและเป็น regular file ขนาดพอเหมาะ
    // ก่อนไป spawn เครื่องมือใด ๆ (fail-closed ตั้งแต่ประตู supply chain)
    if cfg.measured_boot.secure_boot {
        for cert in &cfg.measured_boot.cert_paths {
            let meta = std::fs::metadata(cert).map_err(|e| {
                (
                    SandboxError::Invalid(format!(
                        "hardware secure boot cert unreadable ({}): {e}",
                        cert.display()
                    )),
                    RunVerdict::Clean,
                )
            })?;
            if !meta.is_file() {
                return Err((
                    SandboxError::Invalid(format!(
                        "hardware secure boot cert is not a regular file: {}",
                        cert.display()
                    )),
                    RunVerdict::Clean,
                ));
            }
            if meta.len() == 0 || meta.len() > MAX_CERT_BYTES {
                return Err((
                    SandboxError::Invalid(format!(
                        "hardware secure boot cert size out of range 1..={MAX_CERT_BYTES} bytes: {}",
                        cert.display()
                    )),
                    RunVerdict::Clean,
                ));
            }
        }
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
        // หา QEMU binary (ทางเดียวผ่าน `find_qemu` — ไม่แยก logic ซ้ำซ้อน)
        let qemu_bin = if cfg.qemu_path.as_os_str().is_empty() {
            super::find_qemu().ok_or_else(|| {
                (
                    SandboxError::Disabled("hardware needs qemu-system-x86_64 in PATH".into()),
                    RunVerdict::Clean,
                )
            })?
        } else {
            cfg.qemu_path.clone()
        };

        // supply chain ของ VMM เอง: pin ไว้ก็ต้องตรง
        if !cfg.qemu_sha256.is_empty() {
            verify_artifact(&qemu_bin, &cfg.qemu_sha256, cfg.max_artifact_bytes)
                .map_err(|e| (e, RunVerdict::Clean))?;
        }

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

        // GPU passthrough (SR-IOV VF): เหมือน TEE device — host ต้องเตรียม
        // device/ผูก vfio-pci ให้ครบก่อน ข้อใดขาดคือ Disabled ก่อน spawn
        if cfg.gpu.sriov_enabled {
            probe_gpu_passthrough(cfg).map_err(|e| (e, RunVerdict::Clean))?;
        }

        // Strict attestation บน generic (โหมดจำลอง) เป็น config ที่เป็นไปไม่ได้
        // (ไม่มี TEE จริงให้ attest) — ตายตั้งแต่ประตูก่อน spawn ใด ๆ
        if cfg.tee_type == TeeType::Generic && cfg.attestation_mode == AttestationMode::Strict {
            return Err((
                SandboxError::Disabled(
                    "strict attestation needs a real TEE (SEV-SNP/TDX); generic is simulation-only"
                        .into(),
                ),
                RunVerdict::Clean,
            ));
        }

        // 4b. measured boot host readiness: OVMF firmware
        check_measured_boot_host(cfg, &OVMF_CODE_PATH).map_err(|e| (e, RunVerdict::Clean))?;

        // 4c. vTPM emulator host readiness: swtpm
        if cfg.vtpm.enabled && resolve_swtpm(cfg).is_none() {
            return Err((
                SandboxError::Disabled(
                    "hardware vTPM needs swtpm in PATH or vtpm.swtpm_path".into(),
                ),
                RunVerdict::Clean,
            ));
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
        let (spec, policy, mut cfg, ws) = fixture("qemupin");
        cfg.qemu_path = ws.join("fake-qemu");
        std::fs::write(&cfg.qemu_path, b"untrusted-qemu").unwrap();
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
        if std::path::Path::new("/dev/sev").exists() {
            eprintln!("skip: เครื่องนี้มี /dev/sev (SEV host จริง)");
            return;
        }
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

    // Strict attestation บน generic (โหมดจำลอง) เป็นไปไม่ได้ — ต้อง Disabled
    // ตั้งแต่ประตูก่อน spawn (verdict Clean) ไม่ใช่ผ่านแบบเงียบ ๆ
    #[test]
    fn generic_strict_attestation_is_impossible() {
        let (spec, policy, mut cfg, ws) = fixture("genstrict");
        cfg.tee_type = TeeType::Generic;
        cfg.attestation_mode = AttestationMode::Strict;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Disabled(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // measured boot ไม่มี vTPM = config เป็นไปไม่ได้ → Invalid ตั้งแต่ shape
    #[test]
    fn measured_boot_without_vtpm_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("meas");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = false;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // expected_pcrs ที่ยัง verify ไม่ได้ต้องถูกปฏิเสธ ไม่ใช่รันแล้ว degraded
    #[test]
    fn expected_pcrs_are_rejected_until_pcr_verification_exists() {
        let (spec, policy, mut cfg, ws) = fixture("expectedpcr");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = true;
        cfg.measured_boot.expected_pcrs.insert(0, "00".repeat(32));
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // secure boot ต้องมี cert ให้ตรวจ — ไม่มี = config ตรวจไม่ได้
    #[test]
    fn secure_boot_without_certs_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("sbcert");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = true;
        cfg.measured_boot.secure_boot = true;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ฟิลด์ secure boot ต้องมาคู่กับ measured_boot.enabled เสมอ
    #[test]
    fn secure_boot_without_measured_boot_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("sbdisabled");
        cfg.measured_boot.secure_boot = true;
        cfg.measured_boot.cert_paths = vec![ws.join("cert.pem")];
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // cert ที่ไม่มี secure_boot คือ config ที่สื่อเจตนาไม่ครบ
    #[test]
    fn cert_paths_without_secure_boot_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("certonly");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = true;
        cfg.measured_boot.cert_paths = vec![ws.join("cert.pem")];
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // firmware ที่ไม่ได้ใช้จริงต้องไม่ผ่านเงียบ ๆ
    #[test]
    fn unsupported_measured_boot_firmware_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("firmware");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = true;
        cfg.measured_boot.firmware = "sev-firmware".into();
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // cert หาย/ไม่ใช่ไฟล์จริงต้องตายที่ประตู supply chain ก่อนแตะ host
    #[test]
    fn missing_secure_boot_cert_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("certmissing");
        cfg.measured_boot.enabled = true;
        cfg.vtpm.enabled = true;
        cfg.measured_boot.secure_boot = true;
        cfg.measured_boot.cert_paths = vec![ws.join("no-such-cert.pem")];
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // disk encryption ผูกคีย์ vTPM แต่ปิด vTPM = config เป็นไปไม่ได้
    #[test]
    fn vtpm_key_without_vtpm_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("vtpmkey");
        cfg.disk_encryption.enabled = true;
        cfg.disk_encryption.key_source = "vtpm".into();
        cfg.vtpm.enabled = false;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // MIG/vGPU passthrough ยังไม่ implement — เปิดไว้ต้องตายตั้งแต่ shape
    // (กัน workload รันแบบขาด GPU ที่ operator คาดไว้โดยไม่มีใครรู้)
    #[test]
    fn gpu_mig_vgpu_fail_closed_as_unimplemented() {
        for (tag, mk) in [
            (
                "mig",
                Box::new(|c: &mut HardwareConfig| c.gpu.mig_enabled = true)
                    as Box<dyn Fn(&mut HardwareConfig)>,
            ),
            (
                "vgpu",
                Box::new(|c: &mut HardwareConfig| c.gpu.vgpu_enabled = true),
            ),
        ] {
            let (spec, policy, mut cfg, ws) = fixture(tag);
            mk(&mut cfg);
            assert!(
                matches!(
                    run_in_hardware(&spec, &policy, &cfg),
                    Err((SandboxError::Invalid(_), RunVerdict::Clean))
                ),
                "{tag} ต้องตายตั้งแต่ shape"
            );
            let _ = std::fs::remove_dir_all(&ws);
        }
    }

    // SR-IOV เปิดแต่ไม่ระบุ VF ที่จะผ่าน = รันไม่ได้แบบมีความหวังลอย ๆ
    #[test]
    fn sriov_without_pci_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("sriov-nopci");
        cfg.gpu.sriov_enabled = true;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // sriov_pci โดดเดี่ยวโดยไม่เปิด sriov_enabled = config ที่สื่อเจตนาไม่ครบ
    #[test]
    fn sriov_pci_without_sriov_enabled_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("sriov-onlypci");
        cfg.gpu.sriov_pci = "0000:41:10.0".into();
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // AIVM ไม่สร้าง VFs เอง (ต้อง root + driver binding) — num_vfs>0 คือ
    // config ที่ให้คนอื่นล่วงรู้ว่าเราสั่ง mutate host ซึ่งจะกระทบ host จริง
    #[test]
    fn sriov_num_vfs_fails_closed() {
        let (spec, policy, mut cfg, ws) = fixture("sriov-vfs");
        cfg.gpu.sriov_enabled = true;
        cfg.gpu.sriov_pci = "0000:41:10.0".into();
        cfg.gpu.sriov_num_vfs = 2;
        assert!(matches!(
            run_in_hardware(&spec, &policy, &cfg),
            Err((SandboxError::Invalid(_), RunVerdict::Clean))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // BDF ผิดรูป (รวม shell metachar) ห้ามไปถึง sysfs path/argv — ตายที่ shape
    #[test]
    fn sriov_bad_pci_address_fails_closed() {
        for (tag, addr) in [
            ("inj1", "../etc/passwd"),
            ("inj2", "0000:41:10.$(id)"),
            ("inj3", "0041:10.0"),
            ("inj4", "0000:41:1 0.0"),
            ("inj5", "0000:41:10.8"),
            ("inj6", "00000041:100"),
            ("inj7", "XXXX:41:1 0.0"),
            ("inj8", "0000:41:10.0\nX"),
        ] {
            let (spec, policy, mut cfg, ws) = fixture(tag);
            cfg.gpu.sriov_enabled = true;
            cfg.gpu.sriov_pci = addr.into();
            assert!(
                matches!(
                    run_in_hardware(&spec, &policy, &cfg),
                    Err((SandboxError::Invalid(_), RunVerdict::Clean))
                ),
                "{addr:?} ต้องตายที่ shape"
            );
            let _ = std::fs::remove_dir_all(&ws);
        }
    }

    // parse_pci_address: ต้อง normalize ตัวพิมพ์และปฏิเสธเหลือบมากที่สุด
    #[test]
    fn pci_address_parse_exact() {
        assert_eq!(
            parse_pci_address("0000:41:10.0").as_deref(),
            Some("0000:41:10.0")
        );
        assert_eq!(
            parse_pci_address("0001:AE:Bf.3").as_deref(),
            Some("0001:ae:bf.3")
        );
        assert_eq!(parse_pci_address(""), None);
        assert_eq!(parse_pci_address("0000:41:10.10"), None);
        assert_eq!(parse_pci_address("000:41:10.0"), None);
        assert_eq!(parse_pci_address("0000:41:10:0"), None);
        assert_eq!(parse_pci_address("0000:41:10.G"), None);
        assert_eq!(parse_pci_address("0000:41:10.8"), None);
        assert_eq!(parse_pci_address("0000;41:10.0"), None);
        assert_eq!(parse_pci_address("../../etc/passwd "), None);
    }

    // host ไม่มี device ที่ส่งมา = Disabled ก่อน spawn (deterministic ทุกเครื่อง)
    #[test]
    fn sriov_missing_gpu_device_fails_closed() {
        // BDF ที่กอดเว้นไว้ว่างไม่มีในเครื่อง host ใด ๆ (segment ffff = reserved)
        // อย่าคิดถึง hardware แต่ต้องการยืนยันประตู probe ทำงานเป็น Disabled
        let cfgr = "/sys/bus/pci/devices/ffff:ff:ff.7";
        if std::path::Path::new(cfgr).exists() {
            eprintln!("skip: เครื่องนี้มี PCI device ที่ ffff:ff:ff.7 (ประหลาดผิดคาด)");
            return;
        }
        let (spec, policy, mut cfg, ws) = fixture("sriov-nodev");
        cfg.gpu.sriov_enabled = true;
        cfg.gpu.sriov_pci = "ffff:ff:ff.7".into();
        let r = run_in_hardware(&spec, &policy, &cfg);
        assert!(
            matches!(r, Err((SandboxError::Disabled(_), RunVerdict::Clean))),
            "device ที่ไม่มีต้อง Disabled ไม่ใช่ run เครื่องจริง: {r:?}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // device ที่มีจริงแต่ยังไม่ได้ bind vfio-pci = Disabled รายงานซื่อสัตย์
    // (บน CI ที่ไม่มี GPU กระโดดไป skip — บนเครื่องที่มี CPU/GPU จะเจ็บจริง)
    #[test]
    fn sriov_device_without_vfio_binding_fails_closed() {
        for candidate in ["0000:03:00.0", "0000:01:00.0"] {
            let dev = std::path::Path::new("/sys/bus/pci/devices").join(candidate);
            if !dev.exists() {
                continue;
            }
            // ยัง bind โดย driver อื่น = ประตู probe ต้องปฏิเสธ; device แบบไม่มี
            // driver เลยก็ต้องปฏิเสธเช่นกัน (เป็นความรับผิดของ operator ทั้งคู่)
            // ไม่ลอง bind เอง (root เท่านั้น และเสี่ยงโปรดักชัน)
            if std::fs::read_link(dev.join("driver"))
                .ok()
                .and_then(|l| l.file_name().map(|f| f.to_string_lossy().into_owned()))
                .as_deref()
                == Some("vfio-pci")
            {
                // เครื่องที่ device ถูก bind vfio แล้ว = ไม่เหมาะกับเทสต์ deny path
                eprintln!("skip: {candidate} ถูกผูก vfio-pci แล้ว ใช้ตรวจ deny path ไม่ได้");
                return;
            }
            let (spec, policy, mut cfg, ws) = fixture("sriov-bound");
            cfg.gpu.sriov_enabled = true;
            cfg.gpu.sriov_pci = candidate.into();
            let r = run_in_hardware(&spec, &policy, &cfg);
            assert!(
                matches!(r, Err((SandboxError::Disabled(_), RunVerdict::Clean))),
                "{candidate} ที่ไม่ได้ผูก vfio-pci ต้อง Disabled: {r:?}"
            );
            let _ = std::fs::remove_dir_all(&ws);
            return;
        }
        eprintln!("skip: ไม่มี PCI device ทดสอบบนเครื่องนี้ (CI ธรรมดาหรือไม่มี GPU)");
    }

    // บูตจริงแบบ end-to-end (ต้องมี KVM + QEMU + debugfs + mkfs.ext4 + pins)
    // ข้าม (แต่ยังเขียว) เมื่อรันใน CI ที่ไม่มีของพวกนี้: ตั้ง
    // `AIVM_HARDWARE_PINS=/path/pins.json` เพื่อเปิดเทสต์นี้
    #[test]
    fn real_boot_runs_true_and_false() {
        let pins_path = std::env::var("AIVM_HARDWARE_PINS").unwrap_or_default();
        if pins_path.is_empty() {
            eprintln!("skip: ตั้ง AIVM_HARDWARE_PINS เพื่อทดสอบบูตจริง");
            return;
        }
        if !super::super::kvm_available() || super::super::find_qemu().is_none() {
            eprintln!("skip: เครื่องนี้ไม่มี KVM/QEMU");
            return;
        }
        for tool in ["debugfs", "mkfs.ext4", "ldd"] {
            if which::which(tool).is_err() {
                eprintln!("skip: เครื่องนี้ไม่มี {tool}");
                return;
            }
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
            let cfg = HardwareConfig {
                kernel_path: PathBuf::from(kernel),
                kernel_sha256: ksha.into(),
                rootfs_path: PathBuf::from(rootfs),
                rootfs_sha256: rsha.into(),
                tee_type: TeeType::Generic,
                attestation_mode: AttestationMode::None,
                ..HardwareConfig::default()
            };
            let out = run_in_hardware(&spec, &policy, &cfg)
                .unwrap_or_else(|e| panic!("บูตจริงต้องผ่าน {exe}: {e:?}"));
            assert_eq!(out.code, Some(want), "{exe} ต้อง exit {want}");
            assert!(out.applied.contains(&"qemu-kvm-launch".to_string()));
            assert!(out.applied.contains(&"no-guest-network".to_string()));
            let _ = std::fs::remove_dir_all(&ws);
        }
    }
}
