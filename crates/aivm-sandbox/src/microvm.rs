//! MicroVM backend — Phase 7 Level 2 (สเปก §Level 2: KVM + Firecracker).
//!
//! สถานะ: **skeleton** — สร้าง seam ให้ milestone ถัดไปเติมการ boot/exec จริง
//! ตอนนี้ทำแค่ประตู fail-closed ตามลำดับ (spec gate → supply chain → host
//! readiness) แล้วหยุดด้วย `Disabled` เสมอ ยังไม่มีการ spawn อะไรทั้งสิ้น
//! (`make verify` จึงเขียวได้โดยไม่ต้องมี KVM/Firecracker)
//!
//! ลำดับประตู (ตั้งใจเรียงแบบนี้ ห้ามสลับ):
//! 1. `validate` สเปกงาน (exe/policy/arg/env/cwd — ประตูเดียวกับ Process)
//! 2. `verify_artifact` kernel + rootfs ด้วย sha256 ที่ pin ไว้ (supply chain
//!    ต้องมาก่อนตรวจ host: image ปลอมต้องตายก่อน ไม่ว่าเครื่องจะพร้อมหรือไม่)
//! 3. Linux-only (Firecracker รันบน Linux เท่านั้น)
//! 4. `/dev/kvm` เปิดได้
//! 5. ไบนารี `firecracker` อยู่ใน PATH
//! 6. `Disabled` (การ boot/exec จริงยังไม่ส่งมอบ)

use super::{verify_artifact, ExecOutcome, ExecSpec, SandboxError};
use aivm_policy::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// เพดานขนาด artifact ตั้งต้น (kernel + rootfs ไม่ควรเกินนี้)
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

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
        Ok(())
    }
}

/// รันงานใน MicroVM (skeleton: ประตูครบแล้วหยุดที่ `Disabled`)
///
/// ลำดับตามโมดูล doc — ทุกขั้นไม่ผ่านคือไม่ boot เด็ดขาด (`Invalid` สำหรับ
/// spec/artifact/shape ปลอม, `Disabled` สำหรับ host ไม่พร้อม/ยังไม่ส่งมอบ)
/// แยกชนิด error แบบนี้เพื่อให้ gateway audit เหตุได้ถูก (deny เหมือนกันหมด)
pub fn run_in_microvm(
    spec: &ExecSpec,
    policy: &Policy,
    cfg: &MicroVmConfig,
) -> Result<ExecOutcome, SandboxError> {
    // 1. ประตูสเปกเดียวกับ Process (exe/policy/arg/env/cwd)
    let _canon = super::validate(spec, policy)?;
    // 2. ตัวเลข config ต้องสมเหตุก่อน (ถูกกว่าแตะไฟล์)
    cfg.validate_shape()?;
    // 3. supply chain: kernel + rootfs ต้องตรง hash ที่ pin ไว้
    verify_artifact(&cfg.kernel_path, &cfg.kernel_sha256, cfg.max_artifact_bytes)?;
    verify_artifact(&cfg.rootfs_path, &cfg.rootfs_sha256, cfg.max_artifact_bytes)?;
    // 4. host readiness (Linux + KVM + binary) — ไม่พร้อมคือ Disabled
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (spec, policy);
        return Err(SandboxError::Disabled(
            "microvm backend is Linux-only".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if !super::kvm_available() {
            return Err(SandboxError::Disabled(
                "microvm needs /dev/kvm (KVM not available on this host)".into(),
            ));
        }
        if super::find_firecracker().is_none() {
            return Err(SandboxError::Disabled(
                "microvm needs the firecracker binary in PATH".into(),
            ));
        }
        // 5. การ boot/exec จริงยังไม่ส่งมอบ (milestone ถัดไป)
        Err(SandboxError::Disabled(
            "microvm execution not yet implemented (skeleton); use Process level".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceLimits, SandboxError};
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
            Err(SandboxError::Invalid(_))
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
            Err(SandboxError::Invalid(_))
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
            Err(SandboxError::Invalid(_))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // artifact ครบแต่ backend ยังเป็น skeleton: ต้อง Disabled เสมอ
    // (ไม่ว่าเครื่องจะมี KVM/binary หรือไม่ — ยังไม่มีการ spawn จริง)
    #[test]
    fn valid_artifacts_still_disabled_as_skeleton() {
        let (spec, policy, cfg, ws) = fixture("skel");
        assert!(matches!(
            run_in_microvm(&spec, &policy, &cfg),
            Err(SandboxError::Disabled(_))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }
}
