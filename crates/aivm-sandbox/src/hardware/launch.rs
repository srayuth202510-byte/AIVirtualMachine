//! ขั้น launch/run จริงของ Hardware-isolated VM (Linux + KVM + TEE เท่านั้น).
//!
//! วิธี: **drive-stuffing** แบบเดียวกับ MicroVM — ก็อป kernel/rootfs ที่
//! verify แล้วไป scratch (ห้ามแตะไฟล์ pin) ฉีด `/sbin/aivm-init` ด้วย
//! debugfs สร้าง data drive จาก exe + ldd closure บูตด้วย QEMU/KVM ผ่าน
//! `init=` จับผลทาง serial console ด้วย marker ต่อ nonce แล้ว kill เก็บงาน
//! (guest ไม่มีเน็ตเวิร์กเลยตั้งแต่เกิด — ส่ง `-nic none` ชัดเจน)
//!
//! เครื่องมือ host ที่เรียก (`ldd`, `mkfs.ext4`, `debugfs`, `qemu-system-x86_64`,
//! `swtpm`) คือ infra ของ operator ไม่ใช่ input ของ agent argv ทุกคำสั่งตายตัว
//! ยกเว้น path ที่ผ่าน validate/verify มาแล้ว — agent ปนคำสั่งไม่ได้
//! (ไม่มี shell มาต่อกลางเด็ดขาด ดูเทสต์ `shell_metachars_stay_single_argv`)

use super::{AttestationMode, ExecOutcome, ExecSpec, HardwareConfig, TeeType};
use crate::{verify_artifact, ResourceLimits, RunVerdict, SandboxError};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// เพดาน serial log ที่อ่านมา parse (กันหน่วยความจำบวม)
const MAX_SERIAL_BYTES: u64 = 4 * 1024 * 1024;
/// พื้นที่เผื่อใน data image นอกเหนือไฟล์ staging
const DATA_IMAGE_SPARE_MB: u64 = 16;
/// ขนาด data image อย่างน้อย (mkfs เล็กเกินไปล้ม)
const DATA_IMAGE_MIN_MB: u64 = 32;
/// เวลารอ swtpm socket ปรากฏ
const SWTPM_SOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// ฆ่า child ทิ้งเสมอเมื่อหลุด scope (fail-closed: ไม่มี VM/daemon กำพร้า)
struct KillOnDrop(Option<Child>);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// ขนาด guest จริง = ค่าน้อยสุดระหว่าง quota ระดับ VM (`cfg`) กับ quota
/// ระดับ task (`spec.limits`) — task ไม่มีทางได้ทรัพยากรเกินโควตาตัวเอง
fn effective_guest_size(cfg: &HardwareConfig, limits: &ResourceLimits) -> (u32, u64) {
    let vcpu = (cfg.vcpu_count as u64).min(limits.cpu as u64).clamp(1, 256) as u32;
    let mem = (cfg.mem_mb).min(limits.memory_mb).clamp(1024, 1048576);
    (vcpu, mem)
}

/// RNG เล็กสำหรับ DNA ต่อบูต (xorshift64* — ไม่เพิ่ม dependency)
struct DnaRng(u64);
impl DnaRng {
    fn seed() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0) as u64;
        let p = std::process::id() as u64;
        Self(
            t.wrapping_mul(0x9E3779B97F4A7C15)
                .wrapping_add(p.wrapping_mul(0xBF58476D1CE4E5B9))
                .max(1),
        )
    }
    #[cfg(test)]
    fn seeded(v: u64) -> Self {
        Self(v.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

/// marker สำหรับ parse output (nonce ต่อรันกันชนกับ output ของ payload)
fn markers(nonce: &str) -> (String, String, String, String, String, String) {
    (
        format!("AIVM-{nonce}-OUT-BEGIN"),
        format!("AIVM-{nonce}-OUT-END"),
        format!("AIVM-{nonce}-ERR-BEGIN"),
        format!("AIVM-{nonce}-ERR-END"),
        format!("AIVM-{nonce}-EXIT:"),
        format!("AIVM-{nonce}-FAIL"),
    )
}

/// jitter ขนาด guest ต่อบูต (G5): ลดไม่เกิน 25% จากค่าที่ clamp แล้ว
fn apply_jitter(vcpu: u32, mem: u64, rng: &mut DnaRng) -> (u32, u64) {
    let dv = rng.below(vcpu as u64 / 4 + 1) as u32;
    let dm = rng.below(mem / 4 + 1);
    ((vcpu - dv).max(1), (mem - dm).max(1024))
}

/// ห่อข้อความให้เป็น single-quoted sh literal (กันทุกไบต์ยกเว้น NUL
/// ซึ่ง validate ปฏิเสธไปแล้วตั้งแต่ประตูแรก)
fn sh_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// closure ของ dynamic exe จาก `ldd` (loader อาจไม่มีถ้า static)
struct Closure {
    loader: Option<PathBuf>,
    libs: Vec<PathBuf>,
}

fn clean_err(e: SandboxError) -> (SandboxError, RunVerdict) {
    (e, RunVerdict::Clean)
}

fn ldd_closure(exe: &Path) -> Result<Closure, (SandboxError, RunVerdict)> {
    let spawn_err = |e: std::io::Error| clean_err(SandboxError::Spawn(format!("ldd failed: {e}")));
    let out = Command::new("ldd")
        .arg(exe)
        .stdin(Stdio::null())
        .output()
        .map_err(spawn_err)?;
    let text = String::from_utf8_lossy(&out.stdout);
    // static binary ไม่มี loader/libs — รันตรงได้เลย
    if text.contains("not a dynamic executable") || text.contains("statically linked") {
        return Ok(Closure {
            loader: None,
            libs: vec![],
        });
    }
    if !out.status.success() {
        return Err(clean_err(SandboxError::Spawn(format!(
            "ldd rejected {}",
            exe.display()
        ))));
    }
    let mut libs = vec![];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // รูป `libc.so.6 => /usr/lib/... (0x...)` หรือ `/lib64/ld-... (0x...)`
        let path = if let Some((_, right)) = line.split_once("=>") {
            right.split_whitespace().next().unwrap_or("")
        } else {
            line.split_whitespace().next().unwrap_or("")
        };
        if !path.starts_with('/') || path.contains('(') {
            continue;
        }
        libs.push(PathBuf::from(path));
    }
    let loader = libs
        .iter()
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("ld-"))
                .unwrap_or(false)
        })
        .cloned();
    Ok(Closure { loader, libs })
}

/// ก็อปไฟล์ไป staging โดยคงโครง absolute path + mode (ตาม symlink ไป
/// เอาเนื้อหาจริง — ldd ให้ path ที่ resolve แล้วเป็นส่วนใหญ่)
fn stage_file(staging: &Path, abs: &Path) -> Result<(), (SandboxError, RunVerdict)> {
    let rel = abs.strip_prefix("/").map_err(|_| {
        clean_err(SandboxError::Invalid(
            "closure path must be absolute".into(),
        ))
    })?;
    let dst = staging.join(rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| clean_err(SandboxError::Spawn(format!("staging mkdir failed: {e}"))))?;
    }
    let meta = std::fs::metadata(abs).map_err(|e| {
        clean_err(SandboxError::Spawn(format!(
            "closure stat failed {}: {e}",
            abs.display()
        )))
    })?;
    if !meta.is_file() {
        return Err(clean_err(SandboxError::Spawn(format!(
            "closure not a file: {}",
            abs.display()
        ))));
    }
    std::fs::copy(abs, &dst)
        .map_err(|e| clean_err(SandboxError::Spawn(format!("staging copy failed: {e}"))))?;
    std::fs::set_permissions(&dst, meta.permissions())
        .map_err(|e| clean_err(SandboxError::Spawn(format!("staging chmod failed: {e}"))))?;
    Ok(())
}

/// ขนาดรวมของไฟล์ใต้ dir (ไว้คำนวณขนาด data image)
fn dir_size_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(m) = e.metadata() {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

/// เรียก host tool แบบตายตัว (argv คงที่ยกเว้น path ที่ validate แล้ว)
/// ล้ม = `Spawn` (infra พร้อมไม่พอ ไม่ใช่ spec ผิด)
fn host_tool(prog: &str, args: &[&str]) -> Result<String, (SandboxError, RunVerdict)> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| clean_err(SandboxError::Spawn(format!("{prog} spawn failed: {e}"))))?;
    if !out.status.success() {
        return Err(clean_err(SandboxError::Spawn(format!(
            "{prog} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ))));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// สตาร์ท swtpm (vTPM emulator) แบบ foreground แล้วคืน guard ที่ถือ process
/// ไว้ — guard ตาย = swtpm ถูก kill เสมอ (ไม่มี daemon กำพร้า)
fn spawn_swtpm(
    cfg: &HardwareConfig,
    scratch: &Path,
) -> Result<(KillOnDrop, PathBuf), (SandboxError, RunVerdict)> {
    let swtpm_bin = if cfg.vtpm.swtpm_path.as_os_str().is_empty() {
        which::which("swtpm").map_err(|_| {
            clean_err(SandboxError::Spawn(
                "swtpm binary not found in PATH (install swtpm or set vtpm.swtpm_path)".into(),
            ))
        })?
    } else {
        cfg.vtpm.swtpm_path.clone()
    };
    let state_dir = if cfg.vtpm.tpm_state_dir.as_os_str().is_empty() {
        scratch.join("tpmstate")
    } else {
        cfg.vtpm.tpm_state_dir.clone()
    };
    std::fs::create_dir_all(&state_dir).map_err(|e| {
        clean_err(SandboxError::Spawn(format!(
            "swtpm state dir create failed: {e}"
        )))
    })?;
    let sock = scratch.join("swtpm.sock");
    let child = Command::new(swtpm_bin)
        .arg("socket")
        .arg("--tpm2")
        .arg("--tpmstate")
        .arg(format!("dir={}", state_dir.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={}", sock.display()))
        .arg("--log")
        .arg("level=20")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
        .map_err(|e| clean_err(SandboxError::Spawn(format!("swtpm spawn failed: {e}"))))?;
    let guard = KillOnDrop(Some(child));
    // รอ socket ปรากฏ — ไม่โผล่ในเวลาคือ fail-closed (infra ไม่พร้อม)
    let start = Instant::now();
    while start.elapsed() < SWTPM_SOCK_TIMEOUT {
        if UnixStream::connect(&sock).is_ok() {
            return Ok((guard, sock));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(clean_err(SandboxError::Spawn(
        "swtpm control socket never appeared".into(),
    )))
}

/// สร้าง QEMU command line สำหรับ TEE launch
///
/// หมายเหตุด้านความปลอดภัย: argv ประกอบจากค่าคงที่ + path ที่ผ่าน
/// validate/verify มาแล้วเท่านั้น — ไม่เคยผ่าน shell (`sh -c` ไม่มีในสายนี้)
/// path ประหลาด (ช่องว่าง, quote, `;`, `$()`) จึงเป็นได้แค่ argv ก้อนเดียว
/// (ดูเทสต์ `shell_metachars_stay_single_argv`)
#[allow(clippy::too_many_arguments)]
fn build_qemu_cmd(
    cfg: &HardwareConfig,
    qemu_bin: &Path,
    scratch: &Path,
    kernel_path: &Path,
    initrd_path: Option<&Path>,
    rootfs_path: &Path,
    data_path: &Path,
    swtpm_sock: Option<&Path>,
    eff_vcpu: u32,
    eff_mem: u64,
) -> Result<Command, (SandboxError, RunVerdict)> {
    let mut cmd = Command::new(qemu_bin);

    // `-machine` สตริงเดียว (ห้ามส่งหลายรอบแล้วพึ่งว่าอันหลังกลบอันแรก)
    let (machine, tee_object) = match cfg.tee_type {
        TeeType::Sevsnp => (
            "q35,accel=kvm,memory-encryption=sev0",
            Some("sev-guest,id=sev0,cbitpos=47,reduced-phys-bits=1,policy=0x3"),
        ),
        TeeType::Tdx => (
            "q35,accel=kvm,memory-encryption=tdx0",
            Some("tdx-guest,id=tdx0"),
        ),
        TeeType::Generic => ("q35,accel=kvm", None),
    };
    cmd.arg("-machine").arg(machine);
    if let Some(obj) = tee_object {
        cmd.arg("-object").arg(obj);
    }

    cmd.arg("-cpu")
        .arg("host")
        .arg("-m")
        .arg(format!("{}M", eff_mem))
        .arg("-smp")
        .arg(eff_vcpu.to_string())
        .arg("-nographic")
        .arg("-nodefaults")
        .arg("-no-user-config")
        // guest ไม่มีเน็ตเวิร์กเลยตั้งแต่เกิด (QEMU default มี usermode NIC
        // ถ้าไม่ปิดชัดเจน — จึงส่ง `-nic none` กำกับไว้)
        .arg("-nic")
        .arg("none")
        .arg("-serial")
        .arg(format!("file:{}", scratch.join("serial.log").display()))
        .arg("-monitor")
        .arg("none");

    // Kernel + initrd (init script ถูกฉีดใน rootfs แล้ว ใช้ `init=` ชี้ไปหา)
    cmd.arg("-kernel").arg(kernel_path);
    if let Some(initrd) = initrd_path {
        cmd.arg("-initrd").arg(initrd);
    }
    cmd.arg("-append")
        .arg("console=ttyS0 root=/dev/vda rw panic=1 init=/sbin/aivm-init");

    // Rootfs (สำเนาที่ verify ซ้ำแล้ว) + data drive (exe + ldd closure)
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=off,id=rootfs",
        rootfs_path.display()
    ));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on,id=data",
        data_path.display()
    ));

    // vTPM (swtpm ถูก spawn และถือ guard ไว้โดยผู้เรียกแล้ว)
    if let Some(sock) = swtpm_sock {
        cmd.arg("-chardev")
            .arg(format!("socket,id=chrtpm,path={}", sock.display()));
        cmd.arg("-tpmdev").arg("emulator,id=tpm0,chardev=chrtpm");
        cmd.arg("-device").arg("tpm-tis,tpmdev=tpm0");
    }

    // Measured boot ต้องการเฟิร์มแวร์ที่รองรับ — ถ้าไฟล์ไม่มี QEMU จะล้ม
    // แบบ fail-closed เอง (Spawn ดัง ไม่เงียบข้าม)
    if cfg.measured_boot.enabled {
        cmd.arg("-bios").arg("/usr/share/OVMF/OVMF_CODE_4M.fd");
    }

    // GPU/NPU passthrough ยังไม่ implement (กันเงียบผ่าน: ถ้าเปิดไว้ต้องตาย
    // ตั้งแต่ประตู shape — ดู `validate_shape` ใน hardware.rs)
    cmd.env_clear();
    Ok(cmd)
}

/// Remote Attestation verification (ซื่อสัตย์ตามที่ทำได้จริง)
///
/// ความซื่อสัตย์: ขั้นนี้ตรวจแค่ "มีเครื่องมือขอ quote/report หรือไม่"
/// ยังไม่มีการ verify quote กับ KDS/endorsement keys — ดังนั้น Strict ที่
/// ผ่านจุดนี้จะได้แค่ `attestation-tool-check` ใน applied พร้อม degraded
/// `quote-verification: not-implemented` (ดู `launch_and_run_inner`)
/// ไม่มีทางได้คำว่า `remote-attestation-strict` ใน applied
fn verify_attestation(cfg: &HardwareConfig) -> Result<(), (SandboxError, RunVerdict)> {
    match cfg.attestation_mode {
        AttestationMode::None => return Ok(()),
        AttestationMode::BestEffort => {}
        AttestationMode::Strict => {}
    }
    // Generic = โหมดจำลอง ไม่มี TEE จริงจึง attest อะไรไม่ได้เลย
    // Strict บน generic คือ config ที่เป็นไปไม่ได้ → Disabled (fail-closed)
    // BestEffort บน generic = ข้ามแบบเปิดเผย (รายงานใน degraded)
    if cfg.tee_type == TeeType::Generic {
        if cfg.attestation_mode == AttestationMode::Strict {
            return Err((
                SandboxError::Disabled(
                    "strict attestation needs a real TEE (SEV-SNP/TDX); generic is simulation-only"
                        .into(),
                ),
                RunVerdict::Clean,
            ));
        }
        return Ok(());
    }
    // TEE จริง: ต้องมีเครื่องมือขอ report/quote — ไม่มี = ขาดความสามารถ
    let tool = match cfg.tee_type {
        TeeType::Sevsnp => "sev-tool",
        TeeType::Tdx => "tdx-attest",
        // generic ออกตั้งแต่ข้างบนแล้ว — แขนนี้กัน match ไม่ครบ (fail-closed
        // ไม่ panic ถ้า logic ข้างบนเปลี่ยนในอนาคต)
        TeeType::Generic => {
            return Err((
                SandboxError::Disabled("generic TEE has nothing to attest".into()),
                RunVerdict::Clean,
            ));
        }
    };
    if which::which(tool).is_err() {
        return Err((
            SandboxError::Spawn(format!(
                "TEE attestation tool missing: {tool} (not found in PATH)"
            )),
            RunVerdict::Suspect("attestation-tool-missing"),
        ));
    }
    Ok(())
}

/// Launch + run + capture output
pub(super) fn launch_and_run(
    spec: &ExecSpec,
    canon: &Path,
    cfg: &HardwareConfig,
    qemu_bin: &Path,
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    let spawn_err = |what: &str, e: std::io::Error| {
        (
            SandboxError::Spawn(format!("hardware {what} failed: {e}")),
            RunVerdict::Clean,
        )
    };

    // nonce ต่อรันกัน marker ชนกับ output ของ payload
    let nonce = format!(
        "{:x}{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let scratch = std::env::temp_dir().join(format!("aivm-hw-run-{nonce}"));
    std::fs::create_dir_all(&scratch).map_err(|e| spawn_err("scratch", e))?;

    let r = launch_and_run_inner(spec, canon, cfg, qemu_bin, &scratch, &nonce);

    // ล้าง scratch แบบ best-effort (ผลลัพธ์ parse ไว้หมดแล้ว)
    // ตั้ง AIVM_HARDWARE_KEEP_SCRATCH=1 เพื่อเก็บไว้ดีบัก serial log
    if std::env::var("AIVM_HARDWARE_KEEP_SCRATCH").is_err() {
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        eprintln!("hardware scratch kept at {}", scratch.display());
    }
    r
}

#[allow(clippy::too_many_lines)]
fn launch_and_run_inner(
    spec: &ExecSpec,
    canon: &Path,
    cfg: &HardwareConfig,
    qemu_bin: &Path,
    scratch: &Path,
    nonce: &str,
) -> Result<ExecOutcome, (SandboxError, RunVerdict)> {
    let spawn_err = |what: &str, e: std::io::Error| {
        (
            SandboxError::Spawn(format!("hardware {what} failed: {e}")),
            RunVerdict::Clean,
        )
    };
    // DNA ต่อ launch (G5): image ทุกชุดผ่าน verify ที่ประตูแล้ว (verify ก่อน
    // สุ่มเสมอ) — launch นี้เลือกชุดไหนก็ปลอดภัยเท่ากัน ต่างกันแค่ exploit
    // ผูกตายตัวใช้ซ้ำไม่ได้
    let mut rng = DnaRng::seed();
    let (kpath, ksha, k_alt) = match (&cfg.alt_kernel, rng.below(2)) {
        (Some(a), 1) => (&a.path, &a.sha256, true),
        _ => (&cfg.kernel_path, &cfg.kernel_sha256, false),
    };
    let (ipath_opt, isha, i_alt) = match (&cfg.alt_initrd, rng.below(2)) {
        (Some(a), 1) => (Some(a.path.as_path()), &a.sha256, true),
        _ => (
            if cfg.initrd_path.as_os_str().is_empty() {
                None
            } else {
                Some(cfg.initrd_path.as_path())
            },
            &cfg.initrd_sha256,
            false,
        ),
    };
    let (rpath, rsha, r_alt) = match (&cfg.alt_rootfs, rng.below(2)) {
        (Some(a), 1) => (&a.path, &a.sha256, true),
        _ => (&cfg.rootfs_path, &cfg.rootfs_sha256, false),
    };

    // ก็อป kernel/initrd/rootfs ที่ verify แล้วไป scratch (ห้ามแตะไฟล์ pin
    // ต้นฉบับ ห้ามส่ง path ต้นฉบับให้ QEMU ตรง ๆ) แล้ว verify สำเนาซ้ำ
    // (กันไฟล์ถูกสลับระหว่าง verify กับ launch — สำเนาไม่ตรง = หลักฐาน
    // แทรกแซงกลาง launch → `Compromise`)
    let guest_kernel = scratch.join("vmlinux");
    std::fs::copy(kpath, &guest_kernel).map_err(|e| spawn_err("kernel copy", e))?;
    verify_artifact(&guest_kernel, ksha, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Compromise("kernel-copy-reverify-failed")))?;
    let guest_initrd = ipath_opt.map(|p| {
        let dst = scratch.join("initrd.img");
        (p, dst)
    });
    if let Some((src, dst)) = &guest_initrd {
        std::fs::copy(src, dst).map_err(|e| spawn_err("initrd copy", e))?;
        verify_artifact(dst, isha, cfg.max_artifact_bytes)
            .map_err(|e| (e, RunVerdict::Compromise("initrd-copy-reverify-failed")))?;
    }
    let guest_root = scratch.join("root.img");
    std::fs::copy(rpath, &guest_root).map_err(|e| spawn_err("rootfs copy", e))?;
    verify_artifact(&guest_root, rsha, cfg.max_artifact_bytes)
        .map_err(|e| (e, RunVerdict::Compromise("rootfs-copy-reverify-failed")))?;

    // ขนาด guest = clamp ด้วย quota ระดับ task ก่อน แล้ว jitter ลงถ้าเปิดไว้
    let (eff_vcpu, eff_mem) = effective_guest_size(cfg, &spec.limits);
    let (eff_vcpu, eff_mem) = if cfg.dna_jitter {
        apply_jitter(eff_vcpu, eff_mem, &mut rng)
    } else {
        (eff_vcpu, eff_mem)
    };
    let (m_out_b, m_out_e, m_err_b, m_err_e, m_exit, m_fail) = markers(nonce);

    // staging: exe + loader + libs คงโครง absolute path (guest เห็นใต้ /mnt/data)
    let closure = ldd_closure(canon)?;
    let staging = scratch.join("stage");
    std::fs::create_dir_all(&staging).map_err(|e| spawn_err("staging", e))?;
    stage_file(&staging, canon)?;
    if let Some(ld) = &closure.loader {
        stage_file(&staging, ld)?;
    }
    for lib in &closure.libs {
        // ข้าม loader ซ้ำ (ก็อปไปแล้ว)
        if Some(lib) == closure.loader.as_ref() {
            continue;
        }
        stage_file(&staging, lib)?;
    }
    // guest path = /mnt/data + absolute เดิม
    let guest = |p: &Path| format!("/mnt/data{}", p.display());
    let libpath = {
        let mut dirs: Vec<String> = vec![];
        for lib in closure.libs.iter().filter_map(|p| p.parent()) {
            let g = format!("/mnt/data{}", lib.display());
            if !dirs.contains(&g) {
                dirs.push(g);
            }
        }
        dirs.join(":")
    };
    // ลำดับคำสั่ง loader: loader --library-path DIRS EXE ARGS (exe ต้อง
    // มาก่อน args เสมอ ไม่ใช่หลัง — ไม่งั้น loader จะรัน arg แทน exe)
    let mut invoke = match &closure.loader {
        Some(ld) => format!(
            "{} --library-path {} {}",
            sh_escape(&guest(ld)),
            sh_escape(&libpath),
            sh_escape(&guest(canon))
        ),
        // static binary: รันตรงได้เลย
        None => sh_escape(&guest(canon)),
    };
    for a in &spec.args {
        invoke.push(' ');
        invoke.push_str(&sh_escape(a));
    }
    let out_tmp = format!("/tmp/aivm-{nonce}");
    let err_tmp = format!("/tmp/aivm-{nonce}e");
    let init_sh = format!(
        "#!/bin/sh\nmkdir -p /mnt/data\nmount -t tmpfs tmpfs /tmp 2>/dev/null\nmount -t ext4 -o ro /dev/vdb /mnt/data || {{ echo \"{fail}\"; poweroff -f; }}\n{invoke} >{out_tmp}o 2>{err_tmp}e\nCODE=$?\necho \"{out_b}\"; cat {out_tmp}o; echo \"{out_e}\"\necho \"{err_b}\"; cat {err_tmp}e; echo \"{err_e}\"\necho \"{exit}$CODE\"\npoweroff -f\n",
        fail = m_fail,
        out_tmp = out_tmp,
        err_tmp = err_tmp,
        out_b = m_out_b,
        out_e = m_out_e,
        err_b = m_err_b,
        err_e = m_err_e,
        exit = m_exit,
    );
    let init_host = scratch.join("aivm-init");
    std::fs::write(&init_host, init_sh.as_bytes()).map_err(|e| spawn_err("init write", e))?;
    // ฉีดเข้า root.img สำเนา (debugfs ไม่ต้อง root) + ติดบิต execute
    host_tool(
        "debugfs",
        &[
            "-w",
            "-R",
            &format!("write {} /sbin/aivm-init", init_host.display()),
            guest_root.to_str().ok_or_else(|| {
                clean_err(SandboxError::Spawn(
                    "hardware scratch path not utf-8".into(),
                ))
            })?,
        ],
    )?;
    host_tool(
        "debugfs",
        &[
            "-w",
            "-R",
            "set_inode_field /sbin/aivm-init mode 0100755",
            guest_root.to_str().ok_or_else(|| {
                clean_err(SandboxError::Spawn(
                    "hardware scratch path not utf-8".into(),
                ))
            })?,
        ],
    )?;

    // data image จาก staging (mkfs ไม่ต้อง root)
    let bytes = dir_size_bytes(&staging);
    let size_mb = ((bytes / (1024 * 1024)) + DATA_IMAGE_SPARE_MB).max(DATA_IMAGE_MIN_MB);
    let data_img = scratch.join("data.img");
    host_tool(
        "mkfs.ext4",
        &[
            "-q",
            "-d",
            staging.to_str().ok_or_else(|| {
                clean_err(SandboxError::Spawn(
                    "hardware scratch path not utf-8".into(),
                ))
            })?,
            data_img.to_str().ok_or_else(|| {
                clean_err(SandboxError::Spawn(
                    "hardware scratch path not utf-8".into(),
                ))
            })?,
            &format!("{size_mb}M"),
        ],
    )?;

    // vTPM (ถ้าเปิด): spawn swtpm แล้วถือ guard ไว้ตลอดชีพ VM นี้
    // guard ตาย = swtpm ถูก kill เสมอ ไม่มี daemon กำพร้า
    let (_swtpm_guard, swtpm_sock) = if cfg.vtpm.enabled {
        let (g, s) = spawn_swtpm(cfg, scratch)?;
        (Some(g), Some(s))
    } else {
        (None, None)
    };

    // ประกอบคำสั่ง QEMU (argv ล้วน ไม่มี shell)
    let mut qemu_cmd = build_qemu_cmd(
        cfg,
        qemu_bin,
        scratch,
        &guest_kernel,
        guest_initrd.as_ref().map(|(_, dst)| dst.as_path()),
        &guest_root,
        &data_img,
        swtpm_sock.as_deref(),
        eff_vcpu,
        eff_mem,
    )?;

    // Remote Attestation — ต้องผ่านก่อน spawn (regression #19: เดิมเรียกหลัง
    // qemu spawn = รัน instance บนแพลตฟอร์มที่ attest ไม่ผ่าน, fail-open)
    verify_attestation(cfg)?;

    // Spawn QEMU (serial เขียนลงไฟล์ผ่าน `-serial file:` โดยตรง —
    // ไม่ต้องเปิด handle ค้างไว้ ไฟล์ไม่มีก็อ่านเป็นค่าว่างแล้วรอ marker)
    let serial_log = scratch.join("serial.log");
    let err_log = scratch.join("stderr.log");
    let err_file = std::fs::File::create(&err_log).map_err(|e| spawn_err("stderr log", e))?;
    qemu_cmd.stderr(err_file);
    let mut guard = KillOnDrop(Some(
        qemu_cmd.spawn().map_err(|e| spawn_err("qemu spawn", e))?,
    ));
    let child = guard.0.as_mut().expect("guard holds child");

    // รอ marker (เส้นตายรวมจาก config) ระหว่างนั้นถ้า VMM ตายก่อน = ล้มแบบดัง
    // verdict (G3): VMM ตายก่อน marker = หลักฐานละเมิด boundary → `Compromise`
    // เกินเส้นตาย = ผิดปกติแบบอธิบายได้ → `Suspect`
    let deadline = Instant::now() + Duration::from_secs(cfg.launch_timeout_secs);
    loop {
        if read_capped(&serial_log, MAX_SERIAL_BYTES).contains(&m_exit) {
            break;
        }
        if let Some(st) = child.try_wait().map_err(|e| spawn_err("wait", e))? {
            let tail = exit_diagnostic(&serial_log, &err_log);
            return Err((
                SandboxError::Spawn(format!(
                    "hardware VM exited before completion ({st}): {tail}"
                )),
                RunVerdict::Compromise("vm-died-before-marker"),
            ));
        }
        if Instant::now() > deadline {
            return Err((
                SandboxError::Spawn("hardware VM launch timed out".into()),
                RunVerdict::Suspect("deadline-exceeded"),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // parse ผล (guard จะ kill/reap VMM ที่ halt ค้างให้)
    // nonce ต่อรันทำให้ marker ชนกับ output ของ payload แทบเป็นไปไม่ได้
    let log = read_capped(&serial_log, MAX_SERIAL_BYTES);
    let stdout = between(&log, &m_out_b, &m_out_e);
    let stderr = between(&log, &m_err_b, &m_err_e);
    let code = parse_exit(&log, &m_exit)?;

    // รายงานซื่อสัตย์: อะไร enforce แล้วเข้า applied อะไรยังหย่อนเข้า degraded
    // กฎ: ข้อความใน applied ต้องตรงกับสิ่งที่ตรวจ/ทำจริงใน launch นี้เท่านั้น
    // (ห้าม claim attestation/measured-boot/disk-encryption ที่ยังเป็น stub)
    let tee_tag = match cfg.tee_type {
        TeeType::Sevsnp => "sev-snp",
        TeeType::Tdx => "tdx",
        TeeType::Generic => "generic-sim",
    };
    let mut applied = vec![
        "qemu-kvm-launch".into(),
        format!("tee-device-present:{tee_tag}"),
        "image-pin-verify".into(),
        "kernel-copy-reverify".into(),
        "rootfs-copy-reverify".into(),
        "task-quota-clamp".into(),
        "instance-dna".into(),
        "exe-allowlist".into(),
        "arg-schema".into(),
        "kvm".into(),
        "no-guest-network".into(),
    ];
    if guest_initrd.is_some() {
        applied.push("initrd-copy-reverify".into());
    }
    let mut degraded = vec![
        "env_extra: ignored (not passed to guest)".to_string(),
        "cwd: guest sees / (workspace on read-only data drive)".to_string(),
        "pids_max: not enforced in guest (no cgroup inside hardware VM)".to_string(),
        "serial-output: non-UTF-8 bytes replaced with U+FFFD (lossy)".to_string(),
    ];
    match cfg.attestation_mode {
        AttestationMode::Strict => {
            // ผ่าน verify_attestation มาแล้ว = มี TEE จริง + มี tool ขอ report
            // แต่ยังไม่มีการ verify quote กับ endorsement keys
            applied.push("attestation-tool-check".into());
            degraded.push(
                "quote-verification: not implemented (tool presence only, no KDS/quote verify yet)"
                    .into(),
            );
        }
        AttestationMode::BestEffort => {
            degraded.push("remote-attestation: best-effort (not strict)".into());
        }
        AttestationMode::None => {
            degraded.push("remote-attestation: disabled (AttestationMode::None)".into());
        }
    }
    if cfg.tee_type == TeeType::Generic {
        degraded.push("tee: none (generic simulation, no hardware isolation)".into());
    }
    if !cfg.qemu_sha256.is_empty() {
        applied.push("qemu-pin-verify".into());
    } else {
        degraded.push("vmm-binary: unpinned (set qemu_sha256 to pin QEMU)".into());
    }
    if cfg.disk_encryption.enabled {
        // host ไม่ฉีดคีย์ให้ guest — initrd ของ guest ต้อง unlock เองผ่าน vTPM
        degraded.push(
            "disk-encryption: requested, host injects no key (guest initrd must unlock via vTPM)"
                .into(),
        );
    }
    if cfg.measured_boot.enabled {
        // ยังไม่มีการอ่าน PCR จาก vTPM มาเทียบ expected_pcrs
        degraded.push("measured-boot: requested, PCR comparison not implemented yet".into());
    }
    if cfg.vtpm.enabled {
        applied.push("vtpm-device".into());
    }

    // DNA id ลง audit (ไม่มีช่องว่าง/อักขระพิเศษ — ปลอดภัยใน log)
    let dna_id = format!(
        "hw-{}-k{}-r{}-{}x{}-{}",
        match cfg.tee_type {
            TeeType::Sevsnp => "snp",
            TeeType::Tdx => "tdx",
            TeeType::Generic => "gen",
        },
        k_alt as u8,
        r_alt as u8,
        eff_vcpu,
        eff_mem,
        &nonce[..nonce.len().min(8)],
    );
    let _ = i_alt;

    Ok(ExecOutcome {
        exe: canon.to_string_lossy().to_string(),
        argv: spec.args.clone(),
        code: Some(code),
        stdout,
        stderr,
        applied,
        degraded,
        dna: dna_id,
    })
}

/// อ่านไฟล์ทั้งก้อนแบบมีเพดาน (ไฟล์ยังไม่มี = ค่าว่าง ไม่ใช่ error)
///
/// อ่านเป็น bytes แล้วแปลงแบบ lossy — ไบต์ที่ไม่ใช่ UTF-8 กลายเป็น U+FFFD
/// แทนที่จะทำให้อ่านล้มทั้งก้อน (marker เป็น ASCII จึงยังหาเจอเสมอ;
//  พฤติกรรมนี้รายงานใน `degraded`)
fn read_capped(path: &Path, cap: u64) -> String {
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    let _ = f.take(cap + 1).read_to_end(&mut bytes);
    if bytes.len() as u64 > cap {
        bytes.truncate(cap as usize);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// ท้ายไฟล์ไว้แปะใน error (ดีบักแบบดัง ไม่เงียบ)
fn read_tail(path: &Path, n: usize) -> String {
    let text = read_capped(path, MAX_SERIAL_BYTES);
    let start = text.len().saturating_sub(n);
    text[start..].replace('\n', " | ")
}

/// อ่านหลักฐานท้าย serial.log; ถ้าว่างให้ fallback ไปอ่าน stderr.log ของ QEMU (เช่น kernel format ผิดก่อนเข้า guest)
fn exit_diagnostic(serial_log: &Path, err_log: &Path) -> String {
    let serial = read_tail(serial_log, 2000);
    if !serial.trim().is_empty() {
        return serial;
    }
    read_tail(err_log, 500)
}

/// ข้อความระหว่าง marker คู่สุดท้ายที่เจอ (payload อาจมีบรรทัดอื่นปนได้
/// แต่ชน nonce ต่อรันแทบเป็นไปไม่ได้)
fn between(log: &str, begin: &str, end: &str) -> String {
    let Some(a) = log.rfind(begin) else {
        return String::new();
    };
    let rest = &log[a + begin.len()..];
    let Some(b) = rest.find(end) else {
        return String::new();
    };
    rest[..b].trim_matches('\n').to_string()
}

/// รหัสออกหลัง marker (parse ไม่ได้ = Spawn ดัง ไม่เดา)
/// verdict `Suspect`: serial ถูกป่วน/ไม่สมบูรณ์ — สืบต่อ ไม่ใช่แค่ infra ล้ม
fn parse_exit(log: &str, mark: &str) -> Result<i32, (SandboxError, RunVerdict)> {
    let Some(pos) = log.rfind(mark) else {
        return Err((
            SandboxError::Spawn("hardware exit marker missing".into()),
            RunVerdict::Suspect("exit-marker-missing"),
        ));
    };
    let rest = log[pos + mark.len()..].lines().next().unwrap_or("").trim();
    rest.parse::<i32>().map_err(|_| {
        (
            SandboxError::Spawn("hardware exit code unparsable".into()),
            RunVerdict::Suspect("exit-code-unparsable"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_guest_size_clamp() {
        let cfg = HardwareConfig {
            vcpu_count: 8,
            mem_mb: 8192,
            ..HardwareConfig::default()
        };
        let small = ResourceLimits {
            cpu: 4,
            memory_mb: 4096,
            pids_max: 64,
            storage_mb: 5120,
        };
        assert_eq!(effective_guest_size(&cfg, &small), (4, 4096));

        let big = ResourceLimits {
            cpu: 256,
            memory_mb: 1 << 20,
            pids_max: 64,
            storage_mb: 5120,
        };
        assert_eq!(effective_guest_size(&cfg, &big), (8, 8192));

        let zero = ResourceLimits {
            cpu: 0,
            memory_mb: 0,
            pids_max: 0,
            storage_mb: 0,
        };
        assert_eq!(effective_guest_size(&cfg, &zero), (1, 1024));
    }

    #[test]
    fn markers_roundtrip() {
        let (ob, oe, eb, ee, ex, fail) = markers("n9");
        let log = format!("junk\n{ob}\nhello\n{oe}\n{eb}\nbad\n{ee}\n{ex}3\ntail\n");
        assert_eq!(between(&log, &ob, &oe), "hello");
        assert_eq!(between(&log, &eb, &ee), "bad");
        assert_eq!(parse_exit(&log, &ex).unwrap(), 3);
        assert!(fail.contains("n9"));
    }

    #[test]
    fn parse_exit_missing_marker() {
        assert!(matches!(
            parse_exit("no marker here", "N-EXIT:"),
            Err((
                SandboxError::Spawn(_),
                RunVerdict::Suspect("exit-marker-missing")
            ))
        ));
    }

    #[test]
    fn parse_exit_unparsable() {
        assert!(matches!(
            parse_exit("N-EXIT:abc\n", "N-EXIT:"),
            Err((
                SandboxError::Spawn(_),
                RunVerdict::Suspect("exit-code-unparsable")
            ))
        ));
    }

    #[test]
    fn jitter_bounds() {
        for seed in 1..=200 {
            let mut rng = DnaRng::seeded(seed);
            let (v, m) = apply_jitter(8, 8192, &mut rng);
            assert!((1..=8).contains(&v), "seed {seed}: vcpu {v}");
            assert!((6144..=8192).contains(&m), "seed {seed}: mem {m}");
        }
        let mut rng = DnaRng::seeded(1);
        assert_eq!(apply_jitter(1, 1024, &mut rng), (1, 1024));
    }

    #[test]
    fn dna_rng_deterministic() {
        let (mut a, mut b) = (DnaRng::seeded(42), DnaRng::seeded(42));
        for _ in 0..100 {
            assert_eq!(a.next(), b.next());
        }
    }

    // exec surface ใหม่ (QEMU/swtpm): argv ประกอบตรง ไม่ผ่าน shell —
    // path ประหลาด (ช่องว่าง quote `;` `$()` newline) ต้องเป็น argv ก้อนเดียว
    // เสมอ ไม่มีทางถูกตีความเป็นคำสั่ง (fail-closed ด้าน arg-shape)
    #[test]
    fn shell_metachars_stay_single_argv() {
        let scratch = std::env::temp_dir();
        let evil = PathBuf::from("/tmp/a b'; rm -rf /; '\"$HOME\"/$(id)\nX");
        let cfg = HardwareConfig::default();
        let cmd = build_qemu_cmd(
            &cfg,
            Path::new("/usr/bin/qemu-system-x86_64"),
            &scratch,
            &evil,
            None,
            &evil,
            &evil,
            None,
            2,
            2048,
        )
        .expect("path ประหลาดต้องประกอบ argv ได้ (เป็นแค่ก้อน string)");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // ไม่มี `sh -c` ในสายนี้เด็ดขาด
        assert!(
            !args.iter().any(|a| a == "sh" || a == "-c"),
            "ห้ามมี shell ใน argv: {args:?}"
        );
        // path ประหลาดต้องอยู่ใน argv ก้อนเดียวครบถ้วน (ไม่ถูกตัด/แยก)
        let joined = args.join("\x00");
        assert_eq!(
            joined.matches(evil.to_string_lossy().as_ref()).count(),
            3,
            "kernel/rootfs/data ต้องเป็น argv ก้อนเดียวคนละก้อน: {args:?}"
        );
    }

    // `-machine` ต้องเป็นสตริงเดียวเสมอ (ห้ามส่งหลายรอบแล้วพึ่งว่า QEMU
    // เอาอันหลัง —พฤติกรรมนั้นไม่ได้รับประกัน)
    #[test]
    fn machine_flag_appears_exactly_once() {
        for tee in [TeeType::Sevsnp, TeeType::Tdx, TeeType::Generic] {
            let cfg = HardwareConfig {
                tee_type: tee,
                ..HardwareConfig::default()
            };
            let cmd = build_qemu_cmd(
                &cfg,
                Path::new("/usr/bin/qemu-system-x86_64"),
                &std::env::temp_dir(),
                Path::new("/k"),
                None,
                Path::new("/r"),
                Path::new("/d"),
                None,
                2,
                2048,
            )
            .unwrap();
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                args.iter().filter(|a| *a == "-machine").count(),
                1,
                "tee {tee:?}: -machine ต้องครั้งเดียว: {args:?}"
            );
            // generic ต้องไม่มี memory-encryption ปนมา
            let mpos = args.iter().position(|a| a == "-machine").unwrap();
            let mval = &args[mpos + 1];
            if tee == TeeType::Generic {
                assert!(
                    !mval.contains("memory-encryption"),
                    "generic ต้องไม่มี memory-encryption: {mval}"
                );
            } else {
                assert!(
                    mval.contains("memory-encryption"),
                    "tee {tee:?} ต้องเปิด memory-encryption: {mval}"
                );
            }
        }
    }

    // guest ต้องไม่มีเน็ตเวิร์กตั้งแต่เกิด — QEMU default มี usermode NIC
    // ถ้าไม่ปิด จึงต้องมี `-nic none` กำกับเสมอ (ไม่งั้น claim ใน applied โกหก)
    #[test]
    fn guest_network_is_always_disabled() {
        let cmd = build_qemu_cmd(
            &HardwareConfig::default(),
            Path::new("/usr/bin/qemu-system-x86_64"),
            &std::env::temp_dir(),
            Path::new("/k"),
            None,
            Path::new("/r"),
            Path::new("/d"),
            None,
            2,
            2048,
        )
        .unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let npos = args
            .iter()
            .position(|a| a == "-nic")
            .expect("ต้องมี -nic กำกับ");
        assert_eq!(args[npos + 1], "none");
    }

    // sh_escape ต้องห่อ quote ครบ (init script ฝัง args ทั้งก้อน — payload
    // ปนคำสั่งผ่าน args ไม่ได้)
    #[test]
    fn sh_escape_neutralizes_injection() {
        assert_eq!(sh_escape("a'b"), "'a'\\''b'");
        assert_eq!(sh_escape("$(id)"), "'$(id)'");
        assert_eq!(sh_escape("a;reboot"), "'a;reboot'");
    }

    #[test]
    fn exit_diagnostic_falls_back_to_qemu_stderr_when_serial_is_empty() {
        // เมื่อ QEMU ล้มก่อนเข้า guest (serial.log ว่าง) ต้องดึงข้อความจาก stderr.log มาแสดง
        let dir = std::env::temp_dir().join(format!("aivm-hw-diag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let serial = dir.join("serial.log");
        let stderr = dir.join("stderr.log");
        std::fs::write(&serial, b"").unwrap();
        std::fs::write(
            &stderr,
            b"qemu-system-x86_64: Error loading uncompressed kernel\n",
        )
        .unwrap();
        assert!(exit_diagnostic(&serial, &stderr).contains("Error loading uncompressed kernel"));
        std::fs::write(&serial, b"guest serial panic\n").unwrap();
        assert!(exit_diagnostic(&serial, &stderr).contains("guest serial panic"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
