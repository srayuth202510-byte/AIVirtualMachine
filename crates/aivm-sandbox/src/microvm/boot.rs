//! ขั้น boot/exec จริงของ MicroVM (Linux เท่านั้น).
//!
//! วิธี: **drive-stuffing** — ก็อป rootfs ที่ verify แล้วไป scratch (ห้ามแตะ
//! ไฟล์ pin) ฉีด `/sbin/aivm-init` ด้วย debugfs สร้าง data drive ด้วย
//! `mkfs.ext4 -d` ใส่ exe + ldd closure + อาร์กิวเมนต์ที่ escape แล้ว บูตด้วย
//! `init=` จับผลทาง serial console ด้วย marker ต่อ nonce แล้ว `poweroff`
//! (guest halt แล้ว VMM ไม่ exit เอง host จึง kill เก็บงานเสมอ)
//!
//! เครื่องมือ host ที่เรียก (`ldd`, `mkfs.ext4`, `debugfs`, `firecracker`)
//! คือ infra ของ operator ไม่ใช่ input ของ agent argv ทุกคำสั่งตายตัว
//! ยกเว้น path ที่ผ่าน validate/verify มาแล้ว — agent ปนคำสั่งไม่ได้

use super::{ExecOutcome, ExecSpec, MicroVmConfig};
use crate::SandboxError;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// เส้นตายรวมตั้งแต่ spawn จนจับ marker ได้ (boot ปกติใช้ไม่กี่วินาที)
const BOOT_DEADLINE_SECS: u64 = 60;
/// เพดาน serial log ที่อ่านมา parse (กันหน่วยความจำบวม)
const MAX_SERIAL_BYTES: u64 = 2 * 1024 * 1024;
/// พื้นที่เผื่อใน data image นอกเหนือไฟล์ staging
const DATA_IMAGE_SPARE_MB: u64 = 16;
/// ขนาด data image อย่างน้อย (mkfs เล็กเกินไปล้ม)
const DATA_IMAGE_MIN_MB: u64 = 32;

/// ฆ่า child ทิ้งเสมอเมื่อหลุด scope (fail-closed: ไม่มี VM กำพร้า)
struct KillOnDrop(Option<Child>);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
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

fn ldd_closure(exe: &Path) -> Result<Closure, SandboxError> {
    let spawn_err = |e: std::io::Error| SandboxError::Spawn(format!("ldd failed: {e}"));
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
        return Err(SandboxError::Spawn(format!(
            "ldd rejected {}",
            exe.display()
        )));
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
fn stage_file(staging: &Path, abs: &Path) -> Result<(), SandboxError> {
    let rel = abs
        .strip_prefix("/")
        .map_err(|_| SandboxError::Invalid("closure path must be absolute".into()))?;
    let dst = staging.join(rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SandboxError::Spawn(format!("staging mkdir failed: {e}")))?;
    }
    let meta = std::fs::metadata(abs)
        .map_err(|e| SandboxError::Spawn(format!("closure stat failed {}: {e}", abs.display())))?;
    if !meta.is_file() {
        return Err(SandboxError::Spawn(format!(
            "closure not a file: {}",
            abs.display()
        )));
    }
    std::fs::copy(abs, &dst)
        .map_err(|e| SandboxError::Spawn(format!("staging copy failed: {e}")))?;
    std::fs::set_permissions(&dst, meta.permissions())
        .map_err(|e| SandboxError::Spawn(format!("staging chmod failed: {e}")))?;
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
fn host_tool(prog: &str, args: &[&str]) -> Result<String, SandboxError> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| SandboxError::Spawn(format!("{prog} spawn failed: {e}")))?;
    if !out.status.success() {
        return Err(SandboxError::Spawn(format!(
            "{prog} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// PUT JSON ไป Firecracker API ผ่าน unix socket (ต่อใหม่ทุกครั้ง)
/// 2xx = ผ่าน นอกนั้น = `Spawn` พร้อมเศษ response ไว้ดีบัก (fail-closed แต่ดัง)
///
/// หมายเหตุ: server ตอบ `Connection: keep-alive` เสมอ (เมิน `close` ของเรา)
/// จึงห้าม `read_to_end` — ต้อง parse header หา Content-Length แล้วอ่าน
/// แค่ body ตามนั้น ไม่งั้นค้างจน timeout
fn fc_put(sock: &Path, route: &str, body: &str) -> Result<(), SandboxError> {
    let mut s = UnixStream::connect(sock)
        .map_err(|e| SandboxError::Spawn(format!("microvm api connect failed: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "PUT {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())
        .map_err(|e| SandboxError::Spawn(format!("microvm api write failed: {e}")))?;
    // อ่านจนจบ header ก่อน (เพดานกันบวม)
    let mut raw = vec![];
    let mut buf = [0u8; 4096];
    let header_len = loop {
        let n = s
            .read(&mut buf)
            .map_err(|e| SandboxError::Spawn(format!("microvm api read failed: {e}")))?;
        if n == 0 {
            return Err(SandboxError::Spawn("microvm api closed early".into()));
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(p) = find_sub(&raw, b"\r\n\r\n") {
            break p + 4;
        }
        if raw.len() > 64 * 1024 {
            return Err(SandboxError::Spawn("microvm api headers too large".into()));
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_len]);
    let code: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| SandboxError::Spawn("microvm api bad response".into()))?;
    // อ่าน body ตาม Content-Length (204 ไม่มี body = 0)
    let mut content_len = 0usize;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body_got = raw.len() - header_len;
    while body_got < content_len {
        let n = s
            .read(&mut buf)
            .map_err(|e| SandboxError::Spawn(format!("microvm api read failed: {e}")))?;
        if n == 0 {
            break;
        }
        body_got += n;
    }
    if !(200..300).contains(&code) {
        let snippet: String = head.chars().take(300).collect();
        return Err(SandboxError::Spawn(format!(
            "microvm api {route} -> {code}: {snippet}"
        )));
    }
    Ok(())
}

/// หาตำแหน่ง slice ย่อยใน buffer (ไม่ใช้ memchr เพื่อไม่เพิ่ม dependency)
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// รอไฟล์ socket ปรากฏ (firecracker bind ช้าได้)
fn wait_socket(sock: &Path, timeout: Duration) -> Result<(), SandboxError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if UnixStream::connect(sock).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(SandboxError::Spawn(
        "microvm api socket never appeared".into(),
    ))
}

/// ข้อความระหว่าง marker คู่แรกที่เจอ (payload อาจมีบรรทัดอื่นปนได้
/// แต่ชน nonce ต่อรันแทบเป็นไปไม่ได้)
fn between(log: &str, begin: &str, end: &str) -> String {
    let Some(a) = log.find(begin) else {
        return String::new();
    };
    let rest = &log[a + begin.len()..];
    let Some(b) = rest.find(end) else {
        return String::new();
    };
    rest[..b].trim_matches('\n').to_string()
}

/// boot + รัน + จับผล (เรียกหลังผ่านประตู spec/shape/supply chain/host แล้ว)
pub(super) fn boot_and_run(
    spec: &ExecSpec,
    canon: &Path,
    cfg: &MicroVmConfig,
    fc_bin: &Path,
) -> Result<ExecOutcome, SandboxError> {
    let spawn_err =
        |what: &str, e: std::io::Error| SandboxError::Spawn(format!("microvm {what} failed: {e}"));
    // nonce ต่อรันกัน marker ชนกับ output ของ payload
    let nonce = format!(
        "{:x}{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let scratch = std::env::temp_dir().join(format!("aivm-uvm-run-{nonce}"));
    std::fs::create_dir_all(&scratch).map_err(|e| spawn_err("scratch", e))?;
    let r = boot_and_run_inner(spec, canon, cfg, fc_bin, &scratch, &nonce);
    // ล้าง scratch แบบ best-effort (ผลลัพธ์ parse ไว้หมดแล้ว)
    // ตั้ง AIVM_MICROVM_KEEP_SCRATCH=1 เพื่อเก็บไว้ดีบัก serial log
    if std::env::var("AIVM_MICROVM_KEEP_SCRATCH").is_err() {
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        eprintln!("microvm scratch kept at {}", scratch.display());
    }
    r
}

#[allow(clippy::too_many_lines)]
fn boot_and_run_inner(
    spec: &ExecSpec,
    canon: &Path,
    cfg: &MicroVmConfig,
    fc_bin: &Path,
    scratch: &Path,
    nonce: &str,
) -> Result<ExecOutcome, SandboxError> {
    let spawn_err =
        |what: &str, e: std::io::Error| SandboxError::Spawn(format!("microvm {what} failed: {e}"));
    // 1. ก็อป rootfs ที่ verify แล้วไป scratch (ห้ามเขียนไฟล์ pin ต้นฉบับ)
    let guest_root = scratch.join("root.img");
    std::fs::copy(&cfg.rootfs_path, &guest_root).map_err(|e| spawn_err("rootfs copy", e))?;
    let kernel_abs = cfg
        .kernel_path
        .canonicalize()
        .map_err(|e| SandboxError::Spawn(format!("microvm kernel path failed: {e}")))?;

    // 2. staging: exe + loader + libs คงโครง absolute path
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
    // 3. init script (args ฝังแบบ escape แล้วทั้งก้อน)
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
    let (m_out_b, m_out_e, m_err_b, m_err_e, m_exit) = (
        format!("AIVM-{nonce}-OUT-BEGIN"),
        format!("AIVM-{nonce}-OUT-END"),
        format!("AIVM-{nonce}-ERR-BEGIN"),
        format!("AIVM-{nonce}-ERR-END"),
        format!("AIVM-{nonce}-EXIT:"),
    );
    let init_sh = format!(
        "#!/bin/sh\nmkdir -p /mnt/data\nmount -t tmpfs tmpfs /tmp 2>/dev/null\nmount -t ext4 -o ro /dev/vdb /mnt/data || {{ echo \"AIVM-{nonce}-FAIL-mount\"; poweroff -f; }}\n{invoke} >/tmp/o 2>/tmp/e\nCODE=$?\necho \"{m_out_b}\"; cat /tmp/o; echo \"{m_out_e}\"\necho \"{m_err_b}\"; cat /tmp/e; echo \"{m_err_e}\"\necho \"{m_exit}$CODE\"\npoweroff -f\n"
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
            guest_root
                .to_str()
                .ok_or_else(|| SandboxError::Spawn("microvm scratch path not utf-8".into()))?,
        ],
    )?;
    host_tool(
        "debugfs",
        &[
            "-w",
            "-R",
            "set_inode_field /sbin/aivm-init mode 0100755",
            guest_root
                .to_str()
                .ok_or_else(|| SandboxError::Spawn("microvm scratch path not utf-8".into()))?,
        ],
    )?;

    // 4. data image จาก staging (mkfs ไม่ต้อง root)
    let bytes = dir_size_bytes(&staging);
    let size_mb = ((bytes / (1024 * 1024)) + DATA_IMAGE_SPARE_MB).max(DATA_IMAGE_MIN_MB);
    let data_img = scratch.join("data.img");
    host_tool(
        "mkfs.ext4",
        &[
            "-q",
            "-d",
            staging
                .to_str()
                .ok_or_else(|| SandboxError::Spawn("microvm scratch path not utf-8".into()))?,
            data_img
                .to_str()
                .ok_or_else(|| SandboxError::Spawn("microvm scratch path not utf-8".into()))?,
            &format!("{size_mb}M"),
        ],
    )?;

    // 5. spawn firecracker (serial → ไฟล์, ไม่มีเน็ตเวิร์กเลย)
    let sock = scratch.join("api.sock");
    let serial_log = scratch.join("serial.log");
    let serial_file = std::fs::File::create(&serial_log).map_err(|e| spawn_err("serial log", e))?;
    let err_log = scratch.join("stderr.log");
    let err_file = std::fs::File::create(&err_log).map_err(|e| spawn_err("stderr log", e))?;
    let mut guard = KillOnDrop(Some(
        Command::new(fc_bin)
            .arg("--api-sock")
            .arg(&sock)
            .stdin(Stdio::null())
            .stdout(serial_file)
            .stderr(err_file)
            .env_clear()
            .spawn()
            .map_err(|e| spawn_err("firecracker spawn", e))?,
    ));
    let child = guard.0.as_mut().expect("guard holds child");

    // 6. configure ผ่าน API (ล้มขั้นไหนก็ fail-closed ไม่ boot)
    wait_socket(&sock, Duration::from_secs(5))?;
    fc_put(
        &sock,
        "/machine-config",
        &format!(
            "{{\"vcpu_count\":{},\"mem_size_mib\":{}}}",
            cfg.vcpu_count, cfg.mem_mb
        ),
    )?;
    fc_put(
        &sock,
        "/boot-source",
        &format!(
            "{{\"kernel_image_path\":{},\"boot_args\":\"console=ttyS0 reboot=t panic=1 pci=off init=/sbin/aivm-init\"}}",
            serde_json_string(&kernel_abs.to_string_lossy())
        ),
    )?;
    fc_put(
        &sock,
        "/drives/rootfs",
        &format!(
            "{{\"drive_id\":\"rootfs\",\"path_on_host\":{},\"is_root_device\":true,\"is_read_only\":false}}",
            serde_json_string(&guest_root.to_string_lossy())
        ),
    )?;
    fc_put(
        &sock,
        "/drives/data",
        &format!(
            "{{\"drive_id\":\"data\",\"path_on_host\":{},\"is_root_device\":false,\"is_read_only\":true}}",
            serde_json_string(&data_img.to_string_lossy())
        ),
    )?;
    fc_put(&sock, "/actions", "{\"action_type\":\"InstanceStart\"}")?;

    // 7. รอ marker (เส้นตายรวม) ระหว่างนั้นถ้า VMM ตายก่อน = ล้มแบบดัง
    let deadline = Instant::now() + Duration::from_secs(BOOT_DEADLINE_SECS);
    let exit_mark = format!("AIVM-{nonce}-EXIT:");
    loop {
        if serial_file_contains(&serial_log, &exit_mark, MAX_SERIAL_BYTES) {
            break;
        }
        if let Some(st) = child.try_wait().map_err(|e| spawn_err("wait", e))? {
            let tail = read_tail(&serial_log, 2000);
            return Err(SandboxError::Spawn(format!(
                "microvm exited before completion ({st}): {tail}"
            )));
        }
        if Instant::now() > deadline {
            return Err(SandboxError::Spawn("microvm run timed out".into()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // 8. parse ผล (guard จะ kill/reap VMM ที่ halt ค้างให้)
    // nonce ต่อรันทำให้ marker ชนกับ output ของ payload แทบเป็นไปไม่ได้
    let log = read_capped(&serial_log, MAX_SERIAL_BYTES);
    let stdout = between(&log, &m_out_b, &m_out_e);
    let stderr = between(&log, &m_err_b, &m_err_e);
    let code = parse_exit(&log, &exit_mark)?;
    let _ = child;
    Ok(ExecOutcome {
        exe: canon.to_string_lossy().to_string(),
        argv: spec.args.clone(),
        code: Some(code),
        stdout,
        stderr,
        applied: vec![
            "microvm-boot".into(),
            "image-pin-verify".into(),
            "exe-allowlist".into(),
            "arg-schema".into(),
            "kvm".into(),
            "no-guest-network".into(),
        ],
        degraded: vec![
            "env_extra: ignored (not passed to guest)".into(),
            "cwd: guest sees / (workspace on read-only data drive)".into(),
            "serial-output: must be UTF-8".into(),
        ],
    })
}

/// สตริงเป็น JSON string literal (escape แค่ " กับ \ — path ไม่มีตัวอื่น)
fn serde_json_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// อ่านไฟล์ทั้งก้อนแบบมีเพดาน (เกินเพดานตัดทิ้ง — fail-open ไม่ได้เลยตัด)
fn read_capped(path: &Path, cap: u64) -> String {
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = String::new();
    let _ = f.take(cap + 1).read_to_string(&mut buf);
    if buf.len() as u64 > cap {
        buf.truncate(cap as usize);
    }
    buf
}

/// มี marker ในไฟล์หรือยัง (อ่านแบบมีเพดาน)
fn serial_file_contains(path: &Path, mark: &str, cap: u64) -> bool {
    read_capped(path, cap).contains(mark)
}

/// ท้ายไฟล์ไว้แปะใน error (ดีบักแบบดัง ไม่เงียบ)
fn read_tail(path: &Path, n: usize) -> String {
    let text = read_capped(path, MAX_SERIAL_BYTES);
    let start = text.len().saturating_sub(n);
    text[start..].replace('\n', " | ")
}

/// รหัสออกหลัง marker (parse ไม่ได้ = Spawn ดัง ไม่เดา)
fn parse_exit(log: &str, mark: &str) -> Result<i32, SandboxError> {
    let Some(pos) = log.rfind(mark) else {
        return Err(SandboxError::Spawn("microvm exit marker missing".into()));
    };
    let rest = log[pos + mark.len()..].lines().next().unwrap_or("").trim();
    rest.parse::<i32>()
        .map_err(|_| SandboxError::Spawn("microvm exit code unparsable".into()))
}
