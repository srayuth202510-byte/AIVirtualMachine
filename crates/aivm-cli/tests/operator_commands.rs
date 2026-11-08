//! เทสต์รวมคำสั่ง operator ที่ไม่ต้องมีโมเดลจริง
//! (fixture เดียวกับ tests/snapshots.rs — สร้าง VM ใน temp dir)

use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    base: PathBuf,
    vms: PathBuf,
    config: PathBuf,
    store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("aivm CLI ops {} {nonce}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let config = base.join("current.yaml");
        std::fs::write(&config, "name: trusted\nresources: {cpu: 1}\n").unwrap();
        let f = Self {
            vms: base.join("vms"),
            config,
            store: base.join("store"),
            base,
        };
        f.ok(&["create", "original", "--config", f.config.to_str().unwrap()]);
        std::fs::write(
            f.vms.join("original/workspace/src/data.txt"),
            "fixture data",
        )
        .unwrap();
        f.ok(&["snapshot", "original", "--store", f.store.to_str().unwrap()]);
        f
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_aivm"))
            .arg("--root")
            .arg(&self.vms)
            .args(args)
            .output()
            .unwrap()
    }

    fn bare(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_aivm"))
            .args(args)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn demo_selftest_passes_with_zero_exit() {
    let out = Fixture::new().bare(&["demo"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", stdout);
    assert!(stdout.contains("demo: 14/14 pass"), "{stdout}");
    assert!(stdout.contains("chain verified"), "{stdout}");
}

#[test]
fn verify_audit_reports_chain_and_catches_tampering() {
    let f = Fixture::new();
    let path = f.vms.join("original/audit.jsonl");

    let stdout = f.ok(&["verify-audit", path.to_str().unwrap()]);
    assert!(stdout.contains("chain verified"), "{stdout}");
    // รูปแบบ: "audit snapshot: <count> entries, chain verified"
    let count: u64 = stdout
        .split_whitespace()
        .nth(2)
        .and_then(|w| w.parse().ok())
        .unwrap_or(0);
    assert!(count > 0, "create ต้องเขียน audit record แล้ว: {stdout}");

    // แก้ฟิลด์ canonical หนึ่งบรรทัด → hash_entry ต้องไม่ตรง ตรวจพบเสมอ
    // (ข้อกำหนด I-7: การตัดสินที่ถูกกลืนไม่ได้หายไป)
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    let mut tampered = last.clone();
    tampered["resource"] = "tampered".into();
    let mut forged = String::new();
    if lines.len() > 1 {
        forged.push_str(&lines[..lines.len() - 1].join("\n"));
        forged.push('\n');
    }
    forged.push_str(&tampered.to_string());
    forged.push('\n');
    let forged_path = f.base.join("forged.jsonl");
    std::fs::write(&forged_path, forged).unwrap();
    let out = f.run(&["verify-audit", forged_path.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "แก้เนื้อหา record ย้อนหลังจะต้องคืนไม่ผ่าน: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn audit_command_verifies_chain_and_rejects_bad_names() {
    let f = Fixture::new();
    let good = f.ok(&["audit", "original"]);
    assert!(good.contains("chain verified"), "{good}");

    let out = f.run(&["audit", "../escape"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid VM name"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn logs_trims_to_tail_and_reports_missing_audit() {
    let f = Fixture::new();
    let text = std::fs::read_to_string(f.vms.join("original/audit.jsonl")).unwrap();
    let file_tail: Vec<&str> = text.lines().rev().take(20).collect();
    let stdout = f.ok(&["logs", "original"]);
    let out_lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(out_lines, file_tail, "logs ต้องพิมพ์ tail จากไฟล์จริง");

    // ชื่อถูกต้องแต่ยังไม่มี log → เตือนทาง stderr ไม่ล้ม
    let out = f.run(&["logs", "ghost-vm"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no audit log yet"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn run_requires_a_registered_vm() {
    let f = Fixture::new();
    let out = f.run(&["run", "ghost-vm"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not registered"), "{stderr}");
}

#[test]
fn agent_requires_a_registered_vm() {
    let f = Fixture::new();
    let out = f.run(&["agent", "ghost-vm", "task"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not registered"), "{stderr}");
}
