//! หน่วยความจำแบบ working/session/persistent — ดูสเปก §20.
//!
//! MVP-A: session memory เก็บเป็นไฟล์ใต้ `<workspace>/memory/`
//! Cube ทำหน้าที่เป็นชั้น index ส่วนการค้นคืนตั้งใจให้ง่าย
//! (กวาดแบบ prefix) ไปก่อนจนกว่าจะมี CubeRAG (Phase 6)

use aivm_cube::Cube;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub state: String,
}

pub struct Memory {
    dir: PathBuf,
}

impl Memory {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn store(&self, entry: &MemoryEntry) -> Result<(), MemoryError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| MemoryError::Io(e.to_string()))?;
        let key = redact_secrets(&entry.key);
        let safe: String = key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // regression #33: (1) กรอง secret ที่อาจหลุดเข้า memory (เดิมเก็บ
        // plaintext) (2) เขียน 0600 (เดิม std::fs::write ปล่อยให้ umask ทำ
        // เป็น world-readable)
        let stored = MemoryEntry {
            key,
            value: redact_secrets(&entry.value),
            state: redact_secrets(&entry.state),
        };
        write_private_entry(
            &self.dir.join(format!("{safe}.json")),
            &serde_json::to_string(&stored).unwrap(),
        )?;
        Ok(())
    }

    /// ดึง entry ที่เกี่ยวกับ state ปัจจุบันของ cube (MVP: ทุก entry
    /// ที่ติดป้าย state ปัจจุบัน + จำกัด 20 รายการ)
    pub fn retrieve(&self, cube: &Cube) -> Vec<MemoryEntry> {
        let want = cube.current_state().to_string();
        let mut out = vec![];
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for e in rd.filter_map(|e| e.ok()) {
            if out.len() >= 20 {
                break;
            }
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                if let Ok(entry) = serde_json::from_str::<MemoryEntry>(&t) {
                    if entry.state == want || entry.state == "ANY" {
                        out.push(entry);
                    }
                }
            }
        }
        out
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// เขียนไฟล์ 0600 (temp + rename) — ไม่พึ่ง umask ของระบบ
fn write_private_entry(path: &Path, text: &str) -> Result<(), MemoryError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_file_name(format!(".memory-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(path.parent().unwrap())?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e: std::io::Error| MemoryError::Io(e.to_string()))
}

/// กรอง secret ที่ดูออก (regression #33) — heuristic เพื่อกันค่า plaintext
/// หลุดเข้า memory ถาวร ไม่ใช่เพื่อเป็นเครื่องมือ redact ทั่วไป
fn redact_secrets(value: &str) -> String {
    // PEM bodies span whitespace and lines: never keep a partial private key.
    let lower = value.to_ascii_lowercase();
    if [
        "-----begin",
        "token",
        "secret",
        "password",
        "passwd",
        "key=",
        "bearer ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return "[redacted]".into();
    }
    let prefixes = [
        "AKIA",
        "ASIA",
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "github_pat_",
        "sk-",
    ];
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let rest = &value[i..];
        match prefixes.iter().find(|p| rest.starts_with(**p)) {
            Some(p) => {
                let run = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .map(|c| c.len_utf8())
                    .sum::<usize>();
                if run >= 20 {
                    out.push_str("[redacted]");
                    i += run;
                } else {
                    out.push_str(&rest[..p.len()]);
                    i += p.len();
                }
            }
            None => {
                let ch = rest.chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn entry(value: &str) -> MemoryEntry {
        MemoryEntry {
            key: "k".into(),
            value: value.into(),
            state: "INIT".into(),
        }
    }

    #[test]
    fn store_writes_owner_only_and_redacts_secret() {
        let dir = std::env::temp_dir().join(format!(
            "aivm-mem-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mem = Memory::new(dir.clone());
        let token = "AKIAIOSFODNN7EXAMPLE";
        mem.store(&entry(&format!("prefix {token} suffix")))
            .unwrap();

        let path = dir.join("k.json");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "memory entry ต้องเป็น 0600");
        // Replacing an old permissive file must also produce mode 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        mem.store(&entry(&format!("prefix {token} suffix")))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let stored: MemoryEntry =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(stored.value.contains("[redacted]"));
        assert!(!stored.value.contains(token));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_keeps_ordinary_text_and_short_tokens() {
        assert_eq!(redact_secrets("hello world"), "hello world");
        // "task-" มี "sk-" แต่สั้นเกิน → ไม่ redact
        assert_eq!(redact_secrets("task-force"), "task-force");
        let ghp = "ghp_".to_string() + &"a".repeat(36);
        assert_eq!(redact_secrets(&ghp), "[redacted]");
    }
    #[test]
    fn redact_covers_multiline_keys_and_labeled_credentials() {
        for value in [
            "-----BEGIN PRIVATE KEY-----\nBASE64DATA\n-----END PRIVATE KEY-----",
            "Authorization: Bearer abc123",
            "password=hunter2",
            "api_key=abcdef",
            "{\"secret\":\"value\"}",
        ] {
            assert_eq!(redact_secrets(value), "[redacted]");
        }
        assert_eq!(redact_secrets("ข้อความปกติ"), "ข้อความปกติ");
    }

    #[test]
    fn store_filters_metadata_and_ignores_predictable_temp_symlinks() {
        let dir = std::env::temp_dir().join(format!("aivm-mem-safe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".k.json.tmp")).unwrap();
        let mem = Memory::new(dir.clone());
        mem.store(&entry("safe")).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        mem.store(&MemoryEntry {
            key: token.into(),
            value: "safe".into(),
            state: token.into(),
        })
        .unwrap();
        for file in std::fs::read_dir(&dir).unwrap().flatten() {
            assert!(!file.file_name().to_string_lossy().contains(token));
            assert!(!std::fs::read_to_string(file.path())
                .unwrap()
                .contains(token));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
