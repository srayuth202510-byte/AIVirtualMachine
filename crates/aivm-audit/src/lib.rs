//! ระบบ Audit — ดูสเปก §25.
//!
//! ทุกการตัดสินถูกบันทึกไว้นอกขอบเขต agent เป็นล็อก JSONL แบบ
//! append-only ที่มี hash chaining (ตรวจจับการแก้ไขย้อนหลังได้)
//! ความลับทุกอย่างถูก redact เป็นค่าเริ่มต้น

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialization: {0}")]
    Ser(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp: i64,
    pub agent: String,
    pub session_id: String,
    pub request_id: String,
    pub state: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub policy: String,
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub rule_matched: String,
    #[serde(default)]
    pub state_transition: String,
    pub hash_prev: String,
    pub hash_entry: String,
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seq: u64,
        agent: &str,
        session_id: &str,
        request_id: &str,
        state: &str,
        action: &str,
        resource: &str,
        decision: &str,
        policy: &str,
    ) -> Self {
        Self {
            seq,
            timestamp: Utc::now().timestamp(),
            agent: agent.to_string(),
            session_id: session_id.to_string(),
            request_id: request_id.to_string(),
            state: state.to_string(),
            action: action.to_string(),
            resource: redact(resource),
            decision: decision.to_string(),
            policy: policy.to_string(),
            capability: String::new(),
            result: String::new(),
            rule_matched: String::new(),
            state_transition: String::new(),
            hash_prev: String::new(),
            hash_entry: String::new(),
        }
    }

    fn canonical(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.seq,
            self.timestamp,
            self.agent,
            self.session_id,
            self.request_id,
            self.state,
            self.action,
            self.resource,
            self.decision,
            self.policy,
            self.hash_prev
        )
    }

    pub fn seal(&mut self, prev: &str) {
        self.hash_prev = prev.to_string();
        let mut h = Sha256::new();
        h.update(self.canonical().as_bytes());
        self.hash_entry = hex(&h.finalize());
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// แทนค่าอะไรก็ตามที่ดูเหมือนความลับด้วย [REDACTED]
pub fn redact(s: &str) -> String {
    let lower = s.to_lowercase();
    if lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key=")
        || lower.contains("bearer ")
    {
        "[REDACTED]".to_string()
    } else {
        s.to_string()
    }
}

pub struct AuditWriter {
    path: PathBuf,
    seq: u64,
    prev_hash: String,
}

impl AuditWriter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        // กู้ปลาย chain เดิม เพื่อให้ rotate/restart แล้วต่อเนื่องกัน
        let (seq, prev_hash) = read_tip(&path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
            }
        }
        Ok(Self {
            path,
            seq,
            prev_hash,
        })
    }

    pub fn append(&mut self, mut rec: AuditRecord) -> Result<AuditRecord, AuditError> {
        rec.seq = self.seq;
        rec.seal(&self.prev_hash);
        let line = serde_json::to_string(&rec).map_err(|e| AuditError::Ser(e.to_string()))?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;
        f.sync_data().map_err(|e| AuditError::Io(e.to_string()))?;
        self.prev_hash = rec.hash_entry.clone();
        self.seq += 1;
        Ok(rec)
    }

    /// ตรวจความถูกต้องแบบออฟไลน์: hash chain + seq ที่เพิ่มทีละหนึ่ง
    pub fn verify(path: impl AsRef<Path>) -> Result<u64, AuditError> {
        let text =
            std::fs::read_to_string(path.as_ref()).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut prev = String::new();
        let mut expected_seq = 0u64;
        let mut count = 0u64;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord =
                serde_json::from_str(line).map_err(|e| AuditError::Ser(e.to_string()))?;
            if rec.seq != expected_seq {
                return Err(AuditError::Ser(format!(
                    "sequence gap: expected {expected_seq}, got {}",
                    rec.seq
                )));
            }
            if rec.hash_prev != prev {
                return Err(AuditError::Ser(format!(
                    "hash chain broken at seq {}",
                    rec.seq
                )));
            }
            let mut check = rec.clone();
            let claimed = rec.hash_entry.clone();
            check.hash_entry = String::new();
            check.seal(&prev);
            if check.hash_entry != claimed {
                return Err(AuditError::Ser(format!(
                    "entry hash mismatch at seq {}",
                    rec.seq
                )));
            }
            prev = claimed;
            expected_seq += 1;
            count += 1;
        }
        Ok(count)
    }
}

fn read_tip(path: &Path) -> (u64, String) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, String::new());
    };
    let mut seq = 0u64;
    let mut prev = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<AuditRecord>(line) {
            seq = rec.seq + 1;
            prev = rec.hash_entry;
        }
    }
    (seq, prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies() {
        let dir = std::env::temp_dir().join("aivm-audit-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let mut w = AuditWriter::open(&p).unwrap();
        for i in 0..3 {
            w.append(AuditRecord::new(
                0,
                "coder",
                "sess",
                &format!("req-{i}"),
                "ANALYZE",
                "read",
                "/workspace/a.rs",
                "allow",
                "coding-default",
            ))
            .unwrap();
        }
        assert_eq!(AuditWriter::verify(&p).unwrap(), 3);
    }

    #[test]
    fn secrets_redacted() {
        assert_eq!(redact("GITHUB_TOKEN=abc"), "[REDACTED]");
    }
}
