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
    agent: String,
    session: String,
    policy: String,
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
        harden_file(&path);
        Ok(Self {
            path,
            seq,
            prev_hash,
            agent: "audit".to_string(),
            session: "local".to_string(),
            policy: "rotation".to_string(),
        })
    }

    /// ระบุตัวตนสำหรับ seal record ตอน rotate (builder คืน Self เดิม
    /// runtime เรียกใช้ ส่วนผู้ใช้ open ธรรมดาได้ค่าเริ่มต้น)
    pub fn with_identity(mut self, agent: &str, session: &str, policy: &str) -> Self {
        self.agent = agent.to_string();
        self.session = session.to_string();
        self.policy = policy.to_string();
        self
    }

    /// หมุนไฟล์อย่างปลอดภัย (สเปก §25.2 ข้อ 9): เขียน seal record ปิดไฟล์
    /// เก่า เปลี่ยนชื่อเป็น archive แล้วเปิดไฟล์ใหม่ที่ chain ต่อจาก tip
    /// เดิม (seq เริ่ม 0 ใหม่ แต่ hash ผูกกันข้ามไฟล์)
    pub fn rotate(&mut self, suffix: &str) -> Result<PathBuf, AuditError> {
        let path_str = self.path.to_string_lossy();
        let mut seal = AuditRecord::new(
            0,
            &self.agent.clone(),
            &self.session.clone(),
            &format!("seal_{}", self.seq),
            "AUDIT",
            "seal",
            &path_str,
            "allow",
            &self.policy.clone(),
        );
        seal.result = format!("tip:{}", self.prev_hash);
        self.append(seal)?;
        let stem = self
            .path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "audit".to_string());
        let archived = self.path.with_file_name(format!("{stem}.{suffix}.jsonl"));
        std::fs::rename(&self.path, &archived).map_err(|e| AuditError::Io(e.to_string()))?;
        // ผนึก archive (immutable เมื่อ FS รองรับ): rotate ซ้ำด้วย suffix
        // เดิมจะล้มแบบ fail-closed แทนที่จะเขียนทับของที่ผนึกแล้ว
        let _ = std::process::Command::new("chattr")
            .arg("+i")
            .arg(&archived)
            .output();
        // ไฟล์ใหม่: seq เริ่มใหม่ แต่ prev_hash ยังชี้ tip ที่ seal แล้ว
        // ทำให้ verify_sequence ตรวจความต่อเนื่องข้ามไฟล์ได้
        self.seq = 0;
        std::fs::write(&self.path, "").map_err(|e| AuditError::Io(e.to_string()))?;
        harden_file(&self.path);
        Ok(archived)
    }

    /// ปลาย chain ปัจจุบัน (ใช้ผูกไฟล์ rotate หรือรายงานใน CLI)
    pub fn tip(&self) -> &str {
        &self.prev_hash
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
        drop(f);
        harden_file(&self.path);
        self.prev_hash = rec.hash_entry.clone();
        self.seq += 1;
        Ok(rec)
    }

    /// ตรวจความถูกต้องแบบออฟไลน์: seq เพิ่มทีละหนึ่ง + hash ทุก entry
    /// ถูกต้อง + chain ภายในไฟล์ต่อเนื่องกัน
    ///
    /// หมายเหตุเรื่อง rotate: record แรกของไฟล์ (seq 0) อนุญาตให้
    /// hash_prev ไม่ว่างได้ — นั่นคือจุดต่อจากไฟล์ก่อน (ดู
    /// `verify_sequence` ที่ตรวจรอยต่อข้ามไฟล์) ไฟล์ genesis ที่เริ่ม
    /// ใหม่จริงจะมี hash_prev ว่างตามปกติ
    pub fn verify(path: impl AsRef<Path>) -> Result<u64, AuditError> {
        let text =
            std::fs::read_to_string(path.as_ref()).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut prev: Option<String> = None;
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
            // แถวแรก: รับ hash_prev ใดก็ได้ (genesis หรือจุดต่อ rotate)
            // แถวถัดไป: ต้องต่อจาก entry ก่อนหน้าในไฟล์เดียวกัน
            if let Some(p) = &prev {
                if rec.hash_prev != *p {
                    return Err(AuditError::Ser(format!(
                        "hash chain broken at seq {}",
                        rec.seq
                    )));
                }
            }
            let mut check = rec.clone();
            let claimed = rec.hash_entry.clone();
            check.hash_entry = String::new();
            check.seal(&rec.hash_prev);
            if check.hash_entry != claimed {
                return Err(AuditError::Ser(format!(
                    "entry hash mismatch at seq {}",
                    rec.seq
                )));
            }
            prev = Some(claimed);
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

/// ล้าง flag append-only/immutable ใต้ไดเรกทอรีแบบ best-effort
/// (ให้ลบ temp dir ได้แม้ FS จะรองรับ chattr — ใช้ตอน cleanup เท่านั้น)
pub fn clear_flags(dir: &Path) {
    let _ = std::process::Command::new("chattr")
        .arg("-R")
        .arg("-a")
        .arg(dir)
        .output();
}

/// เสริมความแข็งไฟล์ล็อก (สเปก §25.2 ข้อ 2-3): สิทธิ์อ่านเขียนเฉพาะเจ้าของ
/// (0600) เสมอ ส่วน `chattr +a` (append-only ระดับ FS) พยายามแบบ
/// best-effort — ถ้า FS/สิทธิ์ไม่รองรับก็ข้ามโดยไม่ล้ม (rotate/audit
/// ระดับ record ยังคุมด้วย hash chain อยู่ดี)
fn harden_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perm = meta.permissions();
            if perm.mode() & 0o777 != 0o600 {
                perm.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perm);
            }
        }
    }
    // chattr +a: มีไบนารี + ทำได้ก็ดี ไม่มีก็ข้าม (ไม่ fail)
    if let Ok(status) = std::process::Command::new("chattr")
        .arg("+a")
        .arg(path)
        .output()
    {
        let _ = status.status.success();
    }
}

/// ตรวจทั้งสายไฟล์หลัง rotate: ทุกไฟล์ต้อง verify ผ่าน และปลาย chain
/// ของไฟล์ก่อนหน้าต้องตรงกับ hash_prev ของ record แรกในไฟล์ถัดไป
/// เรียงไฟล์จากเก่าไปใหม่ (archive ก่อน ไฟล์ live ท้ายสุด)
pub fn verify_sequence(paths: &[PathBuf]) -> Result<u64, AuditError> {
    let mut total = 0u64;
    let mut expected_prev = String::new();
    let mut first_file = true;
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut recs: Vec<AuditRecord> = vec![];
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            recs.push(serde_json::from_str(line).map_err(|e| AuditError::Ser(e.to_string()))?);
        }
        if recs.is_empty() {
            continue;
        }
        if !first_file && recs[0].hash_prev != expected_prev {
            return Err(AuditError::Ser(format!(
                "rotation boundary broken before {}",
                path.display()
            )));
        }
        total += AuditWriter::verify(path)?;
        expected_prev = recs
            .last()
            .map(|r| r.hash_entry.clone())
            .unwrap_or_default();
        first_file = false;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// temp dir ชื่อไม่ซ้ำต่อรัน + ล้าง flag ก่อนลบ (กันไฟล์ +a/+i ค้าง)
    fn test_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("aivm-audit-{tag}-{nanos}"))
    }

    fn clean(dir: &Path) {
        clear_flags(dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chain_verifies() {
        let dir = test_dir("chain");
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
        clean(&dir);
    }

    #[test]
    fn secrets_redacted() {
        assert_eq!(redact("GITHUB_TOKEN=abc"), "[REDACTED]");
    }

    fn test_record(w: &mut AuditWriter, id: &str) {
        w.append(AuditRecord::new(
            0,
            "coder",
            "sess",
            id,
            "ANALYZE",
            "read",
            "/workspace/a.rs",
            "allow",
            "coding-default",
        ))
        .unwrap();
    }

    #[test]
    fn rotation_keeps_chain_continuous() {
        let dir = test_dir("rotate");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let mut w = AuditWriter::open(&p)
            .unwrap()
            .with_identity("coder", "sess", "p");
        test_record(&mut w, "r1");
        test_record(&mut w, "r2");
        let archived = w.rotate("20260101").unwrap();
        assert!(archived.exists());
        test_record(&mut w, "r3");
        // ไฟล์ archive มี 3 แถว (2 record + seal) ไฟล์ live มี 1 แถว
        assert_eq!(AuditWriter::verify(&archived).unwrap(), 3);
        assert_eq!(AuditWriter::verify(&p).unwrap(), 1);
        // สายทั้งหมดต่อเนื่องกัน: 2 + seal + 1
        assert_eq!(verify_sequence(&[archived, p]).unwrap(), 4);
        // seq ของไฟล์ใหม่เริ่ม 0 ใหม่ แต่ hash ผูกกับ tip เก่า
        let text = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let first: AuditRecord = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first.seq, 0);
        clean(&dir);
    }

    #[test]
    fn tamper_is_detected() {
        let dir = test_dir("tamper");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let mut w = AuditWriter::open(&p).unwrap();
        test_record(&mut w, "r1");
        test_record(&mut w, "r2");
        // แก้ไขย้อนหลังหนึ่งไบต์: verify ต้องตก
        let mut text = std::fs::read_to_string(&p).unwrap();
        text = text.replacen("ANALYZE", "ANALYZE!", 1);
        std::fs::write(&p, text).unwrap();
        assert!(AuditWriter::verify(&p).is_err());
        clean(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn audit_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("perm");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let mut w = AuditWriter::open(&p).unwrap();
        test_record(&mut w, "r1");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        clean(&dir);
    }
}
