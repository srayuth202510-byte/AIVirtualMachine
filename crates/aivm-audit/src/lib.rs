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

mod rotation;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialization: {0}")]
    Ser(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    #[serde(default = "legacy_hash_version")]
    pub hash_version: u8,
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

fn legacy_hash_version() -> u8 {
    1
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
            hash_version: 2,
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
        if self.hash_version == 2 {
            return serde_json::to_string(&(
                self.hash_version,
                self.seq,
                self.timestamp,
                &self.agent,
                &self.session_id,
                &self.request_id,
                &self.state,
                &self.action,
                &self.resource,
                &self.decision,
                &self.policy,
                &self.capability,
                &self.result,
                &self.rule_matched,
                &self.state_transition,
                &self.hash_prev,
            ))
            .expect("string fields serialize");
        }
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
        rotation::recover(&path, &mut |_| Ok(()))?;
        // กู้ปลาย chain เดิม เพื่อให้ rotate/restart แล้วต่อเนื่องกัน
        if path.exists() {
            Self::verify(&path)?;
        }
        let (seq, prev_hash) = read_tip(&path)?;
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

    /// Rotate with a durable recovery journal. The new log begins with a
    /// continuation record linking it to the sealed archive, including on restart.
    /// Callers must serialize writers to this path (the supervisor uses a lease).
    pub fn rotate(&mut self, suffix: &str) -> Result<PathBuf, AuditError> {
        self.rotate_with_hook(suffix, &mut |_| Ok(()))
    }

    fn rotate_with_hook(
        &mut self,
        suffix: &str,
        hook: &mut impl FnMut(&str) -> Result<(), AuditError>,
    ) -> Result<PathBuf, AuditError> {
        self.recover_rotation()?;
        let archived = rotation::archive_path(&self.path, suffix)?;
        // symlink_metadata also detects dangling symlinks before any seal.
        match std::fs::symlink_metadata(&archived) {
            Ok(_) => return Err(AuditError::Io("archive already exists".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AuditError::Io(e.to_string())),
        }
        let mut seal = AuditRecord::new(
            0,
            &self.agent,
            &self.session,
            &format!("seal_{}", self.seq),
            "AUDIT",
            "seal",
            &self.path.to_string_lossy(),
            "allow",
            &self.policy,
        );
        seal.result = format!("tip:{}", self.prev_hash);
        let seal = self.append(seal)?;
        hook("sealed")?;
        rotation::publish(&self.path, &archived, seal, hook)?;
        hook("journal")?;
        let recovery = rotation::recover(&self.path, hook);
        let tip = read_tip(&self.path);
        if let Ok((seq, hash)) = &tip {
            self.seq = *seq;
            self.prev_hash = hash.clone();
        }
        recovery?;
        tip?;
        Ok(archived)
    }

    fn recover_rotation(&mut self) -> Result<(), AuditError> {
        let recovery = rotation::recover(&self.path, &mut |_| Ok(()));
        if !matches!(recovery, Ok(false)) {
            let tip = read_tip(&self.path);
            if let Ok((seq, hash)) = &tip {
                self.seq = *seq;
                self.prev_hash = hash.clone();
            }
            recovery?;
            tip?;
        }
        Ok(())
    }

    /// ปลาย chain ปัจจุบัน (ใช้ผูกไฟล์ rotate หรือรายงานใน CLI)
    pub fn tip(&self) -> &str {
        &self.prev_hash
    }

    pub fn append(&mut self, rec: AuditRecord) -> Result<AuditRecord, AuditError> {
        self.append_with_hook(rec, &mut |_| Ok(()))
    }

    /// hook ใช้ทดสอบ crash boundaries; caller ต้องถือ exclusive writer lease
    pub fn append_with_hook(
        &mut self,
        mut rec: AuditRecord,
        hook: &mut impl FnMut(&str) -> std::io::Result<()>,
    ) -> Result<AuditRecord, AuditError> {
        self.recover_rotation()?;
        rec.seq = self.seq;
        rec.seal(&self.prev_hash);
        let line = serde_json::to_string(&rec).map_err(|e| AuditError::Ser(e.to_string()))?;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .mode(0o600)
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        hook("opened").map_err(|e| AuditError::Io(e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;
        hook("written").map_err(|e| AuditError::Io(e.to_string()))?;
        f.sync_data().map_err(|e| AuditError::Io(e.to_string()))?;
        hook("synced").map_err(|e| AuditError::Io(e.to_string()))?;
        // fsync directory ด้วยเพื่อให้ชื่อ log ใหม่ durable ก่อนลบ transaction journal
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|e| AuditError::Io(e.to_string()))?;
        hook("directory-synced").map_err(|e| AuditError::Io(e.to_string()))?;
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
            if !matches!(rec.hash_version, 1 | 2) {
                return Err(AuditError::Ser("unsupported audit hash version".into()));
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

fn read_tip(path: &Path) -> Result<(u64, String), AuditError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, String::new())),
        Err(e) => return Err(AuditError::Io(e.to_string())),
    };
    let mut seq = 0u64;
    let mut prev = String::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let rec: AuditRecord =
            serde_json::from_str(line).map_err(|e| AuditError::Ser(e.to_string()))?;
        seq = rec
            .seq
            .checked_add(1)
            .ok_or_else(|| AuditError::Ser("audit sequence overflow".into()))?;
        prev = rec.hash_entry;
    }
    Ok((seq, prev))
}

/// ล้าง flag append-only/immutable ใต้ไดเรกทอรีแบบ best-effort
/// (ให้ลบ temp dir ได้แม้ FS จะรองรับ chattr — ใช้ตอน cleanup เท่านั้น)
pub fn clear_flags(dir: &Path) {
    for flag in ["-i", "-a"] {
        let _ = std::process::Command::new("chattr")
            .args(["-R", flag])
            .arg(dir)
            .output();
    }
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
        // การตรวจทั้งประวัติต้องเริ่ม genesis; verify() ใช้ตรวจ continuation เดี่ยวได้
        if first_file && !recs[0].hash_prev.is_empty() {
            return Err(AuditError::Ser(
                "audit genesis missing: incomplete history".into(),
            ));
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
        // archive: two actions + seal; live: continuation + action.
        assert_eq!(AuditWriter::verify(&archived).unwrap(), 3);
        assert_eq!(AuditWriter::verify(&p).unwrap(), 2);
        assert_eq!(verify_sequence(&[archived, p]).unwrap(), 5);
        // seq ของไฟล์ใหม่เริ่ม 0 ใหม่ แต่ hash ผูกกับ tip เก่า
        let text = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let first: AuditRecord = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first.seq, 0);
        clean(&dir);
    }

    #[test]
    fn full_history_verification_rejects_a_missing_first_archive() {
        let dir = test_dir("missing-genesis");
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&live).unwrap();
        test_record(&mut writer, "before");
        let archive = writer.rotate("001").unwrap();
        test_record(&mut writer, "after");
        assert!(verify_sequence(&[archive.clone(), live.clone()]).is_ok());
        assert!(AuditWriter::verify(&live).is_ok());
        assert!(verify_sequence(std::slice::from_ref(&live))
            .unwrap_err()
            .to_string()
            .contains("genesis missing"));
        clear_flags(&dir);
        std::fs::remove_file(archive).unwrap();
        assert!(verify_sequence(&[live]).is_err());
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

    #[test]
    fn every_evidence_field_is_sealed() {
        let dir = test_dir("evidence");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "r1");
        clear_flags(&dir);
        let original: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        for field in ["result", "capability", "rule_matched", "state_transition"] {
            let mut changed = original.clone();
            changed[field] = "FORGED".into();
            std::fs::write(&path, serde_json::to_string(&changed).unwrap()).unwrap();
            assert!(
                AuditWriter::verify(&path).is_err(),
                "unsealed field: {field}"
            );
            assert!(
                AuditWriter::open(&path).is_err(),
                "must not append to corrupt chain"
            );
        }
        clean(&dir);
    }

    #[test]
    fn rotation_never_overwrites_an_archive() {
        let dir = test_dir("rotate-collision");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "r1");
        let archive = writer.rotate("same").unwrap();
        let old = std::fs::read(&archive).unwrap();
        test_record(&mut writer, "r2");
        let active_before = std::fs::read(&path).unwrap();
        assert!(writer.rotate("same").is_err());
        assert_eq!(std::fs::read(&archive).unwrap(), old);
        assert_eq!(std::fs::read(&path).unwrap(), active_before);
        assert_eq!(AuditWriter::verify(&path).unwrap(), 2);
        clean(&dir);
    }

    #[test]
    fn restart_after_rotation_preserves_the_archive_link() {
        let dir = test_dir("rotate-restart");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        let archive = writer.rotate("01").unwrap();
        let archived_bytes = std::fs::read(&archive).unwrap();
        drop(writer);
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "after");
        assert_eq!(std::fs::read(&archive).unwrap(), archived_bytes);
        assert_eq!(verify_sequence(&[archive, path]).unwrap(), 4);
        clean(&dir);
    }

    // Invoked only by rotation_recovers_after_process_exit_at_each_stage.
    #[test]
    #[ignore = "subprocess helper for the rotation crash test"]
    fn rotation_crash_worker() {
        let path = PathBuf::from(std::env::var_os("AIVM_AUDIT_CRASH_PATH").unwrap());
        let target = std::env::var("AIVM_AUDIT_CRASH_STAGE").unwrap();
        let mut writer = AuditWriter::open(&path).unwrap();
        writer
            .rotate_with_hook("01", &mut |stage| {
                if stage == target {
                    // Exit immediately without unwinding or running Rust destructors.
                    std::process::exit(77);
                }
                Ok(())
            })
            .unwrap();
        panic!("crash stage was not reached: {target}");
    }

    #[test]
    fn rotation_recovers_after_process_exit_at_each_stage() {
        use std::os::unix::fs::PermissionsExt;
        for stage in [
            "sealed",
            "journal_prepared",
            "journal_published",
            "journal",
            "archive",
            "prepared",
            "unhardened",
            "swapped",
            "committed",
        ] {
            let dir = test_dir(stage);
            let path = dir.join("audit.jsonl");
            let mut writer = AuditWriter::open(&path).unwrap();
            test_record(&mut writer, "before");
            drop(writer);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::rotation_crash_worker", "--ignored"])
                .env("AIVM_AUDIT_CRASH_PATH", &path)
                .env("AIVM_AUDIT_CRASH_STAGE", stage)
                .output()
                .unwrap()
                .status;
            assert_eq!(status.code(), Some(77), "{stage}");
            let archive = dir.join("audit.01.jsonl");
            let before = std::fs::read(&archive).ok();
            let mut writer = AuditWriter::open(&path).unwrap();
            if let Some(bytes) = before {
                assert_eq!(std::fs::read(&archive).unwrap(), bytes, "{stage}");
            }
            let archive_bytes = std::fs::read(&archive).ok();
            test_record(&mut writer, "after");
            if let Some(bytes) = archive_bytes {
                assert_eq!(std::fs::read(&archive).unwrap(), bytes, "{stage}");
                assert_eq!(
                    verify_sequence(&[archive.clone(), path.clone()]).unwrap(),
                    4,
                    "{stage}"
                );
                assert_eq!(
                    std::fs::metadata(archive).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            } else {
                // Before journal publication, the sealed log remains active.
                assert!(matches!(stage, "sealed" | "journal_prepared"));
                assert_eq!(AuditWriter::verify(&path).unwrap(), 3);
            }
            assert!(!dir.join("audit.jsonl.rotation").exists(), "{stage}");
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            clean(&dir);
        }
    }

    #[test]
    fn failed_rotation_can_resume_on_the_same_writer() {
        let dir = test_dir("rotate-error");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        // A directory in place of the staging file forces a real I/O failure
        // after the archive has been published, before the active-file swap.
        let obstacle = dir.join("audit.jsonl.rotation-next");
        std::fs::create_dir(&obstacle).unwrap();
        assert!(writer.rotate("01").is_err());
        let archive = dir.join("audit.01.jsonl");
        let bytes = std::fs::read(&archive).unwrap();
        std::fs::remove_dir(obstacle).unwrap();
        test_record(&mut writer, "after");
        assert_eq!(std::fs::read(&archive).unwrap(), bytes);
        assert_eq!(verify_sequence(&[archive, path]).unwrap(), 4);
        clean(&dir);
    }

    #[test]
    fn recovery_refuses_a_corrupt_journal_without_changing_the_log() {
        let dir = test_dir("rotate-corrupt");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        let before = std::fs::read(&path).unwrap();
        std::fs::write(dir.join("audit.jsonl.rotation"), "{partial").unwrap();
        assert!(AuditWriter::open(&path).is_err());
        assert!(writer
            .append(AuditRecord::new(
                0, "a", "s", "r", "AUDIT", "read", "p", "allow", "p"
            ))
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.join("audit.01.jsonl").exists());
        clean(&dir);
    }

    #[test]
    fn recovery_refuses_an_unrelated_archive() {
        let dir = test_dir("rotate-conflict");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        assert!(writer
            .rotate_with_hook("01", &mut |stage| {
                if stage == "journal" {
                    return Err(AuditError::Io("injected failure".into()));
                }
                Ok(())
            })
            .is_err());
        let archive = dir.join("audit.01.jsonl");
        std::fs::write(&archive, "unrelated evidence").unwrap();
        let active = std::fs::read(&path).unwrap();
        assert!(AuditWriter::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), active);
        assert_eq!(std::fs::read(&archive).unwrap(), b"unrelated evidence");
        clean(&dir);
    }

    #[test]
    fn multiple_rotations_remain_continuous_after_restart() {
        let dir = test_dir("rotate-multiple");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        let first = writer.rotate("01").unwrap();
        drop(writer);
        let mut writer = AuditWriter::open(&path).unwrap();
        let second = writer.rotate("02").unwrap();
        drop(writer);
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "after");
        assert_eq!(verify_sequence(&[first, second, path]).unwrap(), 6);
        clean(&dir);
    }

    #[test]
    fn invalid_or_dangling_archive_names_leave_the_chain_untouched() {
        let dir = test_dir("rotate-invalid");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        let before = std::fs::read(&path).unwrap();
        for suffix in ["", "../outside", "a/b", "a\\b"] {
            assert!(writer.rotate(suffix).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let archive = dir.join("audit.link.jsonl");
        std::os::unix::fs::symlink(dir.join("missing"), &archive).unwrap();
        assert!(writer.rotate("link").is_err());
        assert!(std::fs::symlink_metadata(archive)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        clean(&dir);
    }

    #[test]
    fn recovery_rebuilds_partial_staging_or_a_missing_active_log() {
        for missing_active in [false, true] {
            let dir = test_dir("rotate-staging");
            let path = dir.join("audit.jsonl");
            let mut writer = AuditWriter::open(&path).unwrap();
            test_record(&mut writer, "before");
            assert!(writer
                .rotate_with_hook("01", &mut |stage| {
                    if stage == "prepared" {
                        return Err(AuditError::Io("interrupted".into()));
                    }
                    Ok(())
                })
                .is_err());
            drop(writer);
            let archive = dir.join("audit.01.jsonl");
            let bytes = std::fs::read(&archive).unwrap();
            std::fs::write(dir.join("audit.jsonl.rotation-next"), "{partial").unwrap();
            if missing_active {
                clear_flags(&dir);
                std::fs::remove_file(&path).unwrap();
            }
            let mut writer = AuditWriter::open(&path).unwrap();
            test_record(&mut writer, "after");
            assert_eq!(std::fs::read(&archive).unwrap(), bytes);
            assert_eq!(verify_sequence(&[archive, path]).unwrap(), 4);
            clean(&dir);
        }
    }

    #[test]
    fn recovery_preserves_a_partial_active_record_and_stops() {
        let dir = test_dir("rotate-partial-active");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        assert!(writer
            .rotate_with_hook("01", &mut |stage| {
                if stage == "journal" {
                    return Err(AuditError::Io("interrupted".into()));
                }
                Ok(())
            })
            .is_err());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(AuditWriter::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.join("audit.01.jsonl").exists());
        assert!(dir.join("audit.jsonl.rotation").exists());
        clean(&dir);
    }

    #[test]
    fn rotation_errors_after_swap_refresh_the_same_writer() {
        for target in ["swapped", "committed"] {
            let dir = test_dir("rotate-after-swap");
            let path = dir.join("audit.jsonl");
            let mut writer = AuditWriter::open(&path).unwrap();
            test_record(&mut writer, "before");
            assert!(writer
                .rotate_with_hook("01", &mut |stage| {
                    if stage == target {
                        return Err(AuditError::Io("interrupted".into()));
                    }
                    Ok(())
                })
                .is_err());
            test_record(&mut writer, "after");
            assert_eq!(
                verify_sequence(&[dir.join("audit.01.jsonl"), path]).unwrap(),
                4
            );
            clean(&dir);
        }
    }

    #[test]
    fn recovery_stops_if_archive_is_missing_after_swap() {
        let dir = test_dir("rotate-missing-archive");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        test_record(&mut writer, "before");
        assert!(writer
            .rotate_with_hook("01", &mut |stage| {
                if stage == "swapped" {
                    return Err(AuditError::Io("interrupted".into()));
                }
                Ok(())
            })
            .is_err());
        std::fs::remove_file(dir.join("audit.01.jsonl")).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(AuditWriter::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        clean(&dir);
    }
}
