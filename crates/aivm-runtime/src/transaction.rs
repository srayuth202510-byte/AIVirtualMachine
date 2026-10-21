//! WAL สำหรับ state และ audit: commit ที่ผูก digest เท่านั้นยืนยันการเพิ่มสิทธิ์ได้
//! ผู้เรียกต้องถือ exclusive VM lease ตลอดทั้ง mutation และ recovery
use super::{PersistedState, RuntimeError, STATE_FILE};
use aivm_audit::{AuditRecord, AuditWriter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const JOURNAL: &str = ".state-transaction.json";
const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    id: String,
    agent: String,
    policy: String,
    action: String,
    resource: String,
    details: String,
    audit_anchor: String,
    before: PersistedState,
    after: PersistedState,
}

fn io(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Io(error.to_string())
}
fn text(value: &impl Serialize) -> Result<String, RuntimeError> {
    serde_json::to_value(value)
        .and_then(|value| serde_json::to_string(&value))
        .map_err(io)
}
fn state_hash(state: &PersistedState) -> Result<String, RuntimeError> {
    Ok(format!("{:x}", Sha256::digest(text(state)?.as_bytes())))
}
impl Pending {
    fn record(&self, outcome: &str) -> Result<AuditRecord, RuntimeError> {
        let state = if outcome == "rollback" {
            &self.before
        } else {
            &self.after
        };
        let mut record = AuditRecord::new(
            0,
            &self.agent,
            &format!("sess_{}", self.agent),
            &self.id,
            &state.cube.current_state().to_string(),
            &format!("{}-{outcome}", self.action),
            &self.resource,
            if outcome == "rollback" {
                "deny"
            } else {
                "allow"
            },
            &self.policy,
        );
        record.result = text(&serde_json::json!({
            "transaction": self.id, "state_sha256": state_hash(state)?,
            "details": self.details, "outcome": outcome,
        }))?;
        Ok(record)
    }
}

fn clear(
    base: &Path,
    hook: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> Result<(), RuntimeError> {
    std::fs::remove_file(base.join(JOURNAL)).map_err(io)?;
    hook("journal-removed").map_err(io)?;
    std::fs::File::open(base)
        .and_then(|file| file.sync_all())
        .map_err(io)?;
    hook("cleanup-synced").map_err(io)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit(
    base: &Path,
    audit: &mut AuditWriter,
    agent: &str,
    policy: &str,
    action: &str,
    resource: &str,
    details: &str,
    before: PersistedState,
    after: PersistedState,
    hook: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> Result<(), RuntimeError> {
    ensure_clear(base)?;
    let pending = Pending {
        version: 1,
        id: format!("transaction_{}", uuid::Uuid::new_v4()),
        agent: agent.into(),
        policy: policy.into(),
        action: action.into(),
        resource: resource.into(),
        details: details.into(),
        audit_anchor: audit_anchor(base)?,
        before,
        after,
    };
    let journal = text(&pending)?;
    if journal.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(io("transaction journal too large"));
    }
    aivm_tools::state_store::write_private_with_hook(&base.join(JOURNAL), &journal, &mut |stage| {
        hook(&format!("journal-{stage}"))
    })
    .map_err(io)?;
    audit
        .append_with_hook(pending.record("prepare")?, &mut |stage| {
            hook(&format!("prepare-{stage}"))
        })
        .map_err(io)?;
    hook("prepare-appended").map_err(io)?;
    aivm_tools::state_store::write_private_with_hook(
        &base.join(STATE_FILE),
        &text(&pending.after)?,
        &mut |stage| hook(&format!("state-{stage}")),
    )
    .map_err(io)?;
    audit
        .append_with_hook(pending.record("commit")?, &mut |stage| {
            hook(&format!("commit-{stage}"))
        })
        .map_err(io)?;
    hook("commit-appended").map_err(io)?;
    clear(base, hook)
}

pub(super) fn ensure_clear(base: &Path) -> Result<(), RuntimeError> {
    match std::fs::symlink_metadata(base.join(JOURNAL)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(io(
            "pending state transaction requires runtime restart/recovery",
        )),
    }
}

pub(super) fn recover(base: &Path, audit: &mut AuditWriter) -> Result<(), RuntimeError> {
    recover_with_hook(base, audit, &mut |_| Ok(()))
}

fn recover_with_hook(
    base: &Path,
    audit: &mut AuditWriter,
    hook: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> Result<(), RuntimeError> {
    if ensure_clear(base).is_ok() {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(base.join(JOURNAL))
        .map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(io("invalid state transaction journal"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(io("transaction journal too large"));
    }
    let pending: Pending = serde_json::from_slice(&bytes).map_err(io)?;
    if pending.version != 1 || !matches!(pending.action.as_str(), "transition" | "secret-approve") {
        return Err(io("unsupported state transaction journal"));
    }
    let expected = pending.record("commit")?;
    // ตรวจ active chain ก่อน; ถ้าถูก rotate ระหว่าง crash ให้หยุดแทนการเดาผล
    let log_path = base.join("audit.jsonl");
    let log = match std::fs::read_to_string(&log_path) {
        Ok(log) => {
            AuditWriter::verify(&log_path).map_err(io)?;
            log
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(io(error)),
    };
    if audit_anchor(base)? != pending.audit_anchor {
        return Err(io(
            "pending transaction requires operator review after audit rotation",
        ));
    }
    let mut committed = false;
    for line in log.lines().filter(|line| !line.trim().is_empty()) {
        let record: AuditRecord = serde_json::from_str(line).map_err(io)?;
        if record.request_id == pending.id && record.action == expected.action {
            if record.result != expected.result
                || record.agent != expected.agent
                || record.state != expected.state
                || record.decision != "allow"
                || record.session_id != expected.session_id
                || record.resource != expected.resource
                || record.policy != expected.policy
            {
                return Err(io("transaction commit does not match journal"));
            }
            committed = true;
        }
    }
    let state = if committed {
        &pending.after
    } else {
        &pending.before
    };
    aivm_tools::state_store::write_private_with_hook(
        &base.join(STATE_FILE),
        &text(state)?,
        &mut |stage| hook(&format!("recovery-state-{stage}")),
    )
    .map_err(io)?;
    if !committed {
        audit
            .append_with_hook(pending.record("rollback")?, &mut |stage| {
                hook(&format!("recovery-rollback-{stage}"))
            })
            .map_err(io)?;
    } else {
        // commit อาจอ่านได้จาก page cache ทั้งที่ process เดิมยังไม่ fsync
        std::fs::File::open(&log_path)
            .and_then(|file| file.sync_all())
            .map_err(io)?;
        hook("recovery-commit-synced").map_err(io)?;
    }
    hook("recovery-recorded").map_err(io)?;
    clear(base, hook)
}

fn audit_anchor(base: &Path) -> Result<String, RuntimeError> {
    let log = match std::fs::read_to_string(base.join("audit.jsonl")) {
        Ok(log) => log,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(io(error)),
    };
    match log.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => Ok(serde_json::from_str::<AuditRecord>(line)
            .map_err(io)?
            .hash_prev),
        None => Ok(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runtime, VmConfig};
    use aivm_cube::{AgentState, TransitionGuards};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;

    const CONFIG: &str = "name: transactions\ncapabilities:\n  initial: [read:workspace, 'secret:test_tok:write']\nsecrets:\n  allow: ['test_tok:write']\n  hitl_required_for: [high]\n";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(kind: &str) -> Self {
            let base = std::env::temp_dir().join(format!("aivm-tx-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&base).unwrap();
            aivm_tools::state_store::write_private(
                &base.join("secrets.yaml"),
                "test_tok: PRIVATE-TEST-VALUE\n",
            )
            .unwrap();
            let mut runtime =
                Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), base.clone()).unwrap();
            runtime
                .transition_to(AgentState::Analyze, &TransitionGuards::default())
                .unwrap();
            runtime.gateway.caps.caps[0].used_count = 3;
            if kind == "secret-approve" {
                let body = serde_json::json!({"tool":"process.exec", "resource":"test_tok", "scope":"write", "purpose":"test", "risk":"high"}).to_string();
                assert!(runtime
                    .gateway
                    .secret_request(&mut runtime.cube, Some(&body))
                    .is_err());
            }
            runtime.persist().unwrap();
            Self(base)
        }
        fn reopen(&self) -> Runtime {
            Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), self.0.clone()).unwrap()
        }
        fn kill_at(&self, kind: &str, stage: &str) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transaction::tests::crash_child", "--nocapture"])
                .env("AIVM_TX_TEST_ROOT", &self.0)
                .env("AIVM_TX_TEST_KIND", kind)
                .env("AIVM_TX_TEST_STAGE", stage)
                .output()
                .unwrap();
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGKILL),
                "stage {stage} not killed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            aivm_audit::clear_flags(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn crash_hook(stage: &str) -> std::io::Result<()> {
        if std::env::var("AIVM_TX_TEST_STAGE").as_deref() == Ok(stage) {
            // SIGKILL ไม่รัน destructors หรือ rollback ของ process ที่กำลังทดสอบ
            unsafe {
                libc::raise(libc::SIGKILL);
            }
            unreachable!();
        }
        Ok(())
    }

    #[test]
    fn crash_child() {
        let Ok(base) = std::env::var("AIVM_TX_TEST_ROOT") else {
            return;
        };
        let base = PathBuf::from(base);
        let kind = std::env::var("AIVM_TX_TEST_KIND").unwrap();
        if kind == "recovery" {
            let mut audit = AuditWriter::open(base.join("audit.jsonl")).unwrap();
            recover_with_hook(&base, &mut audit, &mut crash_hook).unwrap();
        } else {
            let mut runtime = Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), base).unwrap();
            runtime.transaction_hook = crash_hook;
            if kind == "transition" {
                runtime
                    .transition_to(
                        AgentState::Modify,
                        &TransitionGuards {
                            confidence: 0.95,
                            confidence_threshold: 0.8,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            } else {
                let id = runtime.gateway.live_secret_leases()[0].id.clone();
                runtime.approve_secret_lease(&id, "operator").unwrap();
            }
        }
        panic!("requested crash boundary was not reached");
    }

    fn assert_recovered(fixture: &Fixture, kind: &str) {
        let runtime = fixture.reopen();
        let log = std::fs::read_to_string(fixture.0.join("audit.jsonl")).unwrap();
        let committed = log
            .lines()
            .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
            .any(|record| {
                record.action == format!("{kind}-commit")
                    && (kind != "transition" || record.state == "MODIFY")
            });
        if kind == "transition" {
            assert_eq!(
                runtime.cube.current_state(),
                if committed {
                    AgentState::Modify
                } else {
                    AgentState::Analyze
                }
            );
            assert_eq!(
                runtime
                    .gateway
                    .caps
                    .caps
                    .iter()
                    .any(|cap| cap.action == "write"),
                committed
            );
        } else {
            let leases = runtime.gateway.live_secret_leases();
            assert_eq!(leases.len(), 1);
            assert_eq!(leases[0].hitl_approved, committed);
        }
        assert_eq!(
            runtime.gateway.caps.caps[0].used_count, 3,
            "crash must not reset quotas"
        );
        assert!(!fixture.0.join(JOURNAL).exists());
        assert!(!log.contains("PRIVATE-TEST-VALUE"));
        AuditWriter::verify(fixture.0.join("audit.jsonl")).unwrap();
        drop(runtime);
        let _ = fixture.reopen(); // recovery ซ้ำต้องไม่เปลี่ยนผล
    }

    #[test]
    fn sigkill_at_every_transaction_write_and_sync_boundary() {
        let stages = [
            "journal-created",
            "journal-written",
            "journal-synced",
            "journal-renamed",
            "journal-directory-synced",
            "prepare-opened",
            "prepare-written",
            "prepare-synced",
            "prepare-directory-synced",
            "prepare-appended",
            "state-created",
            "state-written",
            "state-synced",
            "state-renamed",
            "state-directory-synced",
            "commit-opened",
            "commit-written",
            "commit-synced",
            "commit-directory-synced",
            "commit-appended",
            "journal-removed",
            "cleanup-synced",
        ];
        for kind in ["transition", "secret-approve"] {
            for stage in stages {
                let fixture = Fixture::new(kind);
                fixture.kill_at(kind, stage);
                assert_recovered(&fixture, kind);
            }
        }
    }

    #[test]
    fn recovery_is_idempotent_after_sigkill_before_or_after_commit() {
        for kind in ["transition", "secret-approve"] {
            for transaction_stage in ["state-directory-synced", "commit-appended"] {
                for recovery_stage in [
                    "recovery-state-created",
                    "recovery-state-written",
                    "recovery-state-synced",
                    "recovery-state-renamed",
                    "recovery-state-directory-synced",
                    "recovery-recorded",
                    "journal-removed",
                    "cleanup-synced",
                ] {
                    let fixture = Fixture::new(kind);
                    fixture.kill_at(kind, transaction_stage);
                    fixture.kill_at("recovery", recovery_stage);
                    assert_recovered(&fixture, kind);
                }
            }
        }
        for kind in ["transition", "secret-approve"] {
            for recovery_stage in [
                "recovery-rollback-opened",
                "recovery-rollback-written",
                "recovery-rollback-synced",
                "recovery-rollback-directory-synced",
                "recovery-commit-synced",
            ] {
                let fixture = Fixture::new(kind);
                fixture.kill_at(
                    kind,
                    if recovery_stage == "recovery-commit-synced" {
                        "commit-appended"
                    } else {
                        "state-directory-synced"
                    },
                );
                fixture.kill_at("recovery", recovery_stage);
                assert_recovered(&fixture, kind);
            }
        }
    }

    #[test]
    fn io_error_after_commit_or_cleanup_fences_even_without_remaining_journal() {
        fn fail_after_commit(stage: &str) -> std::io::Result<()> {
            if stage == "commit-written" {
                Err(std::io::Error::other("injected audit sync failure"))
            } else {
                Ok(())
            }
        }
        fn fail_after_cleanup(stage: &str) -> std::io::Result<()> {
            if stage == "journal-removed" {
                Err(std::io::Error::other("injected directory sync failure"))
            } else {
                Ok(())
            }
        }
        for hook in [
            fail_after_commit as fn(&str) -> std::io::Result<()>,
            fail_after_cleanup,
        ] {
            let fixture = Fixture::new("transition");
            let mut runtime = fixture.reopen();
            runtime.transaction_hook = hook;
            let guards = TransitionGuards {
                confidence: 0.95,
                confidence_threshold: 0.8,
                ..Default::default()
            };
            assert!(runtime.transition_to(AgentState::Modify, &guards).is_err());
            assert!(runtime.persist().is_err());
            assert!(runtime.transition_to(AgentState::Modify, &guards).is_err());
            assert!(runtime
                .gateway
                .write(&mut runtime.cube, "src/forbidden", "no")
                .is_err());
            drop(runtime);
            assert_recovered(&fixture, "transition");
        }
    }

    #[test]
    fn invalid_journal_or_partial_audit_prevents_boot() {
        let fixture = Fixture::new("transition");
        aivm_tools::state_store::write_private(&fixture.0.join(JOURNAL), "{broken").unwrap();
        assert!(Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), fixture.0.clone()).is_err());
        std::fs::remove_file(fixture.0.join(JOURNAL)).unwrap();
        fixture.kill_at("transition", "state-directory-synced");
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(fixture.0.join("audit.jsonl"))
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        assert!(Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), fixture.0.clone()).is_err());
        assert!(fixture.0.join(JOURNAL).exists());
    }

    #[test]
    fn mismatched_commit_or_rotated_audit_cannot_authorize_recovery() {
        for rotate in [false, true] {
            let fixture = Fixture::new("transition");
            fixture.kill_at("transition", "commit-appended");
            if rotate {
                AuditWriter::open(fixture.0.join("audit.jsonl"))
                    .unwrap()
                    .rotate("pending")
                    .unwrap();
            } else {
                let path = fixture.0.join(JOURNAL);
                let mut pending: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                pending["after"]["caps"]["caps"][0]["used_count"] = 99.into();
                aivm_tools::state_store::write_private(&path, &pending.to_string()).unwrap();
            }
            assert!(
                Runtime::init(VmConfig::from_yaml(CONFIG).unwrap(), fixture.0.clone()).is_err()
            );
            assert!(fixture.0.join(JOURNAL).exists());
        }
    }
}
