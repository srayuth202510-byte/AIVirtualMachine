//! Recovery for interrupted rotation. The caller holds the exclusive writer lease.
use super::{harden_file, read_tip, AuditError, AuditRecord, AuditWriter};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    archive: String,
    seal: AuditRecord,
}

fn io(e: std::io::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sidecar(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(extension);
    path.with_file_name(name)
}

fn sync_parent(path: &Path) -> Result<(), AuditError> {
    File::open(parent(path))
        .and_then(|f| f.sync_all())
        .map_err(io)
}

fn clear_append_only(path: &Path) {
    let _ = std::process::Command::new("chattr")
        .arg("-a")
        .arg(path)
        .output();
}

pub(super) fn archive_path(path: &Path, suffix: &str) -> Result<PathBuf, AuditError> {
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(AuditError::Io("invalid archive suffix".into()));
    }
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    Ok(path.with_file_name(format!("{stem}.{suffix}.jsonl")))
}

// A private, fsynced staging file. Removing an abandoned staging name is safe:
// it has never been published as either an archive or the active log.
fn stage(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io)
}

pub(super) fn publish(
    path: &Path,
    archive: &Path,
    seal: AuditRecord,
    hook: &mut impl FnMut(&str) -> Result<(), AuditError>,
) -> Result<(), AuditError> {
    let pending = Pending {
        archive: archive
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| AuditError::Io("archive name must be UTF-8".into()))?
            .into(),
        seal,
    };
    let bytes = serde_json::to_vec(&pending).map_err(|e| AuditError::Ser(e.to_string()))?;
    let journal = sidecar(path, ".rotation");
    let temporary = sidecar(path, ".rotation-tmp");
    stage(&temporary, &bytes)?;
    hook("journal_prepared")?;
    // Atomic publication without replacing an existing recovery journal.
    fs::hard_link(&temporary, &journal).map_err(io)?;
    hook("journal_published")?;
    sync_parent(path)?;
    fs::remove_file(&temporary).map_err(io)?;
    Ok(())
}

pub(super) fn recover(
    path: &Path,
    hook: &mut impl FnMut(&str) -> Result<(), AuditError>,
) -> Result<bool, AuditError> {
    let journal = sidecar(path, ".rotation");
    match fs::symlink_metadata(&journal) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(io(e)),
        Ok(meta) if !meta.is_file() => {
            return Err(AuditError::Io("invalid rotation journal".into()))
        }
        Ok(_) => {}
    }
    let pending: Pending = serde_json::from_slice(&fs::read(&journal).map_err(io)?)
        .map_err(|e| AuditError::Ser(format!("invalid rotation journal: {e}")))?;
    let archive_name = Path::new(&pending.archive);
    if archive_name.file_name().and_then(|n| n.to_str()) != Some(pending.archive.as_str())
        || Some(archive_name.as_os_str()) == path.file_name()
    {
        return Err(AuditError::Io("invalid archive in rotation journal".into()));
    }
    let archive = path.with_file_name(&pending.archive);
    let mut seal_check = pending.seal.clone();
    seal_check.seal(&pending.seal.hash_prev);
    if seal_check.hash_entry != pending.seal.hash_entry
        || pending.seal.hash_version != 2
        || pending.seal.action != "seal"
    {
        return Err(AuditError::Ser("invalid rotation seal".into()));
    }
    let sealed_tip = (
        pending
            .seal
            .seq
            .checked_add(1)
            .ok_or_else(|| AuditError::Ser("audit sequence overflow".into()))?,
        pending.seal.hash_entry.clone(),
    );
    let mut resume = AuditRecord::new(
        0,
        &pending.seal.agent,
        &pending.seal.session_id,
        &format!("resume_{}", pending.seal.seq),
        "AUDIT",
        "resume",
        &pending.seal.resource,
        "allow",
        &pending.seal.policy,
    );
    // Reconstruct the same record on every retry, independent of wall clock.
    resume.timestamp = pending.seal.timestamp;
    resume.seal(&pending.seal.hash_entry);
    let mut next = serde_json::to_vec(&resume).map_err(|e| AuditError::Ser(e.to_string()))?;
    next.push(b'\n');

    let active = match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io(e)),
    };
    let installed = active.as_deref() == Some(next.as_slice());
    if active.is_some() && !installed {
        AuditWriter::verify(path)?;
        if read_tip(path)? != sealed_tip {
            return Err(AuditError::Ser("active log changed during rotation".into()));
        }
    }
    match fs::symlink_metadata(&archive) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(AuditError::Io("invalid rotation archive".into()));
            }
            AuditWriter::verify(&archive)?;
            if read_tip(&archive)? != sealed_tip {
                return Err(AuditError::Ser(
                    "rotation archive does not match seal".into(),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && active.is_some() && !installed => {
            // The destination is never overwritten, including a concurrent collision.
            // Linux also prohibits hard links to append-only inodes. The durable
            // journal must already exist before temporarily clearing this flag.
            clear_append_only(path);
            fs::hard_link(path, &archive).map_err(io)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AuditError::Io("rotation archive is missing".into()));
        }
        Err(e) => return Err(io(e)),
    }
    sync_parent(path)?;
    hook("archive")?;
    if !installed {
        let temporary = sidecar(path, ".rotation-next");
        stage(&temporary, &next)?;
        hook("prepared")?;
        // Append-only flags are inode flags: clear them before replacing the
        // active name, then harden the separate archive and new log below.
        clear_append_only(path);
        hook("unhardened")?;
        fs::rename(&temporary, path).map_err(io)?;
    }
    sync_parent(path)?;
    hook("swapped")?;
    harden_file(path);
    let _ = std::process::Command::new("chattr")
        .arg("+i")
        .arg(&archive)
        .output();
    fs::remove_file(&journal).map_err(io)?;
    sync_parent(path)?;
    hook("committed")?;
    // A crash during publication can leave this extra link to the journal.
    let _ = fs::remove_file(sidecar(path, ".rotation-tmp"));
    Ok(true)
}
