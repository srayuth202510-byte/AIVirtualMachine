//! Operator-only workspace snapshots. Security state and audit history are never restored.
use crate::{lifecycle, Supervisor, SupervisorError};
use aivm_audit::{AuditRecord, AuditWriter};
use aivm_runtime::VmConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
mod fs;
#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, SupervisorError>;
const MAX_ENTRIES: usize = 10_000;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
fn error(e: impl std::fmt::Display) -> SupervisorError {
    SupervisorError::Runtime(e.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_id(id: &str) -> Result<()> {
    if !id.starts_with("snap-")
        || id.len() > 80
        || id.len() <= 5
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(error("invalid snapshot id"));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub id: String,
    pub source_vm: String,
    pub created_at: String,
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    pub manifest_sha256: String,
    /// Listing checks metadata only; verify/restore additionally hash every payload file.
    pub payload_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    directories: Vec<String>,
    files: Vec<FileEntry>,
    bytes: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    id: String,
    source_vm: String,
    created_at: String,
    source_audit_tip: String,
    inventory: Inventory,
}
impl Manifest {
    fn summary(&self, hash: String, verified: bool) -> SnapshotSummary {
        SnapshotSummary {
            id: self.id.clone(),
            source_vm: self.source_vm.clone(),
            created_at: self.created_at.clone(),
            files: self.inventory.files.len(),
            directories: self.inventory.directories.len(),
            bytes: self.inventory.bytes,
            manifest_sha256: hash,
            payload_verified: verified,
        }
    }
    fn validate(&self, id: &str) -> Result<()> {
        if self.version != 1 || self.id != id {
            return Err(error("snapshot version/id mismatch"));
        }
        valid_id(id)?;
        Supervisor::validate_name(&self.source_vm)?;
        chrono::DateTime::parse_from_rfc3339(&self.created_at).map_err(error)?;
        if !self.source_audit_tip.is_empty() && !valid_hash(&self.source_audit_tip) {
            return Err(error("invalid source audit tip"));
        }
        let inv = &self.inventory;
        if inv.files.len() + inv.directories.len() > MAX_ENTRIES || inv.bytes > MAX_BYTES {
            return Err(error("snapshot limits exceeded"));
        }
        let mut dirs = BTreeSet::new();
        for dir in &inv.directories {
            fs::valid_path(dir)?;
            if !dirs.insert(dir.as_str()) {
                return Err(error("duplicate snapshot directory"));
            }
        }
        let mut paths = dirs.clone();
        let mut total = 0u64;
        for file in &inv.files {
            fs::valid_path(&file.path)?;
            if !paths.insert(file.path.as_str()) || !valid_hash(&file.sha256) {
                return Err(error("duplicate path or invalid file hash"));
            }
            total = total
                .checked_add(file.size)
                .ok_or_else(|| error("snapshot size overflow"))?;
        }
        if total != inv.bytes {
            return Err(error("snapshot total size mismatch"));
        }
        for path in &paths {
            let parent = Path::new(path).parent().unwrap();
            if !parent.as_os_str().is_empty() && !dirs.contains(parent.to_str().unwrap()) {
                return Err(error("snapshot parent is missing or is a file"));
            }
        }
        if inv.directories.windows(2).any(|w| w[0] >= w[1])
            || inv.files.windows(2).any(|w| w[0].path >= w[1].path)
        {
            return Err(error("snapshot paths must be sorted"));
        }
        Ok(())
    }
}

// Resolve existing symlinks even when the requested final directory does not exist yet.
fn location(path: &Path) -> Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::fs::symlink_metadata(path).is_ok() {
                return Err(error("dangling path in snapshot location"));
            }
            let name = path
                .file_name()
                .ok_or_else(|| error("invalid snapshot location"))?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            Ok(location(parent)?.join(name))
        }
        Err(e) => Err(error(e)),
    }
}

struct Repository {
    path: PathBuf,
    root: File,
    _lock: File,
}
impl Repository {
    fn open(store: &Path, vm_root: &Path, create: bool) -> Result<Self> {
        let proposed = location(store)?;
        let vms = location(vm_root)?;
        if proposed.starts_with(&vms) || vms.starts_with(&proposed) {
            return Err(error(
                "snapshot store and VM root must be disjoint directories",
            ));
        }
        // These system trees can be readable to sandboxed processes for dynamic
        // linking/builds. A store there would weaken the agent's read boundary.
        for system in [
            "/usr/lib",
            "/usr/lib64",
            "/lib",
            "/lib64",
            "/usr/include",
            "/usr/libexec/gcc",
        ] {
            if let Ok(system) = std::fs::canonicalize(system) {
                if proposed.starts_with(&system) || system.starts_with(&proposed) {
                    return Err(error(
                        "snapshot store overlaps a sandbox-readable system tree",
                    ));
                }
            }
        }
        if create {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&proposed)
                .map_err(error)?;
        }
        let root = fs::root(&proposed)?;
        let meta = root.metadata().map_err(error)?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(error(
                "snapshot store must be owned by the operator and private (0700)",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(create)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(proposed.join("snapshot.lock"))
            .map_err(error)?;
        let lock_kind = if create { libc::LOCK_EX } else { libc::LOCK_SH };
        if unsafe { libc::flock(lock.as_raw_fd(), lock_kind | libc::LOCK_NB) } != 0 {
            return Err(error("snapshot store is busy"));
        }
        Ok(Self {
            path: proposed,
            root,
            _lock: lock,
        })
    }
    fn metadata(&self, id: &str, expected: Option<&str>) -> Result<(Manifest, String, File)> {
        valid_id(id)?;
        if expected.is_some_and(|hash| !valid_hash(hash)) {
            return Err(error("manifest SHA-256 must be 64 hex characters"));
        }
        let directory = fs::directory(&self.root, std::ffi::OsStr::new(id))?;
        let bytes = fs::read(&directory, "manifest.json", MAX_MANIFEST_BYTES)?;
        let hash = digest(&bytes);
        let stored =
            String::from_utf8(fs::read(&directory, "manifest.sha256", 128)?).map_err(error)?;
        if !stored.trim().eq_ignore_ascii_case(&hash)
            || expected.is_some_and(|pin| !pin.eq_ignore_ascii_case(&hash))
        {
            return Err(error("snapshot manifest SHA-256 mismatch"));
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(error)?;
        manifest.validate(id)?;
        Ok((manifest, hash, directory))
    }
    fn verified(&self, id: &str, expected: Option<&str>) -> Result<(Manifest, String, File)> {
        let (manifest, hash, directory) = self.metadata(id, expected)?;
        let payload = fs::directory(&directory, std::ffi::OsStr::new("data"))?;
        compare(&manifest.inventory, &fs::inventory(&payload, None)?)?;
        Ok((manifest, hash, payload))
    }
    fn prepare(&self, workspace: &Path, source_vm: &str, audit_tip: &str) -> Result<Prepared> {
        if fs::names(&self.root)?.len() >= MAX_ENTRIES {
            return Err(error("snapshot store entry limit exceeded"));
        }
        let id = format!("snap-{}", uuid::Uuid::new_v4());
        let temporary = format!(".pending-{}", uuid::Uuid::new_v4());
        let directory = fs::mkdir(&self.root, std::ffi::OsStr::new(&temporary))?;
        let mut prepared = Prepared {
            path: self.path.join(&temporary),
            temporary,
            id: id.clone(),
            published: false,
            summary: None,
        };
        let payload = fs::mkdir(&directory, std::ffi::OsStr::new("data"))?;
        let source = fs::root(workspace)?;
        let inventory = fs::inventory(&source, Some(&payload))?;
        // Read back the stored bytes before calling the recovery point verified.
        compare(&inventory, &fs::inventory(&payload, None)?)?;
        let manifest = Manifest {
            version: 1,
            id,
            source_vm: source_vm.into(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            source_audit_tip: audit_tip.into(),
            inventory,
        };
        manifest.validate(&manifest.id)?;
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(error)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(error("snapshot manifest size limit exceeded"));
        }
        let hash = digest(&bytes);
        fs::write(&directory, "manifest.json", &bytes)?;
        fs::write(
            &directory,
            "manifest.sha256",
            format!("{hash}\n").as_bytes(),
        )?;
        directory.sync_all().map_err(error)?;
        prepared.summary = Some(manifest.summary(hash, true));
        Ok(prepared)
    }
}
impl Drop for Repository {
    fn drop(&mut self) {
        unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}
struct Prepared {
    path: PathBuf,
    temporary: String,
    id: String,
    published: bool,
    summary: Option<SnapshotSummary>,
}
impl Prepared {
    fn publish(mut self, root: &File) -> Result<SnapshotSummary> {
        fs::publish(root, &self.temporary, &self.id)?;
        self.published = true;
        Ok(self.summary.take().unwrap())
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
fn compare(expected: &Inventory, actual: &Inventory) -> Result<()> {
    if expected.bytes != actual.bytes
        || expected.directories != actual.directories
        || expected.files.len() != actual.files.len()
        || expected.files.iter().zip(&actual.files).any(|(a, b)| {
            a.path != b.path || a.size != b.size || !a.sha256.eq_ignore_ascii_case(&b.sha256)
        })
    {
        return Err(error("snapshot payload integrity mismatch"));
    }
    Ok(())
}
fn audit(
    writer: &mut AuditWriter,
    vm: &str,
    action: &str,
    summary: &SnapshotSummary,
) -> Result<()> {
    let mut record = AuditRecord::new(
        0,
        vm,
        "operator",
        &format!("{action}:{}", summary.id),
        "OPERATOR",
        action,
        &summary.id,
        "allow",
        "operator-recovery",
    );
    record.result = serde_json::json!({
        "status": "prepared",
        "snapshot": summary.id,
        "source_vm": summary.source_vm,
        "manifest_sha256": summary.manifest_sha256,
        "files": summary.files,
        "bytes": summary.bytes
    })
    .to_string();
    writer.append(record).map_err(error)?;
    Ok(())
}

impl Supervisor {
    /// Capture only workspace data while holding the VM operation lease.
    pub fn snapshot(&mut self, name: &str, store: &Path) -> Result<SnapshotSummary> {
        let dir = self.resolve(name)?;
        let _lease = lifecycle::Lease::acquire(&dir, false)?;
        let repo = Repository::open(store, &self.root, true)?;
        let mut writer = AuditWriter::open(dir.join("audit.jsonl")).map_err(error)?;
        let prepared = repo.prepare(&dir.join("workspace"), name, writer.tip())?;
        audit(
            &mut writer,
            name,
            "snapshot.create",
            prepared.summary.as_ref().unwrap(),
        )?;
        prepared.publish(&repo.root)
    }
    /// Metadata listing does not certify payload integrity.
    pub fn snapshots(&self, store: &Path) -> Result<Vec<SnapshotSummary>> {
        let repo = Repository::open(store, &self.root, false)?;
        let mut summaries = Vec::new();
        let names = fs::names(&repo.root)?;
        if names.len() > MAX_ENTRIES {
            return Err(error("too many snapshot store entries"));
        }
        for name in names {
            let Some(id) = name.to_str().filter(|s| s.starts_with("snap-")) else {
                continue;
            };
            let (manifest, hash, _) = repo.metadata(id, None)?;
            summaries.push(manifest.summary(hash, false));
        }
        summaries.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(summaries)
    }
    pub fn verify_snapshot(
        &self,
        store: &Path,
        id: &str,
        expected: Option<&str>,
    ) -> Result<SnapshotSummary> {
        let repo = Repository::open(store, &self.root, false)?;
        let (manifest, hash, _) = repo.verified(id, expected)?;
        Ok(manifest.summary(hash, true))
    }
    /// Restore data into an unpublished new VM using a current operator template.
    /// No source capability state, secret leases, memory or audit files are copied.
    pub fn restore_snapshot(
        &mut self,
        store: &Path,
        id: &str,
        expected: &str,
        name: &str,
        config: VmConfig,
    ) -> Result<SnapshotSummary> {
        Self::validate_name(name)?;
        let repo = Repository::open(store, &self.root, false)?;
        let (manifest, hash, payload) = repo.verified(id, Some(expected))?;
        if name == manifest.source_vm {
            return Err(error("restore requires a new VM name"));
        }
        let summary = manifest.summary(hash, true);
        self.create_prepared(name, config, |dir| {
            let workspace = dir.join("workspace");
            // Only the newly-created empty seed directory; never delete user data.
            std::fs::remove_dir(workspace.join("src")).map_err(error)?;
            let target = fs::root(&workspace)?;
            let copied = fs::inventory(&payload, Some(&target))?;
            // Verify again while copying, so a change after the first verification
            // cannot be published as a restored VM.
            compare(&manifest.inventory, &copied)?;
            for file in &manifest.inventory.files {
                fs::set_executable(&target, &file.path, file.executable)?;
            }
            target.sync_all().map_err(error)?;
            let mut writer = AuditWriter::open(dir.join("audit.jsonl")).map_err(error)?;
            audit(&mut writer, name, "snapshot.restore", &summary)
        })?;
        Ok(summary)
    }
}
