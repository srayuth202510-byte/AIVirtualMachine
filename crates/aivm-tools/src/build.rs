//! พื้นที่ artifacts แบบ bounded slots: gateway สร้างไฟล์, child เขียนเฉพาะ inode ที่เตรียมไว้
use crate::{secure_fs, ToolError};
use aivm_sandbox::{BuildSpec, ResourceLimits};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DIRECTORY: &str = ".aivm-build";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_files")]
    pub max_files: usize,
    #[serde(default = "default_bytes")]
    pub max_bytes: u64,
}
fn default_files() -> usize {
    16
}
fn default_bytes() -> u64 {
    16 * 1024 * 1024
}
impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_files: default_files(),
            max_bytes: default_bytes(),
        }
    }
}
impl BuildConfig {
    pub fn validate(&self) -> Result<(), ToolError> {
        if !(1..=64).contains(&self.max_files)
            || !(1024..=512 * 1024 * 1024).contains(&self.max_bytes)
        {
            return Err(ToolError::Denied("invalid build output quota".into()));
        }
        Ok(())
    }
    pub fn artifact_path(&self, workspace: &Path, name: &str) -> Result<PathBuf, ToolError> {
        self.validate()?;
        if !self.enabled {
            return Err(ToolError::Denied("build outputs are disabled".into()));
        }
        validate_name(name)?;
        Ok(workspace.join(DIRECTORY).join(name))
    }
    pub fn prepare(
        &self,
        workspace: &Path,
        names: &[String],
        limits: &ResourceLimits,
    ) -> Result<BuildSpec, ToolError> {
        self.validate()?;
        if !self.enabled {
            return Err(ToolError::Denied("build outputs are disabled".into()));
        }
        if names.len() > self.max_files {
            return Err(ToolError::Denied("invalid output count".into()));
        }
        let requested: BTreeSet<_> = names.iter().collect();
        if requested.len() != names.len() {
            return Err(ToolError::Denied("duplicate build output".into()));
        }
        for name in names {
            validate_name(name)?;
        }
        let root = workspace.join(DIRECTORY);
        let mut existing = BTreeSet::new();
        let file_limit = self.max_bytes / self.max_files as u64;
        match std::fs::symlink_metadata(&root) {
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
                return Err(ToolError::Denied("invalid build directory".into()))
            }
            Ok(_) => {
                for entry in std::fs::read_dir(&root).map_err(io)? {
                    let entry = entry.map_err(io)?;
                    let name = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| ToolError::Denied("invalid artifact name".into()))?;
                    validate_name(&name)?;
                    let meta = std::fs::symlink_metadata(entry.path()).map_err(io)?;
                    use std::os::unix::fs::MetadataExt;
                    if !meta.is_file() || meta.nlink() != 1 || meta.len() > file_limit {
                        return Err(ToolError::Denied(
                            "unsafe or oversized existing artifact".into(),
                        ));
                    }
                    existing.insert(name);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        existing.extend(names.iter().cloned());
        if existing.len() > self.max_files {
            return Err(ToolError::Denied("build output slots exhausted".into()));
        }
        // จองงบทั้งพื้นที่ก่อนเริ่ม เพื่อให้ source + artifacts ไม่เกิน storage quota
        let mut source_bytes = 0u64;
        for entry in walkdir::WalkDir::new(workspace)
            .into_iter()
            .filter_entry(|entry| entry.path() != root)
        {
            let entry = entry.map_err(|e| ToolError::Io(e.to_string()))?;
            if entry.file_type().is_file() {
                source_bytes = source_bytes.saturating_add(
                    entry
                        .metadata()
                        .map_err(|e| ToolError::Io(e.to_string()))?
                        .len(),
                );
            }
        }
        if source_bytes.saturating_add(self.max_bytes)
            > limits.storage_mb.saturating_mul(1024 * 1024)
        {
            return Err(ToolError::Denied(
                "build reservation exceeds workspace storage quota".into(),
            ));
        }
        let mut outputs = Vec::new();
        for name in names {
            let path = self.artifact_path(workspace, name)?;
            let file = secure_fs::open(workspace, &path, true)?;
            // slot ทุกใบอาจเป็น executable; kernel ยังต้องยอมรับรูปแบบ binary เมื่อ exec
            file.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(io)?;
            outputs.push(path);
        }
        Ok(BuildSpec {
            root,
            outputs,
            max_file_bytes: file_limit,
        })
    }
}
fn io(e: std::io::Error) -> ToolError {
    ToolError::Io(e.to_string())
}
pub fn validate_name(name: &str) -> Result<(), ToolError> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        || name.contains(".env")
        || matches!(
            name,
            "state.json" | "secrets.yaml" | "aivm.yaml" | "audit.jsonl"
        )
    {
        return Err(ToolError::Denied(
            "build output must be a plain artifact filename".into(),
        ));
    }
    Ok(())
}
