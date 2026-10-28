//! สัญญาตรวจผลของ operator: ไม่อนุมานผลทดสอบจากชื่อไฟล์หรือข้อความของ child
use crate::{build, secure_fs, ToolError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierConfig {
    pub executable: String,
    pub argv: Vec<String>,
    /// โปรแกรมภายนอกต้อง pin; build artifact ผูก digest ที่สร้างจริงไว้ใน receipt
    #[serde(default)]
    pub executable_sha256: Option<String>,
    #[serde(default)]
    pub stdout_contains: Option<String>,
    /// คำสั่ง build จาก operator; runtime ส่งผ่าน gateway หลังโมเดลแก้ source
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prepare: Vec<VerifierStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierStep {
    pub executable: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
}

impl VerifierConfig {
    pub fn validate(&self) -> Result<(), ToolError> {
        if self.prepare.len() > 16 {
            return Err(denied("too many verifier preparation steps"));
        }
        for step in &self.prepare {
            if !Path::new(&step.executable).is_absolute()
                || step.executable.len() > 4096
                || step.executable.contains('\0')
                || step.argv.len() > 256
                || step
                    .argv
                    .iter()
                    .any(|arg| arg.len() > 4096 || arg.contains('\0'))
                || step.outputs.len() > 64
            {
                return Err(denied("invalid verifier preparation step"));
            }
            for output in &step.outputs {
                build::validate_name(output)?;
            }
        }
        if let Some(name) = self.executable.strip_prefix("build:") {
            build::validate_name(name)?;
        } else if !Path::new(&self.executable).is_absolute() || self.executable_sha256.is_none() {
            return Err(denied(
                "external verifier requires an absolute path and SHA-256 pin",
            ));
        }
        if self
            .executable_sha256
            .as_ref()
            .is_some_and(|hash| hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
            || self.argv.len() > 256
            || self
                .argv
                .iter()
                .any(|arg| arg.len() > 4096 || arg.contains('\0'))
            || self
                .stdout_contains
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 4096)
        {
            return Err(denied("invalid verifier contract"));
        }
        Ok(())
    }

    pub fn execution_plan(&self) -> Result<Vec<crate::ToolRequest>, ToolError> {
        self.validate()?;
        if self.prepare.is_empty() {
            return Ok(Vec::new());
        }
        let mut plan = self
            .prepare
            .iter()
            .map(|step| crate::ToolRequest {
                tool: "process.exec".into(),
                path: step.executable.clone(),
                content: Some(
                    serde_json::json!({"argv":step.argv,"outputs":step.outputs}).to_string(),
                ),
            })
            .collect::<Vec<_>>();
        plan.push(crate::ToolRequest {
            tool: "process.exec".into(),
            path: self.executable.clone(),
            content: Some(serde_json::json!({"argv":self.argv}).to_string()),
        });
        Ok(plan)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Failed,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub status: VerificationStatus,
    pub contract_sha256: String,
    pub executable_sha256: String,
    pub workspace_sha256: String,
    pub exit_code: Option<i32>,
    pub reason: String,
    pub audit_id: String,
}

pub(crate) struct PreparedVerification {
    pub config: VerifierConfig,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub workspace_sha256: String,
    pub contract_sha256: String,
}

fn denied(message: &str) -> ToolError {
    ToolError::Denied(message.into())
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_file(mut file: std::fs::File, budget: &mut u64) -> Result<String, ToolError> {
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > *budget {
        return Err(denied(
            "verification requires bounded regular files with one link",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        *budget = budget
            .checked_sub(count as u64)
            .ok_or_else(|| denied("verification byte budget exceeded"))?;
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn executable_digest(workspace: &Path, path: &Path) -> Result<String, ToolError> {
    let file = if path.starts_with(workspace) {
        secure_fs::open(workspace, path, false)?
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(io)?
    };
    hash_file(file, &mut (256 * 1024 * 1024))
}

/// รวมชื่อและเนื้อหาไฟล์ทุกใบ ยกเว้น build slots; ไม่ตาม symlink และไม่ข้าม error
pub(crate) fn workspace_digest(workspace: &Path) -> Result<String, ToolError> {
    let mut paths = Vec::new();
    let build_root = workspace.join(build::DIRECTORY);
    for (count, entry) in walkdir::WalkDir::new(workspace)
        .min_depth(1)
        .into_iter()
        .filter_entry(|entry| entry.path() != build_root)
        .enumerate()
    {
        let entry = entry.map_err(|e| ToolError::Io(e.to_string()))?;
        if count >= 4096 {
            return Err(denied("verification entry budget exceeded"));
        }
        if !entry.file_type().is_dir() {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    let mut budget = 64 * 1024 * 1024;
    let mut entries = Vec::new();
    for path in paths {
        let name = path
            .strip_prefix(workspace)
            .map_err(|_| denied("outside workspace"))?
            .to_str()
            .ok_or_else(|| denied("verification requires UTF-8 paths"))?
            .to_string();
        let hash = hash_file(secure_fs::open(workspace, &path, false)?, &mut budget)?;
        entries.push((name, hash));
    }
    Ok(digest(
        &serde_json::to_vec(&entries).map_err(|e| ToolError::Io(e.to_string()))?,
    ))
}

impl PreparedVerification {
    pub fn new(
        config: VerifierConfig,
        workspace: &Path,
        executable: &Path,
    ) -> Result<Self, ToolError> {
        config.validate()?;
        let executable_sha256 = executable_digest(workspace, executable)?;
        if config
            .executable_sha256
            .as_ref()
            .is_some_and(|pin| !pin.eq_ignore_ascii_case(&executable_sha256))
        {
            return Err(denied("verifier executable SHA-256 mismatch"));
        }
        Ok(Self {
            contract_sha256: digest(
                &serde_json::to_vec(&config).map_err(|e| ToolError::Io(e.to_string()))?,
            ),
            executable_sha256,
            workspace_sha256: workspace_digest(workspace)?,
            executable: executable.to_owned(),
            config,
        })
    }

    pub fn finish(self, workspace: &Path, code: Option<i32>, stdout: &str) -> VerificationRecord {
        let result = (|| {
            if executable_digest(workspace, &self.executable)? != self.executable_sha256
                || workspace_digest(workspace)? != self.workspace_sha256
            {
                return Err(denied("verification inputs changed during execution"));
            }
            if code != Some(0) {
                return Err(denied("verifier did not exit successfully"));
            }
            if self
                .config
                .stdout_contains
                .as_ref()
                .is_some_and(|text| !stdout.contains(text))
            {
                return Err(denied("verifier output contract not satisfied"));
            }
            Ok(())
        })();
        VerificationRecord {
            status: if result.is_ok() {
                VerificationStatus::Verified
            } else {
                VerificationStatus::Failed
            },
            reason: result
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "operator verifier contract satisfied".into()),
            contract_sha256: self.contract_sha256,
            executable_sha256: self.executable_sha256,
            workspace_sha256: self.workspace_sha256,
            exit_code: code,
            audit_id: String::new(),
        }
    }
}

fn io(error: std::io::Error) -> ToolError {
    ToolError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("aivm-verification-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(path.join("src")).unwrap();
            std::fs::write(path.join("src/main.c"), b"source").unwrap();
            std::fs::create_dir(path.join(build::DIRECTORY)).unwrap();
            std::fs::write(path.join(build::DIRECTORY).join("tests"), b"binary").unwrap();
            Self(path)
        }
        fn executable(&self) -> PathBuf {
            self.0.join(build::DIRECTORY).join("tests")
        }
        fn config(&self) -> VerifierConfig {
            VerifierConfig {
                executable: "build:tests".into(),
                argv: vec![],
                executable_sha256: None,
                stdout_contains: Some("2 tests passed".into()),
                prepare: Vec::new(),
            }
        }
        fn prepare(&self) -> PreparedVerification {
            PreparedVerification::new(self.config(), &self.0, &self.executable()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn preparation_is_bounded_and_preserves_legacy_contracts() {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        assert!(!serde_json::to_string(&config).unwrap().contains("prepare"));
        assert!(config.execution_plan().unwrap().is_empty());
        config.prepare = vec![VerifierStep {
            executable: "/usr/bin/cc".into(),
            argv: vec!["-pipe".into()],
            outputs: vec!["main.o".into()],
        }];
        assert_eq!(config.execution_plan().unwrap().len(), 2);
        let mut invalid = config.clone();
        invalid.prepare[0].outputs = vec!["../escape".into()];
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.prepare[0].executable = "cc".into();
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.prepare = vec![config.prepare[0].clone(); 17];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn contract_checks_exit_output_and_unchanged_source_and_executable() {
        let fixture = Fixture::new();
        let record = fixture
            .prepare()
            .finish(&fixture.0, Some(0), "2 tests passed");
        assert!(matches!(record.status, VerificationStatus::Verified));
        assert_eq!(record.executable_sha256, digest(b"binary"));
        assert_eq!(record.workspace_sha256.len(), 64);
        assert!(matches!(
            fixture
                .prepare()
                .finish(&fixture.0, Some(1), "2 tests passed")
                .status,
            VerificationStatus::Failed
        ));
        assert!(matches!(
            fixture
                .prepare()
                .finish(&fixture.0, None, "2 tests passed")
                .status,
            VerificationStatus::Failed
        ));
        assert!(matches!(
            fixture
                .prepare()
                .finish(&fixture.0, Some(0), "exit status: 0")
                .status,
            VerificationStatus::Failed
        ));
        let before = fixture.prepare();
        std::fs::write(fixture.0.join("src/main.c"), b"changed").unwrap();
        assert!(matches!(
            before.finish(&fixture.0, Some(0), "2 tests passed").status,
            VerificationStatus::Failed
        ));
        let before = fixture.prepare();
        std::fs::write(fixture.executable(), b"changed binary").unwrap();
        assert!(matches!(
            before.finish(&fixture.0, Some(0), "2 tests passed").status,
            VerificationStatus::Failed
        ));
    }

    #[test]
    fn invalid_pins_links_and_verification_budget_fail_closed() {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.executable_sha256 = Some("0".repeat(64));
        assert!(PreparedVerification::new(config, &fixture.0, &fixture.executable()).is_err());
        let mut config = fixture.config();
        config.executable = "/usr/bin/cargo".into();
        assert!(config.validate().is_err());
        std::os::unix::fs::symlink("/etc/passwd", fixture.0.join("link")).unwrap();
        assert!(workspace_digest(&fixture.0).is_err());
        std::fs::remove_file(fixture.0.join("link")).unwrap();
        std::fs::hard_link(fixture.0.join("src/main.c"), fixture.0.join("hardlink")).unwrap();
        assert!(workspace_digest(&fixture.0).is_err());
        std::fs::remove_file(fixture.0.join("hardlink")).unwrap();
        let file = std::fs::File::create(fixture.0.join("huge")).unwrap();
        file.set_len(64 * 1024 * 1024 + 1).unwrap();
        assert!(workspace_digest(&fixture.0).is_err());
    }
}
