//! Opt-in cache ของ model bytes แบบ kernel-sealed; การใช้ RAM ต้องมี lease รวมข้าม process
use super::*;

pub(super) struct CachedModel {
    image: staging::WorkerImage,
    _permit: resources::Permit,
}
impl CachedModel {
    pub(super) fn prepare(config: &ModelConfig) -> Result<Option<Self>, WorkerError> {
        let Some(limits) = config.worker_limits.as_ref() else {
            return Ok(None);
        };
        if limits.host_resources.cache_mb == 0 {
            return Ok(None);
        }
        let local = config.local.as_ref().ok_or_else(|| {
            WorkerError::InvalidRequest("model cache requires local config".into())
        })?;
        if local.model_sha256.is_empty()
            || !matches!(
                local.worker_launcher,
                WorkerLauncher::Process | WorkerLauncher::ProcessNamespace
            )
        {
            return Err(WorkerError::InvalidRequest(
                "sealed model cache requires pinned model and process launcher".into(),
            ));
        }
        let file = crate::artifact::open_regular(&local.model_path)
            .map_err(|_| WorkerError::InvalidRequest("open cache source".into()))?;
        let bytes = file
            .metadata()
            .map_err(|_| WorkerError::Failed("stat cache source".into()))?
            .len();
        let reserved = bytes.div_ceil(1024 * 1024);
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None)?;
        let permit = resources::Permit::cache(&limits.host_resources, reserved, &control)?;
        let mut stage = StagedConfig::new()?;
        let image = staging::prepare_image(
            Path::new(&local.model_path),
            Some(&local.model_sha256),
            stage.directory(),
            &control,
            true,
            bytes,
        )?;
        stage.cleanup()?;
        Ok(Some(Self {
            image,
            _permit: permit,
        }))
    }
    pub(super) fn child_path(&self) -> PathBuf {
        self.image.child_path()
    }
    pub(super) fn inherit(&self, command: &mut Command) {
        self.image.inherit(command);
    }
    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.image.path
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn cached_model_is_immutable_and_survives_source_changes() {
        // cache ยืนยัน bytes ด้วย pin แล้วต้องไม่เปลี่ยนตาม source หรือ writer ที่เปิด fd ใหม่
        let root = std::env::temp_dir().join(format!("aivm-cache-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("weights");
        std::fs::write(&source, b"approved model").unwrap();
        let config = ModelConfig {
            local: Some(crate::LocalModelConfig {
                model_path: source.to_string_lossy().into(),
                model_sha256: format!("{:x}", Sha256::digest(b"approved model")),
                ..Default::default()
            }),
            worker_limits: Some(InferenceLimits {
                host_resources: HostResources {
                    root: root.join("quota"),
                    cache_mb: 1,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let cache = CachedModel::prepare(&config).unwrap().unwrap();
        std::fs::write(&source, b"changed model").unwrap();
        assert_eq!(std::fs::read(cache.path()).unwrap(), b"approved model");
        assert!(std::fs::write(cache.path(), b"changed cache").is_err());
        assert!(crate::artifact::is_sealed(
            &crate::artifact::open_regular(cache.path().to_str().unwrap()).unwrap()
        ));
        drop(cache);
        assert!(CachedModel::prepare(&config).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
