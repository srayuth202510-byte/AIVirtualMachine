use aivm_model::worker::{HostResources, InferenceLimits};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

// fixture ใช้ echo/สคริปต์เล็ก จองตามงานจริงและแยก quota จาก operator กับ test อื่น
pub struct TestResources {
    root: PathBuf,
}

impl TestResources {
    pub fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "aivm-worker-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn limits(&self) -> InferenceLimits {
        InferenceLimits {
            memory_mb: 256,
            storage_mb: 1,
            // RLIMIT_NPROC นับทั้ง UID; อย่าให้ process ของเครื่อง dev ขวาง transport fixture
            pids_max: 8192,
            host_resources: HostResources {
                root: self.root.join("quota"),
                max_requests: 2,
                memory_mb: 1024,
                storage_mb: 16,
                queue_timeout_ms: 1000,
                cache_mb: 0,
            },
            ..Default::default()
        }
    }
}

impl Drop for TestResources {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
