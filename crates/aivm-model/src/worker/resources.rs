//! คุมจำนวนงานและยอดจอง RAM/staging รวมข้าม process ที่ใช้ quota root เดียวกัน
use super::*;
use std::fs::File;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HostResources {
    pub root: PathBuf,
    pub max_requests: usize,
    pub memory_mb: u64,
    pub storage_mb: u64,
    pub queue_timeout_ms: u64,
    /// เพดาน cache แบบ sealed ใน RAM รวมทุก client; 0 = ปิด
    pub cache_mb: u64,
}

impl Default for HostResources {
    fn default() -> Self {
        #[cfg(unix)]
        let uid = unsafe { libc::geteuid() };
        #[cfg(not(unix))]
        let uid = 0;
        Self {
            root: PathBuf::from(format!("/tmp/aivm-host-quota-v1-{uid}")),
            max_requests: 2,
            memory_mb: default_memory_budget(),
            storage_mb: 16384,
            queue_timeout_ms: 30_000,
            cache_mb: 0,
        }
    }
}

fn default_memory_budget() -> u64 {
    // จองให้ participating workers สูงสุด 75% ของ RAM; โปรแกรมอื่นยังต้องมี host-level capacity planning
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")
                    .and_then(|tail| tail.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            })
        })
        .map(|kb| kb / 1024 * 3 / 4)
        .unwrap_or(4096)
}

fn staging_capacity() -> Result<(bool, u64), WorkerError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open(std::env::temp_dir())
            .map_err(|_| WorkerError::Resources("inspect staging filesystem".into()))?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: fd มีเจ้าของ และอ่าน struct เฉพาะเมื่อ syscall สำเร็จ
        if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0
            || unsafe { libc::fstatvfs(file.as_raw_fd(), space.as_mut_ptr()) } != 0
        {
            return Err(WorkerError::Resources("inspect staging capacity".into()));
        }
        let fs = unsafe { fs.assume_init() };
        let space = unsafe { space.assume_init() };
        let free = (u128::from(space.f_bavail) * u128::from(space.f_frsize) / (1024 * 1024))
            .min(u128::from(u64::MAX)) as u64;
        Ok((fs.f_type == libc::TMPFS_MAGIC, free))
    }
    #[cfg(not(target_os = "linux"))]
    Err(WorkerError::Resources(
        "staging capacity requires Linux".into(),
    ))
}

pub(super) struct Permit {
    _lease: File,
}

impl Drop for Permit {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self._lease.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

impl Permit {
    pub(super) fn acquire(
        limits: &InferenceLimits,
        control: &RequestControl<'_>,
    ) -> Result<Self, WorkerError> {
        Self::reserve(limits, control, false)
    }

    pub(super) fn cache(
        cfg: &HostResources,
        memory_mb: u64,
        control: &RequestControl<'_>,
    ) -> Result<Self, WorkerError> {
        let limits = InferenceLimits {
            memory_mb,
            storage_mb: 0,
            host_resources: cfg.clone(),
            ..Default::default()
        };
        Self::reserve(&limits, control, true)
    }

    fn reserve(
        limits: &InferenceLimits,
        control: &RequestControl<'_>,
        cache_request: bool,
    ) -> Result<Self, WorkerError> {
        Self::reserve_with_capacity(limits, control, cache_request, staging_capacity)
    }

    fn reserve_with_capacity(
        limits: &InferenceLimits,
        control: &RequestControl<'_>,
        cache_request: bool,
        mut capacity: impl FnMut() -> Result<(bool, u64), WorkerError>,
    ) -> Result<Self, WorkerError> {
        #[cfg(not(unix))]
        return Err(WorkerError::Resources(
            "host admission requires Unix file locks".into(),
        ));
        #[cfg(unix)]
        {
            use std::io::{Seek, SeekFrom};
            use std::os::{
                fd::AsRawFd,
                unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            };
            let cfg = &limits.host_resources;
            let (ram_backed, _) = capacity()?;
            let requested_memory = limits
                .memory_mb
                .checked_add(if ram_backed && !cache_request {
                    limits.storage_mb
                } else {
                    0
                })
                .ok_or_else(|| WorkerError::Resources("RAM reservation overflow".into()))?;
            if cfg.max_requests == 0
                || cfg.max_requests > 64
                || cfg.memory_mb == 0
                || cfg.storage_mb == 0
                || cfg.queue_timeout_ms == 0
                || !cfg.root.is_absolute()
            {
                return Err(WorkerError::InvalidRequest(
                    "invalid host resource limits".into(),
                ));
            }
            if requested_memory > cfg.memory_mb
                || limits.storage_mb > cfg.storage_mb
                || (cache_request && limits.memory_mb > cfg.cache_mb)
            {
                return Err(WorkerError::Resources(
                    "request exceeds host reservation capacity".into(),
                ));
            }
            match std::fs::DirBuilder::new().mode(0o700).create(&cfg.root) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(WorkerError::Resources("create host quota root".into())),
            }
            let meta = std::fs::symlink_metadata(&cfg.root)
                .map_err(|_| WorkerError::Resources("stat host quota root".into()))?;
            if !meta.is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o777 != 0o700
            {
                return Err(WorkerError::Resources(
                    "host quota root must be private and owned by this UID".into(),
                ));
            }
            let open = |path: &Path| -> Result<File, WorkerError> {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|_| WorkerError::Resources("open quota lease".into()))?;
                let meta = file
                    .metadata()
                    .map_err(|_| WorkerError::Resources("stat quota lease".into()))?;
                if !meta.is_file()
                    || meta.nlink() != 1
                    || meta.uid() != unsafe { libc::geteuid() }
                    || meta.mode() & 0o077 != 0
                {
                    return Err(WorkerError::Resources(
                        "invalid quota lease owner/type/mode".into(),
                    ));
                }
                Ok(file)
            };
            let mut registry = open(&cfg.root.join("registry"))?;
            let until = Instant::now()
                .checked_add(Duration::from_millis(cfg.queue_timeout_ms))
                .ok_or_else(|| WorkerError::InvalidRequest("queue deadline overflow".into()))?;
            loop {
                control.check("admission queue")?;
                if Instant::now() >= until {
                    return Err(WorkerError::Resources(
                        "admission queue deadline exceeded".into(),
                    ));
                }
                // SAFETY: ทดลอง lock โดยไม่ค้าง จึงยังตรวจ cancellation/deadline ได้
                if unsafe { libc::flock(registry.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
                {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                let attempt = (|| {
                    registry
                        .seek(SeekFrom::Start(0))
                        .map_err(|_| WorkerError::Resources("read quota policy".into()))?;
                    let mut policy = String::new();
                    (&registry)
                        .take(4097)
                        .read_to_string(&mut policy)
                        .map_err(|_| WorkerError::Resources("read quota policy".into()))?;
                    let encoded = serde_json::to_string(cfg).unwrap();
                    if policy.is_empty() {
                        registry
                            .write_all(encoded.as_bytes())
                            .map_err(|_| WorkerError::Resources("write quota policy".into()))?;
                        registry
                            .sync_all()
                            .map_err(|_| WorkerError::Resources("sync quota policy".into()))?;
                    } else if serde_json::from_str::<HostResources>(&policy).ok().as_ref()
                        != Some(cfg)
                    {
                        return Err(WorkerError::Resources(
                            "host quota policy mismatch; operator must use one shared policy"
                                .into(),
                        ));
                    }
                    let (mut memory, mut storage, mut cached) = (0u64, 0u64, 0u64);
                    let mut available = None;
                    for (is_cache, prefix) in [(false, "slot"), (true, "cache")] {
                        for index in 0..cfg.max_requests {
                            let mut file = open(&cfg.root.join(format!("{prefix}-{index}")))?;
                            if unsafe {
                                libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
                            } == 0
                            {
                                if available.is_none() && is_cache == cache_request {
                                    available = Some(file);
                                } else {
                                    // unlock ชัดเจน: fork ของ thread อื่นอาจถือสำเนา fd ก่อน exec
                                    unsafe {
                                        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                                    }
                                }
                            } else {
                                let mut text = String::new();
                                (&mut file)
                                    .take(1025)
                                    .read_to_string(&mut text)
                                    .map_err(|_| {
                                        WorkerError::Resources("read active reservation".into())
                                    })?;
                                // probe lock ที่ยังไม่ publish reservation อาจถูก fork สืบทอดชั่วคราว
                                // ต้องรอ ไม่ถือว่าไม่มีการจอง และไม่ตีความเป็นข้อมูลเสียทันที
                                if text.is_empty() {
                                    if let Some(file) = available.take() {
                                        unsafe {
                                            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                                        }
                                    }
                                    return Ok(None);
                                }
                                let row: (u64, u64) =
                                    serde_json::from_str(&text).map_err(|_| {
                                        WorkerError::Resources("invalid active reservation".into())
                                    })?;
                                if is_cache {
                                    cached = cached.checked_add(row.0).ok_or_else(|| {
                                        WorkerError::Resources("cache reservation overflow".into())
                                    })?;
                                }
                                memory = memory.checked_add(row.0).ok_or_else(|| {
                                    WorkerError::Resources("memory reservation overflow".into())
                                })?;
                                storage = storage.checked_add(row.1).ok_or_else(|| {
                                    WorkerError::Resources("storage reservation overflow".into())
                                })?;
                            }
                        }
                    }
                    let (_, free_staging) = capacity()?;
                    if (cache_request && cached > cfg.cache_mb.saturating_sub(limits.memory_mb))
                        || memory > cfg.memory_mb.saturating_sub(requested_memory)
                        || storage > cfg.storage_mb.saturating_sub(limits.storage_mb)
                        || storage.saturating_add(limits.storage_mb) > free_staging
                    {
                        if let Some(file) = available.take() {
                            unsafe {
                                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                            }
                        }
                        return Ok(None);
                    }
                    if let Some(mut file) = available {
                        file.set_len(0)
                            .map_err(|_| WorkerError::Resources("clear reservation".into()))?;
                        file.seek(SeekFrom::Start(0))
                            .map_err(|_| WorkerError::Resources("seek reservation".into()))?;
                        write!(file, "[{},{}]", requested_memory, limits.storage_mb)
                            .map_err(|_| WorkerError::Resources("write reservation".into()))?;
                        return Ok(Some(Self { _lease: file }));
                    }
                    Ok(None)
                })();
                unsafe {
                    libc::flock(registry.as_raw_fd(), libc::LOCK_UN);
                }
                if let Some(permit) = attempt? {
                    return Ok(permit);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn small_staging_admits_fixtures_but_still_rejects_production_reservations() {
        // CI อาจเหลือพื้นที่ไม่ถึง 5 GiB; จำลอง probe โดยไม่เติมดิสก์หรือเปลี่ยน TMPDIR ของ test อื่น
        for ram_backed in [false, true] {
            let root =
                std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
            let mut fixture = InferenceLimits::test_fixture(root.clone());
            fixture.host_resources.memory_mb = 16 * 1024;
            fixture.host_resources.storage_mb = 16 * 1024;
            fixture.host_resources.queue_timeout_ms = 20;
            let production = InferenceLimits {
                host_resources: fixture.host_resources.clone(),
                ..Default::default()
            };
            let token = AtomicBool::new(false);
            let control = RequestControl::new(&token, None).unwrap();
            let error = Permit::reserve_with_capacity(&production, &control, false, || {
                Ok((ram_backed, 2048))
            })
            .err()
            .expect("5 GiB reservation must wait when only 2 GiB is free");
            assert!(error
                .to_string()
                .contains("admission queue deadline exceeded"));
            let permit =
                Permit::reserve_with_capacity(&fixture, &control, false, || Ok((ram_backed, 2048)))
                    .expect("small fixture must reach the behavior under test");
            drop(permit);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn physical_staging_capacity_counts_active_reservations_and_recovers_after_release() {
        // มี slot และ host quota เหลือก็ต้องรอ ถ้าพื้นที่จริงถูกงานที่ยัง active จองหมดแล้ว
        let root = std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
        let mut limits = InferenceLimits::test_fixture(root.clone());
        limits.host_resources.queue_timeout_ms = 20;
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        let first =
            Permit::reserve_with_capacity(&limits, &control, false, || Ok((false, 1))).unwrap();
        let error = Permit::reserve_with_capacity(&limits, &control, false, || Ok((false, 1)))
            .err()
            .expect("two reservations cannot share one MiB of physical capacity");
        assert!(error
            .to_string()
            .contains("admission queue deadline exceeded"));
        drop(first);
        drop(Permit::reserve_with_capacity(&limits, &control, false, || Ok((false, 1))).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reservations_wait_cancel_and_release_without_oversubscribing() {
        // ใช้ root เฉพาะ test และ request ที่รวม RAM เกิน cap แม้ยังมี slot ว่าง
        let root = std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
        let limits = InferenceLimits {
            memory_mb: 6,
            storage_mb: 1,
            host_resources: HostResources {
                root: root.clone(),
                max_requests: 2,
                memory_mb: 10,
                storage_mb: 10,
                queue_timeout_ms: 20,
                cache_mb: 0,
            },
            ..Default::default()
        };
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        let permit = Permit::acquire(&limits, &control).unwrap();
        assert!(matches!(
            Permit::acquire(&limits, &control),
            Err(WorkerError::Resources(_))
        ));
        token.store(true, Ordering::Relaxed);
        assert_eq!(
            Permit::acquire(&limits, &control).err().unwrap().code(),
            "cancelled"
        );
        token.store(false, Ordering::Relaxed);
        drop(permit);
        let _next = Permit::acquire(&limits, &control).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ram_backed_staging_counts_against_the_shared_memory_budget() {
        let root = std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
        let limits = InferenceLimits {
            memory_mb: 2,
            storage_mb: 6,
            host_resources: HostResources {
                root: root.clone(),
                memory_mb: 10,
                storage_mb: 100,
                queue_timeout_ms: 25,
                ..Default::default()
            },
            ..Default::default()
        };
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        let first = Permit::acquire(&limits, &control).unwrap();
        let second = Permit::acquire(&limits, &control);
        if staging_capacity().unwrap().0 {
            assert_eq!(second.err().unwrap().code(), "resources_unavailable");
        } else {
            assert!(second.is_ok());
        }
        drop(first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_inherited_probe_lock_waits_until_release_instead_of_reporting_corruption() {
        use std::os::fd::AsRawFd;
        let root = std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
        let limits = InferenceLimits::test_fixture(root.clone());
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        drop(Permit::acquire(&limits, &control).unwrap());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("cache-0"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let until = Instant::now() + Duration::from_millis(30);
        let release = std::thread::spawn(move || {
            while Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        });
        let permit = Permit::acquire(&limits, &control).unwrap();
        assert!(
            Instant::now() >= until,
            "unknown active reservation must block admission"
        );
        release.join().unwrap();
        drop(permit);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quota_policy_cannot_be_silently_weakened_by_another_client() {
        let root = std::env::temp_dir().join(format!("aivm-quota-test-{}", uuid::Uuid::new_v4()));
        let mut limits = InferenceLimits::test_fixture(root.clone());
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        drop(Permit::acquire(&limits, &control).unwrap());
        limits.host_resources.max_requests += 1;
        assert!(Permit::acquire(&limits, &control)
            .err()
            .unwrap()
            .to_string()
            .contains("policy mismatch"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, unix))]
mod process_tests {
    use super::*;

    fn limits(root: PathBuf) -> InferenceLimits {
        InferenceLimits {
            memory_mb: 6,
            storage_mb: 1,
            host_resources: HostResources {
                root,
                max_requests: 2,
                memory_mb: 10,
                storage_mb: 10,
                queue_timeout_ms: 25,
                cache_mb: 0,
            },
            ..Default::default()
        }
    }

    #[test]
    fn quota_child_process() {
        let Some(root) = std::env::var_os("AIVM_QUOTA_CHILD_ROOT") else {
            return;
        };
        let cfg = limits(PathBuf::from(root));
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        let result = Permit::acquire(&cfg, &control);
        match std::env::var("AIVM_QUOTA_CHILD_MODE").unwrap().as_str() {
            "hold" => {
                let _permit = result.unwrap();
                std::fs::write(cfg.host_resources.root.join("ready"), b"ready").unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "deny" => assert_eq!(result.err().unwrap().code(), "resources_unavailable"),
            "allow" => {
                let _permit = result.unwrap();
            }
            _ => panic!("invalid quota test mode"),
        }
    }

    #[test]
    fn host_quota_is_shared_across_processes_and_recovers_after_sigkill() {
        // เรียก binary จริงสาม process: ยอดรวมเกิน cap ต้องถูกปฏิเสธและคืน lease เมื่อถูก kill
        let root =
            std::env::temp_dir().join(format!("aivm-quota-process-{}", uuid::Uuid::new_v4()));
        let run = |mode: &str| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "worker::resources::process_tests::quota_child_process",
                    "--nocapture",
                ])
                .env("AIVM_QUOTA_CHILD_ROOT", &root)
                .env("AIVM_QUOTA_CHILD_MODE", mode)
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            command
        };
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut holder = KillOnDrop(run("hold").spawn().unwrap());
        let until = Instant::now() + Duration::from_secs(3);
        while !root.join("ready").exists() {
            assert!(Instant::now() < until, "quota child did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
        let denied = run("deny").output().unwrap();
        assert!(
            denied.status.success(),
            "{}",
            String::from_utf8_lossy(&denied.stderr)
        );
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        let allowed = run("allow").output().unwrap();
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
