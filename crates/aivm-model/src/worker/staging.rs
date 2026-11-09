//! เป็นเจ้าของ staging, ตรวจ cleanup และกู้ขยะหลัง process หยุดโดยไม่แตะงานที่ยังรัน
use super::*;
use std::fs::File;

pub(super) struct StagedConfig {
    pub(super) path: PathBuf,
    pub(super) lease: Option<File>,
}

impl StagedConfig {
    pub(super) fn new() -> Result<Self, WorkerError> {
        Self::new_in(std::env::temp_dir())
    }

    /// สร้าง staging ใต้ root ที่กำหนด เพื่อให้แต่ละ test แยกขอบเขต recovery
    /// ไม่แชร์ `/tmp` ร่วมกันระหว่าง threads และไม่ต้องแก้ `TMPDIR` ของ process
    pub(super) fn new_in(root: PathBuf) -> Result<Self, WorkerError> {
        Self::recover(&root)?;
        let directory = root.join(format!(
            "aivm-model-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| WorkerError::Failed("create private staging directory".into()))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&directory)
            .map_err(|_| WorkerError::Failed("create staging directory".into()))?;
        let mut staged = Self {
            path: directory.join("config.json"),
            lease: None,
        };
        let mut lease = new_private_file(&directory.join(".lease-pending"), 0o600)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: descriptor มีเจ้าของตลอดอายุ request; lock ไม่ถูกปล่อยระหว่าง cleanup
            if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(WorkerError::Cleanup("cannot lock staging lease".into()));
            }
        }
        lease
            .write_all(b"AIVM staging lease v1\n")
            .map_err(|_| WorkerError::Cleanup("write staging lease marker".into()))?;
        std::fs::rename(directory.join(".lease-pending"), directory.join(".lease"))
            .map_err(|_| WorkerError::Cleanup("publish staging lease".into()))?;
        staged.lease = Some(lease);
        Ok(staged)
    }

    pub(super) fn directory(&self) -> &Path {
        self.path.parent().unwrap()
    }

    pub(super) fn cleanup(&mut self) -> Result<(), WorkerError> {
        match std::fs::remove_dir_all(self.directory()) {
            Ok(()) => {
                self.lease.take();
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.lease.take();
                Ok(())
            }
            Err(_) => Err(WorkerError::Cleanup(format!(
                "residual={}",
                self.directory().display()
            ))),
        }
    }

    /// ลบเฉพาะ directory ของ UID นี้ที่มี marker ของเราและไม่มีเจ้าของถือ lease แล้ว
    pub(super) fn recover(root: &Path) -> Result<(), WorkerError> {
        #[cfg(unix)]
        {
            use std::os::{
                fd::AsRawFd,
                unix::fs::{MetadataExt, OpenOptionsExt},
            };
            // serialize recovery เพื่อไม่ให้อีก scanner กำลังลบ entry เดียวกันตอนเรารายงานผล
            // SAFETY: geteuid เป็น pure syscall ไม่มี precondition
            let lock_path = PathBuf::from(format!("/tmp/.aivm-staging-recovery-{}.lock", unsafe {
                libc::geteuid()
            }));
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(lock_path)
                .map_err(|_| WorkerError::Cleanup("open recovery lock".into()))?;
            let lock_meta = lock
                .metadata()
                .map_err(|_| WorkerError::Cleanup("stat recovery lock".into()))?;
            if !lock_meta.is_file()
                // SAFETY: geteuid เป็น pure syscall ไม่มี precondition
                || lock_meta.uid() != unsafe { libc::geteuid() }
                || lock_meta.nlink() != 1
                || lock_meta.mode() & 0o077 != 0
            {
                return Err(WorkerError::Cleanup("invalid recovery lock".into()));
            }
            // SAFETY: lock เป็น fd ที่เปิดอยู่ตลอดอายุการสแกนนี้
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(WorkerError::Cleanup("lock recovery registry".into()));
            }
            let entries = std::fs::read_dir(root)
                .map_err(|_| WorkerError::Cleanup("cannot inspect staging root".into()))?;
            for entry in entries {
                let entry = entry
                    .map_err(|_| WorkerError::Cleanup("cannot enumerate staging root".into()))?;
                let name = entry.file_name();
                let text = name.to_string_lossy();
                let Some((pid, nonce)) = text
                    .strip_prefix("aivm-model-")
                    .and_then(|tail| tail.split_once('-'))
                else {
                    continue;
                };
                if pid.parse::<u32>().is_err() || uuid::Uuid::parse_str(nonce).is_err() {
                    continue;
                }
                let meta = match std::fs::symlink_metadata(entry.path()) {
                    Ok(meta) => meta,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        return Err(WorkerError::Cleanup("cannot inspect staging entry".into()))
                    }
                };
                if !meta.is_dir()
                    // SAFETY: geteuid เป็น pure syscall ไม่มี precondition
                    || meta.uid() != unsafe { libc::geteuid() }
                    || meta.mode() & 0o777 != 0o700
                {
                    continue;
                }
                let lease_path = entry.path().join(".lease");
                let lease = match std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(lease_path)
                {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        return Err(WorkerError::Cleanup("cannot inspect staging lease".into()))
                    }
                };
                let meta = lease
                    .metadata()
                    .map_err(|_| WorkerError::Cleanup("cannot stat staging lease".into()))?;
                // SAFETY: geteuid เป็น pure syscall ไม่มี precondition
                if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1
                {
                    continue;
                }
                let mut marker = Vec::new();
                (&lease)
                    .take(64)
                    .read_to_end(&mut marker)
                    .map_err(|_| WorkerError::Cleanup("read staging lease marker".into()))?;
                if marker != b"AIVM staging lease v1\n" {
                    continue;
                }
                // SAFETY: nonblocking lock probe บนไฟล์ marker ที่ตรวจชนิดและเจ้าของแล้ว
                if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    continue;
                }
                match std::fs::remove_dir_all(entry.path()) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => {
                        return Err(WorkerError::Cleanup(format!(
                            "residual={}",
                            entry.path().display()
                        )))
                    }
                }
            }
        }
        Ok(())
    }
}

impl Drop for StagedConfig {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            // panic/unwind ยังมี marker ให้ startup recovery และรายงานที่ไม่มีเนื้อหา request
            eprintln!("aivm: {error}");
        }
    }
}

pub(super) fn new_private_file(path: &Path, mode: u32) -> Result<File, WorkerError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    options
        .open(path)
        .map_err(|_| WorkerError::Failed("create private file".into()))
}

pub(super) struct WorkerImage {
    pub(super) path: PathBuf,
    _file: Option<File>,
}

impl WorkerImage {
    pub(super) fn child_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        if let Some(file) = &self._file {
            use std::os::fd::AsRawFd;
            return PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        }
        self.path.clone()
    }

    pub(super) fn inherit(&self, command: &mut Command) {
        #[cfg(unix)]
        if let Some(file) = &self._file {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let fd = file.as_raw_fd();
            // SAFETY: เปลี่ยน flag เฉพาะ child descriptor; parent ยัง CLOEXEC ตามเดิม
            // ใช้ fcntl เท่านั้นหลัง fork เพื่อให้ exec ใน user namespace ไม่ต้องอ่าน proc ของ parent
            unsafe {
                command.pre_exec(move || {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
}

pub(super) fn prepare_worker(
    path: &Path,
    expected: Option<&str>,
    directory: &Path,
    control: &RequestControl<'_>,
    sealed: bool,
) -> Result<WorkerImage, WorkerError> {
    prepare_image(
        path,
        expected,
        directory,
        control,
        sealed,
        256 * 1024 * 1024,
    )
}

pub(super) fn prepare_image(
    path: &Path,
    expected: Option<&str>,
    directory: &Path,
    control: &RequestControl<'_>,
    sealed: bool,
    maximum: u64,
) -> Result<WorkerImage, WorkerError> {
    let Some(expected) = expected.filter(|hash| !hash.is_empty()) else {
        return Ok(WorkerImage {
            path: path.to_path_buf(),
            _file: None,
        });
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(WorkerError::InvalidRequest(
            "worker pin must be 64 hex characters".into(),
        ));
    }
    control.check("worker snapshot")?;
    let source = path
        .to_str()
        .ok_or_else(|| WorkerError::InvalidRequest("worker path is not UTF-8".into()))?;
    let mut input = crate::artifact::open_regular(source)
        .map_err(|_| WorkerError::Failed("open pinned worker".into()))?;
    #[cfg(target_os = "linux")]
    if sealed {
        use sha2::{Digest, Sha256};
        use std::io::{Seek, SeekFrom};
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: ชื่อ NUL-terminated; fd ที่สำเร็จมี File เป็นเจ้าของเพียงตัวเดียว
        let fd = unsafe {
            libc::memfd_create(
                c"aivm-worker".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(WorkerError::Failed("create sealed worker image".into()));
        }
        // SAFETY: fd >= 0 เป็น memfd ใหม่ที่เพิ่งสร้างและส่งมอบ ownership ให้ File ทันที
        let mut file = unsafe { File::from_raw_fd(fd) };
        control.copy(&mut input, &mut file, maximum, "worker snapshot")?;
        // SAFETY: fd เป็นของ file ที่ยังเปิดอยู่ใน scope นี้
        if unsafe { libc::fchmod(fd, 0o500) } != 0
            // SAFETY: fd เป็น memfd ที่เปิดด้วย MFD_ALLOW_SEALING และยังเปิดอยู่
            || unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } != 0
        {
            return Err(WorkerError::Failed("seal worker image".into()));
        }
        // seal ก่อน hash เพื่อกัน writer อีก process ที่ UID เดียวกันสลับ bytes หลังตรวจ
        file.seek(SeekFrom::Start(0))
            .map_err(|_| WorkerError::Failed("seek sealed worker".into()))?;
        let mut hash = Sha256::new();
        control.copy(&mut file, &mut hash, maximum, "worker verification")?;
        if !format!("{:x}", hash.finalize()).eq_ignore_ascii_case(expected) {
            return Err(WorkerError::Failed("artifact sha256 mismatch".into()));
        }
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ));
        return Ok(WorkerImage {
            path,
            _file: Some(file),
        });
    }
    #[cfg(not(target_os = "linux"))]
    if sealed {
        return Err(WorkerError::InvalidRequest(
            "sealed worker execution requires Linux".into(),
        ));
    }
    let snapshot = directory.join("worker");
    let mut output = new_private_file(&snapshot, 0o600)?;
    control.copy(&mut input, &mut output, maximum, "worker snapshot")?;
    output
        .sync_all()
        .map_err(|_| WorkerError::Failed("sync worker snapshot".into()))?;
    drop(output);
    control.verify_worker(&snapshot, expected)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o500))
            .map_err(|_| WorkerError::Failed("protect worker snapshot".into()))?;
    }
    Ok(WorkerImage {
        path: snapshot,
        _file: None,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};

    const LEASE_CHILD_ENV: &str = "AIVM_STAGING_LEASE_CHILD";

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().join(format!(
                "aivm-staging-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn pinned_worker_snapshot_survives_source_replacement_and_in_place_writes() {
        // exec ต้องใช้ bytes ที่ตรวจแล้ว แม้ source inode และ pathname เปลี่ยนหลังตรวจ
        let root = TestRoot::new();
        let mut stage = StagedConfig::new_in(root.path().to_path_buf()).unwrap();
        let source = stage.directory().join("source");
        let approved = b"#!/bin/sh\nprintf approved";
        std::fs::write(&source, approved).unwrap();
        let token = AtomicBool::new(false);
        let control = RequestControl::new(&token, None).unwrap();
        let image = prepare_worker(
            &source,
            Some(&format!("{:x}", Sha256::digest(approved))),
            stage.directory(),
            &control,
            true,
        )
        .unwrap();
        std::fs::write(&source, b"#!/bin/sh\nprintf hostile").unwrap();
        std::fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink("/bin/false", &source).unwrap();
        let result = Command::new(&image.path).output().unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"approved");
        assert!(std::fs::write(&image.path, b"changed").is_err());
        stage.cleanup().unwrap();
    }

    #[test]
    fn recovery_keeps_owned_leases_and_removes_abandoned_requests() {
        // lease ที่ยังมีเจ้าของต้องรอด; เมื่อปิด descriptor แล้วจึงกู้ได้ — ไม่มี sleep/retry
        let root = TestRoot::new();
        let mut active = StagedConfig::new_in(root.path().to_path_buf()).unwrap();
        let path = active.directory().to_path_buf();
        StagedConfig::recover(root.path()).unwrap();
        assert!(path.exists(), "recover ต้องไม่ลบ staging ที่ lease ยังถูกถือ");

        drop(active.lease.take());
        std::mem::forget(active);
        StagedConfig::recover(root.path()).unwrap();
        assert!(!path.exists(), "recover ต้องกู้ staging ที่ถูกทิ้งหลังปิด lease");
    }

    #[test]
    fn recovery_respects_a_live_lease_holder_process() {
        // process จริงถือ lease ข้าม barrier; recovery ต้องรอจน process ตายแล้วจึงกู้
        let root = TestRoot::new();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worker::staging::tests::lease_holder_child",
                "--nocapture",
            ])
            .env(LEASE_CHILD_ENV, root.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let directory = loop {
            let line = lines
                .next()
                .expect("lease holder exited before announcing its directory")
                .unwrap();
            if let Some(path) = line.strip_prefix("AIVM-LEASE-DIR ") {
                break PathBuf::from(path);
            }
        };
        assert!(directory.exists());

        StagedConfig::recover(root.path()).unwrap();
        assert!(
            directory.exists(),
            "recover ต้องไม่ลบ staging ที่ process เจ้าของ lease ยังมีชีวิต"
        );

        child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());

        StagedConfig::recover(root.path()).unwrap();
        assert!(
            !directory.exists(),
            "recover ต้องกู้ staging ได้หลัง process เจ้าของ lease ตาย"
        );
    }

    #[test]
    fn lease_holder_child() {
        // helper ที่ test แม่เรียกซ้ำ; รันตามปกติจะ no-op
        let Some(root) = std::env::var_os(LEASE_CHILD_ENV) else {
            return;
        };
        let stage = StagedConfig::new_in(PathBuf::from(root)).unwrap();
        println!("AIVM-LEASE-DIR {}", stage.directory().display());
        let mut barrier = [0u8; 1];
        let _ = std::io::stdin().read(&mut barrier);
        // จบ process โดยไม่ cleanup: kernel ปิด descriptor และปล่อย flock เอง
        std::mem::forget(stage);
    }

    #[test]
    fn checked_cleanup_reports_failure_instead_of_success() {
        let root = TestRoot::new();
        let mut stage = StagedConfig::new_in(root.path().to_path_buf()).unwrap();
        let directory = stage.directory().to_path_buf();
        std::fs::remove_dir_all(&directory).unwrap();
        std::fs::write(&directory, b"blocked").unwrap();
        assert_eq!(stage.cleanup().unwrap_err().code(), "cleanup_failed");
        std::fs::remove_file(directory).unwrap();
    }

    #[test]
    #[ignore = "stress: make test-staging-stress"]
    fn concurrent_recovery_stress() {
        let rounds: usize = std::env::var("AIVM_STAGING_STRESS_ROUNDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000);
        let threads: usize = std::env::var("AIVM_STAGING_STRESS_THREADS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8)
            .max(1);
        let per_thread = rounds.div_ceil(threads);
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(move || {
                    for _ in 0..per_thread {
                        let root = TestRoot::new();
                        let mut active = StagedConfig::new_in(root.path().to_path_buf()).unwrap();
                        let path = active.directory().to_path_buf();
                        StagedConfig::recover(root.path()).unwrap();
                        assert!(path.exists());
                        drop(active.lease.take());
                        std::mem::forget(active);
                        StagedConfig::recover(root.path()).unwrap();
                        assert!(!path.exists());
                    }
                });
            }
        });
    }
}
