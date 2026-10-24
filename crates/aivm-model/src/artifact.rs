//! ผูก bytes ที่ตรวจ hash กับไฟล์ที่ loader ใช้จริงตลอดอายุ mmap
use crate::{ModelError, MAX_MODEL_BYTES};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

fn failed(message: impl Into<String>) -> ModelError {
    ModelError::LoadFailed(message.into())
}

pub(super) fn open_regular(path: &str) -> Result<File, ModelError> {
    #[cfg(target_os = "linux")]
    if path.starts_with("/proc/") && path.contains("/fd/") {
        // ตาม descriptor path เฉพาะเมื่อ kernel ยืนยัน seals ครบ; regular symlink ยังถูกปฏิเสธ
        let file = File::open(path).map_err(|_| failed("sealed artifact not readable"))?;
        if is_sealed(&file) {
            return Ok(file);
        }
        return Err(failed("descriptor artifact must be kernel sealed"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // ไม่ตาม symlink ปลายทาง และไม่ค้างเมื่อผู้โจมตีแทนไฟล์ด้วย FIFO
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| failed(format!("model not readable: {e}")))?;
    let meta = file.metadata().map_err(|_| failed("model not statable"))?;
    if !meta.is_file() {
        return Err(failed("model is not a regular file"));
    }
    if meta.len() > MAX_MODEL_BYTES {
        return Err(failed("model too large"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(super) fn is_sealed(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: descriptor ยังมีเจ้าของ และ F_GET_SEALS ไม่แก้สถานะไฟล์
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    seals >= 0 && seals & required == required
}

pub(super) fn file_sha256(file: &mut File) -> Result<String, ModelError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| failed("model not seekable"))?;
    let mut hasher = Sha256::new();
    // จำกัดตอนอ่านด้วย เพราะต้นทางอาจโตหลัง fstat
    copy_bounded(file, &mut hasher, MAX_MODEL_BYTES, false)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_bounded(
    input: impl Read,
    output: &mut impl std::io::Write,
    maximum: u64,
    ram_backed_snapshot: bool,
) -> Result<(), ModelError> {
    let copied = std::io::copy(&mut input.take(maximum + 1), output).map_err(|e| {
        // ENOSPC ของ tmpfs คือ RAM-backed staging เต็ม; ไม่เรียก disk-full ทั่วไปว่า OOM
        if ram_backed_snapshot && e.raw_os_error() == Some(libc::ENOSPC) {
            failed("model snapshot tmpfs capacity exhausted (RAM-backed staging)")
        } else {
            failed(format!("model artifact read/copy failed: {e}"))
        }
    })?;
    if copied > maximum {
        return Err(failed("model too large"));
    }
    Ok(())
}

#[cfg(any(feature = "llama", test))]
pub(super) struct PreparedModelFile {
    // fd เป็นเจ้าของ inode; path นี้ใช้ได้ตราบที่ fd ยังไม่ถูกปิด
    _file: File,
    load_path: String,
}

#[cfg(any(feature = "llama", test))]
impl PreparedModelFile {
    #[cfg(target_os = "linux")]
    pub(super) fn new(path: &str, expected: &str) -> Result<Self, ModelError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

        if !expected.is_empty()
            && (expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(failed("bad model hash (must be 64 hex chars)"));
        }
        let mut source = open_regular(path)?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: fd มีเจ้าของ และอ่าน struct เฉพาะเมื่อ syscall สำเร็จ
        if unsafe { libc::fstatvfs(source.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(failed("cannot inspect model mount"));
        }
        let stat = unsafe { stat.assume_init() };
        let meta = source
            .metadata()
            .map_err(|_| failed("model not statable"))?;
        // Container/MicroVM มีสำเนาแยกบน read-only mount อยู่แล้ว
        // ต้องไม่มี hard link หรือสิทธิ์เขียนจาก UID ที่ไม่อยู่ใน trust root
        let read_only_staged = stat.f_flag & libc::ST_RDONLY != 0
            && meta.nlink() == 1
            && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
            && meta.mode() & 0o022 == 0;
        let mut file = if read_only_staged || is_sealed(&source) {
            source
        } else {
            // ชื่อใช้แยกการจอง directory เท่านั้น ไม่ใช่ secret: create + 0700
            // เป็น boundary จริง และไม่ต้องรอ entropy ใน MicroVM ที่เพิ่งบูต
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| failed("model staging clock before epoch"))?
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "aivm-gguf-{}-{timestamp}-{}",
                std::process::id(),
                NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|e| failed(format!("private model staging: {e}")))?;
            let snapshot = directory.join("model.gguf");
            let output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&snapshot)
                .map_err(|e| failed(format!("create model snapshot: {e}")));
            // unlink ก่อน copy: worker ที่ถูก kill ระหว่าง copy ไม่ทิ้ง GGUF ขนาดใหญ่
            let unlink = if output.is_ok() {
                std::fs::remove_file(&snapshot)
            } else {
                Ok(())
            };
            let cleanup = std::fs::remove_dir(&directory);
            let mut output = output?;
            unlink.map_err(|e| failed(format!("unlink model snapshot: {e}")))?;
            cleanup.map_err(|e| failed(format!("remove model staging directory: {e}")))?;
            let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: output fd ยังมีเจ้าของ; อ่าน statfs เฉพาะเมื่อ syscall สำเร็จ
            if unsafe { libc::fstatfs(output.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
                return Err(failed("cannot inspect snapshot filesystem"));
            }
            let ram_backed = unsafe { filesystem.assume_init() }.f_type == libc::TMPFS_MAGIC;
            copy_bounded(&mut source, &mut output, MAX_MODEL_BYTES, ram_backed)?;
            output
                .set_permissions(std::fs::Permissions::from_mode(0o400))
                .map_err(|e| failed(format!("protect model snapshot: {e}")))?;
            // เปิด fd read-only ไปยัง inode เดียวกัน แล้วปิด writer ก่อน hash
            let file = File::open(format!("/proc/self/fd/{}", output.as_raw_fd()))
                .map_err(|e| failed(format!("open model snapshot: {e}")))?;
            drop(output);
            file
        };
        if !expected.is_empty() && !file_sha256(&mut file)?.eq_ignore_ascii_case(expected) {
            return Err(failed("model sha256 mismatch (refusing to load)"));
        }
        let load_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        Ok(Self {
            _file: file,
            load_path,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn new(_path: &str, _expected: &str) -> Result<Self, ModelError> {
        Err(failed(
            "protected GGUF loading requires Linux /proc/self/fd",
        ))
    }

    pub(super) fn load_path(&self) -> &str {
        &self.load_path
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn snapshot_capacity_failure_distinguishes_tmpfs_from_disk_and_other_io_errors() {
        struct Failure(i32);
        impl std::io::Write for Failure {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(self.0))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for (ram_backed, errno, expected) in [
            (true, libc::ENOSPC, true),
            (false, libc::ENOSPC, false),
            (true, libc::EACCES, false),
        ] {
            let error =
                copy_bounded(&b"weights"[..], &mut Failure(errno), 100, ram_backed).unwrap_err();
            assert_eq!(
                error.to_string().contains("tmpfs capacity exhausted"),
                expected
            );
        }
    }

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("aivm-artifact-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn model(&self) -> String {
            self.0.join("model.gguf").to_str().unwrap().into()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn verified_bytes_survive_source_replacement_and_in_place_writes() {
        let fixture = Fixture::new();
        let path = fixture.model();
        let bytes = b"verified model weights";
        std::fs::write(&path, bytes).unwrap();
        let expected = format!("{:x}", Sha256::digest(bytes));
        let prepared = PreparedModelFile::new(&path, &expected.to_uppercase()).unwrap();
        let metadata = prepared._file.metadata().unwrap();
        assert_eq!(
            metadata.nlink(),
            0,
            "snapshot must have no mutable pathname"
        );
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert_ne!(metadata.ino(), std::fs::metadata(&path).unwrap().ino());

        // เขียน inode เดิม แล้วแทน pathname ด้วย symlink: loader ยังได้ bytes ที่ hash ผ่าน
        std::fs::write(&path, b"malicious in-place rewrite").unwrap();
        assert_eq!(std::fs::read(prepared.load_path()).unwrap(), bytes);
        std::fs::rename(&path, fixture.0.join("old.gguf")).unwrap();
        let replacement = fixture.0.join("replacement.gguf");
        std::fs::write(&replacement, b"malicious replacement").unwrap();
        symlink(&replacement, &path).unwrap();
        assert_eq!(std::fs::read(prepared.load_path()).unwrap(), bytes);
    }

    // ใช้ GGUF จริงแต่แก้เฉพาะสำเนาของ fixture; ไม่แตะไฟล์โมเดลของ operator
    #[cfg(feature = "llama")]
    #[test]
    #[ignore = "requires AIVM_GGUF and operator-approved AIVM_GGUF_SHA256"]
    fn real_loader_uses_verified_snapshot_after_source_tampering() {
        use crate::{LlamaBackend, LlamaModel, LlamaModelParams};

        let original = std::env::var("AIVM_GGUF").expect("set AIVM_GGUF");
        let expected = std::env::var("AIVM_GGUF_SHA256").expect("pin AIVM_GGUF_SHA256");
        assert!(!expected.is_empty(), "a trusted model pin is required");
        let fixture = Fixture::new();
        let path = fixture.model();
        std::fs::copy(original, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let prepared = PreparedModelFile::new(&path, &expected).unwrap();

        // ทำลาย inode เดิมแล้วแทนชื่อด้วย symlink ก่อน llama.cpp เปิดไฟล์
        std::fs::write(&path, b"invalid GGUF written after verification").unwrap();
        let replaced = fixture.0.join("replaced.gguf");
        std::fs::rename(&path, &replaced).unwrap();
        symlink(&replaced, &path).unwrap();
        assert!(open_regular(&path).is_err());
        let mut verified = File::open(prepared.load_path()).unwrap();
        assert!(file_sha256(&mut verified)
            .unwrap()
            .eq_ignore_ascii_case(&expected));

        let backend = LlamaBackend::init().unwrap();
        let params = LlamaModelParams::default().with_n_gpu_layers(0);
        let model = LlamaModel::load_from_file(&backend, prepared.load_path(), &params)
            .expect("llama.cpp must load the verified snapshot despite source tampering");
        assert!(model.n_vocab() > 0);
    }

    #[test]
    fn source_changed_before_verification_fails_closed() {
        let fixture = Fixture::new();
        let path = fixture.model();
        std::fs::write(&path, b"untrusted replacement").unwrap();
        let expected = format!("{:x}", Sha256::digest(b"approved weights"));
        let error = PreparedModelFile::new(&path, &expected).err().unwrap();
        assert!(error.to_string().contains("model sha256 mismatch"));
        assert!(PreparedModelFile::new(&path, "invalid pin").is_err());
    }

    #[test]
    fn unpinned_development_load_still_uses_private_snapshot() {
        let fixture = Fixture::new();
        let path = fixture.model();
        std::fs::write(&path, b"development weights").unwrap();
        let prepared = PreparedModelFile::new(&path, "").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            std::fs::read(prepared.load_path()).unwrap(),
            b"development weights"
        );
    }

    #[test]
    fn symlinks_special_files_and_oversized_models_are_rejected() {
        let fixture = Fixture::new();
        let path = fixture.model();
        let target = fixture.0.join("target.gguf");
        std::fs::write(&target, b"weights").unwrap();
        symlink(&target, &path).unwrap();
        assert!(PreparedModelFile::new(&path, "").is_err());
        assert!(crate::model_file_sha256(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let fifo = std::ffi::CString::new(path.clone()).unwrap();
        // SAFETY: CString มี NUL terminator และมีอายุตลอด syscall
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(PreparedModelFile::new(&path, "").is_err());
        std::fs::remove_file(&path).unwrap();
        File::create(&path)
            .unwrap()
            .set_len(MAX_MODEL_BYTES + 1)
            .unwrap();
        assert!(PreparedModelFile::new(&path, "").is_err());
        assert!(PreparedModelFile::new(fixture.0.to_str().unwrap(), "").is_err());
    }

    #[test]
    fn copy_limit_applies_to_bytes_read_even_if_source_grows() {
        let mut output = Vec::new();
        assert!(copy_bounded(std::io::repeat(b'x'), &mut output, 4, false).is_err());
        assert_eq!(output.len(), 5, "must stop after quota plus one byte");
        output.clear();
        copy_bounded(&b"four"[..], &mut output, 4, false).unwrap();
        assert_eq!(output, b"four");
    }
}
