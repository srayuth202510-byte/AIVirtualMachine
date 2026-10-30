//! งบเวลาจาก control plane และ I/O ที่ตรวจ cancellation ระหว่าง chunks
use super::*;
use sha2::{Digest, Sha256};
use std::cell::Cell;

pub(super) struct RequestControl<'a> {
    started: Instant,
    deadline: Option<Instant>,
    cancelled: &'a AtomicBool,
    phase: Cell<&'static str>,
    execution_started: Cell<Option<Instant>>,
}

impl<'a> RequestControl<'a> {
    pub(super) fn new(
        cancelled: &'a AtomicBool,
        total_ms: Option<u64>,
    ) -> Result<Self, WorkerError> {
        let started = Instant::now();
        let deadline = total_ms
            .map(|ms| {
                if ms == 0 {
                    return Err(WorkerError::InvalidRequest(
                        "total timeout must be positive".into(),
                    ));
                }
                started
                    .checked_add(Duration::from_millis(ms))
                    .ok_or_else(|| {
                        WorkerError::InvalidRequest("total timeout overflows clock".into())
                    })
            })
            .transpose()?;
        Ok(Self {
            started,
            deadline,
            cancelled,
            phase: Cell::new("validation"),
            execution_started: Cell::new(None),
        })
    }

    pub(super) fn check(&self, phase: &'static str) -> Result<(), WorkerError> {
        self.phase.set(phase);
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(WorkerError::Cancelled(format!(
                "inference cancelled during {phase}"
            )));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(WorkerError::Deadline(format!(
                "total inference deadline exceeded during {phase}"
            )));
        }
        Ok(())
    }

    pub(super) fn begin_execution(&self) -> Result<(), WorkerError> {
        self.check("execution")?;
        self.execution_started.set(Some(Instant::now()));
        Ok(())
    }

    pub(super) fn execution_deadline(&self, timeout_ms: u64) -> Result<Instant, WorkerError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or_else(|| WorkerError::InvalidRequest("worker timeout overflows clock".into()))?;
        Ok(self.deadline.map_or(deadline, |total| total.min(deadline)))
    }

    pub(super) fn remaining_ms(&self, maximum: u64) -> Result<u64, WorkerError> {
        self.check("sandbox setup")?;
        Ok(self.deadline.map_or(maximum, |deadline| {
            maximum.min(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .max(1) as u64,
            )
        }))
    }

    pub(super) fn copy(
        &self,
        input: &mut impl Read,
        output: &mut impl Write,
        maximum: u64,
        phase: &'static str,
    ) -> Result<u64, WorkerError> {
        let mut buffer = [0u8; 64 * 1024];
        let mut copied = 0u64;
        loop {
            self.check(phase)?;
            // อ่านเผื่อหนึ่ง byte เพื่อจับไฟล์ที่โตหลัง fstat แต่ไม่เขียนเกิน quota
            let read_limit = maximum
                .saturating_sub(copied)
                .saturating_add(1)
                .min(buffer.len() as u64) as usize;
            let n = match input.read(&mut buffer[..read_limit]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.map_err(|e| WorkerError::Failed(format!("{phase} read: {e}")))?,
            };
            self.check(phase)?;
            if n == 0 {
                return Ok(copied);
            }
            if n as u64 > maximum.saturating_sub(copied) {
                return Err(WorkerError::LimitExceeded(format!("{phase} bytes")));
            }
            output
                .write_all(&buffer[..n])
                .map_err(|e| WorkerError::Failed(format!("{phase} write: {e}")))?;
            copied += n as u64;
        }
    }

    pub(super) fn verify_worker(&self, path: &Path, expected: &str) -> Result<(), WorkerError> {
        self.check("worker verification")?;
        if expected.is_empty() {
            return Ok(());
        }
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WorkerError::Failed(
                "worker verification failed: bad model hash (must be 64 hex chars)".into(),
            ));
        }
        let path = path
            .to_str()
            .ok_or_else(|| WorkerError::Failed("worker path is not UTF-8".into()))?;
        let mut file = crate::artifact::open_regular(path)
            .map_err(|e| WorkerError::Failed(format!("worker verification failed: {e}")))?;
        let mut hash = Sha256::new();
        self.copy(
            &mut file,
            &mut hash,
            crate::MAX_MODEL_BYTES,
            "worker verification",
        )?;
        if !format!("{:x}", hash.finalize()).eq_ignore_ascii_case(expected) {
            return Err(WorkerError::Failed(
                "worker verification failed: model sha256 mismatch (refusing to load)".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn finish(
        &self,
        result: Result<InferenceResponse, WorkerError>,
        cleanup_started: Instant,
    ) -> Result<InferenceResponse, WorkerError> {
        let now = Instant::now();
        let execution = self.execution_started.get().unwrap_or(cleanup_started);
        let ms = |duration: Duration| duration.as_millis().min(u64::MAX as u128) as u64;
        let usage = ControlPlaneUsage {
            preparation_ms: ms(execution.duration_since(self.started)),
            execution_ms: ms(cleanup_started.duration_since(execution)),
            cleanup_ms: ms(now.duration_since(cleanup_started)),
            total_ms: ms(now.duration_since(self.started)),
        };
        let result = result.and_then(|mut response| {
            self.check("completion")?;
            // ไม่เชื่อ timing ที่ worker ส่งมา: client เขียนทับจากนาฬิกาของตัวเองเสมอ
            response.control_plane_usage = Some(usage.clone());
            Ok(response)
        });
        result.map_err(|error| WorkerError::Context {
            source: Box::new(error),
            phase: self.phase.get().into(),
            usage,
        })
    }

    pub(super) fn with_launch_cancellation<T>(&self, run: impl FnOnce(&AtomicBool) -> T) -> T {
        // token ราย request แยกจาก token ของ client เพื่อให้ใช้ client เดิมได้หลัง timeout
        let cancelled = AtomicBool::new(false);
        let finished = AtomicBool::new(false);
        let deadline = self.deadline;
        let external = self.cancelled;
        struct Finish<'a>(&'a AtomicBool);
        impl Drop for Finish<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        std::thread::scope(|scope| {
            let _finish = Finish(&finished);
            scope.spawn(|| {
                while !finished.load(Ordering::Relaxed) {
                    if external.load(Ordering::Relaxed)
                        || deadline.is_some_and(|end| Instant::now() >= end)
                    {
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            run(&cancelled)
        })
    }
}

pub(super) use super::staging::StagedConfig;

pub(super) fn open_artifact(path: &Path) -> Result<std::fs::File, WorkerError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // ป้องกัน FIFO/symlink ที่ถูกสลับเข้ามาหลัง canonicalize ไม่ให้ open ค้าง
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| WorkerError::Failed(format!("open artifact: {e}")))?;
    if !file
        .metadata()
        .map_err(|e| WorkerError::Failed(format!("artifact metadata: {e}")))?
        .is_file()
    {
        return Err(WorkerError::InvalidRequest(
            "model artifact must be a regular file".into(),
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffered_stream_delta_is_rejected_after_cancellation() {
        // frame ที่รออยู่ใน buffer ต้องไม่ถึง callback หลัง operator ยกเลิก
        let cancelled = AtomicBool::new(true);
        let control = RequestControl::new(&cancelled, None).unwrap();
        assert_buffered_delta_is_rejected(&control);
    }

    #[test]
    fn buffered_stream_delta_is_rejected_after_total_deadline() {
        // จำลองงบหมดก่อนส่ง frame โดยไม่พึ่ง sleep หรือ host sandbox
        let cancelled = AtomicBool::new(false);
        let mut control = RequestControl::new(&cancelled, Some(1000)).unwrap();
        control.deadline = Some(Instant::now() - Duration::from_secs(1));
        assert_buffered_delta_is_rejected(&control);
    }

    fn assert_buffered_delta_is_rejected(control: &RequestControl<'_>) {
        let request = InferenceRequest {
            protocol_version: PROTOCOL_VERSION,
            output_mode: Default::default(),
            request_id: "req-1".into(),
            model_id: "echo".into(),
            prompt: "hello".into(),
            stream: true,
            max_output_tokens: 16,
            timeout_ms: 2000,
            temperature: None,
        };
        let mut streamed = String::new();
        let mut callbacks = 0;
        let result = consume_delta(
            r#"{"protocol_version":1,"request_id":"req-1","delta":"buffered"}"#,
            &request,
            &mut streamed,
            &mut |_| {
                callbacks += 1;
                Ok(())
            },
            control,
        );
        assert!(result.is_err(), "buffered delta must be rejected");
        assert_eq!(callbacks, 0);
        assert!(streamed.is_empty());
    }

    #[test]
    fn controlled_worker_hash_accepts_only_the_approved_bytes() {
        // เส้น hash ใหม่ต้องรักษาการตรวจ pin เดิม รวมตัวพิมพ์ใหญ่และรูปแบบที่ผิด
        let path = std::env::temp_dir().join(format!("aivm-worker-pin-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"approved worker").unwrap();
        let expected = format!("{:x}", Sha256::digest(b"approved worker"));
        let cancelled = AtomicBool::new(false);
        let control = RequestControl::new(&cancelled, None).unwrap();
        control
            .verify_worker(&path, &expected.to_uppercase())
            .unwrap();
        let wrong = control.verify_worker(&path, &"00".repeat(32)).unwrap_err();
        assert!(wrong.to_string().contains("sha256 mismatch"), "{wrong}");
        assert!(control.verify_worker(&path, "bad-pin").is_err());
        std::fs::write(&path, b"changed worker").unwrap();
        assert!(control.verify_worker(&path, &expected).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn growing_input_cannot_write_past_the_storage_budget() {
        // จำลอง source ที่โตหลังตรวจ metadata: ห้ามเขียน bytes ส่วนเกินลง staging
        let cancelled = AtomicBool::new(false);
        let control = RequestControl::new(&cancelled, None).unwrap();
        let mut source = std::io::Cursor::new(vec![7; 128 * 1024 + 1]);
        let mut output = Vec::new();
        let error = control
            .copy(&mut source, &mut output, 128 * 1024, "artifact staging")
            .unwrap_err();
        assert!(matches!(error, WorkerError::LimitExceeded(_)));
        assert_eq!(output.len(), 128 * 1024);
    }

    #[test]
    fn cancellation_during_read_prevents_the_next_write() {
        // เปลี่ยน token ระหว่าง read โดยไม่พึ่ง sleep หรือจังหวะ scheduler
        struct CancelOnRead<'a>(&'a AtomicBool);
        impl Read for CancelOnRead<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                bytes[0] = 1;
                self.0.store(true, Ordering::Relaxed);
                Ok(1)
            }
        }
        let cancelled = AtomicBool::new(false);
        let control = RequestControl::new(&cancelled, None).unwrap();
        let mut output = Vec::new();
        let error = control
            .copy(
                &mut CancelOnRead(&cancelled),
                &mut output,
                4096,
                "artifact staging",
            )
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(output.is_empty());
    }

    #[test]
    fn expired_setup_does_not_read_any_input() {
        // งบหมดก่อนเริ่ม staging ต้องไม่แตะ source หรือเรียก worker
        let cancelled = AtomicBool::new(false);
        let mut control = RequestControl::new(&cancelled, Some(1000)).unwrap();
        control.deadline = Some(Instant::now() - Duration::from_secs(1));
        let mut input = std::io::Cursor::new(vec![1; 8]);
        let error = control
            .copy(&mut input, &mut Vec::new(), 8, "artifact staging")
            .unwrap_err();
        assert!(
            error.to_string().contains("total inference deadline"),
            "{error}"
        );
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn launcher_timeout_uses_a_private_token_and_handles_unwinding() {
        // timeout ไม่ตั้ง token ถาวรของ client; watcher ต้องจบได้แม้ launcher panic
        let external = AtomicBool::new(false);
        let mut control = RequestControl::new(&external, Some(1000)).unwrap();
        control.deadline = Some(Instant::now() - Duration::from_secs(1));
        control.with_launch_cancellation(|cancelled| {
            let until = Instant::now() + Duration::from_secs(2);
            while !cancelled.load(Ordering::Relaxed) && Instant::now() < until {
                std::thread::yield_now();
            }
            assert!(cancelled.load(Ordering::Relaxed));
        });
        assert!(!external.load(Ordering::Relaxed));
        let control = RequestControl::new(&external, None).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            control.with_launch_cancellation(|_| panic!("synthetic launcher panic"));
        }));
        assert!(result.is_err());
        control.with_launch_cancellation(|cancelled| assert!(!cancelled.load(Ordering::Relaxed)));
    }

    #[test]
    fn staging_owner_removes_partial_files_when_preparation_fails() {
        // เตรียมได้ไฟล์แรกแต่ไฟล์ถัดไปหาย: guard ต้องล้างทั้ง directory
        let root =
            std::env::temp_dir().join(format!("aivm-stage-cleanup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source");
        std::fs::write(&source, b"weights").unwrap();
        let directory = root.join("private");
        std::fs::create_dir(&directory).unwrap();
        let cancelled = AtomicBool::new(false);
        let control = RequestControl::new(&cancelled, None).unwrap();
        let mut config = ModelConfig {
            local: Some(crate::LocalModelConfig {
                model_path: source.to_string_lossy().into_owned(),
                manifest_path: Some(root.join("missing").to_string_lossy().into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        {
            let _owner = StagedConfig {
                path: directory.join("config.json"),
                lease: None,
            };
            let result = stage_local_artifacts(
                &mut config,
                &directory,
                &InferenceLimits::default(),
                &control,
            );
            assert!(result.is_err());
            assert!(directory.join("process-artifact-0").exists());
        }
        assert!(!directory.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn artifact_open_rejects_fifo_and_replaced_symlink_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir().join(format!("aivm-stage-open-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"approved").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(open_artifact(&link).is_err());
        let fifo = root.join("fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: C string ยังมีเจ้าของและ path อยู่ใน test directory ส่วนตัว
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(open_artifact(&fifo).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
