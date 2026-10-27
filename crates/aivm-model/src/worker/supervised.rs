//! แยก preparation/helper ออกจาก caller; stream events ไม่เรียก user callback ใน watchdog
use super::*;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerRequest {
    pub config: ModelConfig,
    pub request: InferenceRequest,
    pub limits: InferenceLimits,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WorkerEvent {
    Delta { request_id: String, text: String },
    Complete { response: Box<InferenceResponse> },
    Error { error: WorkerError },
}

static PENDING_JOBS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct PendingJob;
impl PendingJob {
    fn acquire() -> Result<Self, WorkerError> {
        if PENDING_JOBS
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < 64).then_some(count + 1)
            })
            .is_err()
        {
            return Err(WorkerError::Resources("controller queue is full".into()));
        }
        Ok(Self)
    }
}
impl Drop for PendingJob {
    fn drop(&mut self) {
        PENDING_JOBS.fetch_sub(1, Ordering::Relaxed);
    }
}

struct ControllerImage {
    executable: staging::WorkerImage,
    cache: Option<Arc<super::cache::CachedModel>>,
}

/// สร้างตอน boot: snapshot/controller pin validation อยู่นอกงบของแต่ละ request
pub struct SupervisedClient {
    image: Arc<ControllerImage>,
    cancelled: Arc<AtomicBool>,
}

impl SupervisedClient {
    pub fn new(path: &Path, pin: &str) -> Result<Self, WorkerError> {
        if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WorkerError::InvalidRequest(
                "controller requires a SHA-256 pin".into(),
            ));
        }
        let mut stage = StagedConfig::new()?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let control = RequestControl::new(&cancelled, None)?;
        let executable =
            staging::prepare_worker(path, Some(pin), stage.directory(), &control, true)?;
        stage.cleanup()?;
        Ok(Self {
            image: Arc::new(ControllerImage {
                executable,
                cache: None,
            }),
            cancelled,
        })
    }

    pub(super) fn keep_cache(
        &mut self,
        cache: Option<Arc<super::cache::CachedModel>>,
    ) -> Result<(), WorkerError> {
        Arc::get_mut(&mut self.image)
            .ok_or_else(|| WorkerError::InvalidRequest("controller already started".into()))?
            .cache = cache;
        Ok(())
    }

    pub fn start(
        &self,
        config: &ModelConfig,
        request: InferenceRequest,
        limits: &InferenceLimits,
    ) -> Result<WorkerJob, WorkerError> {
        request.validate(limits, request.prompt.split_whitespace().count())?;
        let total = limits.total_timeout_ms.ok_or_else(|| {
            WorkerError::InvalidRequest("supervised requests require total_timeout_ms".into())
        })?;
        let pending = PendingJob::acquire()?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(total))
            .ok_or_else(|| WorkerError::InvalidRequest("total timeout overflows clock".into()))?;
        let (sender, receiver) = mpsc::sync_channel(8);
        let (terminal_sender, terminal) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let job_cancelled = cancelled.clone();
        let external = self.cancelled.clone();
        let image = self.image.clone();
        let mut config = config.clone();
        // controller เป็น control plane ที่เชื่อถือได้; ป้องกัน recursion ก่อนส่งให้ direct client
        if let Some(local) = config.local.as_mut() {
            local.controller_path = None;
            local.controller_sha256 = None;
        }
        let input = ControllerRequest {
            config,
            request,
            limits: limits.clone(),
        };
        std::thread::Builder::new()
            .name("aivm-controller".into())
            .spawn(move || {
                let _pending = pending;
                let result = supervise(
                    &image,
                    input,
                    started,
                    deadline,
                    &job_cancelled,
                    &external,
                    &sender,
                );
                let _ = terminal_sender.send(result);
            })
            .map_err(|_| WorkerError::Resources("cannot start controller watchdog".into()))?;
        Ok(WorkerJob {
            receiver,
            terminal,
            completion: None,
            terminal_error: None,
            cleanup: None,
            cancelled,
            deadline,
            finished: false,
        })
    }

    pub fn cancellation_token(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
}

/// ผู้ใช้ดึง event เอง จึงไม่มี callback ของผู้ใช้มาขวางการบังคับ deadline
pub struct WorkerJob {
    receiver: Receiver<WorkerEvent>,
    terminal: Receiver<Result<InferenceResponse, WorkerError>>,
    completion: Option<InferenceResponse>,
    terminal_error: Option<WorkerError>,
    cleanup: Option<Result<(), WorkerError>>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    finished: bool,
}

impl WorkerJob {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    fn record_terminal(&mut self, result: Result<InferenceResponse, WorkerError>) {
        match result {
            Ok(response) => {
                self.completion = Some(response);
                self.cleanup = Some(Ok(()));
            }
            Err(error) => {
                self.cleanup = Some(if error.code() == "cleanup_failed" {
                    Err(error.clone())
                } else {
                    Ok(())
                });
                self.terminal_error = Some(error);
            }
        }
    }

    /// true = watchdog ตรวจ cleanup เสร็จ; false = ยัง pending โดยไม่อ้างว่าสำเร็จ
    pub fn wait_for_cleanup(&mut self, timeout: Duration) -> Result<bool, WorkerError> {
        if self.cleanup.is_none() {
            match self.terminal.recv_timeout(timeout) {
                Ok(result) => self.record_terminal(result),
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(false),
                Err(_) => {
                    return Err(WorkerError::Cleanup(
                        "controller cleanup outcome unavailable".into(),
                    ))
                }
            }
        }
        self.cleanup.clone().unwrap().map(|()| true)
    }

    pub fn next_event(&mut self) -> Result<WorkerEvent, WorkerError> {
        if self.finished {
            return Err(WorkerError::InvalidRequest(
                "worker job already finished".into(),
            ));
        }
        loop {
            if let Ok(result) = self.terminal.try_recv() {
                self.record_terminal(result);
            }
            if let Some(error) = self.terminal_error.take() {
                self.finished = true;
                return Err(error);
            }
            if Instant::now() >= self.deadline {
                self.cancel();
                self.finished = true;
                return Err(WorkerError::Deadline(
                    "total inference deadline; cleanup may be pending; use wait_for_cleanup".into(),
                ));
            }
            if let Ok(event) = self.receiver.try_recv() {
                return Ok(event);
            }
            if let Some(response) = self.completion.take() {
                self.finished = true;
                return Ok(WorkerEvent::Complete {
                    response: Box::new(response),
                });
            }
            match self.receiver.recv_timeout(
                Duration::from_millis(2)
                    .min(self.deadline.saturating_duration_since(Instant::now())),
            ) {
                Ok(event) => {
                    if Instant::now() >= self.deadline {
                        self.cancel();
                        self.finished = true;
                        return Err(WorkerError::Deadline(
                            "total inference deadline before stream delivery".into(),
                        ));
                    }
                    return Ok(event);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    match self
                        .terminal
                        .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                    {
                        Ok(result) => self.record_terminal(result),
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                        Err(_) => {
                            self.finished = true;
                            return Err(WorkerError::Failed(
                                "controller event channel closed".into(),
                            ));
                        }
                    }
                }
            }
        }
    }
}

impl Drop for WorkerJob {
    fn drop(&mut self) {
        if !self.finished {
            self.cancel();
        }
    }
}

fn deliver(sender: &SyncSender<WorkerEvent>, event: WorkerEvent) -> Result<(), WorkerError> {
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            Err(WorkerError::Resources("stream consumer is too slow".into()))
        }
        Err(TrySendError::Disconnected(_)) => Err(WorkerError::Cancelled(
            "stream consumer disconnected".into(),
        )),
    }
}

fn supervise(
    image: &ControllerImage,
    input: ControllerRequest,
    started: Instant,
    deadline: Instant,
    cancelled: &AtomicBool,
    external: &AtomicBool,
    sender: &SyncSender<WorkerEvent>,
) -> Result<InferenceResponse, WorkerError> {
    // ให้ filesystem/setup/cleanup ที่ค้างอยู่ใน thread นี้; caller รอ event แบบมี deadline
    let mut stage = StagedConfig::new()?;
    let result = (|| {
        let mut command = Command::new(image.executable.child_path());
        image.executable.inherit(&mut command);
        if let Some(cache) = &image.cache {
            cache.inherit(&mut command);
        }
        command
            .arg("--control")
            .env_clear()
            .env("TMPDIR", stage.directory())
            // controller ใช้ host helpers; ส่งเฉพาะ PATH ของ operator ไม่ส่ง secrets/LD_* ต่อ
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let parent = unsafe { libc::getpid() };
            // SAFETY: pre_exec ใช้เฉพาะ async-signal-safe syscalls
            unsafe {
                command.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0
                        || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != parent
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command
            .spawn()
            .map_err(|_| WorkerError::Failed("spawn controller".into()))?;
        let mut child = ChildGuard {
            child,
            terminated: false,
        };
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let payload = serde_json::to_vec(&input)
            .map_err(|_| WorkerError::InvalidRequest("encode controller request".into()))?;
        std::thread::spawn(move || {
            let _ = stdin
                .write_all(&payload)
                .and_then(|_| stdin.write_all(b"\n"));
        });
        let (tx, rx) = mpsc::sync_channel(8);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut total = 0usize;
            loop {
                let mut line = String::new();
                let event = reader
                    .by_ref()
                    .take((MAX_RESPONSE_BYTES + 1) as u64)
                    .read_line(&mut line)
                    .map_err(|_| WorkerError::Protocol("controller transport read".into()))
                    .and_then(|n| {
                        total = total.saturating_add(n);
                        if n == 0 {
                            return Err(WorkerError::Failed(
                                "controller returned no completion".into(),
                            ));
                        }
                        if total > MAX_RESPONSE_BYTES {
                            return Err(WorkerError::LimitExceeded(
                                "controller response bytes".into(),
                            ));
                        }
                        serde_json::from_str::<WorkerEvent>(&line)
                            .map_err(|_| WorkerError::Protocol("invalid controller frame".into()))
                    });
                let done = !matches!(event, Ok(WorkerEvent::Delta { .. }));
                if tx.send(event).is_err() || done {
                    break;
                }
            }
        });
        let mut tree = ProcessTree::default();
        if let Some(local) = input.config.local.as_ref() {
            if let WorkerLauncher::Container { config } = &local.worker_launcher {
                tree.cgroup_root = Some(config.cgroup_root.clone());
            }
        }
        let mut completion = None;
        let result = (|| loop {
            tree.observe(child.id());
            if cancelled.load(Ordering::Relaxed) || external.load(Ordering::Relaxed) {
                return Err(WorkerError::Cancelled(
                    "supervised request cancelled".into(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(WorkerError::Deadline(
                    "total inference deadline in controller".into(),
                ));
            }
            if let Some(event) = completion.take() {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| WorkerError::Failed("wait controller".into()))?
                {
                    if status.success() {
                        break Ok(event);
                    }
                    return Err(WorkerError::Failed(
                        "controller exited unsuccessfully".into(),
                    ));
                }
                completion = Some(event);
            } else {
                match rx.recv_timeout(Duration::from_millis(5)) {
                    Ok(Ok(event @ WorkerEvent::Delta { .. })) => {
                        if let WorkerEvent::Delta { request_id, .. } = &event {
                            if request_id != &input.request.request_id {
                                return Err(WorkerError::Protocol(
                                    "controller delta identity mismatch".into(),
                                ));
                            }
                        }
                        deliver(sender, event)?;
                    }
                    Ok(Ok(WorkerEvent::Complete { mut response })) => {
                        response.validate(&input.request)?;
                        if let Some(usage) = response.control_plane_usage.as_mut() {
                            usage.total_ms =
                                started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        }
                        completion = Some(WorkerEvent::Complete { response });
                    }
                    Ok(Ok(WorkerEvent::Error { error })) => return Err(error),
                    Ok(Err(error)) => return Err(error),
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    Err(_) => return Err(WorkerError::Failed("controller channel closed".into())),
                }
            }
            if completion.is_some() {
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        // อ่าน identities ก่อนฆ่า parent เพื่อเก็บลูกที่เปลี่ยน process group ด้วย
        tree.observe(child.id());
        tree.terminate();
        child.terminate();
        tree.cleanup()?;
        result
    })();
    // owner อยู่ฝั่ง parent: แม้ controller ถูก kill ระหว่าง copy ก็ยังตรวจ cleanup ได้
    let cleanup_started = Instant::now();
    let cleanup = stage.cleanup();
    let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let cleanup_ms = cleanup_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let result = match cleanup {
        Ok(()) => result,
        Err(error) => {
            return Err(WorkerError::CleanupAfterFailure {
                cleanup: error.to_string(),
                source: Box::new(
                    result
                        .err()
                        .unwrap_or_else(|| WorkerError::Cleanup("completion not released".into())),
                ),
            })
        }
    };
    match result {
        Ok(WorkerEvent::Complete { mut response }) => {
            if let Some(usage) = response.control_plane_usage.as_mut() {
                let child = usage
                    .preparation_ms
                    .saturating_add(usage.execution_ms)
                    .saturating_add(usage.cleanup_ms);
                usage.preparation_ms = usage
                    .preparation_ms
                    .saturating_add(elapsed.saturating_sub(child).saturating_sub(cleanup_ms));
                usage.cleanup_ms = usage.cleanup_ms.saturating_add(cleanup_ms);
                usage.total_ms = elapsed;
            }
            Ok(*response)
        }
        Ok(_) => Err(WorkerError::Protocol("controller did not complete".into())),
        Err(error) => Err(WorkerError::Context {
            source: Box::new(error),
            phase: "controller".into(),
            usage: ControlPlaneUsage {
                preparation_ms: 0,
                execution_ms: elapsed.saturating_sub(cleanup_ms),
                cleanup_ms,
                total_ms: elapsed,
            },
        }),
    }
}

#[derive(Default)]
struct ProcessTree {
    processes: std::collections::BTreeMap<u32, u64>,
    cgroup_root: Option<PathBuf>,
    cgroups: std::collections::BTreeMap<PathBuf, u64>,
}

impl ProcessTree {
    fn identity(pid: u32) -> Option<u64> {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()?
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }
    fn observe(&mut self, pid: u32) {
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for task in tasks.flatten() {
                if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
                    for child in text
                        .split_whitespace()
                        .filter_map(|p| p.parse::<u32>().ok())
                    {
                        if let Some(identity) = Self::identity(child) {
                            self.processes.insert(child, identity);
                            self.observe_cgroup(child);
                            self.observe(child);
                        }
                    }
                }
            }
        }
    }
    fn observe_cgroup(&mut self, pid: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Some(root) = &self.cgroup_root else {
                return;
            };
            if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                if let Some(relative) = text.lines().find_map(|line| line.strip_prefix("0::/")) {
                    let path = Path::new("/sys/fs/cgroup").join(relative);
                    if path
                        .strip_prefix(root)
                        .ok()
                        .and_then(|relative| relative.components().next())
                        .is_some_and(|first| {
                            first.as_os_str().to_string_lossy().starts_with("aivm-")
                        })
                    {
                        if let Ok(meta) = std::fs::symlink_metadata(&path) {
                            if meta.is_dir() {
                                self.cgroups.insert(path, meta.ino());
                            }
                        }
                    }
                }
            }
        }
    }
    fn cleanup(&self) -> Result<(), WorkerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let until = Instant::now() + Duration::from_secs(2);
            for (path, inode) in &self.cgroups {
                loop {
                    match std::fs::symlink_metadata(path) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                        Ok(meta) if meta.ino() == *inode && meta.is_dir() => (),
                        _ => {
                            return Err(WorkerError::Cleanup(
                                "controller cgroup identity changed".into(),
                            ))
                        }
                    }
                    let _ = std::fs::write(path.join("cgroup.kill"), "1");
                    if std::fs::remove_dir(path).is_ok() {
                        break;
                    }
                    if Instant::now() >= until {
                        return Err(WorkerError::Cleanup(
                            "controller cgroup still populated".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let mut remaining = Vec::new();
            for (&pid, &identity) in &self.processes {
                match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                    Ok(text) => {
                        let current = text
                            .rsplit_once(") ")
                            .and_then(|(_, tail)| tail.split_whitespace().nth(19))
                            .and_then(|value| value.parse::<u64>().ok())
                            .ok_or_else(|| {
                                WorkerError::Cleanup("cannot verify descendant identity".into())
                            })?;
                        if current == identity {
                            remaining.push((pid, identity));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => {
                        return Err(WorkerError::Cleanup(
                            "cannot verify descendant termination".into(),
                        ))
                    }
                }
            }
            if remaining.is_empty() {
                break;
            }
            if Instant::now() >= until {
                return Err(WorkerError::Cleanup(format!(
                    "residual processes={remaining:?}"
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
    fn terminate(&self) {
        for path in self.cgroups.keys() {
            let _ = std::fs::write(path.join("cgroup.kill"), "1");
        }
        for (&pid, &identity) in self.processes.iter().rev() {
            if Self::identity(pid) == Some(identity) {
                // SAFETY: เทียบ starttime ก่อนส่ง signal; parent ยังไม่ได้ reap ลูก
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
    }
}

/// Entry point ของ pinned controller binary; ไม่ให้ model intents เรียก mode นี้ผ่าน gateway
pub fn serve_controller() -> Result<(), WorkerError> {
    let mut frame = String::new();
    std::io::stdin()
        .lock()
        .take((MAX_PROMPT_BYTES * 6 + 65537) as u64)
        .read_line(&mut frame)
        .map_err(|_| WorkerError::Protocol("read controller request".into()))?;
    if frame.len() > MAX_PROMPT_BYTES * 6 + 65536 {
        return Err(WorkerError::LimitExceeded(
            "controller request bytes".into(),
        ));
    }
    let input: ControllerRequest = serde_json::from_str(&frame)
        .map_err(|_| WorkerError::InvalidRequest("invalid controller request".into()))?;
    let executable = input
        .config
        .local
        .as_ref()
        .and_then(|local| local.worker_path.clone())
        .ok_or_else(|| WorkerError::InvalidRequest("controller requires worker_path".into()))?;
    let client = WorkerClient::new(executable);
    let mut stdout = std::io::stdout().lock();
    let mut emit = |event: &WorkerEvent| -> Result<(), WorkerError> {
        serde_json::to_writer(&mut stdout, event)
            .map_err(|_| WorkerError::Failed("write controller frame".into()))?;
        stdout
            .write_all(b"\n")
            .and_then(|_| stdout.flush())
            .map_err(|_| WorkerError::Failed("flush controller frame".into()))
    };
    let result = if input.request.stream {
        client.infer_stream(
            &input.config,
            input.request.clone(),
            &input.limits,
            &mut |text| {
                emit(&WorkerEvent::Delta {
                    request_id: input.request.request_id.clone(),
                    text: text.into(),
                })
            },
        )
    } else {
        client.infer(&input.config, input.request.clone(), &input.limits)
    };
    match result {
        Ok(response) => emit(&WorkerEvent::Complete {
            response: Box::new(response),
        }),
        Err(error) => emit(&WorkerEvent::Error { error }),
    }
}
