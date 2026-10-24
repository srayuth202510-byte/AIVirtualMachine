//! File transport and live output observation for container/MicroVM workers.
use super::*;

impl WorkerClient {
    pub(super) fn infer_sandboxed(
        &self,
        config: &ModelConfig,
        config_path: &Path,
        request: &InferenceRequest,
        limits: &InferenceLimits,
        on_delta: &mut dyn FnMut(&str) -> Result<(), WorkerError>,
        run: &RunContext<'_, '_>,
    ) -> Result<InferenceResponse, WorkerError> {
        let control = run.control;
        let executable = &run.image.path;
        control.check("sandbox prerequisites")?;
        use aivm_sandbox::{ExecSpec, ResourceLimits};
        let fail = |error: &dyn std::fmt::Display| {
            let text = error.to_string();
            if text.contains("microvm run timed out") {
                WorkerError::Deadline("microvm run timed out".into())
            } else if text.contains("wall-clock timeout") {
                WorkerError::Deadline("container wall-clock timeout".into())
            } else if text.contains("artifact hash mismatch") {
                WorkerError::Failed("artifact sha256 mismatch".into())
            } else {
                WorkerError::Failed(safe_worker_diagnostic(&text).into())
            }
        };
        let local = config
            .local
            .as_ref()
            .ok_or_else(|| WorkerError::InvalidRequest("local config required".into()))?;
        if let WorkerLauncher::Container { config } = &local.worker_launcher {
            let probe = config.probe();
            control.check("sandbox prerequisites")?;
            if !probe.bubblewrap || !probe.init || !probe.cgroup_v2_quotas {
                return Err(WorkerError::Failed(format!(
                    "container prerequisites unavailable: {probe:?}"
                )));
            }
        }
        let request_path = config_path.with_extension("request.json");
        let config_path_guest = config_path.with_extension("guest.json");
        let result = (|| {
            let mut batch_request = request.clone();
            batch_request.stream = request.stream;
            write_private(
                &request_path,
                &serde_json::to_vec(&batch_request).map_err(|e| fail(&e))?,
            )?;
            let executable = executable.canonicalize().map_err(|e| fail(&e))?;
            let mut policy = aivm_policy::Policy::default();
            policy.process.allow = vec![executable.to_string_lossy().into_owned()];
            let mut guest_config = config.clone();
            let mut artifacts = vec![local.model_path.clone()];
            artifacts.extend(
                [
                    local.manifest_path.clone(),
                    local.tokenizer_path.clone(),
                    local.config_path.clone(),
                ]
                .into_iter()
                .flatten(),
            );
            #[cfg(not(feature = "microvm"))]
            let microvm = false;
            #[cfg(feature = "microvm")]
            let microvm = matches!(local.worker_launcher, WorkerLauncher::Microvm { .. });
            let mut mounted = std::collections::BTreeMap::new();
            let mut size = 0u64;
            for (index, artifact) in artifacts.into_iter().enumerate() {
                control.check("sandbox artifact staging")?;
                let path = Path::new(&artifact).canonicalize().map_err(|e| fail(&e))?;
                if !path.is_file() {
                    return Err(WorkerError::InvalidRequest(
                        "artifact must be a file".into(),
                    ));
                }
                let maximum = limits.storage_mb.saturating_mul(1024 * 1024);
                if std::fs::metadata(&path).map_err(|e| fail(&e))?.len()
                    > maximum.saturating_sub(size)
                {
                    return Err(WorkerError::LimitExceeded("staging storage".into()));
                }
                // สำเนา private/read-only ทั้งสอง tier: mode ของ source (เช่น 0664)
                // ต้องไม่ทำให้ loader มองว่า staged input ยังเปิดให้ UID อื่นเขียนได้
                let staged = config_path
                    .parent()
                    .unwrap()
                    .join(format!("artifact-{index}"));
                size += stage_readonly_artifact(&path, &staged, control, maximum - size)?;
                policy
                    .filesystem
                    .read
                    .push(staged.to_string_lossy().into_owned());
                mounted.insert(path, staged);
            }
            let map = |path: &Path| {
                let staged = mounted.get(path).map_or(path, PathBuf::as_path);
                if microvm {
                    format!("/mnt/data{}", staged.display())
                } else {
                    staged.to_string_lossy().into_owned()
                }
            };
            let guest_local = guest_config.local.as_mut().unwrap();
            guest_local.model_path = map(&Path::new(&local.model_path)
                .canonicalize()
                .map_err(|e| fail(&e))?);
            for path in [
                &mut guest_local.manifest_path,
                &mut guest_local.tokenizer_path,
                &mut guest_local.config_path,
            ]
            .into_iter()
            .flatten()
            {
                *path = map(&Path::new(path).canonicalize().map_err(|e| fail(&e))?);
            }
            write_private(
                &config_path_guest,
                &serde_json::to_vec(&guest_config).map_err(|e| fail(&e))?,
            )?;
            policy.filesystem.read.extend([
                config_path_guest.to_string_lossy().into_owned(),
                request_path.to_string_lossy().into_owned(),
            ]);
            let spec = ExecSpec {
                exe: executable,
                args: vec![
                    "--config".into(),
                    map(&config_path_guest),
                    "--request".into(),
                    map(&request_path),
                ],
                cwd: config_path.parent().unwrap().to_path_buf(),
                workspace: config_path.parent().unwrap().to_path_buf(),
                env_extra: vec![],
                limits: ResourceLimits {
                    cpu: (limits.cpu_seconds / 60).max(1).min(u64::from(u32::MAX)) as u32,
                    memory_mb: limits.memory_mb,
                    pids_max: limits.pids_max,
                    storage_mb: limits.storage_mb,
                },
                timeout_ms: control.remaining_ms(request.timeout_ms)?,
                build: None,
            };
            control.begin_execution()?;
            let mut streamed = String::new();
            let outcome = control.with_launch_cancellation(|cancelled| -> Result<_, WorkerError> {
                let outcome = if request.stream {
                    std::thread::scope(|scope| -> Result<_, WorkerError> {
                        let (sender, receiver) = mpsc::channel::<Vec<u8>>();
                        let handle = scope.spawn(|| -> Result<_, WorkerError> {
                            Ok(match &local.worker_launcher {
                                WorkerLauncher::Container { config } => {
                                    aivm_sandbox::container::run_observed(
                                        &spec,
                                        &policy,
                                        config,
                                        cancelled,
                                        Some(sender),
                                    )
                                    .map_err(|e| fail(&e))?
                                }
                                #[cfg(feature = "microvm")]
                                WorkerLauncher::Microvm { config } => {
                                    if config.fc_sha256.is_empty() {
                                        return Err(WorkerError::InvalidRequest(
                                            "MicroVM requires firecracker hash pin".into(),
                                        ));
                                    }
                                    aivm_sandbox::microvm::run_in_microvm_observed(
                                        &spec,
                                        &policy,
                                        config,
                                        cancelled,
                                        Some(sender),
                                    )
                                    .map_err(|(e, _)| fail(&e))?
                                }
                                _ => {
                                    return Err(WorkerError::InvalidRequest(
                                        "expected sandbox launcher".into(),
                                    ))
                                }
                            })
                        });
                        let mut pending = Vec::new();
                        let mut total = 0usize;
                        let mut failure = None;
                        while let Ok(bytes) = receiver.recv() {
                            total = total.saturating_add(bytes.len());
                            if total > MAX_RESPONSE_BYTES {
                                failure = Some(WorkerError::LimitExceeded("stream bytes".into()));
                                cancelled.store(true, Ordering::Relaxed);
                            }
                            if failure.is_none() {
                                pending.extend_from_slice(&bytes);
                                while let Some(end) = pending.iter().position(|byte| *byte == b'\n')
                                {
                                    let line: Vec<_> = pending.drain(..=end).collect();
                                    let line = String::from_utf8_lossy(&line);
                                    if line.trim() == "aivm-container-init:ready-v1" {
                                        continue;
                                    }
                                    let result = consume_delta(
                                        line.trim(),
                                        request,
                                        &mut streamed,
                                        on_delta,
                                        control,
                                    );
                                    if let Err(error) = result {
                                        failure = Some(error);
                                        cancelled.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        }
                        let outcome = handle
                            .join()
                            .map_err(|_| WorkerError::Failed("sandbox launcher panicked".into()))?;
                        if let Some(error) = failure {
                            return Err(error);
                        }
                        outcome
                    })?
                } else {
                    match &local.worker_launcher {
                        WorkerLauncher::Container { config } => {
                            aivm_sandbox::container::run_cancellable(
                                &spec, &policy, config, cancelled,
                            )
                            .map_err(|e| fail(&e))?
                        }
                        #[cfg(feature = "microvm")]
                        WorkerLauncher::Microvm { config } => {
                            if config.fc_sha256.is_empty() {
                                return Err(WorkerError::InvalidRequest(
                                    "MicroVM requires firecracker hash pin".into(),
                                ));
                            }
                            aivm_sandbox::microvm::run_in_microvm_cancellable(
                                &spec, &policy, config, cancelled,
                            )
                            .map_err(|(e, _)| fail(&e))?
                        }
                        _ => {
                            return Err(WorkerError::InvalidRequest(
                                "expected sandbox launcher".into(),
                            ))
                        }
                    }
                };
                Ok(outcome)
            });
            control.check("sandbox execution")?;
            let outcome = outcome?;
            if !outcome.success() {
                return Err(WorkerError::Failed(format!(
                    "sandbox worker exit {:?}: {}",
                    outcome.code,
                    safe_worker_diagnostic(&outcome.stderr)
                )));
            }
            let mut response: InferenceResponse =
                serde_json::from_str(outcome.stdout.trim().lines().last().unwrap_or(""))
                    .map_err(|_| WorkerError::Protocol("invalid sandbox completion JSON".into()))?;
            if request.stream && response.output.as_deref() != Some(streamed.as_str()) {
                return Err(WorkerError::Protocol(
                    "sandbox stream differs from final output".into(),
                ));
            }
            response.applied_limits.extend(outcome.applied);
            response.applied_limits.extend(
                outcome
                    .degraded
                    .into_iter()
                    .map(|item| format!("degraded:{item}")),
            );
            Ok(response)
        })();
        let _ = std::fs::remove_file(request_path);
        let _ = std::fs::remove_file(config_path_guest);
        result
    }
}

fn stage_readonly_artifact(
    source: &Path,
    destination: &Path,
    control: &RequestControl<'_>,
    maximum: u64,
) -> Result<u64, WorkerError> {
    let mut input = super::control::open_artifact(source)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(destination)
        .map_err(|e| WorkerError::Failed(format!("stage artifact: {e}")))?;
    let copied = control.copy(&mut input, &mut output, maximum, "sandbox artifact staging")?;
    let mut permissions = output
        .metadata()
        .map_err(|e| WorkerError::Failed(format!("staged metadata: {e}")))?
        .permissions();
    permissions.set_readonly(true);
    output
        .set_permissions(permissions)
        .map_err(|e| WorkerError::Failed(format!("protect staged artifact: {e}")))?;
    control.check("sandbox artifact staging")?;
    Ok(copied)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn staged_artifact_has_distinct_inode_and_no_write_permissions() {
        let directory = std::env::temp_dir().join(format!("aivm-stage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source.gguf");
        let staged = directory.join("staged.gguf");
        std::fs::write(&source, b"approved weights").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();
        let cancelled = AtomicBool::new(false);
        let control = RequestControl::new(&cancelled, None).unwrap();
        stage_readonly_artifact(&source, &staged, &control, 1024).unwrap();
        assert_eq!(std::fs::metadata(&staged).unwrap().mode() & 0o222, 0);
        assert_ne!(
            std::fs::metadata(&staged).unwrap().ino(),
            std::fs::metadata(&source).unwrap().ino()
        );
        std::fs::write(&source, b"changed weights").unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), b"approved weights");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
