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
    ) -> Result<InferenceResponse, WorkerError> {
        use aivm_sandbox::{ExecSpec, ResourceLimits};
        let fail = |error: &dyn std::fmt::Display| WorkerError::Failed(error.to_string());
        let local = config
            .local
            .as_ref()
            .ok_or_else(|| WorkerError::InvalidRequest("local config required".into()))?;
        if let WorkerLauncher::Container { config } = &local.worker_launcher {
            let probe = config.probe();
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
            let executable = self.executable.canonicalize().map_err(|e| fail(&e))?;
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
                if self.cancelled.load(Ordering::Relaxed) {
                    return Err(WorkerError::Failed("inference cancelled".into()));
                }
                let path = Path::new(&artifact).canonicalize().map_err(|e| fail(&e))?;
                if !path.is_file() {
                    return Err(WorkerError::InvalidRequest(
                        "artifact must be a file".into(),
                    ));
                }
                size = size.saturating_add(std::fs::metadata(&path).map_err(|e| fail(&e))?.len());
                if size > limits.storage_mb.saturating_mul(1024 * 1024) {
                    return Err(WorkerError::LimitExceeded("staging storage".into()));
                }
                let staged = if microvm {
                    path.clone()
                } else {
                    // A distinct inode avoids exposing source files through hard links.
                    let staged = config_path
                        .parent()
                        .unwrap()
                        .join(format!("artifact-{index}"));
                    std::fs::copy(&path, &staged).map_err(|e| fail(&e))?;
                    staged
                };
                policy
                    .filesystem
                    .read
                    .push(staged.to_string_lossy().into_owned());
                mounted.insert(path, staged);
            }
            let map = |path: &Path| {
                if microvm {
                    format!("/mnt/data{}", path.display())
                } else {
                    mounted.get(path).map_or_else(
                        || path.to_string_lossy().into_owned(),
                        |p| p.to_string_lossy().into_owned(),
                    )
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
                timeout_ms: request.timeout_ms,
                build: None,
            };
            let mut streamed = String::new();
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
                                    &self.cancelled,
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
                                    &self.cancelled,
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
                        }
                        if failure.is_none() {
                            pending.extend_from_slice(&bytes);
                            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                                let line: Vec<_> = pending.drain(..=end).collect();
                                let line = String::from_utf8_lossy(&line);
                                if line.trim() == "aivm-container-init:ready-v1" {
                                    continue;
                                }
                                let result =
                                    consume_delta(line.trim(), request, &mut streamed, on_delta);
                                if let Err(error) = result {
                                    failure = Some(error);
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
                            &spec,
                            &policy,
                            config,
                            &self.cancelled,
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
                            &spec,
                            &policy,
                            config,
                            &self.cancelled,
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
            if !outcome.success() {
                return Err(WorkerError::Failed(format!(
                    "sandbox worker exit {:?}: {}",
                    outcome.code, outcome.stderr
                )));
            }
            let mut response: InferenceResponse =
                serde_json::from_str(outcome.stdout.trim().lines().last().unwrap_or(""))
                    .map_err(|e| fail(&e))?;
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
