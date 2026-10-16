use super::*;
use crate::VmStatus;
use aivm_cube::{AgentState, TransitionGuards};
use aivm_runtime::Runtime;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    base: PathBuf,
    store: PathBuf,
    supervisor: Supervisor,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("aivm-recovery-{}", uuid::Uuid::new_v4()));
        let mut supervisor = Supervisor::new(base.join("vms"));
        supervisor.create("source", config()).unwrap();
        Self {
            store: base.join("backups"),
            base,
            supervisor,
        }
    }
    fn workspace(&self) -> PathBuf {
        self.supervisor.vm_dir("source").join("workspace")
    }
    fn snapshot(&mut self) -> SnapshotSummary {
        self.supervisor.snapshot("source", &self.store).unwrap()
    }
    fn data(&self, snapshot: &SnapshotSummary) -> PathBuf {
        self.store.join(&snapshot.id).join("data")
    }
    fn restore(&mut self, snapshot: &SnapshotSummary, name: &str) -> Result<SnapshotSummary> {
        self.supervisor.restore_snapshot(
            &self.store,
            &snapshot.id,
            &snapshot.manifest_sha256,
            name,
            config(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}
fn config() -> VmConfig {
    VmConfig::from_yaml("name: trusted-current\nresources: {cpu: 2}").unwrap()
}
fn rewrite(
    f: &Fixture,
    snapshot: &SnapshotSummary,
    change: impl FnOnce(&mut serde_json::Value),
) -> String {
    let dir = f.store.join(&snapshot.id);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    change(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap();
    let hash = digest(&bytes);
    std::fs::write(dir.join("manifest.json"), bytes).unwrap();
    std::fs::write(dir.join("manifest.sha256"), &hash).unwrap();
    hash
}

#[test]
fn restores_deleted_and_overwritten_data_without_rolling_back_security_state() {
    let mut f = Fixture::new();
    let workspace = f.workspace();
    std::fs::write(workspace.join("src/binary"), [0, 255, 128, 10]).unwrap();
    std::fs::write(workspace.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        workspace.join("run.sh"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    std::fs::create_dir(workspace.join("empty")).unwrap();
    f.supervisor
        .transition("source", AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    f.supervisor
        .transition(
            "source",
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.99,
                ..Default::default()
            },
        )
        .unwrap();
    let source = f.supervisor.vm_dir("source");
    std::fs::write(source.join("secrets.yaml"), "OLD_SECRET_MUST_NOT_RETURN").unwrap();
    std::fs::write(source.join("memory-marker"), "untrusted old memory").unwrap();
    let point = f.snapshot();
    let source_state = std::fs::read(source.join("state.json")).unwrap();
    let audit_before = std::fs::read(source.join("audit.jsonl")).unwrap();
    std::fs::remove_file(workspace.join("src/binary")).unwrap();
    std::fs::write(workspace.join("run.sh"), "damaged").unwrap();
    f.restore(&point, "recovered").unwrap();
    let dest = f.supervisor.vm_dir("recovered");
    assert_eq!(
        std::fs::read(dest.join("workspace/src/binary")).unwrap(),
        [0, 255, 128, 10]
    );
    assert_eq!(
        std::fs::read_to_string(dest.join("workspace/run.sh")).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
    assert!(dest.join("workspace/empty").is_dir());
    assert_eq!(
        std::fs::metadata(dest.join("workspace/run.sh"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!dest.join("secrets.yaml").exists());
    assert!(!dest.join("memory-marker").exists());
    assert_eq!(
        std::fs::read(source.join("state.json")).unwrap(),
        source_state
    );
    assert_eq!(
        std::fs::read(source.join("audit.jsonl")).unwrap(),
        audit_before
    );
    let rt = Runtime::init(config(), dest.clone()).unwrap();
    assert_eq!(rt.cube.state, AgentState::Init);
    assert!(rt.gateway.live_secret_leases().is_empty());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dest.join("state.json")).unwrap()).unwrap();
    assert_eq!(saved["leases"], serde_json::json!([]));
    let audit = std::fs::read_to_string(dest.join("audit.jsonl")).unwrap();
    assert!(audit.contains("snapshot.restore"));
    assert!(audit.contains(&point.manifest_sha256));
    assert!(!audit.contains("snapshot.create"));
    AuditWriter::verify(dest.join("audit.jsonl")).unwrap();
}

#[test]
fn retains_multiple_points_and_lists_metadata_without_claiming_payload_verification() {
    let mut f = Fixture::new();
    std::fs::write(f.workspace().join("value"), "old").unwrap();
    let first = f.snapshot();
    std::fs::write(f.workspace().join("value"), "new").unwrap();
    let second = f.snapshot();
    let listed = f.supervisor.snapshots(&f.store).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|s| !s.payload_verified));
    assert_ne!(first.id, second.id);
    f.restore(&first, "old-copy").unwrap();
    f.restore(&second, "new-copy").unwrap();
    assert_eq!(
        std::fs::read_to_string(f.supervisor.vm_dir("old-copy").join("workspace/value")).unwrap(),
        "old"
    );
    assert_eq!(
        std::fs::read_to_string(f.supervisor.vm_dir("new-copy").join("workspace/value")).unwrap(),
        "new"
    );
    let verified = f
        .supervisor
        .verify_snapshot(&f.store, &first.id, Some(&first.manifest_sha256))
        .unwrap();
    assert!(verified.payload_verified);
    assert_eq!(std::fs::metadata(&f.store).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::metadata(f.data(&first).join("value"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(f.data(&first).join("value"))
            .unwrap()
            .nlink(),
        1
    );
}

#[test]
fn corrupt_missing_and_extra_payloads_prevent_restore_before_creating_a_vm() {
    for mode in ["corrupt", "missing", "extra"] {
        let mut f = Fixture::new();
        std::fs::write(f.workspace().join("value"), "good").unwrap();
        let point = f.snapshot();
        let data = f.data(&point);
        match mode {
            "corrupt" => std::fs::write(data.join("value"), "evil").unwrap(),
            "missing" => std::fs::remove_file(data.join("value")).unwrap(),
            _ => std::fs::write(data.join("extra"), "extra").unwrap(),
        }
        assert!(f
            .supervisor
            .verify_snapshot(&f.store, &point.id, None)
            .is_err());
        assert!(f.restore(&point, "recovered").is_err());
        assert!(!f.supervisor.vm_dir("recovered").exists());
        assert_eq!(f.supervisor.snapshots(&f.store).unwrap().len(), 1);
    }
}

#[test]
fn pinned_digest_rejects_a_rewritten_manifest_even_if_its_checksum_is_replaced() {
    let mut f = Fixture::new();
    std::fs::write(f.workspace().join("value"), "good").unwrap();
    let point = f.snapshot();
    rewrite(&f, &point, |m| {
        m["inventory"]["files"][0]["executable"] = true.into()
    });
    assert!(f.restore(&point, "recovered").is_err());
    assert!(!f.supervisor.vm_dir("recovered").exists());
}

#[test]
fn rejects_traversal_duplicates_missing_parents_and_unknown_versions() {
    for case in [
        "traversal",
        "absolute",
        "duplicate",
        "parent",
        "version",
        "size",
    ] {
        let mut f = Fixture::new();
        std::fs::write(f.workspace().join("value"), "good").unwrap();
        let point = f.snapshot();
        let hash = rewrite(&f, &point, |m| match case {
            "traversal" => m["inventory"]["files"][0]["path"] = "../../escape".into(),
            "absolute" => m["inventory"]["files"][0]["path"] = "/etc/passwd".into(),
            "parent" => m["inventory"]["files"][0]["path"] = "missing/leaf".into(),
            "version" => m["version"] = 999.into(),
            "size" => m["inventory"]["bytes"] = u64::MAX.into(),
            _ => {
                let file = m["inventory"]["files"][0].clone();
                m["inventory"]["files"].as_array_mut().unwrap().push(file);
            }
        });
        assert!(
            f.supervisor
                .restore_snapshot(&f.store, &point.id, &hash, "recovered", config())
                .is_err(),
            "{case}"
        );
        assert!(!f.supervisor.vm_dir("recovered").exists());
    }
}

#[test]
fn rejects_workspace_and_payload_symlinks_hardlinks_and_special_files() {
    for kind in ["symlink-file", "symlink-dir", "hardlink", "fifo"] {
        let mut f = Fixture::new();
        let outside = f.base.join("outside");
        std::fs::write(&outside, "private").unwrap();
        let path = f.workspace().join("unsafe");
        match kind {
            "symlink-file" => symlink(&outside, &path).unwrap(),
            "symlink-dir" => symlink(&f.base, &path).unwrap(),
            "hardlink" => std::fs::hard_link(&outside, &path).unwrap(),
            _ => {
                let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        assert!(f.supervisor.snapshot("source", &f.store).is_err(), "{kind}");
        assert!(f.supervisor.snapshots(&f.store).unwrap().is_empty());
        assert!(std::fs::read_dir(&f.store).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pending-")));
    }
    let mut f = Fixture::new();
    std::fs::write(f.workspace().join("value"), "good").unwrap();
    let point = f.snapshot();
    std::fs::remove_file(f.data(&point).join("value")).unwrap();
    symlink(f.workspace().join("value"), f.data(&point).join("value")).unwrap();
    assert!(f.restore(&point, "recovered").is_err());
}

#[test]
fn rejects_overlapping_and_nonprivate_stores() {
    let mut f = Fixture::new();
    for store in [
        f.workspace().join("backups"),
        f.supervisor.root.clone(),
        f.base.clone(),
    ] {
        assert!(f.supervisor.snapshot("source", &store).is_err());
    }
    symlink(f.workspace(), f.base.join("alias")).unwrap();
    assert!(f
        .supervisor
        .snapshot("source", &f.base.join("alias"))
        .is_err());
    std::fs::create_dir(&f.store).unwrap();
    std::fs::set_permissions(&f.store, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.supervisor.snapshot("source", &f.store).is_err());
}

#[test]
fn rejects_running_vm_and_busy_store() {
    let mut f = Fixture::new();
    let source = f.supervisor.vm_dir("source");
    let lease = lifecycle::Lease::acquire(&source, false).unwrap();
    assert!(f.supervisor.snapshot("source", &f.store).is_err());
    assert!(!f.store.exists());
    drop(lease);
    let repo = Repository::open(&f.store, &f.supervisor.root, true).unwrap();
    assert!(f.supervisor.snapshot("source", &f.store).is_err());
    drop(repo);
    f.snapshot();
}

#[test]
fn restore_never_overwrites_the_source_or_an_existing_target_and_failure_can_retry() {
    let mut f = Fixture::new();
    std::fs::write(f.workspace().join("value"), "good").unwrap();
    let point = f.snapshot();
    assert!(f.restore(&point, "source").is_err());
    f.supervisor.create("existing", config()).unwrap();
    std::fs::write(
        f.supervisor.vm_dir("existing").join("workspace/keep"),
        "keep",
    )
    .unwrap();
    assert!(f.restore(&point, "existing").is_err());
    assert_eq!(
        std::fs::read_to_string(f.supervisor.vm_dir("existing").join("workspace/keep")).unwrap(),
        "keep"
    );
    let mut bad = config();
    bad.runtime.isolation = "invalid".into();
    assert!(f
        .supervisor
        .restore_snapshot(
            &f.store,
            &point.id,
            &point.manifest_sha256,
            "recovered",
            bad
        )
        .is_err());
    assert!(!f.supervisor.vm_dir("recovered").exists());
    f.restore(&point, "recovered").unwrap();
    assert_eq!(f.supervisor.status("recovered"), Some(VmStatus::Created));
}

#[test]
fn oversized_sparse_files_and_too_deep_trees_are_rejected_without_publishing() {
    let mut f = Fixture::new();
    let huge = f.workspace().join("huge");
    File::create(&huge).unwrap().set_len(MAX_BYTES + 1).unwrap();
    assert!(f.supervisor.snapshot("source", &f.store).is_err());
    std::fs::remove_file(huge).unwrap();
    let mut nested = f.workspace();
    for _ in 0..65 {
        nested = nested.join("d");
        std::fs::create_dir(&nested).unwrap();
    }
    assert!(f.supervisor.snapshot("source", &f.store).is_err());
    assert!(f.supervisor.snapshots(&f.store).unwrap().is_empty());
}

#[test]
fn failed_preparation_is_not_discoverable_and_preserves_existing_vms() {
    let mut f = Fixture::new();
    let result = f.supervisor.create_prepared("incomplete", config(), |dir| {
        std::fs::write(dir.join("workspace/partial"), "partial").map_err(error)?;
        Err(error("injected restore copy failure"))
    });
    assert!(result.is_err());
    assert!(!f.supervisor.vm_dir("incomplete").exists());
    assert!(Supervisor::new(f.supervisor.root.clone())
        .status("incomplete")
        .is_none());
    assert!(f.workspace().is_dir());
}

#[test]
fn mediated_agent_tools_and_sandboxed_processes_cannot_read_or_delete_backups() {
    let mut f = Fixture::new();
    std::fs::write(f.workspace().join("src/value"), "RECOVERY_PRIVATE_DATA").unwrap();
    let point = f.snapshot();
    let data = f.data(&point).join("src/value");
    let path = data.to_str().unwrap();
    let mut cfg = config();
    cfg.tools.allow = vec!["/usr/bin/cat".into(), "/usr/bin/rm".into()];
    let mut rt = Runtime::init(cfg, f.supervisor.vm_dir("source")).unwrap();
    rt.transition_to(AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    rt.transition_to(
        AgentState::Modify,
        &TransitionGuards {
            confidence: 0.99,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(rt.gateway.read(&mut rt.cube, path).is_err());
    assert!(rt.gateway.write(&mut rt.cube, path, "destroy").is_err());
    let allowed = rt
        .gateway
        .exec(
            &mut rt.cube,
            "/usr/bin/cat",
            &[f.workspace()
                .join("src/value")
                .to_string_lossy()
                .into_owned()],
        )
        .unwrap();
    assert!(allowed.ok);
    let denied = rt
        .gateway
        .exec(&mut rt.cube, "/usr/bin/cat", &[path.into()])
        .unwrap();
    assert!(!denied.ok);
    assert!(!denied.output.contains("RECOVERY_PRIVATE_DATA"));
    let deletion = rt
        .gateway
        .exec(&mut rt.cube, "/usr/bin/rm", &[path.into()])
        .unwrap();
    assert!(!deletion.ok);
    assert_eq!(
        std::fs::read_to_string(data).unwrap(),
        "RECOVERY_PRIVATE_DATA"
    );
    assert!(f
        .supervisor
        .verify_snapshot(&f.store, &point.id, Some(&point.manifest_sha256))
        .is_ok());
}

#[test]
fn restore_uses_the_current_operator_config_and_does_not_replay_modify_grants() {
    let mut f = Fixture::new();
    f.supervisor
        .transition("source", AgentState::Analyze, &TransitionGuards::default())
        .unwrap();
    f.supervisor
        .transition(
            "source",
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.99,
                ..Default::default()
            },
        )
        .unwrap();
    let point = f.snapshot();
    let mut current = config();
    current.resources.cpu = 1;
    f.supervisor
        .restore_snapshot(
            &f.store,
            &point.id,
            &point.manifest_sha256,
            "current",
            current,
        )
        .unwrap();
    let dir = f.supervisor.vm_dir("current");
    let saved = VmConfig::from_file(&dir.join("aivm.yaml")).unwrap();
    assert_eq!(saved.resources.cpu, 1);
    let rt = Runtime::init(saved, dir).unwrap();
    assert_eq!(rt.cube.state, AgentState::Init);
    assert!(!rt
        .gateway
        .caps
        .caps
        .iter()
        .any(|cap| cap.action == "write" || cap.action == "execute"));
}

#[test]
fn lists_ignore_abandoned_staging_and_verification_works_with_a_readonly_lock() {
    let mut f = Fixture::new();
    let point = f.snapshot();
    std::fs::create_dir(f.store.join(".pending-interrupted")).unwrap();
    std::fs::write(f.store.join(".pending-interrupted/partial"), "partial").unwrap();
    std::fs::set_permissions(
        f.store.join("snapshot.lock"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    assert_eq!(f.supervisor.snapshots(&f.store).unwrap().len(), 1);
    assert!(
        f.supervisor
            .verify_snapshot(&f.store, &point.id, Some(&point.manifest_sha256))
            .unwrap()
            .payload_verified
    );
    f.restore(&point, "readonly-recovered").unwrap();
}
