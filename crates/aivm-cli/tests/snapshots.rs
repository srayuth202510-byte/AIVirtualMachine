use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    base: PathBuf,
    vms: PathBuf,
    store: PathBuf,
    config: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("aivm CLI recovery {} {nonce}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let config = base.join("current.yaml");
        std::fs::write(&config, "name: trusted\nresources: {cpu: 1}\n").unwrap();
        let f = Self {
            vms: base.join("vms"),
            store: base.join("backups"),
            base,
            config,
        };
        f.ok(&["create", "original", "--config", f.config.to_str().unwrap()]);
        std::fs::write(
            f.vms.join("original/workspace/src/data.txt"),
            "before damage",
        )
        .unwrap();
        f
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_aivm"))
            .arg("--root")
            .arg(&self.vms)
            .args(args)
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
    fn snapshot(&self) -> serde_json::Value {
        serde_json::from_str(&self.ok(&[
            "snapshot",
            "original",
            "--store",
            self.store.to_str().unwrap(),
        ]))
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn operator_cli_restores_deleted_data_into_a_new_vm_with_a_separate_audit() {
    let f = Fixture::new();
    let point = f.snapshot();
    let id = point["id"].as_str().unwrap();
    let digest = point["manifest_sha256"].as_str().unwrap();
    let old_audit = std::fs::read(f.vms.join("original/audit.jsonl")).unwrap();
    std::fs::remove_file(f.vms.join("original/workspace/src/data.txt")).unwrap();
    let listed: serde_json::Value =
        serde_json::from_str(&f.ok(&["snapshots", "--store", f.store.to_str().unwrap()])).unwrap();
    assert_eq!(listed[0]["payload_verified"], false);
    let verified: serde_json::Value = serde_json::from_str(&f.ok(&[
        "verify-snapshot",
        id,
        "--store",
        f.store.to_str().unwrap(),
        "--manifest-sha256",
        digest,
    ]))
    .unwrap();
    assert_eq!(verified["payload_verified"], true);
    let restored: serde_json::Value = serde_json::from_str(&f.ok(&[
        "restore",
        id,
        "recovered",
        "--store",
        f.store.to_str().unwrap(),
        "--manifest-sha256",
        digest,
        "--config",
        f.config.to_str().unwrap(),
    ]))
    .unwrap();
    assert_eq!(restored["vm"], "recovered");
    assert_eq!(
        std::fs::read_to_string(f.vms.join("recovered/workspace/src/data.txt")).unwrap(),
        "before damage"
    );
    assert!(!f.vms.join("original/workspace/src/data.txt").exists());
    assert_eq!(
        std::fs::read(f.vms.join("original/audit.jsonl")).unwrap(),
        old_audit
    );
    assert!(f.ok(&["audit", "recovered"]).contains("chain verified"));
    assert!(f.ok(&["state", "recovered"]).contains("INIT"));
}

#[test]
fn cli_rejects_corrupt_payloads_and_requires_an_explicit_trusted_digest() {
    let f = Fixture::new();
    let point = f.snapshot();
    let id = point["id"].as_str().unwrap();
    let digest = point["manifest_sha256"].as_str().unwrap();
    let missing = f.run(&[
        "restore",
        id,
        "recovered",
        "--store",
        f.store.to_str().unwrap(),
        "--config",
        f.config.to_str().unwrap(),
    ]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--manifest-sha256"));
    std::fs::write(f.store.join(id).join("data/src/data.txt"), "tampered").unwrap();
    assert!(!f
        .run(&["verify-snapshot", id, "--store", f.store.to_str().unwrap()])
        .status
        .success());
    assert!(!f
        .run(&[
            "restore",
            id,
            "recovered",
            "--store",
            f.store.to_str().unwrap(),
            "--manifest-sha256",
            digest,
            "--config",
            f.config.to_str().unwrap()
        ])
        .status
        .success());
    assert!(!f.vms.join("recovered").exists());
}
