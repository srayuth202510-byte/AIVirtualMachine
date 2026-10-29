//! SIGKILL จริงที่ source/quota/audit/receipt boundaries; ไม่มี kill switch ใน production
use super::*;
use aivm_capability::Capability;
use std::os::unix::process::ExitStatusExt;

fn fixture(root: &Path) -> (ToolGateway, Cube) {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    if !workspace.join("src/main.c").exists() {
        std::fs::write(workspace.join("src/main.c"), b"OLD").unwrap();
    }
    let policy = Policy::from_yaml(&format!("name: crash\nfilesystem:\n  read: [{}]\n  write: [{}/src]\n  deny: ['**/.env*']\nprocess:\n  deny: [/bin/sh]\nnetwork:\n  deny: ['10.0.0.0/8']\n",workspace.display(),workspace.display())).unwrap();
    let mut caps = CapabilitySet::new(vec![Capability::new(
        "write",
        "filesystem",
        &workspace.join("src").display().to_string(),
    )
    .with_constraints(aivm_capability::Constraints::new().with_max_total_bytes(16384))]);
    let mut cube = Cube::new("crash");
    let state = root.join("state.json");
    if state.exists() {
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        caps = serde_json::from_value(saved["caps"].clone()).unwrap();
        cube = serde_json::from_value(saved["cube"].clone()).unwrap();
    }
    let audit = AuditWriter::open(root.join("audit.jsonl")).unwrap();
    let mut gateway = ToolGateway::new(workspace, policy, caps, audit, "crash", "crash");
    gateway.state_path = Some(state);
    (gateway, cube)
}

#[test]
fn crash_child() {
    let Ok(root) = std::env::var("AIVM_FAULT_DIRECTORY") else {
        return;
    };
    let phase = std::env::var("AIVM_FAULT_PHASE").unwrap();
    let case = std::env::var("AIVM_FAULT_CASE").unwrap();
    let (mut gateway, mut cube) = fixture(Path::new(&root));
    let mut hook = |stage: &str| {
        if stage == phase {
            unsafe {
                libc::raise(libc::SIGKILL);
            }
            unreachable!();
        }
        Ok(())
    };
    match case.as_str() {
        "write" => {
            gateway
                .write_with_hook(&mut cube, "src/main.c", &"N".repeat(8192), &mut hook)
                .unwrap();
        }
        "audit" => {
            let row = AuditRecord::new(
                0, "crash", "crash", "probe", "INIT", "probe", "source", "allow", "crash",
            );
            gateway
                .audit
                .append_with_hook(row, &mut |stage| hook(&format!("audit-{stage}")))
                .unwrap();
        }
        "receipt" => {
            gateway.begin_task(&mut cube, "repair bug").unwrap();
            let executable = std::fs::canonicalize("/bin/true").unwrap();
            let config = verification::VerifierConfig {
                executable: executable.display().to_string(),
                argv: vec![],
                executable_sha256: Some(verification::digest(&std::fs::read(&executable).unwrap())),
                stdout_contains: None,
                prepare: vec![],
                counterexample: None,
            };
            let prepared =
                verification::PreparedVerification::new(config, &gateway.workspace, &executable)
                    .unwrap();
            let code = std::process::Command::new(&executable)
                .status()
                .unwrap()
                .code();
            let record = prepared.finish(&gateway.workspace, code, "");
            gateway
                .publish_verification_with_hook(&cube, "verifier", record, &mut hook)
                .unwrap();
        }
        _ => panic!("unknown crash scenario"),
    }
    panic!("requested crash boundary was not reached");
}

#[test]
fn sigkill_preserves_source_quota_audit_and_receipt_recovery() {
    let write = [
        "quota-created",
        "quota-written",
        "quota-synced",
        "quota-renamed",
        "quota-directory-synced",
        "quota-checkpointed",
        "file-created",
        "file-partial",
        "file-synced",
        "file-renamed",
        "file-directory-synced",
    ];
    let audit = [
        "audit-opened",
        "audit-written",
        "audit-synced",
        "audit-directory-synced",
    ];
    let receipt = [
        "receipt-opened",
        "receipt-written",
        "receipt-synced",
        "receipt-directory-synced",
        "receipt-delivered",
    ];
    for (case, phases) in [
        ("write", write.as_slice()),
        ("audit", audit.as_slice()),
        ("receipt", receipt.as_slice()),
    ] {
        for phase in phases {
            let root = std::env::temp_dir().join(format!("aivm-fault-{}", uuid::Uuid::new_v4()));
            let (gateway, cube) = fixture(&root);
            gateway.checkpoint(&cube).unwrap();
            drop(gateway);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "failure_tests::crash_child", "--nocapture"])
                .env("AIVM_FAULT_DIRECTORY", &root)
                .env("AIVM_FAULT_CASE", case)
                .env("AIVM_FAULT_PHASE", phase)
                .output()
                .unwrap()
                .status;
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "{case}:{phase}: {status}"
            );
            let (mut restored, mut cube) = fixture(&root);
            recover_workspace_writes(&restored.workspace).unwrap();
            let bytes = std::fs::read(restored.workspace.join("src/main.c")).unwrap();
            assert!(
                bytes == b"OLD" || bytes == vec![b'N'; 8192],
                "partial source at {phase}"
            );
            if bytes.len() == 8192 {
                assert_eq!(restored.caps.caps[0].used_bytes, 8192);
            }
            if phase.starts_with("file-") || *phase == "quota-checkpointed" {
                assert_eq!(restored.caps.caps[0].used_bytes, 8192);
            }
            AuditWriter::verify(root.join("audit.jsonl")).unwrap();
            let text = std::fs::read_to_string(root.join("audit.jsonl")).unwrap_or_default();
            let prior = text
                .lines()
                .filter_map(|line| serde_json::from_str::<AuditRecord>(line).ok())
                .find(|row| row.action == "verification")
                .map(|row| {
                    let mut receipt: verification::VerificationRecord =
                        serde_json::from_str(&row.result).unwrap();
                    receipt.audit_id = row.hash_entry;
                    receipt
                });
            let task = restored
                .begin_task(&mut cube, "resume after crash")
                .unwrap();
            let outcome = restored
                .finalize_task(
                    &mut cube,
                    &task,
                    contracts::Execution::Completed,
                    contracts::SolutionOrigin::Unknown,
                    prior.as_ref(),
                )
                .unwrap();
            assert!(
                !outcome.is_verified(),
                "old/lost receipt revived at {phase}"
            );
            aivm_audit::clear_flags(&root);
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}
