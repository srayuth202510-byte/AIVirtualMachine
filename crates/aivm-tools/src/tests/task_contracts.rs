use super::*;

#[test]
fn repair_audit_requires_issued_task_identity_and_never_creates_verification() {
    let (mut gateway, mut cube, dir) = harness();
    let task = gateway.begin_task(&mut cube, "repair audit").unwrap();
    assert!(gateway
        .audit_repair_state(&mut cube, &task, r#"{"schema":1,"task_id":"another-task"}"#)
        .is_err());
    let mut forged = task.clone();
    forged.revision += 1;
    let body = serde_json::json!({"schema":1,"task_id":task.task_id,"verification_failures":[]})
        .to_string();
    assert!(gateway
        .audit_repair_state(&mut cube, &forged, &body)
        .is_err());
    gateway.audit_repair_state(&mut cube, &task, &body).unwrap();
    let outcome = gateway
        .finalize_task(
            &mut cube,
            &task,
            contracts::Execution::Completed,
            contracts::SolutionOrigin::Model,
            None,
        )
        .unwrap();
    assert!(!outcome.is_verified());
    assert!(outcome.receipt_ids.is_empty());
    aivm_audit::clear_flags(&dir);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn final_outcome_rejects_stale_forged_and_previous_task_receipts() {
    use contracts::{Execution, SolutionOrigin, Verification};
    for mode in ["current", "stale", "forged", "previous", "summary_only"] {
        let (mut gateway, mut cube, dir) = exec_harness();
        gateway.workspace = dir.join("workspace");
        std::fs::create_dir(&gateway.workspace).unwrap();
        std::fs::write(gateway.workspace.join("source.c"), "version-one").unwrap();
        let executable = std::fs::canonicalize("/bin/true")
            .unwrap()
            .display()
            .to_string();
        gateway.verifier = Some(verification::VerifierConfig {
            executable: executable.clone(),
            argv: vec![],
            executable_sha256: Some(verification::digest(&std::fs::read(&executable).unwrap())),
            stdout_contains: None,
            prepare: vec![],
            counterexample: None,
        });
        let mut task = gateway.begin_task(&mut cube, "repair bug").unwrap();
        let mut receipt = gateway
            .exec(&mut cube, &executable, &[])
            .unwrap()
            .verification
            .unwrap();
        match mode {
            "stale" => std::fs::write(gateway.workspace.join("source.c"), "version-two").unwrap(),
            "forged" => receipt.contract_sha256 = "f".repeat(64),
            "previous" => task = gateway.begin_task(&mut cube, "another bug").unwrap(),
            _ => {}
        }
        let outcome = gateway
            .finalize_task(
                &mut cube,
                &task,
                Execution::Completed,
                SolutionOrigin::ModelRepair,
                (mode != "summary_only").then_some(&receipt),
            )
            .unwrap();
        assert_eq!(
            outcome.is_verified(),
            mode == "current",
            "{mode}: {outcome:?}"
        );
        if mode == "stale" {
            assert_eq!(outcome.verification, Verification::Stale);
        }
        assert_eq!(outcome.task_id, task.task_id);
        AuditWriter::verify(dir.join("audit.jsonl")).unwrap();
        aivm_audit::clear_flags(&dir);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn verification_requires_exact_operator_contract_and_trusted_execution_result() {
    let (mut gateway, mut cube, dir) = exec_harness();
    // เหมือน Runtime จริง: audit อยู่นอก workspace ที่กำลังตรวจ digest
    gateway.workspace = dir.join("workspace");
    std::fs::create_dir(&gateway.workspace).unwrap();
    let exe = std::fs::canonicalize("/bin/true")
        .unwrap()
        .display()
        .to_string();
    let args = vec!["test".to_string()];
    // ชื่อ argv และ exit 0 ไม่มีสิทธิ์สร้างหลักฐานเอง
    assert!(gateway
        .exec(&mut cube, &exe, &args)
        .unwrap()
        .verification
        .is_none());
    gateway.verifier = Some(verification::VerifierConfig {
        executable: exe.clone(),
        argv: args.clone(),
        executable_sha256: Some(verification::digest(&std::fs::read(&exe).unwrap())),
        stdout_contains: None,
        prepare: Vec::new(),
        counterexample: None,
    });
    let result = gateway.exec(&mut cube, &exe, &args).unwrap();
    let record = result.verification.unwrap();
    assert!(matches!(
        record.status,
        verification::VerificationStatus::Verified
    ));
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.audit_id.len(), 64);
    assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .contains(&record.audit_id));
    // argv ต้องตรงทุกตัว แม้คำสั่งที่เหลือ exit 0 เหมือนกัน
    assert!(gateway
        .exec(&mut cube, &exe, &[])
        .unwrap()
        .verification
        .is_none());
    gateway.verifier.as_mut().unwrap().stdout_contains = Some("test result: 2 passed".into());
    let result = gateway.exec(&mut cube, &exe, &args).unwrap();
    assert!(result.ok);
    assert!(matches!(
        result.verification.unwrap().status,
        verification::VerificationStatus::Failed
    ));
    gateway.verifier.as_mut().unwrap().executable_sha256 = Some("0".repeat(64));
    assert!(gateway.exec(&mut cube, &exe, &args).is_err());
    let req = ToolRequest {
        tool: "process.exec".into(),
        path: exe,
        content: Some(r#"{"argv":["test"],"verification":{"status":"verified"}}"#.into()),
    };
    assert!(gateway.dispatch(&mut cube, &req).is_err());
    aivm_audit::clear_flags(&dir);
    let _ = std::fs::remove_dir_all(dir);
}
