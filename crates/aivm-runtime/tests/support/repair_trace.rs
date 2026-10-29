//! Operator-only native observations; ไม่เพิ่ม tool หรือสิทธิ์ให้โมเดล
use super::*;
use aivm_tools::contracts::{Execution, SolutionOrigin};
use sha2::{Digest, Sha256};

fn measure(source: &[u8], out: &std::path::Path, label: &str) -> serde_json::Value {
    let mut fixture = Fixture::new(true);
    fixture.modify();
    std::fs::write(fixture.runtime.workspace.join("src/main.c"), source).unwrap();
    let steps = fixture.build_steps();
    fixture.prepare_verifier(&steps[..2]);
    let task = fixture
        .runtime
        .gateway
        .begin_task(
            &mut fixture.runtime.cube,
            "Operator-only measurement of native values; not a repair-success check",
        )
        .unwrap();
    let mut checks = Vec::new();
    for encoded in steps {
        let request: ToolRequest = serde_json::from_str(&encoded).unwrap();
        let result = fixture
            .runtime
            .gateway
            .dispatch(&mut fixture.runtime.cube, &request);
        let ok = result.as_ref().is_ok_and(|value| value.ok);
        checks.push(match result {
            Ok(result) => serde_json::to_value(result).unwrap(),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        });
        if !ok {
            break;
        }
    }
    let receipt: Option<aivm_tools::verification::VerificationRecord> = checks
        .last()
        .and_then(|row| row.get("verification"))
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()).unwrap());
    let outcome = fixture
        .runtime
        .gateway
        .finalize_task(
            &mut fixture.runtime.cube,
            &task,
            Execution::Completed,
            SolutionOrigin::OperatorPatch,
            receipt.as_ref(),
        )
        .unwrap();
    // ปิดการใช้ gateway ก่อนเปิด writer ต่อปลาย chain เพื่อผูก stdout กับ bytes ที่วัดจริง
    let snapshot = json!({"task_id":task.task_id,"label":label,
        "source_sha256":format!("{:x}",Sha256::digest(source)),
        "checks_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&checks).unwrap())),
        "verification_audit_id":receipt.as_ref().map(|value|&value.audit_id)});
    let mut record = aivm_audit::AuditRecord::new(
        0,
        "operator-trace",
        &task.task_id,
        "native-observation",
        "OPERATOR_MEASUREMENT",
        "native-trace-observation",
        &task.task_id,
        "allow",
        "operator-only",
    );
    record.rule_matched = "native-output-snapshot".into();
    record.result = snapshot.to_string();
    let record = AuditWriter::open(fixture.root.join("audit.jsonl"))
        .unwrap()
        .append(record)
        .unwrap();
    let mut snapshot = snapshot;
    snapshot["audit_id"] = json!(record.hash_entry);
    AuditWriter::verify(fixture.root.join("audit.jsonl")).unwrap();
    std::fs::copy(
        fixture.root.join("audit.jsonl"),
        out.join(format!("{label}-audit.jsonl")),
    )
    .unwrap();
    json!({"task_contract":task,"outcome":outcome,"verification":receipt,"snapshot":snapshot,
           "source_sha256":format!("{:x}",Sha256::digest(source)),"checks":checks})
}

#[test]
#[ignore = "operator-only: run via scripts/run-repair-trace.py"]
fn operator_dynamic_trace_probe() {
    let root = PathBuf::from(std::env::var("AIVM_REPAIR_TRACE_BUNDLE").unwrap());
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["schema"], 1);
    assert_eq!(bundle["kind"], "native_integer_function_trace");
    let source = std::fs::read(root.join("source.c")).unwrap();
    let original = std::fs::read(root.join("original.c")).unwrap();
    let traced = std::fs::read(root.join("traced.c")).unwrap();
    // รับเฉพาะไฟล์ชื่อคงที่ใน bundle และผูก bytes ก่อนใช้ fixture/gateway เดิม
    for (bytes, key) in [
        (&source, "source_sha256"),
        (&original, "original_sha256"),
        (&traced, "traced_sha256"),
    ] {
        assert!(bytes.len() <= 65536);
        assert_eq!(bundle[key], format!("{:x}", Sha256::digest(bytes)));
    }
    let out = root.join("measurement");
    std::fs::create_dir(&out).unwrap();
    let original = measure(&original, &out, "original");
    let traced = measure(&traced, &out, "traced");
    std::fs::write(
        out.join("report.json"),
        serde_json::to_vec_pretty(&json!({
            "schema":1,"kind":"operator_trace_measurement_not_repair",
            "original":original,"traced":traced
        }))
        .unwrap(),
    )
    .unwrap();
}
