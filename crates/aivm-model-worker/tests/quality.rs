//! วัดคุณภาพคำตอบจริงแยกจากการผ่าน protocol; oracle คงที่และไม่มีการ execute output
use aivm_model::{worker::*, ModelConfig};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Instant};

fn correct(case: &Value, output: &str) -> bool {
    if let Some(expected) = case.get("exact").and_then(Value::as_str) {
        return output.trim() == expected;
    }
    case.get("json").is_some_and(|expected| {
        serde_json::from_str::<Value>(output.trim()).ok().as_ref() == Some(expected)
    })
}

#[test]
fn quality_oracle_rejects_markdown_extra_fields_and_wrong_answers() {
    // JSON schema ผ่านไม่ได้แปลว่าความหมายตรงโจทย์ และห้ามตัด markdown เพื่อช่วยคะแนน
    let case = json!({"json":{"tool":"filesystem.read","path":"src/seed.txt"}});
    assert!(correct(
        &case,
        r#"{"tool":"filesystem.read","path":"src/seed.txt"}"#
    ));
    assert!(!correct(
        &case,
        r#"{"tool":"filesystem.read","path":".env"}"#
    ));
    assert!(!correct(&case, "```json\n{}\n```"));
    assert!(!correct(
        &case,
        r#"{"tool":"filesystem.read","path":"src/seed.txt","extra":true}"#
    ));
    assert!(!correct(&json!({"exact":"42"}), "The answer is 42"));
}

#[test]
#[ignore = "requires pinned model config; emits task scores independently of protocol success"]
fn real_model_quality_and_latency() {
    let path = PathBuf::from(
        std::env::var("AIVM_WORKER_HOST_CONFIG").expect("pinned ModelConfig JSON required"),
    );
    let evidence = PathBuf::from(
        std::env::var("AIVM_WORKER_QUALITY_EVIDENCE").expect("evidence output required"),
    );
    let bytes = std::fs::read(&path).unwrap();
    let config: ModelConfig = serde_json::from_slice(&bytes).unwrap();
    let corpus_text = include_str!("../../../examples/model-quality.json");
    let corpus: Value = serde_json::from_str(corpus_text).unwrap();
    let local = config.local.as_ref().unwrap();
    assert!(!local.model_sha256.is_empty());
    assert!(local
        .worker_sha256
        .as_ref()
        .is_some_and(|pin| !pin.is_empty()));
    let limits = config.worker_limits.clone().unwrap_or_default();
    let boot = Instant::now();
    let client = WorkerClient::from_config(&config).unwrap();
    let boot_ms = boot.elapsed().as_millis();
    let mut rows = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let request = InferenceRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: case["id"].as_str().unwrap().into(),
            model_id: config.name.clone(),
            prompt: case["prompt"].as_str().unwrap().into(),
            stream: false,
            max_output_tokens: local.max_tokens,
            timeout_ms: limits.timeout_ms,
        };
        let started = Instant::now();
        let result = client.infer(&config, request, &limits);
        match result {
            Ok(response)=>rows.push(json!({"id":case["id"],"infrastructure_passed":response.verification.status==VerificationStatus::Verified,"task_correct":correct(case,response.output.as_deref().unwrap_or("")),"output":response.output,"usage":response.control_plane_usage,"elapsed_ms":started.elapsed().as_millis()})),
            Err(error)=>rows.push(json!({"id":case["id"],"infrastructure_passed":false,"task_correct":false,"error_code":error.code(),"error":error,"elapsed_ms":started.elapsed().as_millis()})),
        }
        let score = rows
            .iter()
            .filter(|row| row["task_correct"] == true)
            .count();
        let report = json!({"schema":1,"scope":corpus["scope"],"config_sha256":format!("{:x}",Sha256::digest(&bytes)),"corpus_sha256":format!("{:x}",Sha256::digest(corpus_text.as_bytes())),"client_boot_ms":boot_ms,"completed":rows.len(),"total":corpus["cases"].as_array().unwrap().len(),"task_correct":score,"cases":rows});
        std::fs::write(&evidence, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    assert!(
        rows.iter().all(|row| row["infrastructure_passed"] == true),
        "inspect quality evidence for infrastructure failures"
    );
    eprintln!(
        "model quality: {}/{} task oracles passed (not a production accuracy estimate)",
        rows.iter()
            .filter(|row| row["task_correct"] == true)
            .count(),
        rows.len()
    );
}
