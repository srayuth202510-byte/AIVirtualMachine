//! วัดคุณภาพคำตอบจริงแยกจากการผ่าน protocol; oracle คงที่และไม่มีการ execute output
use aivm_model::{worker::*, ModelConfig, OutputMode};
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

// เลือกตามชนิดงานที่ freeze ไว้ ไม่อ่านค่า expected answer มาสร้าง grammar
fn task_mode(case: &Value) -> OutputMode {
    match case["id"].as_str().unwrap() {
        "extract" | "nested-extract" => OutputMode::Text,
        "strict-read-intent"
        | "untrusted-override"
        | "different-read-intent"
        | "injected-read-intent" => OutputMode::AgentIntent,
        _ => OutputMode::Json,
    }
}

fn format_metrics(case: &Value, output: &str) -> (Option<bool>, Option<bool>) {
    let mode = task_mode(case);
    if mode.is_text() {
        return (None, None);
    }
    (
        Some(serde_json::from_str::<Value>(output).is_ok()),
        Some(mode.validate(output).is_ok()),
    )
}

fn failure_kind(case: &Value, output: &str) -> Option<&'static str> {
    if correct(case, output) {
        return None;
    }
    // ใช้ตัด fence เพื่อวิเคราะห์สาเหตุเท่านั้น ห้ามเอาผลนี้ไปเพิ่มคะแนน strict oracle
    let trimmed = output.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|text| text.strip_suffix("```"));
    Some(if unfenced.is_some_and(|text| correct(case, text)) {
        "markdown_fence"
    } else {
        "answer_or_other_format"
    })
}

fn prompt_for(case: &Value, profile: Option<&Value>) -> String {
    let mut prompt = case["prompt"].as_str().unwrap().to_string();
    if let Some(profile) = profile {
        prompt.push_str(profile["suffix"].as_str().unwrap());
    }
    prompt
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
    assert_eq!(
        failure_kind(&json!({"json":[2,5,9]}), "```json\n[2,5,9]\n```"),
        Some("markdown_fence")
    );
    assert_eq!(
        failure_kind(
            &case,
            "```json\n{\"tool\":\"filesystem.read\",\"path\":\".env\"}\n```"
        ),
        Some("answer_or_other_format")
    );
    assert_eq!(failure_kind(&json!({"exact":"42"}), "42"), None);
}

#[test]
fn formatting_profile_preserves_tasks_and_uses_no_oracle_values() {
    let profile: Value =
        serde_json::from_str(include_str!("../../../examples/model-quality-format.json")).unwrap();
    for text in [
        include_str!("../../../examples/model-quality.json"),
        include_str!("../../../examples/model-quality-holdout.json"),
    ] {
        let corpus: Value = serde_json::from_str(text).unwrap();
        let mut ids = std::collections::BTreeSet::new();
        for case in corpus["cases"].as_array().unwrap() {
            assert!(ids.insert(case["id"].as_str().unwrap()));
            let raw = prompt_for(case, None);
            assert_eq!(raw, case["prompt"].as_str().unwrap());
            assert_eq!(
                prompt_for(case, Some(&profile)),
                format!("{raw}{}", profile["suffix"].as_str().unwrap())
            );
            // oracle ที่เปลี่ยนต้องไม่เปลี่ยน prompt ของ model
            let mut changed = case.clone();
            changed["exact"] = json!("not-the-answer");
            changed["json"] = json!({"not":"the answer"});
            assert_eq!(
                prompt_for(case, Some(&profile)),
                prompt_for(&changed, Some(&profile))
            );
            assert_eq!(task_mode(case), task_mode(&changed));
        }
    }
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
    let corpus_name = std::env::var("AIVM_QUALITY_CORPUS").unwrap_or_else(|_| "baseline".into());
    let corpus_text = match corpus_name.as_str() {
        "baseline" => include_str!("../../../examples/model-quality.json"),
        "holdout" => include_str!("../../../examples/model-quality-holdout.json"),
        other => panic!("unknown quality corpus: {other}"),
    };
    let corpus: Value = serde_json::from_str(corpus_text).unwrap();
    let style = std::env::var("AIVM_QUALITY_PROMPT_STYLE").unwrap_or_else(|_| "raw".into());
    let profile_text = include_str!("../../../examples/model-quality-format.json");
    let profile: Value = serde_json::from_str(profile_text).unwrap();
    let profile = match style.as_str() {
        "raw" | "structured" => None,
        "strict" => Some(&profile),
        other => panic!("unknown quality prompt style: {other}"),
    };
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
        let mode = if style == "structured" {
            task_mode(case)
        } else {
            OutputMode::Text
        };
        let request = InferenceRequest {
            protocol_version: mode.protocol_version(),
            output_mode: mode,
            request_id: case["id"].as_str().unwrap().into(),
            model_id: config.name.clone(),
            prompt: prompt_for(case, profile),
            stream: false,
            max_output_tokens: local.max_tokens,
            timeout_ms: limits.timeout_ms,
            temperature: None,
        };
        let request_prompt = request.prompt.clone();
        let started = Instant::now();
        let result = client.infer(&config, request, &limits);
        match result {
            Ok(response)=> {
                let (format_valid, schema_valid) = format_metrics(case, response.output.as_deref().unwrap_or(""));
                rows.push(json!({"format_valid":format_valid,"schema_valid":schema_valid,"output_mode":response.output_mode,"grammar_id":response.grammar_id,"termination":response.termination,"id":case["id"],"prompt":request_prompt,"infrastructure_passed":response.verification.status==VerificationStatus::Verified,"task_correct":correct(case,response.output.as_deref().unwrap_or("")),"failure_kind":failure_kind(case,response.output.as_deref().unwrap_or("")),"output":response.output,"usage":response.control_plane_usage,"elapsed_ms":started.elapsed().as_millis()}));
            },
            Err(error)=>rows.push(json!({"id":case["id"],"prompt":request_prompt,"output_mode":mode,"grammar_id":mode.grammar_id(),"format_valid":false,"schema_valid":false,"termination":error.code(),"infrastructure_passed":false,"task_correct":false,"error_code":error.code(),"error":error,"elapsed_ms":started.elapsed().as_millis()})),
        }
        let score = rows
            .iter()
            .filter(|row| row["task_correct"] == true)
            .count();
        let report = json!({"schema":1,"scope":corpus["scope"],"corpus":corpus_name,"prompt_style":style,"prompt_profile_sha256":profile.map(|_|format!("{:x}",Sha256::digest(profile_text.as_bytes()))),"config_sha256":format!("{:x}",Sha256::digest(&bytes)),"corpus_sha256":format!("{:x}",Sha256::digest(corpus_text.as_bytes())),"client_boot_ms":boot_ms,"completed":rows.len(),"total":corpus["cases"].as_array().unwrap().len(),"task_correct":score,"cases":rows});
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
