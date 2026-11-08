use super::*;

#[test]
fn unsupported_guest_secret_injection_preserves_the_lease() {
    for (level, rule) in [
        (SandboxLevel::MicroVm, "secret-unsupported-microvm"),
        (SandboxLevel::Hardware, "secret-unsupported-hardware"),
    ] {
        let (mut gw, mut cube, dir) = secret_harness();
        let response = gw
            .dispatch(
                &mut cube,
                &ToolRequest {
                    tool: "secret.request".into(),
                    path: "-".into(),
                    content: Some(secret_body("process.exec", "test_token", "read", "low")),
                },
            )
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&response.output).unwrap();
        let id = value["lease_id"].as_str().unwrap();
        gw.level = level;
        let result = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/bin/true".into(),
                content: Some(serde_json::json!({"argv": [], "secret": id}).to_string()),
            },
        );
        assert!(matches!(result, Err(ToolError::Denied(_))));
        let broker = gw.secret_broker_mut().unwrap();
        assert_eq!(broker.get_lease(id).unwrap().uses, 0);
        assert_eq!(broker.use_lease(id).unwrap(), "TOP-SECRET-XYZ");
        assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .contains(rule));
        aivm_audit::clear_flags(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }
}

// harness สำหรับ secrets: broker + นโยบาย allow แคบ + secret ค่าปลอม
// (+ execute cap สำหรับ /usr/bin/printenv ไว้พิสูจน์ injection —
// `env` ตรง ๆ โดน interpreter denylist ถูกต้องแล้ว)
fn secret_harness() -> (ToolGateway, Cube, PathBuf) {
    let (mut gw, cube, dir) = exec_harness();
    let env_real = std::fs::canonicalize("/usr/bin/printenv")
        .unwrap()
        .to_string_lossy()
        .to_string();
    gw.policy.process.allow.push(env_real.clone());
    gw.caps.grant(aivm_capability::Capability::new(
        "execute", "process", &env_real,
    ));
    let mut broker = aivm_secrets::SecretBroker::new(
        aivm_secrets::SecretPolicy {
            low_risk_allow: vec!["*".into()],
            allow: vec!["test_token:read".into(), "test_token:write".into()],
            deny: vec![],
            hitl_required_for: vec![aivm_secrets::RiskLevel::High],
            max_ttl_seconds: 3600,
            max_uses_allowed: 5,
        },
        None,
    );
    broker.register_secret("test_token".into(), "TOP-SECRET-XYZ".into());
    let mut gw = gw.with_secret_broker(broker);
    for scope in ["test_token:read", "test_token:write"] {
        gw.caps
            .grant(aivm_capability::Capability::new("use", "secret", scope));
    }
    (gw, cube, dir)
}

fn secret_body(tool: &str, resource: &str, scope: &str, risk: &str) -> String {
    serde_json::json!({
        "tool": tool,
        "resource": resource,
        "scope": scope,
        "purpose": "test",
        "risk": risk,
    })
    .to_string()
}

// G4: secret.request low-risk ออก lease ให้ (คืนแต่ id + metadata —
// value ห้ามปรากฏทั้งใน output และ audit)
#[test]
fn secret_request_issues_lease_without_value() {
    let (mut gw, mut cube, dir) = secret_harness();
    let r = gw
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(secret_body("process.exec", "test_token", "read", "low")),
            },
        )
        .unwrap();
    assert!(r.ok);
    assert_eq!(r.decision, "allow");
    let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
    let lease_id = v["lease_id"].as_str().expect("ต้องมี lease_id");
    assert!(!lease_id.is_empty());
    assert!(
        !r.output.contains("TOP-SECRET-XYZ"),
        "value ห้ามกลับไป AI context"
    );
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("lease-issued"));
    assert!(!log.contains("TOP-SECRET-XYZ"), "value ห้ามลง audit");
}

// G4: high-risk ไม่มี approval = DENY + audit hitl-required
#[test]
fn secret_request_high_risk_denies_hitl() {
    let (mut gw, mut cube, dir) = secret_harness();
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "secret.request".into(),
            path: "-".into(),
            content: Some(secret_body("process.exec", "test_token", "write", "high")),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("hitl-required"));
}

// G4: schema ผิด = DENY (non-JSON, ขาดฟิลด์, เกินฟิลด์, tool ผิด)
#[test]
fn secret_request_malformed_denies() {
    let (mut gw, mut cube, dir) = secret_harness();
    let bad = vec![
        "not json".to_string(),
        serde_json::json!({"tool": "process.exec"}).to_string(),
        serde_json::json!({
            "tool": "process.exec", "resource": "test_token", "scope": "read",
            "purpose": "t", "risk": "low", "extra": 1,
        })
        .to_string(),
        secret_body("network.fetch", "test_token", "read", "low"),
    ];
    for b in &bad {
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(b.clone()),
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))), "ต้อง deny: {b}");
    }
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("\"decision\":\"deny\""));
}

// G4: ไม่มี broker = DENY (fail-closed ไม่มีทางเงียบผ่าน)
#[test]
fn secret_request_unconfigured_denies() {
    let (mut gw, mut cube, dir) = exec_harness();
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "secret.request".into(),
            path: "-".into(),
            content: Some(secret_body("process.exec", "test_token", "read", "low")),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("secret-unconfigured"));
}

// G4: exec แนบ lease ฉีด secret เข้า child env (อ่านค่าผ่าน printenv)
// แต่ audit ต้องไม่มีค่า + lease ใช้ซ้ำไม่ได้ (one-time)
#[test]
fn secret_exec_injects_and_redacts_and_burns() {
    let (mut gw, mut cube, dir) = secret_harness();
    let r = gw
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "secret.request".into(),
                path: "-".into(),
                content: Some(secret_body("process.exec", "test_token", "read", "low")),
            },
        )
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
    let lease_id = v["lease_id"].as_str().unwrap().to_string();
    // คีย์ env ตาม SecretInjector (resource/scope ตัวใหญ่ _ แทน -/:)
    let key = "AIVM_SECRET_TEST_TOKEN_READ";
    let run = |gw: &mut ToolGateway, cube: &mut Cube, lease: Option<String>| {
        gw.dispatch(
            cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/usr/bin/printenv".into(),
                content: Some(serde_json::json!({"argv": [key], "secret": lease}).to_string()),
            },
        )
    };
    // ครั้งแรก: inject สำเร็จ เห็นค่าใน stdout
    let r = run(&mut gw, &mut cube, Some(lease_id.clone())).unwrap();
    assert!(r.ok);
    assert_eq!(
        r.output, "[REDACTED]",
        "output ของ secret consumer ต้องไม่เข้าบริบทโมเดล"
    );
    // ใช้ซ้ำ: one-time lease หมดแล้ว
    let r = run(&mut gw, &mut cube, Some(lease_id));
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("lease-exhausted"));
    // audit ทั้งไฟล์ต้องไม่มีค่า secret เลย
    assert!(!log.contains("TOP-SECRET-XYZ"), "value ห้ามลง audit เด็ดขาด");
}

#[test]
fn issued_secret_lease_requires_retained_authority_without_recharging_issuance() {
    for revoke in [false, true] {
        let (mut gw, mut cube, dir) = secret_harness();
        let cap = gw
            .caps
            .caps
            .iter_mut()
            .find(|c| c.resource == "secret" && c.scope == "test_token:read")
            .unwrap();
        cap.max_uses = Some(1);
        let result = gw
            .secret_request(
                &mut cube,
                Some(&secret_body("process.exec", "test_token", "read", "low")),
            )
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let id = value["lease_id"].as_str().unwrap();
        assert_eq!(
            gw.caps
                .caps
                .iter()
                .find(|c| c.resource == "secret" && c.scope == "test_token:read")
                .unwrap()
                .used_count,
            1
        );
        if revoke {
            gw.caps.revoke_where(|cap| cap.resource == "secret");
        }
        let result = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/usr/bin/printenv".into(),
                content: Some(
                    serde_json::json!({"argv": ["AIVM_SECRET_TEST_TOKEN_READ"], "secret": id})
                        .to_string(),
                ),
            },
        );
        if revoke {
            assert!(matches!(result, Err(ToolError::Denied(_))));
            assert_eq!(
                gw.secret_broker_mut().unwrap().get_lease(id).unwrap().uses,
                0
            );
            assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
                .unwrap()
                .contains("secret-capability-revoked"));
        } else {
            assert!(
                result.unwrap().ok,
                "issued lease must survive exhausted issuance quota"
            );
        }
        aivm_audit::clear_flags(&dir);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

// G4: exec ไม่แนบ lease = ไม่มี secret ใน env (ไม่รั่วข้าม run)
// (printenv ตัวแปรที่ไม่มี exit 1 — decision ต้อง allow แต่ output ว่าง)
#[test]
fn secret_exec_without_lease_has_no_secret() {
    let (mut gw, mut cube, _d) = secret_harness();
    let r = gw
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "process.exec".into(),
                path: "/usr/bin/printenv".into(),
                content: Some(
                    serde_json::json!({"argv": ["AIVM_SECRET_TEST_TOKEN_READ"]}).to_string(),
                ),
            },
        )
        .unwrap();
    assert_eq!(r.decision, "allow");
    assert!(!r.output.contains("TOP-SECRET-XYZ"));
}

// G4: exec แนบ secret ระดับ microvm = DENY (inject ไม่ได้ — ไม่เงียบทิ้ง)
#[test]
fn secret_exec_microvm_level_denies() {
    let (mut gw, mut cube, dir) = secret_harness();
    gw.level = SandboxLevel::MicroVm;
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some(serde_json::json!({"argv": [], "secret": "lease-xyz"}).to_string()),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("secret-unsupported-microvm"));
}
