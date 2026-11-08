use super::*;
use crate::network::{parse_host_port, parse_url, public_addresses, NetworkFetchRequest};

#[test]
fn read_only_http_accepts_only_bodyless_reads_without_method_overrides() {
    // ทดสอบทางอนุญาตด้วยโดยไม่เปิด socket ไปยังระบบภายนอก
    for method in ["GET", "HEAD", "get", "head"] {
        let req: NetworkFetchRequest =
            serde_json::from_value(serde_json::json!({"method":method})).unwrap();
        assert!(req.validate_read_only(true).is_ok());
    }
    for json in [
        serde_json::json!({"method":"POST"}),
        serde_json::json!({"method":"OPTIONS"}),
        serde_json::json!({"body":""}),
        serde_json::json!({"headers":{"X-HTTP-Method-Override":"PUT"}}),
        serde_json::json!({"headers":{"X-HTTP-Method":"PUT"}}),
    ] {
        let req: NetworkFetchRequest = serde_json::from_value(json).unwrap();
        assert!(req.validate_read_only(true).is_err());
        assert!(req.validate_read_only(false).is_ok());
    }
}

#[test]
fn rejected_network_responses_consume_and_persist_the_remaining_budget() {
    // อ่าน response ที่ใหญ่เกินสองครั้งแล้วต้องหมดงบ แม้ไม่คืนข้อมูลให้ agent
    let (mut gw, mut cube, dir) = harness();
    gw.state_path = Some(dir.join("state.json"));
    gw.caps.grant(
        Capability::new("network:fetch", "network", "registry.invalid:443").with_constraints(
            aivm_capability::Constraints {
                max_response_bytes: Some(3),
                max_total_bytes: Some(8),
                ..Default::default()
            },
        ),
    );
    let idx = gw.caps.caps.len() - 1;
    for expected in [4, 8] {
        let mut response = std::io::Cursor::new(vec![b'x'; 100]);
        assert!(gw.read_network_response(&cube, idx, &mut response).is_err());
        assert_eq!(response.position(), 4);
        assert_eq!(gw.caps.caps[idx].used_bytes, expected);
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(gw.state_path.as_ref().unwrap()).unwrap())
                .unwrap();
        assert_eq!(saved["caps"]["caps"][idx]["used_bytes"], expected);
    }
    // ต้องหยุดที่ capability ก่อน DNS ของ .invalid โดยไม่พึ่งเพดานจำนวน calls
    let error = gw
        .network_fetch(&mut cube, "https://registry.invalid/", None)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("network capability or constraint"),
        "{error}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn network_reader_bounds_total_bytes_and_charges_partial_read_errors() {
    struct BrokenResponse(bool);
    impl std::io::Read for BrokenResponse {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                return Err(std::io::Error::other("response interrupted"));
            }
            self.0 = true;
            buffer[..3].copy_from_slice(b"abc");
            Ok(3)
        }
    }
    let (mut gw, cube, dir) = harness();
    gw.state_path = Some(dir.join("state.json"));
    gw.caps.grant(
        Capability::new("network:fetch", "network", "registry.invalid:443").with_constraints(
            aivm_capability::Constraints {
                max_response_bytes: Some(100),
                max_total_bytes: Some(5),
                ..Default::default()
            },
        ),
    );
    let idx = gw.caps.caps.len() - 1;
    assert!(matches!(
        gw.read_network_response(&cube, idx, BrokenResponse(false)),
        Err(ToolError::Io(_))
    ));
    assert_eq!(gw.caps.caps[idx].used_bytes, 3);
    let mut response = std::io::Cursor::new(vec![b'x'; 100]);
    assert!(gw.read_network_response(&cube, idx, &mut response).is_err());
    assert_eq!(response.position(), 3, "เหลืองบสองไบต์พร้อม lookahead อีกหนึ่ง");
    assert_eq!(gw.caps.caps[idx].used_bytes, 6);
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(gw.state_path.as_ref().unwrap()).unwrap()).unwrap();
    assert_eq!(saved["caps"]["caps"][idx]["used_bytes"], 6);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn network_response_exactly_at_budget_is_accepted_and_charged() {
    let (mut gw, cube, dir) = harness();
    gw.caps.grant(
        Capability::new("network:fetch", "network", "registry.invalid:443").with_constraints(
            aivm_capability::Constraints {
                max_response_bytes: Some(3),
                max_total_bytes: Some(3),
                ..Default::default()
            },
        ),
    );
    let idx = gw.caps.caps.len() - 1;
    assert_eq!(
        gw.read_network_response(&cube, idx, &b"abc"[..]).unwrap(),
        b"abc"
    );
    assert_eq!(gw.caps.caps[idx].used_bytes, 3);
    // ขอบบนของ counter ต้องยังปฏิเสธ lookahead ที่เกินงบ แม้ยอดจะ saturate
    gw.caps.caps[idx].constraints.max_total_bytes = Some(u64::MAX);
    gw.caps.caps[idx].used_bytes = u64::MAX - 1;
    let mut oversized = std::io::Cursor::new(b"abc");
    assert!(gw
        .read_network_response(&cube, idx, &mut oversized)
        .is_err());
    assert_eq!(oversized.position(), 2);
    assert_eq!(gw.caps.caps[idx].used_bytes, u64::MAX);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn network_constraints_cannot_be_skipped_when_quota_exhausts() {
    let (mut gw, mut cube, _) = harness();
    gw.policy.network.read_only = false;
    gw.policy.network.allow = vec!["example.com".into()];
    gw.policy.require_test_before_network = false;
    gw.caps.grant(
        Capability::new("network:connect", "network", "example.com:443")
            .with_max_uses(1)
            .with_constraints(aivm_capability::Constraints::new().with_max_bytes(1)),
    );
    let result = gw.network_fetch(
        &mut cube,
        "https://example.com/",
        Some(r#"{"method":"POST","body":"xx"}"#),
    );
    assert!(matches!(result, Err(ToolError::Denied(_))));
    let cap = gw
        .caps
        .caps
        .iter()
        .find(|c| c.resource == "network")
        .unwrap();
    assert_eq!(cap.used_count, 0, "constraint ต้องตรวจครบก่อน consume/ส่งข้อมูล");
}

#[test]
fn private_network_destinations_and_unknown_schema_are_denied() {
    for host in ["127.0.0.2", "10.1.2.3", "::ffff:127.0.0.1", "::1"] {
        assert!(public_addresses(host, 443).is_err());
    }
    assert!(parse_url("http://example.com/").is_err());
    assert!(parse_url("HTTP://example.com:443/").is_err());
    assert_eq!(
        parse_url("https://Example.com/path").unwrap(),
        ("example.com".into(), 443, "https".into())
    );
    assert_eq!(parse_url("https://example.com:8443/path").unwrap().1, 8443);
    assert!(parse_url("file:///etc/passwd").is_err());
    assert!(parse_url("https://user:pass@example.com/").is_err());
    assert!(serde_json::from_str::<NetworkFetchRequest>(r#"{"redirects":true}"#).is_err());
    assert_eq!(parse_host_port("[::1]:443").unwrap(), ("::1".into(), 443));
}
