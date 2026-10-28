//! ตรวจขอบเขต registry/data ผ่าน gateway จริง โดยไม่ส่ง request ออกเครือข่าย
use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::Cube;
use aivm_policy::Policy;
use aivm_tools::{ToolGateway, ToolRequest};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (Fixture, ToolGateway, Cube) {
    let root = Fixture(std::env::temp_dir().join(format!(
        "aivm-registry-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    )));
    std::fs::create_dir_all(root.0.join("src")).unwrap();
    let ws = root.0.to_string_lossy();
    let policy = Policy::from_yaml(&format!(
        "name: registry-containment\nfilesystem:\n  read: [{ws}]\n  write: [{ws}/src]\n  deny: ['**/.env*']\nprocess:\n  deny: [/bin/sh]\nnetwork:\n  allow: [registry.invalid]\n  deny: ['10.0.0.0/8']\n"
    )).unwrap();
    // จงใจให้ capability เก่ามีสิทธิ์เขียน; policy ใหม่ยังต้องกันได้ก่อน DNS
    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws),
        Capability::new("write", "filesystem", &format!("{ws}/src")),
        Capability::new("network:fetch", "network", "registry.invalid:443"),
        Capability::new("network:connect", "network", "registry.invalid:443"),
    ]);
    let audit = AuditWriter::open(root.0.join("audit.jsonl")).unwrap();
    let gateway = ToolGateway::new(
        root.0.clone(),
        policy,
        caps,
        audit,
        "agent",
        "registry-test",
    );
    (root, gateway, Cube::new("registry-test"))
}

#[test]
fn shared_registry_writes_and_raw_connections_are_denied_and_audited() {
    let (root, mut gateway, mut cube) = fixture();
    for method in ["POST", "PUT", "PATCH", "DELETE", "post"] {
        let request = serde_json::json!({"method":method,"body":"synthetic-board-note"});
        let error = gateway
            .network_fetch(
                &mut cube,
                "https://registry.invalid/artifactory/board/note",
                Some(&request.to_string()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("read-only network"), "{error}");
    }
    for body in [
        r#"{"method":"GET","body":"synthetic-board-note"}"#,
        r#"{"method":"HEAD","body":""}"#,
        r#"{"headers":{"x-HtTp-MeThOd-OvErRiDe":"PUT"}}"#,
        r#"{"headers":{"X-HTTP-Method":"PUT"}}"#,
    ] {
        let error = gateway
            .network_fetch(&mut cube, "https://registry.invalid/", Some(body))
            .unwrap_err();
        assert!(error.to_string().contains("read-only network"), "{error}");
    }
    let error = gateway
        .network_connect(&mut cube, "registry.invalid:443", Some(r#"{"tls":true}"#))
        .unwrap_err();
    assert!(error.to_string().contains("read-only network"));
    assert!(gateway
        .caps
        .caps
        .iter()
        .all(|cap| cap.used_count == 0 && cap.used_bytes == 0));
    AuditWriter::verify(root.0.join("audit.jsonl")).unwrap();
    let rows: Vec<AuditRecord> = std::fs::read_to_string(root.0.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 10);
    assert!(rows.iter().all(|row| row.decision == "deny"));
}

#[test]
fn special_ipv6_destinations_are_denied_before_dns_even_when_allowlisted() {
    let (root, mut gateway, mut cube) = fixture();
    gateway.policy.require_test_before_network = false;
    for ip in [
        "64:ff9b::a9fe:a9fe",
        "2002:a9fe:a9fe::1",
        "fec0::1",
        "2001:2::1",
        "3fff::1",
    ] {
        let scope = format!("[{ip}]:443");
        gateway.policy.network.allow.push(scope.clone());
        gateway
            .caps
            .grant(Capability::new("network:fetch", "network", &scope));
        let error = gateway
            .network_fetch(&mut cube, &format!("https://[{ip}]/"), None)
            .unwrap_err();
        assert!(
            error.to_string().contains("network policy denied"),
            "{ip}: {error}"
        );
    }
    AuditWriter::verify(root.0.join("audit.jsonl")).unwrap();
}

#[test]
fn dataset_template_text_is_inert_and_cannot_write_another_workspace() {
    let (root, mut gateway, mut cube) = fixture();
    let (other, _, _) = fixture();
    let text = r#"{"templates":{"sample":"{{ 7 * 7 }}"},"simple_templates":false,"note":"template.render is not authorized"}"#;
    std::fs::write(root.0.join("src/dataset.json"), text).unwrap();
    assert_eq!(
        gateway.read(&mut cube, "src/dataset.json").unwrap().output,
        text
    );
    assert!(gateway
        .dispatch(
            &mut cube,
            &ToolRequest {
                tool: "template.render".into(),
                path: "src/dataset.json".into(),
                content: Some(text.into()),
            }
        )
        .is_err());
    // positive control: สิทธิ์เขียนใช้งานได้จริงใน workspace ของตัวเอง
    assert!(
        gateway
            .write(&mut cube, "src/local-note.txt", "local data")
            .unwrap()
            .ok
    );
    assert!(gateway
        .write(
            &mut cube,
            &other.0.join("src/board.txt").to_string_lossy(),
            text
        )
        .is_err());
    assert!(!other.0.join("src/board.txt").exists());
    assert_eq!(
        std::fs::read_to_string(root.0.join("src/dataset.json")).unwrap(),
        text
    );
    AuditWriter::verify(root.0.join("audit.jsonl")).unwrap();
}
