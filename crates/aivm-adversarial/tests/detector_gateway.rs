//! Bridge real gateway requests to the Python detector, without synthetic audit records.
use aivm_audit::AuditWriter;
use aivm_capability::{Capability, CapabilitySet};
use aivm_cube::Cube;
use aivm_policy::Policy;
use aivm_tools::ToolGateway;
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        aivm_audit::clear_flags(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn gateway() -> (Fixture, ToolGateway, Cube) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        Fixture(std::env::temp_dir().join(format!("aivm-detector-{}-{nonce}", std::process::id())));
    std::fs::create_dir_all(root.0.join("src")).unwrap();
    std::fs::write(root.0.join("src/safe.txt"), "safe").unwrap();
    std::fs::write(root.0.join(".env"), "SYNTHETIC_SECRET=test").unwrap();
    let scope = root.0.to_string_lossy();
    let policy = Policy::from_yaml(&format!(
        "name: detector\nfilesystem:\n  read: [{scope}]\n  deny: ['**/.env*']\n"
    ))
    .unwrap();
    let caps = CapabilitySet::new(vec![Capability::new("read", "filesystem", &scope)]);
    let writer = AuditWriter::open(root.0.join("audit.jsonl")).unwrap();
    let gateway = ToolGateway::new(root.0.clone(), policy, caps, writer, "detector", "session");
    (root, gateway, Cube::new("detector"))
}

fn detected(directory: &Path) -> Vec<String> {
    let path = directory.join("audit.jsonl");
    AuditWriter::verify(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/qwen-audit.py");
    // Rust verifies the actual gateway chain above. Python only reads it and
    // evaluates rules; this cannot invoke a model, tool, or supervisor action.
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import importlib.util,json,pathlib,sys; \
             s=importlib.util.spec_from_file_location('review',sys.argv[1]); \
             m=importlib.util.module_from_spec(s); s.loader.exec_module(m); \
             rows=m.load_records(pathlib.Path(sys.argv[2]).read_bytes()); \
             print(json.dumps(sorted({a['category'] for a in m.inspect_records(rows)})))",
        )
        .arg(script)
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(before, std::fs::read(&path).unwrap());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn legitimate_gateway_read_does_not_raise_an_alert() {
    let (root, mut gateway, mut cube) = gateway();
    assert!(gateway.read(&mut cube, "src/safe.txt").unwrap().ok);
    assert!(detected(&root.0).is_empty());
}

#[test]
fn actual_boundary_denials_become_boundary_and_burst_alerts() {
    let (root, mut gateway, mut cube) = gateway();
    for _ in 0..19 {
        assert!(gateway.read(&mut cube, "../../outside.txt").is_err());
    }
    assert_eq!(detected(&root.0), ["boundary_violation"]);
    assert!(gateway.read(&mut cube, "../../outside.txt").is_err());
    assert_eq!(detected(&root.0), ["boundary_violation", "deny_burst"]);
}

#[test]
fn actual_sensitive_denial_is_detected() {
    let (root, mut gateway, mut cube) = gateway();
    assert!(gateway.read(&mut cube, ".env").is_err());
    assert_eq!(detected(&root.0), ["sensitive_access"]);
}
