//! Gateway regression suites share only their fixtures.
use super::*;
use aivm_capability::Capability;
use aivm_cube::Cube;

mod filesystem;
mod gateway;
mod network;
mod process;
mod secrets;
mod task_contracts;

fn harness() -> (ToolGateway, Cube, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "aivm-tools-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let ws_real = dir.canonicalize().unwrap_or(dir.clone());
    let policy = Policy::from_yaml(&format!(
        r#"
name: test
filesystem:
  read: [{}]
  write: [{}/src]
  deny: ["**/.env*", "**/secrets/**"]
process: {{allow: [], deny: [/bin/sh]}}
network: {{allow: [], deny: ['10.0.0.0/8']}}
"#,
        ws_real.display(),
        ws_real.display()
    ))
    .unwrap();
    let caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &ws_real.to_string_lossy()),
        Capability::new("write", "filesystem", &format!("{}/src", ws_real.display())),
        Capability::new("search", "filesystem", &ws_real.to_string_lossy()),
    ]);
    let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
    let gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess");
    (gw, Cube::new("t"), dir)
}

fn exec_harness() -> (ToolGateway, Cube, PathBuf) {
    let (mut gw, cube, dir) = harness();
    let allow: Vec<String> = ["/bin/true", "/bin/false"]
        .iter()
        .map(|e| {
            std::fs::canonicalize(e)
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    gw.policy.process.allow = allow.clone();
    for exe in &allow {
        gw.caps
            .grant(aivm_capability::Capability::new("execute", "process", exe));
    }
    (gw, cube, dir)
}
