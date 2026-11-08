use super::*;

#[test]
fn search_only_grant_finds_content_and_charges_its_own_byte_budget() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("src/search.txt"), "unique-search-marker").unwrap();
    gw.caps.caps.retain(|cap| cap.action == "search");
    gw.caps.caps[0].constraints.max_total_bytes = Some(20);
    let result = gw.search(&mut cube, "unique-search-marker").unwrap();
    assert!(result
        .output
        .contains("src/search.txt:1: unique-search-marker"));
    assert_eq!(gw.caps.caps[0].used_bytes, 20);
    assert!(gw.search(&mut cube, "unique-search-marker").is_err());
    // search ไม่ได้ให้สิทธิ์ filesystem.read หรือ retrieval context โดยอ้อม
    assert!(gw.read(&mut cube, "src/search.txt").is_err());
    assert!(gw.context_files(&mut cube).unwrap().is_empty());
    aivm_audit::clear_flags(&dir);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cached_reads_enforce_current_size_constraints() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("src/data.txt"), "0123456789").unwrap();
    gw.read(&mut cube, "src/data.txt").unwrap();
    gw.caps
        .caps
        .iter_mut()
        .find(|c| c.action == "read")
        .unwrap()
        .constraints
        .max_bytes = Some(1);
    assert!(matches!(
        gw.read(&mut cube, "src/data.txt"),
        Err(ToolError::Denied(_))
    ));
    assert!(std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .contains("size-constraint"));

    // A write must not prime a cache entry that bypasses a limited read.
    gw.write(&mut cube, "src/data.txt", "more data").unwrap();
    assert!(gw.read(&mut cube, "src/data.txt").is_err());
    gw.write(&mut cube, "src/data.txt", "x").unwrap();
    assert_eq!(gw.read(&mut cube, "src/data.txt").unwrap().output, "x");
    aivm_audit::clear_flags(&dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn missing_write_content_never_truncates_a_file() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("src/data.txt"), "keep me").unwrap();
    for json in [
        r#"{"tool":"filesystem.write","path":"src/data.txt"}"#,
        r#"{"tool":"filesystem.write","path":"src/data.txt","content":null}"#,
    ] {
        let request: ToolRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(
            gw.dispatch(&mut cube, &request),
            Err(ToolError::Denied(_))
        ));
        assert_eq!(
            std::fs::read_to_string(dir.join("src/data.txt")).unwrap(),
            "keep me"
        );
    }
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert_eq!(log.matches("missing-content").count(), 2);
    gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "filesystem.write".into(),
            path: "src/data.txt".into(),
            content: Some(String::new()),
        },
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(dir.join("src/data.txt")).unwrap().len(),
        0
    );
    aivm_audit::clear_flags(&dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_reads_are_cached_and_writes_are_idempotent() {
    let (mut gw, mut cube, dir) = harness();
    let path = dir.join("src/cache.txt");
    std::fs::write(&path, "original").unwrap();

    assert_eq!(
        gw.read(&mut cube, "src/cache.txt").unwrap().output,
        "original"
    );
    // An agent run reuses what it already loaded, even if an out-of-band
    // change occurs. Mediated writes and process execution invalidate it.
    std::fs::write(&path, "external change").unwrap();
    assert_eq!(
        gw.read(&mut cube, "src/cache.txt").unwrap().output,
        "original"
    );

    let changed = gw.write(&mut cube, "src/cache.txt", "original").unwrap();
    assert_eq!(changed.output, "written");
    let unchanged = gw.write(&mut cube, "src/cache.txt", "original").unwrap();
    assert_eq!(unchanged.output, "unchanged");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");

    gw.write(&mut cube, "src/cache.txt", "updated").unwrap();
    assert_eq!(
        gw.read(&mut cube, "src/cache.txt").unwrap().output,
        "updated"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn traversal_denied() {
    let (mut gw, mut cube, _d) = harness();
    let r = gw.read(&mut cube, "../../etc/passwd");
    assert!(matches!(r, Err(ToolError::Denied(_))));
}

#[test]
fn write_outside_src_denied() {
    let (mut gw, mut cube, _d) = harness();
    let r = gw.write(&mut cube, "README.md", "hi");
    // README อยู่ root ของ workspace: write อนุญาตแค่ */src
    assert!(r.is_err());
}

#[test]
fn write_inside_src_allowed() {
    let (mut gw, mut cube, _d) = harness();
    let r = gw.write(&mut cube, "src/a.rs", "fn main(){}");
    assert!(r.is_ok());
}

// regression: search/RAG ต้องไม่คืนไฟล์ที่ policy ห้ามอ่าน
#[test]
fn search_and_context_respect_file_denials() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("private.txt"), "PRIVATE-REGRESSION").unwrap();
    gw.policy
        .filesystem
        .deny
        .push(dir.join("private.txt").display().to_string());
    assert!(gw.read(&mut cube, "private.txt").is_err());
    assert!(!gw
        .search(&mut cube, "PRIVATE-REGRESSION")
        .unwrap()
        .output
        .contains("PRIVATE-REGRESSION"));
    assert!(!gw
        .context_files(&mut cube)
        .unwrap()
        .iter()
        .any(|(_, text)| text.contains("PRIVATE-REGRESSION")));
}

#[test]
fn audit_failure_prevents_write() {
    let (mut gw, mut cube, dir) = harness();
    aivm_audit::clear_flags(&dir);
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        gw.write(&mut cube, "src/blocked.rs", "x"),
        Err(ToolError::Audit(_))
    ));
    assert!(!dir.join("src/blocked.rs").exists());
}

#[test]
fn file_size_constraints_apply_to_reads_and_writes() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("src/large.rs"), "too large").unwrap();
    for cap in &mut gw.caps.caps {
        cap.constraints.max_bytes = Some(1);
    }
    assert!(gw.read(&mut cube, "src/large.rs").is_err());
    assert!(gw.write(&mut cube, "src/new.rs", "too large").is_err());
    assert!(!dir.join("src/new.rs").exists());
}

#[test]
fn consumed_read_bytes_are_checkpointed_before_returning_content() {
    let (mut gw, mut cube, dir) = harness();
    let path = gw.workspace.join("src/budget.txt");
    std::fs::write(&path, "123456").unwrap();
    gw.state_path = Some(dir.join("state.json"));
    let read_cap = gw
        .caps
        .caps
        .iter_mut()
        .find(|cap| cap.action == "read")
        .unwrap();
    read_cap.constraints.max_total_bytes = Some(100);

    assert_eq!(
        gw.read(&mut cube, "src/budget.txt").unwrap().output,
        "123456"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    let saved_cap = saved["caps"]["caps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cap| cap["action"] == "read")
        .unwrap();
    assert_eq!(saved_cap["used_bytes"], 6);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn exhausted_capability_cannot_supply_larger_file_constraints() {
    let (mut gw, mut cube, dir) = harness();
    std::fs::write(dir.join("src/large.rs"), "large").unwrap();
    let scope = dir.display().to_string();
    gw.caps = CapabilitySet::new(vec![
        Capability::new("read", "filesystem", &scope)
            .with_max_uses(1)
            .with_constraints(aivm_capability::Constraints::new().with_max_bytes(1)),
        Capability::new("read", "filesystem", &scope)
            .with_max_uses(0)
            .with_constraints(aivm_capability::Constraints::new().with_max_bytes(100)),
    ]);
    assert!(gw.read(&mut cube, "src/large.rs").is_err());
}
