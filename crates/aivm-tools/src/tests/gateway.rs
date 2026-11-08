use super::*;

#[test]
fn unknown_tool_denied() {
    let (mut gw, mut cube, _d) = harness();
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "shell.exec".into(),
            path: "x".into(),
            content: None,
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
}

// G1: deny burst ครบ threshold → gateway quarantine (allow ที่ควรผ่านก็ตาย)
// deterministic: threshold default 20, ทุก deny เกิดในเสี้ยววินาทีเดียวกัน
#[test]
fn probing_burst_quarantines_gateway() {
    // เส้นแบ่ง: 19 denies ยังปกติ
    let (mut gw, mut cube, _d) = exec_harness();
    let probe = ToolRequest {
        tool: "filesystem.read".into(),
        path: "../../etc/passwd".into(),
        content: None,
    };
    for _ in 0..19 {
        assert!(gw.dispatch(&mut cube, &probe).is_err());
    }
    let ok = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    assert!(ok.is_ok(), "19 denies ต้องยังไม่ quarantine");

    // ครบ 20 = quarantine ครั้งที่ 21 (ของที่ควร allow) ต้องตายพร้อม audit
    let (mut gw, mut cube, dir) = exec_harness();
    for _ in 0..20 {
        assert!(gw.dispatch(&mut cube, &probe).is_err());
    }
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("quarantine-started"), "ต้องมีรอยเริ่ม quarantine");
    assert!(
        log.contains("quarantine-probing"),
        "ต้องมีรอย deny ระหว่าง quarantine"
    );
}
