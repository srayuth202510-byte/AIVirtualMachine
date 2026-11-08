use super::*;

#[test]
fn exec_reports_exit_status_without_deny() {
    let (mut gw, mut cube, _d) = exec_harness();
    let exe = |p: &str| ToolRequest {
        tool: "process.exec".into(),
        path: p.into(),
        content: Some("[]".into()),
    };
    // exit 0 = ok:true
    let r = gw.dispatch(&mut cube, &exe("/bin/true")).unwrap();
    assert!(r.ok);
    // exit ไม่ใช่ 0 = รันสำเร็จแต่ล้มเหลว (ok:false ไม่ใช่ DENY)
    let r = gw.dispatch(&mut cube, &exe("/bin/false")).unwrap();
    assert!(!r.ok);
    assert_eq!(r.decision, "allow");
}

#[test]
fn exec_denied_without_execute_cap() {
    let (mut gw, mut cube, _d) = harness();
    let real = std::fs::canonicalize("/bin/true").unwrap();
    gw.policy.process.allow = vec![real.to_string_lossy().to_string()];
    // harness ไม่มี execute cap: ต้อง no-capability
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
}

/// regression #11: process rule แบบมีเงื่อนไข (`when`) ต้องถูกคุมที่
/// gateway ด้วย state จริงของ cube — allow list พื้นฐานข้าม rule ไม่ได้
#[test]
fn exec_denied_by_state_conditional_process_rule() {
    let (mut gw, mut cube, dir) = exec_harness();
    // cube เริ่มต้นที่ INIT (as_str => "INIT")
    let exe = std::fs::canonicalize("/bin/true")
        .unwrap()
        .to_string_lossy()
        .to_string();
    gw.policy.rules.push(aivm_policy::Rule {
        id: "no-exec-in-init".into(),
        action: "execute".into(),
        resource: "process".into(),
        scope: exe.clone(),
        when: Some("state == 'INIT'".into()),
        effect: Some("deny".into()),
    });
    let r = gw.exec(&mut cube, &exe, &[]);
    assert!(matches!(r, Err(ToolError::Denied(_))), "must deny: {r:?}");
    // decision ใหม่ทุกอันมี audit record (I-7)
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("no-exec-in-init"), "audit: {log}");
    aivm_audit::clear_flags(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exec_honors_capability_timeout_constraint() {
    let (mut gw, mut cube, _dir) = harness();
    let exe = std::fs::canonicalize("/bin/true").unwrap();
    let exe = exe.to_string_lossy().to_string();
    gw.policy.process.allow.push(exe.clone());
    gw.caps.grant(
        aivm_capability::Capability::new("execute", "process", &exe)
            .with_constraints(aivm_capability::Constraints::new().with_timeout_ms(1)),
    );
    assert!(matches!(
        gw.exec(&mut cube, &exe, &[]),
        Err(ToolError::Denied(_))
    ));
}

// Phase 7: ระดับที่ยังไม่มี backend ต้อง DENY พร้อม audit (I-7)
// แม้ policy + capability จะอนุญาตครบ (ประตู level มาก่อน execute)
// หมายเหตุ: เปิดฟีเจอร์ `microvm` แล้วเคสนี้ตายด้วย Invalid (artifact
// ของ config default หาย) แทน Disabled — deny + audit เหมือนกัน
#[test]
fn exec_denied_on_unimplemented_level_with_audit() {
    let (mut gw, mut cube, dir) = exec_harness();
    gw.level = SandboxLevel::MicroVm;
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    assert!(matches!(r, Err(ToolError::Denied(_))));
    // ต้องมี audit decision ที่ deny ด้วยเหตุระดับ level
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(
        log.contains("level-disabled") || log.contains("level-invalid"),
        "ต้อง audit การ deny ระดับ level"
    );
    assert!(log.contains("\"decision\":\"deny\""));
}

// Level 3 (Hardware): ไม่ว่าเปิดฟีเจอร์หรือไม่ ต้อง DENY พร้อม audit
// ไม่มีฟีเจอร์ = Disabled (level-disabled); มีฟีเจอร์ + config default
// (= `None`) = Invalid ตั้งแต่ artifact หาย (level-invalid) — deny +
// audit เหมือนกัน (I-7)
#[test]
fn exec_denied_on_hardware_level_with_audit() {
    let (mut gw, mut cube, dir) = exec_harness();
    gw.level = SandboxLevel::Hardware;
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
    assert!(
        log.contains("level-disabled") || log.contains("level-invalid"),
        "ต้อง audit การ deny ระดับ hardware"
    );
    assert!(log.contains("\"decision\":\"deny\""));
}

// Level 3 (ฟีเจอร์ hardware): artifact ปลอมต้อง DENY พร้อม audit
// (deterministic ทุกเครื่อง — supply chain ตายก่อนถึงขั้น launch)
#[cfg(feature = "hardware")]
#[test]
fn exec_with_tampered_hardware_artifact_denied_with_audit() {
    let (mut gw, mut cube, dir) = exec_harness();
    let kern = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&kern, b"k").unwrap();
    std::fs::write(&rootfs, b"r").unwrap();
    gw.level = SandboxLevel::Hardware;
    gw.hardware_cfg = Some(aivm_sandbox::hardware::HardwareConfig {
        kernel_path: kern,
        // hash ผิดเจตนา (ของจริงคือ sha256 ของ b"k")
        kernel_sha256: "00".repeat(32),
        rootfs_path: rootfs,
        rootfs_sha256: "11".repeat(32),
        tee_type: aivm_sandbox::hardware::TeeType::Generic,
        attestation_mode: aivm_sandbox::hardware::AttestationMode::None,
        ..aivm_sandbox::hardware::HardwareConfig::default()
    });
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
    assert!(log.contains("level-invalid"));
    assert!(log.contains("\"decision\":\"deny\""));
    assert!(
        log.contains("verdict:clean:no-interference-evidence"),
        "deny ตั้งแต่ประตูต้องลง verdict: {log}"
    );
}

#[test]
fn container_prerequisite_denial_is_audited() {
    let (mut gw, mut cube, dir) = exec_harness();
    gw.level = SandboxLevel::Container;
    gw.container_cfg.bubblewrap = dir.join("missing-bwrap");
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    assert!(
        matches!(r, Err(ToolError::Denied(ref msg)) if msg.contains("container prerequisites"))
    );
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("level-disabled"));
    assert!(log.contains("\"decision\":\"deny\""));
    assert!(log.contains("verdict:clean"));
}

// Phase 7 (ฟีเจอร์ microvm): artifact ปลอมต้อง DENY พร้อม audit
// (deterministic ทุกเครื่อง — supply chain ตายก่อนถึงขั้น boot)
// ส่วน path บูตจริงมีเทสต์ host-gated ฝั่ง sandbox คุมอยู่แล้ว
#[cfg(feature = "microvm")]
#[test]
fn exec_with_tampered_artifact_denied_with_audit() {
    let (mut gw, mut cube, dir) = exec_harness();
    let kern = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&kern, b"k").unwrap();
    std::fs::write(&rootfs, b"r").unwrap();
    gw.level = SandboxLevel::MicroVm;
    gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
        kernel_path: kern,
        // hash ผิดเจตนา (ของจริงคือ sha256 ของ b"k")
        kernel_sha256: "00".repeat(32),
        rootfs_path: rootfs,
        rootfs_sha256: "11".repeat(32),
        ..aivm_sandbox::microvm::MicroVmConfig::default()
    });
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
    assert!(log.contains("level-invalid"));
    assert!(log.contains("\"decision\":\"deny\""));
}

// Phase 7 + G3 (ฟีเจอร์ microvm): deny ตั้งแต่ประตูต้องมี verdict ใน audit
// (deterministic ทุกเครื่อง — ยังไม่เกิด run = verdict:clean + เหตุผล)
#[cfg(feature = "microvm")]
#[test]
fn exec_denied_at_gate_audits_verdict() {
    let (mut gw, mut cube, dir) = exec_harness();
    let kern = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&kern, b"k").unwrap();
    std::fs::write(&rootfs, b"r").unwrap();
    gw.level = SandboxLevel::MicroVm;
    gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
        kernel_path: kern,
        kernel_sha256: "00".repeat(32),
        rootfs_path: rootfs,
        rootfs_sha256: "11".repeat(32),
        ..aivm_sandbox::microvm::MicroVmConfig::default()
    });
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
    assert!(log.contains("\"decision\":\"deny\""));
    assert!(
        log.contains("verdict:clean:no-interference-evidence"),
        "deny ตั้งแต่ประตูต้องลง verdict: {log}"
    );
}

// Phase 7 (ฟีเจอร์ microvm): pin ของไบนารี VMM ไม่ตรงต้อง DENY พร้อม
// audit เช่นกัน (supply chain ของ VMM เอง — attacker สลับไบนารีใน PATH
// แล้ว pin จับได้ต้องตายตั้งแต่ประตู ไม่ใช่บูตด้วย VMM ปลอม)
#[cfg(feature = "microvm")]
#[test]
fn exec_with_tampered_fc_pin_denied_with_audit() {
    use sha2::{Digest, Sha256};
    // sha256 hex ของไบต์ตั้งต้น (เทสต์คุมเอง ไม่พึ่งค่าตายตัว)
    fn hex_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
    let (mut gw, mut cube, dir) = exec_harness();
    let kern = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&kern, b"k").unwrap();
    std::fs::write(&rootfs, b"r").unwrap();
    // pin ของ kernel/rootfs ถูก (ผ่านด่านแรก) แต่ pin ของ VMM ผิดเจตนา
    gw.level = SandboxLevel::MicroVm;
    gw.microvm_cfg = Some(aivm_sandbox::microvm::MicroVmConfig {
        kernel_path: kern,
        kernel_sha256: hex_of(b"k"),
        rootfs_path: rootfs,
        rootfs_sha256: hex_of(b"r"),
        fc_sha256: "22".repeat(32),
        ..aivm_sandbox::microvm::MicroVmConfig::default()
    });
    let r = gw.dispatch(
        &mut cube,
        &ToolRequest {
            tool: "process.exec".into(),
            path: "/bin/true".into(),
            content: Some("[]".into()),
        },
    );
    // เครื่องที่มี firecracker = pin ผิดต้องตายด้วย Invalid;
    // เครื่องที่ไม่มี = ไปไม่ถึงขั้นตรวจ pin (Disabled) — deny + audit ทั้งคู่
    assert!(matches!(r, Err(ToolError::Denied(_))));
    let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("level-invalid") || log.contains("level-disabled"));
    assert!(log.contains("\"decision\":\"deny\""));
}
