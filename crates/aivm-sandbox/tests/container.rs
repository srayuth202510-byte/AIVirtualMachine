#![cfg(target_os = "linux")]
use aivm_policy::Policy;
use aivm_sandbox::{
    container::{self, ContainerConfig},
    ExecSpec, ResourceLimits, SandboxError,
};
use std::path::PathBuf;

fn workspace() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aivm-container-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}
fn spec(exe: PathBuf, ws: &std::path::Path) -> ExecSpec {
    ExecSpec {
        exe,
        args: Vec::new(),
        cwd: ws.to_path_buf(),
        workspace: ws.to_path_buf(),
        env_extra: Vec::new(),
        limits: ResourceLimits::default(),
        timeout_ms: 3000,
        build: None,
    }
}
#[test]
fn missing_backend_never_executes_payload() {
    let ws = workspace();
    let exe = std::fs::canonicalize("/usr/bin/touch").unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: test\nfilesystem: {{deny: ['**/.env*']}}\nprocess:\n  allow: [{}]\n  deny: [/bin/sh]\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n",
        exe.display()
    ))
    .unwrap();
    let mut spec = spec(exe, &ws);
    let marker = ws.join("executed");
    spec.args.push(marker.to_string_lossy().into_owned());
    let cfg = ContainerConfig {
        bubblewrap: ws.join("missing-bwrap"),
        ..Default::default()
    };
    assert!(matches!(
        container::run(&spec, &policy, &cfg),
        Err(SandboxError::Disabled(_))
    ));
    assert!(!marker.exists());
    std::fs::remove_dir_all(ws).unwrap();
}

/// Deliberately ignored in ordinary CI. Requires real delegated cgroups and installed helper.
/// AIVM_CONTAINER_TEST_CONFIG points to JSON containing bubblewrap/init/cgroup_root.
#[test]
#[ignore = "requires bubblewrap, root-owned helper, user namespaces and delegated cgroup v2"]
fn real_container_enforces_boundary_and_quotas() {
    let cfg_path =
        std::env::var("AIVM_CONTAINER_TEST_CONFIG").expect("set AIVM_CONTAINER_TEST_CONFIG");
    let cfg: ContainerConfig = serde_json::from_slice(&std::fs::read(cfg_path).unwrap()).unwrap();
    let ws = workspace();
    let exe = ws.join("boundary");
    assert!(std::process::Command::new("cc")
        .args(["-O0", "-o"])
        .arg(&exe)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/container-boundary.c"
        ))
        .status()
        .unwrap()
        .success());
    let readable_exe = ws.join("readable-exe");
    std::fs::copy("/usr/bin/true", &readable_exe).unwrap();
    let allowed = ws.join("allowed");
    let denied = ws.join("secret");
    let link = ws.join("link");
    std::fs::write(&allowed, "original").unwrap();
    std::fs::write(&denied, "hidden").unwrap();
    std::os::unix::fs::symlink(&denied, &link).unwrap();
    let policy = Policy::from_yaml(&format!(
        "name: test\nprocess:\n  allow: [{}]\n  deny: [/bin/sh]\nfilesystem:\n  read: ['{}/**']\n  write: ['{}']\n  deny: ['{}']\nnetwork: {{allow: [], deny: ['10.0.0.0/8']}}\n",
        exe.display(), ws.display(), allowed.display(), denied.display())).unwrap();
    let mut s = spec(exe, &ws);
    let entries = || {
        std::fs::read_dir(&cfg.cgroup_root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before = entries();
    s.args = vec!["read".into(), allowed.to_string_lossy().into_owned()];
    let out = container::run(&s, &policy, &cfg).unwrap();
    assert!(out.success(), "{}", out.stderr);
    assert_eq!(out.stdout, "original");
    for mechanism in [
        "landlock-filesystem",
        "seccomp-filter",
        "pid-namespace",
        "readonly-root",
        "cgroup-tree-cleanup",
    ] {
        assert!(
            out.applied.iter().any(|v| v == mechanism),
            "missing {mechanism}"
        );
    }
    assert!(out.degraded.is_empty());
    for path in [
        &denied,
        &link,
        &PathBuf::from("/etc/passwd"),
        &PathBuf::from("/dev/dri/renderD128"),
    ] {
        s.args = vec!["read".into(), path.to_string_lossy().into_owned()];
        assert_eq!(container::run(&s, &policy, &cfg).unwrap().code, Some(20));
    }
    s.args = vec!["write".into(), allowed.to_string_lossy().into_owned()];
    assert!(container::run(&s, &policy, &cfg).unwrap().success());
    assert_eq!(std::fs::read_to_string(&allowed).unwrap(), "changed");
    s.args = vec![
        "create".into(),
        ws.join("new-file").to_string_lossy().into_owned(),
    ];
    assert_eq!(container::run(&s, &policy, &cfg).unwrap().code, Some(23));
    s.args = vec!["exec".into(), readable_exe.to_string_lossy().into_owned()];
    assert_eq!(container::run(&s, &policy, &cfg).unwrap().code, Some(24));
    s.args = vec!["socket".into()];
    assert!(!container::run(&s, &policy, &cfg).unwrap().success());
    s.limits.pids_max = 8;
    s.args = vec!["fork".into()];
    let out = container::run(&s, &policy, &cfg).unwrap();
    assert!(out.success());
    assert!(out.stdout.starts_with("limited:"));
    assert_eq!(
        entries(),
        before,
        "fork descendants/cgroup must be cleaned up"
    );
    s.limits.memory_mb = 64;
    s.args = vec!["memory".into()];
    // Aggregate OOM may kill the monitor as well; an error is fail-closed.
    if let Ok(out) = container::run(&s, &policy, &cfg) {
        assert!(out.stdout.contains("limited") || !out.success());
    }
    assert_eq!(entries(), before);
    s.args = vec!["sleep".into()];
    s.timeout_ms = 500;
    let worker_spec = s.clone();
    let worker_policy = policy.clone();
    let worker_cfg = cfg.clone();
    let worker =
        std::thread::spawn(move || container::run(&worker_spec, &worker_policy, &worker_cfg));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut observed = false;
    while std::time::Instant::now() < deadline && !worker.is_finished() {
        for name in entries().difference(&before) {
            let root = cfg.cgroup_root.join(name);
            let procs = std::fs::read_to_string(root.join("cgroup.procs")).unwrap_or_default();
            if procs.trim().is_empty() {
                continue;
            }
            assert_eq!(
                std::fs::read_to_string(root.join("cpu.max"))
                    .unwrap()
                    .trim(),
                "200000 100000"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("memory.max"))
                    .unwrap()
                    .trim(),
                "67108864"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("pids.max"))
                    .unwrap()
                    .trim(),
                "8"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("memory.swap.max"))
                    .unwrap()
                    .trim(),
                "0"
            );
            observed = true;
        }
        if observed {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(worker
        .join()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("timeout"));
    assert!(
        observed,
        "must observe launcher/target attached to an enforced cgroup"
    );
    assert_eq!(entries(), before, "timeout must remove the entire cgroup");
    s.timeout_ms = 3000;
    s.args = vec!["reserved-exit".into()];
    s.env_extra = vec![("TEST_SECRET".into(), "must-not-appear-in-error".into())];
    let error = container::run(&s, &policy, &cfg).unwrap_err().to_string();
    assert!(
        !error.contains("must-not-appear-in-error"),
        "errors must not expose payload stderr"
    );
    std::fs::remove_dir_all(ws).unwrap();
}

#[test]
fn init_enforces_file_reads_and_execution_without_namespace_privileges() {
    let ws = workspace();
    let allowed = ws.join("allowed");
    let denied = ws.join("denied");
    let readable_exe = ws.join("readable-exe");
    std::fs::write(&allowed, "visible").unwrap();
    std::fs::write(&denied, "hidden").unwrap();
    std::fs::copy("/usr/bin/true", &readable_exe).unwrap();
    let cat = std::fs::canonicalize("/usr/bin/cat").unwrap();
    let mut grants = vec![
        (ws.clone(), 8u64),
        (allowed.clone(), 4),
        (readable_exe.clone(), 4),
        (cat.clone(), 5),
    ];
    for path in [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
    ] {
        if std::path::Path::new(path).exists() {
            grants.push((PathBuf::from(path), 13));
        }
    }
    let plan_path = ws.join("plan.json");
    let run = |exe: &std::path::Path, args: Vec<String>| {
        let plan = serde_json::json!({"exe": exe, "args": args, "grants": grants, "fsize": 1024});
        std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_aivm-container-init"))
            .arg("--plan")
            .arg(&plan_path)
            .env_clear()
            .output()
            .unwrap()
    };
    let out = run(&cat, vec![allowed.to_string_lossy().into_owned()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"aivm-container-init:ready-v1\nvisible");
    let out = run(&cat, vec![denied.to_string_lossy().into_owned()]);
    assert!(!out.status.success());
    assert_eq!(out.stdout, b"aivm-container-init:ready-v1\n");
    let out = run(&readable_exe, vec![]);
    assert_eq!(
        out.status.code(),
        Some(125),
        "read permission must not permit execution"
    );
    std::fs::remove_dir_all(ws).unwrap();
}
