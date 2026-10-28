#!/usr/bin/env python3
"""Validate a trusted GGUF on all worker tiers and retain reproducible evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
import release_evidence


PROJECT = Path(__file__).resolve().parent.parent


def digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def snapshot(model, expected, pins_path):
    # ใช้ pin ที่ operator อนุมัติเท่านั้น; ห้ามเปลี่ยน pin ตามไฟล์ที่พบเอง
    entries = {"model": {"path": str(model), "sha256": expected}}
    pins = json.loads(pins_path.read_text())
    for kind in ("kernel", "rootfs", "binary"):
        entries[kind] = pins[kind]
    result = {}
    for name, entry in entries.items():
        pin = entry["sha256"]
        if not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
            raise ValueError(f"{name}: expected a trusted SHA-256 pin")
        path = Path(entry["path"]).resolve(strict=True)
        actual = digest(path)
        if actual != pin.lower():
            raise ValueError(f"{name}: sha256 mismatch (refusing validation)")
        result[name] = {"path": str(path), "bytes": path.stat().st_size,
                        "sha256": actual}
    result["pins"] = {"path": str(pins_path), "sha256": digest(pins_path)}
    return result


def exact_test_passed(log):
    # exit 0 อย่างเดียวไม่พอ: ชื่อเทสต์ผิดหรือ skip ต้องไม่กลายเป็นผลผ่าน
    return (
        bool(re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", log, re.M))
        and not re.search(r"\bskip(?:ped)?\b", log, re.I)
    )


def failure_evidence_passed(path):
    # log ผ่านแต่หลักฐานขาด/ไม่ครบต้องไม่กลายเป็นผลผ่านของ failure suite
    try:
        rows = json.loads(Path(path).read_text())
        cases = ["timeout", "recovery-after-timeout", "memory", "recovery-after-memory"]
        if not isinstance(rows, list) or len(rows) != len(cases):
            return False
        for case, row in zip(cases, rows):
            if not isinstance(row, dict) or row.get("case") != case:
                return False
            if any(row.get(field) is not True for field in ("passed", "descendants_reaped", "staging_clean")):
                return False
            if not isinstance(row.get("observed_processes"), dict) or not row["observed_processes"]:
                return False
            if not all(isinstance(pid, str) and pid.isdecimal() and int(pid) > 0
                       and type(start) is int and start > 0
                       for pid, start in row["observed_processes"].items()):
                return False
            if case.startswith("recovery-"):
                if row.get("verification") != "verified":
                    return False
            elif (row.get("stream_deltas") != 0 or not isinstance(row.get("error"), str)
                  or not row["error"] or type(row.get("elapsed_ms")) is not int
                  or not 0 <= row["elapsed_ms"] < 180_000):
                return False
            elif case == "timeout" and row.get("timeout_ms") != 100:
                return False
            elif case == "memory" and row.get("memory_mb") != 128:
                return False
            elif case == "memory" and row.get("memory_failure_kind") not in (
                    "allocation-failure", "guest-oom-diagnostic", "ram-backed-staging-capacity"):
                return False
        return True
    except (OSError, ValueError, TypeError):
        return False


def quality_evidence_passed(path, corpus_path=None):
    # งานผิดต้องสะท้อนคะแนน แต่ห้ามใช้ model-only benchmark เป็นหลักฐานว่า tool task สำเร็จ
    try:
        report = json.loads(Path(path).read_text())
        expected = json.loads(Path(corpus_path or PROJECT / "examples/model-quality.json").read_text())["cases"]
        # malformed evidence ต้องคืน false เช่นเดียวกับ record ที่ขาด ห้าม crash หรือรับ bool เป็น count
        if not isinstance(report, dict) or any(type(report.get(key)) is not int
                for key in ("schema", "completed", "total", "task_correct")):
            return False
        rows = report["cases"]
        return (isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
                and report["schema"] == 1 and report["completed"] == report["total"] == len(expected)
                and [row["id"] for row in rows] == [row["id"] for row in expected]
                and all(row["infrastructure_passed"] is True and type(row["task_correct"]) is bool for row in rows)
                and report["task_correct"] == sum(row["task_correct"] for row in rows))
    except (OSError,ValueError,TypeError,KeyError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quality", action="store_true", help="Also measure fixed task oracles and cold/warm preparation with a reused client")
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--candidate-config", type=Path, help="Bind the exact release candidate worker config to host evidence")
    parser.add_argument("--worker-profile", choices=("debug", "release"), default="release")
    parser.add_argument("--out", type=Path, default=PROJECT / "target/model-host-validation")
    args = parser.parse_args()
    profile_args = ["--release"] if args.worker_profile == "release" else []
    source_before = release_evidence.source_identity()
    candidate_hash = digest(args.candidate_config) if args.candidate_config else None
    model = args.model.resolve(strict=True)
    pins = args.pins.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    def save(name, data):
        (out / name).write_text(json.dumps(data, indent=2) + "\n")

    metadata = {
        "client_timezone": "Asia/Bangkok",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT,
                                           text=True).strip(),
        "source_diff_sha256": hashlib.sha256(subprocess.check_output(
            ["git", "diff", "HEAD", "--binary"], cwd=PROJECT)).hexdigest(),
        "platform": platform.platform(),
        "supervised_control": os.environ.get("AIVM_SUPERVISED_CONTROL") == "1",
        "quality_requested": args.quality,
        "meminfo": Path("/proc/meminfo").read_text(),
    }
    save("host.json", metadata)
    sources = [
        "scripts/validate-model-host.py", "scripts/test-worker-host.sh",
        "crates/aivm-model/src/artifact.rs", "crates/aivm-model-worker/tests/worker.rs",
        "crates/aivm-model/src/worker.rs", "crates/aivm-model/src/worker/control.rs",
        "crates/aivm-model/src/worker/launcher.rs", "crates/aivm-model-worker/src/main.rs",
        "crates/aivm-model/src/worker/staging.rs", "crates/aivm-model/src/worker/supervised.rs",
        "crates/aivm-model/src/worker/resources.rs", "crates/aivm-model/src/worker/cache.rs",
        "crates/aivm-model/src/lib.rs", "crates/aivm-model-worker/tests/hardening.rs",
        "crates/aivm-model-worker/tests/quality.rs", "examples/model-quality.json",
        "crates/aivm-runtime/src/lib.rs",
        "crates/aivm-model-worker/tests/failure_recovery.rs",
        "crates/aivm-sandbox/src/lib.rs", "crates/aivm-sandbox/src/container.rs",
        "crates/aivm-sandbox/src/microvm/boot.rs",
        "crates/aivm-runtime/tests/coding_workflow.rs",
    ]
    save("validation-sources.json", {name: digest(PROJECT / name) for name in sources})
    results = []
    env = dict(os.environ, AIVM_GGUF=str(model), AIVM_GGUF_SHA256=args.model_sha256,
               AIVM_WORKER_PROFILE=args.worker_profile,
               CARGO_TARGET_DIR=str(PROJECT / "target"))

    def run(name, command, exact=False, extra_env=None, evidence=None, quality=False):
        print(f"START {name}", flush=True)
        if evidence is not None:
            Path(evidence).unlink(missing_ok=True)
        start = time.monotonic()
        with (out / f"{name}.log").open("w") as log:
            try:
                code = subprocess.run(command, cwd=PROJECT, env=dict(env, **(extra_env or {})), stdout=log,
                                      stderr=subprocess.STDOUT, timeout=900).returncode
            except subprocess.TimeoutExpired:
                code = 124
        content = (out / f"{name}.log").read_text(errors="replace")
        passed = code == 0 and (not exact or exact_test_passed(content))
        if evidence is not None:
            passed = passed and (quality_evidence_passed(evidence) if quality else failure_evidence_passed(evidence))
        row = {"name": name, "command": command, "returncode": code,
               "exact": exact, "log_sha256": digest(out / f"{name}.log"),
               "passed": passed, "elapsed_seconds": round(time.monotonic() - start, 2),
               "summaries": re.findall(r"^test result:.*$", content, re.M),
               "log": f"{name}.log"}
        if evidence is not None:
            row["evidence"] = Path(evidence).name
            if Path(evidence).is_file():
                row["evidence_sha256"] = digest(evidence)
            if quality and quality_evidence_passed(evidence):
                score = json.loads(Path(evidence).read_text())
                row["quality"] = {key: score.get(key) for key in ("task_correct", "total", "client_boot_ms")}
        results.append(row)
        save("results.json", results)
        print(f"END {name}: passed={passed}, seconds={row['elapsed_seconds']}", flush=True)
        if not passed:
            print("\n".join(content.splitlines()[-25:]), flush=True)
        return passed

    before = snapshot(model, args.model_sha256, pins)
    save("artifacts-before.json", before)
    if not run("build-worker", ["cargo", "build", "--locked", *profile_args, "-p", "aivm-model-worker",
                                "--features", "llama,microvm"]):
        return 1
    built_worker = PROJECT / "target" / args.worker_profile / "aivm-model-worker"
    built_worker_sha256 = digest(built_worker)
    worker = out / "validated-worker"
    shutil.copyfile(built_worker, worker)
    worker.chmod(0o500)
    if digest(worker) != built_worker_sha256:
        raise ValueError("worker changed during validation snapshot")
    env.update(AIVM_VALIDATED_WORKER=str(worker), AIVM_VALIDATED_WORKER_SHA256=built_worker_sha256)
    before["worker"] = {"path": str(worker), "sha256": digest(worker)}
    save("artifacts-before.json", before)
    run("probe", ["cargo", "run", "--locked", "-q", "-p", "aivm-cli", "--", "probe"])
    try:
        if args.candidate_config:
            release_evidence.candidate_config(args.candidate_config, before)
            run("candidate-worker", ["cargo", "test", "--locked", *profile_args, "-p", "aivm-model-worker", "--features", "llama,microvm",
                "--test", "worker", "real_isolated_worker_host_validation", "--", "--exact", "--ignored", "--nocapture"], exact=True,
                extra_env={"AIVM_WORKER_HOST_CONFIG": str(args.candidate_config.resolve())})
        run("protected-loader", ["cargo", "test", "--locked", *profile_args, "-p", "aivm-model",
                                 "--features", "llama,microvm",
                                 "artifact::tests::real_loader_uses_verified_snapshot_after_source_tampering",
                                 "--", "--exact", "--ignored", "--nocapture"], exact=True)
        for tier in ("process_namespace", "container", "microvm"):
            run(f"worker-{tier}", ["sh", "scripts/test-worker-host.sh", tier,
                                   str(model), str(pins)], exact=True)
            evidence = out / f"failure-recovery-{tier}.json"
            run(f"failure-recovery-{tier}", ["sh", "scripts/test-worker-host.sh", tier,
                str(model), str(pins), "failure-recovery"], exact=True,
                extra_env={"AIVM_WORKER_HOST_EVIDENCE": str(evidence)}, evidence=evidence)
        if args.quality:
            for scenario in ("quality", "quality-cache"):
                evidence = out / f"{scenario}.json"
                run(scenario, ["sh", "scripts/test-worker-host.sh", "process_namespace", str(model), str(pins), scenario], exact=True,
                    extra_env={"AIVM_WORKER_HOST_EVIDENCE": str(evidence)}, evidence=evidence, quality=True)
    finally:
        # ทดสอบเสร็จแล้วต้องยืนยันว่า fixture/pins/worker ต้นฉบับไม่ถูกเปลี่ยน
        after = snapshot(model, args.model_sha256, pins)
        after["worker"] = {"path": str(worker), "sha256": digest(worker)}
        save("artifacts-after.json", after)
        save("integrity.json", {"artifacts_unchanged": before == after})
        source_after = release_evidence.source_identity()
        candidate_ok = True
        if args.candidate_config:
            try:
                release_evidence.candidate_config(args.candidate_config, before)
                candidate_ok = digest(args.candidate_config) == candidate_hash
            except (OSError, ValueError, KeyError, TypeError):
                candidate_ok = False
        save("release-evidence.json", {"schema": 1, "source_before": source_before, "source_after": source_after,
            "worker_build_profile":args.worker_profile,
            "built_worker_sha256":built_worker_sha256,
            "candidate_config_sha256": candidate_hash,
            "pins_sha256": digest(pins), "artifacts_before": before, "artifacts_after": after, "results": results,
            "passed": before == after and source_before == source_after and candidate_ok and all(row["passed"] for row in results)})
    return 0 if before == after and source_before == source_after and candidate_ok and all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
