#!/usr/bin/env python3
"""Validate a trusted GGUF on all worker tiers and retain reproducible evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time
from datetime import datetime, timezone


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=PROJECT / "target/model-host-validation")
    args = parser.parse_args()
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
    }
    save("host.json", metadata)
    sources = [
        "scripts/validate-model-host.py", "scripts/test-worker-host.sh",
        "crates/aivm-model/src/artifact.rs", "crates/aivm-model-worker/tests/worker.rs",
        "crates/aivm-sandbox/src/lib.rs", "crates/aivm-sandbox/src/container.rs",
    ]
    save("validation-sources.json", {name: digest(PROJECT / name) for name in sources})
    results = []
    env = dict(os.environ, AIVM_GGUF=str(model), AIVM_GGUF_SHA256=args.model_sha256,
               CARGO_TARGET_DIR=str(PROJECT / "target"))

    def run(name, command, exact=False):
        print(f"START {name}", flush=True)
        start = time.monotonic()
        with (out / f"{name}.log").open("w") as log:
            try:
                code = subprocess.run(command, cwd=PROJECT, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=900).returncode
            except subprocess.TimeoutExpired:
                code = 124
        content = (out / f"{name}.log").read_text(errors="replace")
        passed = code == 0 and (not exact or exact_test_passed(content))
        row = {"name": name, "command": command, "returncode": code,
               "passed": passed, "elapsed_seconds": round(time.monotonic() - start, 2),
               "summaries": re.findall(r"^test result:.*$", content, re.M),
               "log": f"{name}.log"}
        results.append(row)
        save("results.json", results)
        print(f"END {name}: passed={passed}, seconds={row['elapsed_seconds']}", flush=True)
        if not passed:
            print("\n".join(content.splitlines()[-25:]), flush=True)
        return passed

    before = snapshot(model, args.model_sha256, pins)
    save("artifacts-before.json", before)
    if not run("build-worker", ["cargo", "build", "--locked", "-p", "aivm-model-worker",
                                "--features", "llama,microvm"]):
        return 1
    worker = PROJECT / "target/debug/aivm-model-worker"
    before["worker"] = {"path": str(worker), "sha256": digest(worker)}
    save("artifacts-before.json", before)
    run("probe", ["cargo", "run", "--locked", "-q", "-p", "aivm-cli", "--", "probe"])
    try:
        run("protected-loader", ["cargo", "test", "--locked", "-p", "aivm-model",
                                 "--features", "llama,microvm",
                                 "artifact::tests::real_loader_uses_verified_snapshot_after_source_tampering",
                                 "--", "--exact", "--ignored", "--nocapture"], exact=True)
        for tier in ("process_namespace", "container", "microvm"):
            run(f"worker-{tier}", ["sh", "scripts/test-worker-host.sh", tier,
                                   str(model), str(pins)], exact=True)
    finally:
        # ทดสอบเสร็จแล้วต้องยืนยันว่า fixture/pins/worker ต้นฉบับไม่ถูกเปลี่ยน
        after = snapshot(model, args.model_sha256, pins)
        after["worker"] = {"path": str(worker), "sha256": digest(worker)}
        save("artifacts-after.json", after)
        save("integrity.json", {"artifacts_unchanged": before == after})
    return 0 if before == after and all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
