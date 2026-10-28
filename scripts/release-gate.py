#!/usr/bin/env python3
"""Fail closed unless source, candidate config, pins and host/repair evidence agree."""
import argparse
import json
from pathlib import Path
import re
import importlib.util
import release_evidence as evidence


def evaluate(commit, config, pins, host_path, benchmark, minimum_successes):
    current = evidence.source_identity()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or current["commit"] != commit or not current["clean"]:
        raise ValueError("release requires the requested exact commit and a clean source tree")
    host = evidence.load(host_path)
    if (host.get("schema") != 1 or host.get("worker_build_profile") != "release" or host.get("source_before") != current or host.get("source_after") != current
            or host.get("candidate_config_sha256") != evidence.digest(config)
            or host.get("pins_sha256") != evidence.digest(pins)
            or host.get("artifacts_before") != host.get("artifacts_after")
            or host.get("built_worker_sha256") != host.get("artifacts_before", {}).get("worker", {}).get("sha256")
            or host.get("passed") is not True):
        raise ValueError("host validation belongs to another source/config/pin set or failed")
    required = {"build-worker", "candidate-worker", "protected-loader", "worker-process_namespace", "worker-container", "worker-microvm",
                "failure-recovery-process_namespace", "failure-recovery-container", "failure-recovery-microvm"}
    rows = host["results"]
    if not required.issubset({row["name"] for row in rows}) or any(row["passed"] is not True for row in rows):
        raise ValueError("required host validation scenarios missing/failed")
    spec = importlib.util.spec_from_file_location("host_validator", evidence.PROJECT / "scripts/validate-model-host.py")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    for row in rows:
        if row.get("returncode") != 0 or row["log"] != f'{row["name"]}.log' or Path(row["log"]).name != row["log"]:
            raise ValueError("host command/log identity mismatch")
        log = Path(host_path).parent / row["log"]
        if evidence.digest(log) != row.get("log_sha256"):
            raise ValueError("host validation log changed")
        if row["name"] not in ("build-worker", "probe") and (row.get("exact") is not True or not validator.exact_test_passed(log.read_text())):
            raise ValueError("host scenario was skipped or did not run exactly one test")
        if row["name"].startswith("failure-recovery-"):
            if Path(row["evidence"]).name != row["evidence"]:
                raise ValueError("unsafe host evidence path")
            recovery = Path(host_path).parent / row["evidence"]
            if evidence.digest(recovery) != row.get("evidence_sha256") or not validator.failure_evidence_passed(recovery):
                raise ValueError("failure recovery evidence incomplete or changed")
    evidence.candidate_config(config, host["artifacts_before"])
    pin_data = evidence.load(pins)
    for name in ("kernel", "rootfs", "binary"):
        if (evidence.digest(pin_data[name]["path"]) != pin_data[name]["sha256"]
                or host["artifacts_before"].get(name, {}).get("sha256") != pin_data[name]["sha256"]):
            raise ValueError(f"{name}: pin mismatch")
    score = evidence.validate_benchmark(benchmark, current, evidence.digest(config))
    if type(minimum_successes) is not int or not 0 <= minimum_successes <= score["total"] or score["successes"] < minimum_successes:
        raise ValueError("repair quality threshold not met")
    if evidence.source_identity() != current:
        raise ValueError("source changed during release gate")
    return {"schema": 1, "passed": True, "commit": commit, "source_sha256": current["source_sha256"],
            "config_sha256": evidence.digest(config), "pins_sha256": evidence.digest(pins),
            "host_evidence_sha256": evidence.digest(host_path), "benchmark_sha256": evidence.digest(benchmark),
            "minimum_successes": minimum_successes, "quality": score}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "pins", "host-evidence", "benchmark", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--minimum-successes", type=int, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(args.commit, args.config, args.pins, args.host_evidence, args.benchmark, args.minimum_successes)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"schema": 1, "passed": False, "error": str(error)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
