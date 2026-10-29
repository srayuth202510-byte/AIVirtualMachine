#!/usr/bin/env python3
"""Collect a bounded native trace of one int-only C function through the existing gateway."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

import release_evidence as evidence
import repair_trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--input", required=True, help='JSON parameter values, e.g. {"b":-3,"e":1}')
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-events", type=int, default=32)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--profile", choices=("debug", "release"), default="release")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 1800:
        parser.error("timeout must be 1..1800 seconds")
    # อ่านแบบมีเพดานก่อนส่งให้ Clang; ไม่รับโค้ดสคริปต์หรือ command จากโมเดล
    with args.source.open("rb") as stream:
        source = stream.read(repair_trace.MAX_SOURCE + 1)
    bundle, original, traced = repair_trace.prepare(
        source, args.function, evidence.decode_json(args.input), args.max_events)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "source.c").write_bytes(source)
    (out / "original.c").write_bytes(original)
    (out / "traced.c").write_bytes(traced)
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n")
    if args.prepare_only:
        print(f"Prepared {len(bundle['sites'])} sites: {out}; native execution has not run")
        return 0
    identity = evidence.source_identity()
    files = {name: evidence.digest(out / name) for name in ("source.c", "original.c", "traced.c", "bundle.json")}
    spec = importlib.util.spec_from_file_location("repair_runner", evidence.PROJECT / "scripts/run-repair-benchmark.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    command = ["cargo", "test", "--locked", "-p", "aivm-runtime", "--test", "coding_workflow"]
    if args.profile == "release":
        command.append("--release")
    command += ["repair_trace::operator_dynamic_trace_probe", "--", "--exact", "--ignored", "--nocapture"]
    env = dict(os.environ, AIVM_REPAIR_TRACE_BUNDLE=str(out))
    with (out / "run.log").open("w") as log:
        code = runner.run_group(command, env, log, args.timeout_seconds)
    result = {"schema": 1, "kind": "native_trace_collection_not_repair", "passed": False,
              "returncode": code, "command": command, "source_before": identity,
              "source_after": evidence.source_identity(), "bundle_files": files,
              "repair_verified": False}
    try:
        if code != 0 or result["source_after"] != identity or any(evidence.digest(out / name) != value for name, value in files.items()):
            raise ValueError("native collector failed or input/source identity changed")
        measurement = evidence.load(out / "measurement/report.json")
        for label, expected in (("original", bundle["original_sha256"]), ("traced", bundle["traced_sha256"])):
            if measurement[label]["source_sha256"] != expected:
                raise ValueError("measured translation unit does not match bundle")
        trace = repair_trace.validate_measurements(bundle, measurement, {
            label: out / f"measurement/{label}-audit.jsonl" for label in ("original", "traced")})
        (out / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
        (out / "context.txt").write_text(repair_trace.render(trace))
        result.update(passed=True, actual=trace["actual"], event_count=len(trace["events"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
    (out / "runner.json").write_text(json.dumps(result, indent=2) + "\n")
    print(repair_trace.render(trace) if result["passed"] else "Trace unavailable: " + result["error"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
