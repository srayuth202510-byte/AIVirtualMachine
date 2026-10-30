#!/usr/bin/env python3
"""Run the frozen 24-task repair corpus and retain evidence and patches for review."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import signal
import time
import release_evidence as evidence


def run_group(command, env, log, timeout):
    process = subprocess.Popen(command, cwd=evidence.PROJECT, env=env, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return 124 if isinstance(error, subprocess.TimeoutExpired) else 130


def interpretation_cases(baseline_path):
    baseline = evidence.load(baseline_path)
    if baseline.get("trace_config_sha256") is not None:
        evidence.validate_benchmark(
            baseline_path,
            baseline["source_identity"],
            baseline["model_config_sha256"],
            trace_config_sha256=baseline["trace_config_sha256"],
        )
    else:
        evidence.validate_benchmark(baseline_path, baseline["source_identity"], baseline["model_config_sha256"])
    corpus = evidence.load(evidence.PROJECT / "examples/repair-benchmark.json")
    selected = []
    for case, row in zip(corpus["cases"], baseline["cases"]):
        source = Path(baseline_path).parent / case["id"] / "source.c"
        # เลือกจากหลักฐานจริง ไม่ hard-code รายชื่อหรือแก้ corpus เพื่อให้คะแนนดีขึ้น
        if not row["task_success"] and source.read_text().rstrip("\n") == case["buggy"].rstrip("\n"):
            selected.append(case["id"])
    if not selected:
        raise ValueError("baseline contains no failed unchanged-source repairs")
    return baseline, selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fresh_model", "reference_control", "interpretation_experiment"), default="fresh_model")
    parser.add_argument("--baseline-report", type=Path, help="Validated original report; required for interpretation experiment")
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--trace-config", type=Path, help="Pinned native trace collector config")
    parser.add_argument("--profile", choices=("release", "debug"), default="release")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise ValueError("output directory must be new; preserve prior evidence")
    out.mkdir(parents=True)
    started = time.monotonic()
    source = evidence.source_identity()
    config_hash = None
    trace_hash = None
    selected = None
    baseline_hash = None
    experimental = args.mode == "interpretation_experiment"
    if experimental:
        if args.baseline_report is None:
            raise ValueError("interpretation_experiment requires --baseline-report")
        baseline, selected = interpretation_cases(args.baseline_report.resolve())
        baseline_hash = evidence.digest(args.baseline_report)
    elif args.baseline_report is not None:
        raise ValueError("--baseline-report is only valid for interpretation_experiment")
    if args.trace_config is not None:
        try:
            evidence.trace_config(args.trace_config)
        except (OSError, ValueError, KeyError, TypeError) as error:
            (out / "preflight.json").write_text(json.dumps({"passed": False, "error": str(error), "source_identity": source}, indent=2) + "\n")
            print(f"preflight failed: {error}")
            return 1
        trace_hash = evidence.digest(args.trace_config)
    command = ["cargo", "test", "--locked", "-p", "aivm-runtime", "--test", "coding_workflow"]
    if args.profile == "release":
        command.append("--release")
    if args.mode != "reference_control":
        if args.model_config is None:
            raise ValueError("model runs require --model-config with approved pins")
        try:
            evidence.candidate_config(args.model_config)
        except (OSError, ValueError, KeyError, TypeError) as error:
            (out / "preflight.json").write_text(json.dumps({"passed": False, "error": str(error), "source_identity": source}, indent=2) + "\n")
            print(f"preflight failed: {error}")
            return 1
        config_hash = evidence.digest(args.model_config)
        if experimental and config_hash != baseline["model_config_sha256"]:
            raise ValueError("interpretation experiment must use the original model config/pins")
        test = "fresh_model_interpretation_experiment" if experimental else "fresh_model_repair_benchmark"
        command += [f"repair_benchmark::{test}", "--", "--exact", "--ignored", "--nocapture"]
    else:
        command += ["repair_benchmark::repair_corpus_baselines_and_reference_controls", "--", "--exact", "--nocapture"]
    env = dict(os.environ, AIVM_REPAIR_BENCHMARK_OUT=str(out), AIVM_SOURCE_IDENTITY=json.dumps(source))
    if args.model_config:
        env["AIVM_WORKER_HOST_CONFIG"] = str(args.model_config.resolve())
    if args.trace_config:
        env["AIVM_REPAIR_TRACE_CONFIG"] = str(args.trace_config.resolve())
    if selected is not None:
        env["AIVM_REPAIR_INTERPRETATION_CASES"] = json.dumps(selected)
    with (out / "run.log").open("w") as log:
        code = run_group(command, env, log, args.timeout_seconds)
    result = {"schema": 1, "returncode": code, "command": command, "build_profile":args.profile,"elapsed_seconds": time.monotonic() - started,
              "source_before": source, "source_after": evidence.source_identity(), "passed": False,
              "baseline_sha256":baseline_hash,"experiment_case_ids":selected,"trace_config_sha256":trace_hash}
    try:
        result["score"] = evidence.validate_benchmark(out / "report.json", source, config_hash,
                                                    allow_control=args.mode == "reference_control", experiment_case_ids=selected,
                                                    trace_config_sha256=trace_hash)
        result["passed"] = (code == 0 and result["source_before"] == result["source_after"]
                            and (args.model_config is None or evidence.digest(args.model_config) == config_hash)
                            and (args.trace_config is None or evidence.digest(args.trace_config) == trace_hash))
        if experimental:
            result["passed"] = result["passed"] and evidence.digest(args.baseline_report) == baseline_hash
            report = evidence.load(out / "report.json")
            result["comparison"] = {"baseline_successes":0,"experiment_successes":report["task_successes"],
                "total":len(selected),"interpretation_schema_valid":sum(row["task_interpretation"]["parsed"] is not None for row in report["cases"]),
                "release_evidence":False,"scope":"Selected previous no-op failures; one additional interpretation call per case; not a full-corpus or model-only comparison."}
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
    (out / "runner.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("source_before", "source_after")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
