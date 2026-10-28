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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fresh_model", "reference_control"), default="fresh_model")
    parser.add_argument("--model-config", type=Path)
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
    command = ["cargo", "test", "--locked", "-p", "aivm-runtime", "--test", "coding_workflow"]
    if args.profile == "release":
        command.append("--release")
    if args.mode == "fresh_model":
        if args.model_config is None:
            raise ValueError("fresh_model requires --model-config with approved pins")
        try:
            evidence.candidate_config(args.model_config)
        except (OSError, ValueError, KeyError, TypeError) as error:
            (out / "preflight.json").write_text(json.dumps({"passed": False, "error": str(error), "source_identity": source}, indent=2) + "\n")
            print(f"preflight failed: {error}")
            return 1
        config_hash = evidence.digest(args.model_config)
        command += ["repair_benchmark::fresh_model_repair_benchmark", "--", "--exact", "--ignored", "--nocapture"]
    else:
        command += ["repair_benchmark::repair_corpus_baselines_and_reference_controls", "--", "--exact", "--nocapture"]
    env = dict(os.environ, AIVM_REPAIR_BENCHMARK_OUT=str(out), AIVM_SOURCE_IDENTITY=json.dumps(source))
    if args.model_config:
        env["AIVM_WORKER_HOST_CONFIG"] = str(args.model_config.resolve())
    with (out / "run.log").open("w") as log:
        code = run_group(command, env, log, args.timeout_seconds)
    result = {"schema": 1, "returncode": code, "command": command, "build_profile":args.profile,"elapsed_seconds": time.monotonic() - started,
              "source_before": source, "source_after": evidence.source_identity(), "passed": False}
    try:
        result["score"] = evidence.validate_benchmark(out / "report.json", source, config_hash,
                                                    allow_control=args.mode == "reference_control")
        result["passed"] = (code == 0 and result["source_before"] == result["source_after"]
                            and (args.model_config is None or evidence.digest(args.model_config) == config_hash))
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
    (out / "runner.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("source_before", "source_after")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
