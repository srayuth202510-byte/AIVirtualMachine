#!/usr/bin/env python3
"""Compare raw/format-guided prompts on unchanged oracles through a pinned worker."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

PROJECT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("host", Path(__file__).with_name("validate-model-host.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
CORPORA = {"baseline": PROJECT / "examples/model-quality.json",
           "holdout": PROJECT / "examples/model-quality-holdout.json"}
PROFILE = PROJECT / "examples/model-quality-format.json"


def score(case, output):
    if not isinstance(output, str):
        return False
    if "exact" in case:
        return output.strip() == case["exact"]
    try:
        # เปรียบเทียบชนิด JSON ด้วย ไม่ให้ true == 1 หรือ false == 0 ของ Python ช่วยคะแนน
        actual = json.loads(output)
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
        return canonical(actual) == canonical(case["json"])
    except (ValueError, TypeError):
        return False


def valid_report(path, corpus, style, config_hash):
    if not HOST.quality_evidence_passed(path, CORPORA[corpus]):
        return False
    report = json.loads(path.read_text())
    cases = json.loads(CORPORA[corpus].read_text())["cases"]
    suffix = json.loads(PROFILE.read_text())["suffix"] if style == "strict" else ""
    return (report.get("config_sha256") == config_hash
            and report.get("corpus_sha256") == HOST.digest(CORPORA[corpus])
            and report.get("corpus") == corpus and report.get("prompt_style") == style
            and report.get("prompt_profile_sha256") == (HOST.digest(PROFILE) if style == "strict" else None)
            and all(row.get("prompt") == case["prompt"] + suffix
                    and row["task_correct"] == score(case, row.get("output"))
                    for case, row in zip(cases, report["cases"])))


def compare(raw, strict):
    # คะแนนที่ดีขึ้นไม่กลบ regressions รายงานทุก case ที่เปลี่ยนแยกกัน
    return {"raw_correct": raw["task_correct"], "strict_correct": strict["task_correct"],
            "total": raw["total"],
            "improved": [a["id"] for a, b in zip(raw["cases"], strict["cases"])
                         if not a["task_correct"] and b["task_correct"]],
            "regressed": [a["id"] for a, b in zip(raw["cases"], strict["cases"])
                          if a["task_correct"] and not b["task_correct"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Pinned ModelConfig JSON; identical for all four runs")
    parser.add_argument("--out", required=True, type=Path, help="New evidence directory; existing directories are rejected")
    args = parser.parse_args()
    config = args.config.resolve(strict=True)
    config_bytes = config.read_bytes()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    out = args.out.resolve()
    out.mkdir(parents=True, mode=0o700)
    # เก็บ config เดิมครบเพื่อ replay โดยไม่ re-pin หรือปรับ sampling/context ระหว่าง A/B
    copied_config = out / "config.json"
    copied_config.write_bytes(config_bytes)
    copied_config.chmod(0o600)
    command = ["cargo", "test", "--locked", "-p", "aivm-model-worker", "--features", "llama,microvm",
               "--test", "quality", "real_model_quality_and_latency", "--", "--exact", "--ignored", "--nocapture"]
    summary = {"schema": 1, "scope": "Synthetic prompt-format comparison; scores are separate from infrastructure gates.",
               "config_sha256": config_hash, "command": command, "runs": [], "comparisons": {},
               "sources": {str(path.relative_to(PROJECT)): HOST.digest(path) for path in
                           [Path(__file__).resolve(), PROJECT / "scripts/validate-model-host.py",
                            PROJECT / "crates/aivm-model-worker/tests/quality.rs", *CORPORA.values(), PROFILE]}}
    for corpus in CORPORA:
        reports = {}
        for style in ("raw", "strict"):
            name = f"{corpus}-{style}"
            evidence = out / f"{name}.json"
            env = dict(os.environ, AIVM_WORKER_HOST_CONFIG=str(copied_config),
                       AIVM_WORKER_QUALITY_EVIDENCE=str(evidence), AIVM_QUALITY_CORPUS=corpus,
                       AIVM_QUALITY_PROMPT_STYLE=style)
            print(f"Running {name}", flush=True)
            started = time.monotonic()
            log_path = out / f"{name}.log"
            with log_path.open("w") as log:
                result = subprocess.run(command, cwd=PROJECT, env=env, stdout=log, stderr=subprocess.STDOUT)
            passed = (result.returncode == 0 and HOST.exact_test_passed(log_path.read_text())
                      and HOST.digest(copied_config) == config_hash
                      and valid_report(evidence, corpus, style, config_hash))
            summary["runs"].append({"name": name, "exit_code": result.returncode,
                                    "infrastructure_passed": passed, "elapsed_seconds": time.monotonic() - started})
            if passed:
                reports[style] = json.loads(evidence.read_text())
            (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        if len(reports) == 2:
            summary["comparisons"][corpus] = compare(reports["raw"], reports["strict"])
    summary["infrastructure_passed"] = all(row["infrastructure_passed"] for row in summary["runs"])
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary["comparisons"], indent=2))
    return 0 if summary["infrastructure_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
