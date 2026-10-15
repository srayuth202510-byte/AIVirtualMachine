#!/usr/bin/env python3
"""Evaluate rules and model suggestions separately against labeled audit fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path)
    args = parser.parse_args()
    cases_dir = PROJECT / "examples/audit-review"
    cases = json.loads((cases_dir / "cases.json").read_text())
    results = []
    for case in cases:
        print("Reviewing " + case["name"] + "...", file=sys.stderr, flush=True)
        path = cases_dir / case["file"]
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        command = [sys.executable, str(PROJECT / "scripts/qwen-audit.py"), str(path)]
        if args.model:
            command += ["--model", str(args.model.resolve())]
        process = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if process.returncode:
            raise RuntimeError(case["name"] + ": " + process.stderr[-1000:])
        report = json.loads(process.stdout)
        assert before == hashlib.sha256(path.read_bytes()).hexdigest(), "input was modified"
        expected = set(case["expected_categories"])
        rules = {row["category"] for row in report["rule_alerts"]}
        model = report["model_review"]
        suggested = {row["category"] for row in model["findings"]}
        valid = model["status"] == "validated_structure"
        results.append({"case": case["name"], "expected": sorted(expected),
                        "rules_exact_match": rules == expected,
                        "model_status": model["status"],
                        "model_exact_match": valid and suggested == expected if args.model else None,
                        "model_missed_categories": sorted(expected - suggested) if args.model else None,
                        "model_extra_categories": sorted(suggested - expected) if args.model else None})
    result = {"cases": results, "rules_passed": sum(row["rules_exact_match"] for row in results),
              "total": len(results),
              "model_passed": sum(row["model_exact_match"] is True for row in results) if args.model else None,
              "scope": "small synthetic fixtures; not a security accuracy benchmark"}
    print(json.dumps(result, indent=2))
    return 0 if all(row["rules_exact_match"] for row in results) and (
        not args.model or all(row["model_exact_match"] for row in results)) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
