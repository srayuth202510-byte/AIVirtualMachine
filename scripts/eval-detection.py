#!/usr/bin/env python3
"""Measure detection errors separately from policy conformance on synthetic scenarios."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

module = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("aivm-supervisor.py"))
sup = importlib.util.module_from_spec(module)
module.loader.exec_module(sup)
audit = sup.watch.audit
PROJECT = Path(__file__).resolve().parents[1]
CORPUS = PROJECT / "examples/detection/cases.json"
BASE_TIME = 1700000000
FIELDS = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id", "state",
          "action", "resource", "decision", "policy", "capability", "result", "rule_matched",
          "state_transition", "hash_prev"]


def file_hash(path):
    result = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def seal(rows, previous="", start=0):
    result = []
    for seq, original in enumerate(rows, start):
        row = {**original, "seq": seq, "hash_prev": previous}
        row["hash_entry"] = sup.digest(json.dumps([row[key] for key in FIELDS],
                                                separators=(",", ":"), ensure_ascii=False).encode())
        previous = row["hash_entry"]
        result.append(row)
    return result


def encode(rows):
    return ("\n".join(json.dumps(row, separators=(",", ":"), ensure_ascii=False) for row in rows) + "\n").encode()


def records(case):
    rows = []
    for group in case["events"]:
        for index in range(group.get("count", 1)):
            rows.append({"hash_version": 2, "seq": len(rows),
                         "timestamp": BASE_TIME + group.get("offset", 0) + index * group.get("interval", 0),
                         "agent": group.get("agent", "test-agent"), "session_id": group.get("session", "test-session"),
                         "request_id": "req_" + str(len(rows)), "state": "INIT", "action": group.get("action", "read"),
                         "resource": group.get("resource", "workspace/src/file.txt"),
                         "decision": group.get("decision", "deny"), "policy": "test-policy", "capability": "",
                         "result": "synthetic", "rule_matched": group.get("rule", "policy-deny"),
                         "state_transition": "", "hash_prev": ""})
    return seal(rows)


class RecordingAdapter:
    """Simulation boundary: record effects, never start a process or contact systemd."""
    def __init__(self):
        self.units, self.effects = {}, []

    def observe(self, instance):
        return self.units.get(instance["id"], "missing")

    def start(self, instance):
        self.units[instance["id"]] = "running"
        self.effects.append("start")

    def stop(self, instance):
        self.units[instance["id"]] = "failed"
        self.effects.append("stop")


def response_test(case, rows, raw, directory, binary):
    spec = {"binary": str(binary), "replicas": 1, "max_replacements": 1,
            "window_seconds": 60, "job_timeout_seconds": 300}
    store = sup.Store(directory, spec)
    adapter = RecordingAdapter()
    evidence = sup.Evidence(directory, spec)
    controller = sup.Controller(store, adapter, evidence, apply=True, now=lambda: BASE_TIME)
    unchanged = True
    reports = []
    def poll():
        nonlocal unchanged
        before = {path.name: file_hash(path) for path in source.parent.glob("audit.jsonl*")}
        reports.extend(controller.reconcile())
        after = {path.name: file_hash(path) for path in source.parent.glob("audit.jsonl*")}
        unchanged = unchanged and before == after
    try:
        with store.locked():
            controller.reconcile()
            instance = store.load()["instances"][0]
            source = directory / "instances" / instance["id"] / "audit.jsonl"
            source.parent.mkdir(parents=True)
            if case.get("completed"):
                adapter.units[instance["id"]] = "completed"
            if case.get("rotate_after"):
                at = case["rotate_after"]
                prefix = rows[:at]
                source.write_bytes(encode(prefix))
                poll()
                closing = {**prefix[-1], "action": "seal", "state": "AUDIT", "decision": "allow",
                           "result": "tip:" + prefix[-1]["hash_entry"], "rule_matched": ""}
                closing = seal([closing], prefix[-1]["hash_entry"], start=at)
                with source.open("ab") as file:
                    file.write(encode(closing))
                poll()
                source.rename(source.with_name("audit.jsonl.1"))
                source.write_bytes(encode(seal(rows[at:], closing[-1]["hash_entry"])))
                poll()  # observe the old sealed inode being replaced
                poll()  # read and correlate the new file
            elif case.get("batches"):
                cursor = 0
                for count in case["batches"]:
                    with source.open("ab") as file:
                        file.write(encode(rows[cursor:cursor + count]))
                    cursor += count
                    poll()
                if cursor != len(rows):
                    raise ValueError("batch sizes do not cover the scenario")
            else:
                source.write_bytes(raw)
                poll()
            instances = store.load()["instances"]
            response = "hold" if instances[0].get("hold") else (
                "replace" if len(instances) > 1 else "none")
            stopped = adapter.effects.count("stop")
            ordered = adapter.effects == (["start", "stop", "start"] if response == "replace" else
                                          ["start", "stop"] if response == "hold" else ["start"])
            return {"actual": response, "expected": case["response"], "effects": adapter.effects,
                    "matches_policy": response == case["response"] and ordered,
                    "source_unchanged": unchanged, "stopped_instances": stopped,
                    "blocked_reports": [row for row in reports if row["action"] == "blocked"]}
    finally:
        evidence.close()


def confusion(pairs):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "abstained_positive": 0, "abstained_negative": 0}
    for expected, predicted in pairs:
        if predicted is None:
            counts["abstained_positive" if expected else "abstained_negative"] += 1
        else:
            counts[("tp" if predicted else "fn") if expected else ("fp" if predicted else "tn")] += 1
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None
    return {**counts, "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": ratio(counts["tp"], counts["tp"] + counts["fn"] + counts["abstained_positive"]),
            "false_positive_rate": ratio(counts["fp"], counts["fp"] + counts["tn"]),
            "classified_fraction": ratio(counts["tp"] + counts["fp"] + counts["tn"] + counts["fn"], len(pairs)),
            "evaluated": len(pairs)}


def evaluate(binary, model=None, model_limit=8, corpus=CORPUS):
    provenance = {"corpus_sha256": file_hash(corpus), "evaluator_sha256": file_hash(Path(__file__)),
                  "binary_sha256": file_hash(binary), "model_sha256": file_hash(model) if model else None,
                  "detector_sources": {name: file_hash(Path(__file__).with_name(name))
                                       for name in ["qwen-audit.py", "qwen-audit-watch.py", "aivm-supervisor.py"]},
                  "python_version": sys.version,
                  "model_settings": {"seed": 42, "temperature": 0, "top_k": 1, "ctx_size": 8192,
                                     "max_tokens": 768, "max_attempts": 2, "threads": 4} if model else None}
    dataset = audit.decode(corpus.read_text())
    if dataset["schema"] != 1 or len({case["id"] for case in dataset["cases"]}) != len(dataset["cases"]):
        raise ValueError("invalid scenario schema or duplicate IDs")
    results, normalized, model_jobs = [], {}, 0
    with tempfile.TemporaryDirectory(prefix="aivm-detection-") as temporary:
        root = Path(temporary)
        for index, case in enumerate(dataset["cases"]):
            print("Evaluating " + case["id"], file=sys.stderr, flush=True)
            rows = records(case)
            raw = encode(rows)
            if case.get("corruption") == "hash":
                raw = raw.replace(b"workspace/src/file.txt", b"workspace/src/tampered.txt", 1)
            elif case.get("corruption") == "partial":
                raw = raw[:-1]
            source = root / "snapshot.jsonl"
            source.write_bytes(raw)
            verified = subprocess.run([str(binary), "verify-audit", str(source)],
                                      capture_output=True, timeout=30).returncode == 0
            alerts = audit.inspect_records(rows) if verified and case["categories"] is not None else []
            categories = sorted({alert["category"] for alert in alerts})
            response = response_test(case, rows, raw, root / str(index), binary)
            result = {"id": case["id"], "label": case["label"], "description": case["description"],
                      "source_sha256": sup.digest(raw), "snapshot_chain_verified": verified,
                      "rule_categories": categories if case["categories"] is not None else None,
                      "expected_categories": case["categories"],
                      "rules_match_policy": categories == sorted(case["categories"]) if case["categories"] is not None else None,
                      "response": response, "limitation": case.get("limitation"), "model": {"status": "not_requested"}}
            if case["categories"] is not None:
                events = audit.model_events(rows, alerts)
                normalized.setdefault(sup.digest(sup.canonical(events).encode()), []).append(
                    {"id": case["id"], "label": case["label"]})
                if model and model_jobs < model_limit:
                    model_jobs += 1
                    try:
                        review = audit.review_with_model(binary, root, model, events[-32:])
                        valid = review["status"] == "validated_structure"
                        suggested = sorted({finding["category"] for finding in review["findings"]})
                        result["model"] = {"status": review["status"], "categories": suggested,
                                           "findings": review["findings"], "retry_count": len(review["attempts"]),
                                           "records": min(32, len(events)), "total_records": len(events),
                                           "matches_category_labels": valid and suggested == sorted(case["categories"])}
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                        result["model"] = {"status": "unavailable", "error": str(error)}
            results.append(result)
    labeled = [row for row in results if row["label"] in {"attack", "benign"}]
    reviewed = [row for row in labeled if row["model"]["status"] != "not_requested"]
    failures = [row["id"] for row in results if row["rules_match_policy"] is False
                or not row["response"]["matches_policy"] or not row["response"]["source_unchanged"]]
    return {"scope": "synthetic labeled scenarios; not exploit detection accuracy on real-world traffic",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "provenance": provenance,
            "execution": "real Rust audit verification and real supervisor; runtime effects use RecordingAdapter only",
            "cases": results, "total": len(results), "policy_regressions": failures,
            "rules_risk_metrics": confusion([(row["label"] == "attack", bool(row["rule_categories"])) for row in labeled]),
            "containment_risk_metrics": confusion([(row["label"] == "attack", row["response"]["actual"] == "replace") for row in labeled]),
            "model_risk_metrics": confusion([(row["label"] == "attack", bool(row["model"].get("categories"))
                                              if row["model"]["status"] == "validated_structure" else None) for row in reviewed]),
            "model_coverage": {"reviewed": len(reviewed), "eligible": len(labeled), "limit": model_limit,
                               "unreviewed_case_ids": [row["id"] for row in labeled if row["model"]["status"] == "not_requested"]},
            "indistinguishable_normalized_inputs": [group for group in normalized.values()
                                                    if len({row["label"] for row in group}) > 1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS, help="Labeled evaluation corpus; keep holdout separate from rule tuning")
    parser.add_argument("--model", type=Path, help="Optional real local GGUF; never given tools")
    parser.add_argument("--model-limit", type=int, default=8, help="Review first N eligible cases, 1..100 (default 8)")
    parser.add_argument("--output", type=Path, help="Also save the complete report as JSON")
    args = parser.parse_args()
    if not 1 <= args.model_limit <= 100:
        raise ValueError("model-limit must be 1..100")
    model = args.model.resolve(strict=True) if args.model else None
    build = ["cargo", "build", "-q", "-p", "aivm-cli"] + (["--features", "llama"] if model else [])
    subprocess.run(build, cwd=PROJECT, check=True, timeout=600)
    with tempfile.TemporaryDirectory(prefix="aivm-detection-bin-") as temporary:
        binary = Path(temporary) / "aivm"
        shutil.copy2(PROJECT / "target/debug/aivm", binary)
        report = evaluate(binary, model, args.model_limit, args.corpus.resolve(strict=True))
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(output, end="")
    return 1 if report["policy_regressions"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
