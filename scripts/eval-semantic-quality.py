#!/usr/bin/env python3
"""Evaluate protected semantic verification; distinguish recorded candidates from fresh inference."""
import argparse
import hashlib
import json
import release_evidence
import os
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parent.parent
CORPUS = PROJECT / "examples/semantic-quality.json"
AUDIT_FIELDS = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id",
                "state", "action", "resource", "decision", "policy", "capability", "result",
                "rule_matched", "state_transition", "hash_prev"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(raw):
    # ปฏิเสธ JSON types ที่ Python ยอมรับแต่ Rust/Serde ไม่รับ
    value = json.loads(raw)
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def task_correct(task, raw):
    try:
        value = decode(raw)
        integer = lambda x: type(x) is int and -(2**31) <= x < 2**31
        if task["kind"] == "sort":
            return (isinstance(value, list) and all(integer(x) for x in value)
                    and value == sorted(task["values"]))
        result = task["left"] + task["right"]
        return integer(result) and integer(value) and value == result
    except (ValueError, TypeError, UnicodeError):
        return False


def schema_valid(task, raw):
    try:
        if len(raw.encode()) > 4096:
            return False
        value = decode(raw)
        integer = lambda x: type(x) is int and -(2**31) <= x < 2**31
        return (isinstance(value, list) and len(value) <= 64 and all(integer(x) for x in value)
                if task["kind"] == "sort" else integer(value))
    except (ValueError, TypeError, UnicodeError, AttributeError):
        return False


def same_json(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(right, sort_keys=True, separators=(",", ":"))


def audit_records(path):
    previous = ""
    records = {}
    for number, line in enumerate(path.read_text().splitlines()):
        record = json.loads(line)
        if record.get("hash_version") != 2 or record["seq"] != number or record["hash_prev"] != previous:
            raise ValueError("invalid audit identity/chain")
        canonical = json.dumps([record[key] for key in AUDIT_FIELDS], ensure_ascii=False, separators=(",", ":"))
        actual = hashlib.sha256(canonical.encode()).hexdigest()
        if actual != record["hash_entry"]:
            raise ValueError("invalid audit digest")
        previous = actual
        records[actual] = record
    if not records:
        raise ValueError("empty audit")
    return records


def valid_receipt(receipt, records):
    if (not isinstance(receipt, dict) or receipt.get("status") != "verified"
            or type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0):
        return False
    record = records.get(receipt.get("audit_id"))
    if not record or record["action"] != "verification" or record["decision"] != "allow":
        return False
    # audit บันทึก receipt ก่อนใส่ audit_id ของ entry นั้น; เปรียบเทียบเนื้อหาที่เหลือครบ
    recorded = json.loads(record["result"])
    return all(recorded.get(key) == value for key, value in receipt.items() if key != "audit_id")


def validate_report(path, mode, config_hash=None):
    try:
        report = json.loads(path.read_text())
        corpus = json.loads(CORPUS.read_text())
        cases = corpus["cases"]
        if (report.get("schema") != 1 or report.get("mode") != mode
                or type(report.get("first_correct")) is not int or type(report.get("assisted_correct")) is not int
                or report.get("corpus_sha256") != digest(CORPUS)
                or report.get("model_config_sha256") != config_hash
                or report.get("completed") != len(cases) or report.get("total") != len(cases)
                or len(report.get("cases", [])) != len(cases)):
            return False
        first_scores, final_scores = [], []
        for case, row in zip(cases, report["cases"]):
            run = row["run"]
            expected_origin = "fresh_model" if mode == "fresh_model" else case["candidate_origin"]
            if (row["id"] != case["id"] or not same_json(row["task"], case["task"]) or not same_json(run["task"], case["task"])
                    or row["prompt"] != case["prompt"] or row["candidate_origin"] != expected_origin
                    or not run["attempts"] or run["attempts"][0]["prompt"] != case["prompt"]):
                return False
            initial = run["attempts"][0].get("output")
            if mode == "replay" and initial != case["initial_candidate"]:
                return False
            first = task_correct(case["task"], initial)
            if row["first_correct"] is not first or run["attempts"][0]["task_correct"] is not first:
                return False
            for attempt in run["attempts"]:
                raw = attempt.get("output")
                try:
                    decode(raw)
                    format_valid = True
                except (ValueError, TypeError, UnicodeError):
                    format_valid = False
                if (attempt["task_correct"] is not task_correct(case["task"], raw)
                        or attempt["format_valid"] is not format_valid
                        or attempt["schema_valid"] is not schema_valid(case["task"], raw)
                        or attempt.get("infrastructure_status") not in ("completed", "output_rejected", "model_error")
                        or (mode == "fresh_model" and attempt["infrastructure_status"] == "model_error")
                        or (raw is not None and attempt["infrastructure_status"] != "completed")):
                    return False
            audit_name = row["audit_file"]
            if audit_name != f'{case["id"]}.audit.jsonl' or Path(audit_name).name != audit_name:
                return False
            audit = path.parent / audit_name
            if digest(audit) != row["audit_sha256"]:
                return False
            records = audit_records(audit)
            if not release_evidence.valid_outcome(run.get("outcome"), run.get("task_contract"), run.get("verification"), records):
                return False
            correct = task_correct(case["task"], run.get("output"))
            if (not correct or row["assisted_correct"] is not True or run["status"] != "verified"
                    or run["termination"] != "verified" or not valid_receipt(run.get("verification"), records)):
                return False
            final = run["verification"]
            if not any(action.get("verification") == final and action["phase"] == "semantic_verifier" and action["ok"] for action in run["actions"]):
                return False
            origin = run.get("origin")
            expected_origin = {"tool_solver":"tool_solver", "model_with_verifier":"model", "model_repair_with_verifier":"model_repair"}.get(origin)
            if run["outcome"].get("solution_origin") != expected_origin or run["outcome"].get("verification") != "passed":
                return False
            if origin == "tool_solver":
                if not any(action["phase"] == "tool_solver" and valid_receipt(action.get("verification"), records) for action in run["actions"]):
                    return False
            elif origin == "model_with_verifier":
                if not first or len(run["attempts"]) != 1:
                    return False
            elif origin == "model_repair_with_verifier":
                if len(run["attempts"]) < 2 or not run["attempts"][-1]["task_correct"]:
                    return False
            else:
                return False
            for action in run["actions"]:
                receipt = action.get("verification")
                if receipt and receipt["status"] == "verified" and not valid_receipt(receipt, records):
                    return False
            expected = json.dumps(case["expected"], separators=(",", ":"))
            if not task_correct(case["task"], expected):
                return False
            first_scores.append(first)
            final_scores.append(correct)
        return report["first_correct"] == sum(first_scores) and report["assisted_correct"] == sum(final_scores)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--config", type=Path, help="Pinned worker config; omit for recorded/probe replay")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, mode=0o700)
    env = dict(os.environ, AIVM_SEMANTIC_EVIDENCE=str(out))
    mode, config_hash = "replay", None
    test = "semantic_quality_replay"
    if args.config:
        config = args.config.resolve(strict=True)
        config_hash = digest(config)
        env["AIVM_WORKER_HOST_CONFIG"] = str(config)
        mode, test = "fresh_model", "real_model_semantic_quality"
    command = ["cargo", "test", "--locked", "-p", "aivm-runtime", "--test", "coding_workflow", test,
               "--", "--exact", "--nocapture"]
    if args.config:
        command.append("--ignored")
    sources = [Path(__file__).resolve(), PROJECT / "crates/aivm-runtime/src/semantic.rs",
               PROJECT / "crates/aivm-runtime/src/lib.rs", PROJECT / "Cargo.lock",
               PROJECT / "crates/aivm-runtime/tests/coding_workflow.rs", CORPUS]
    source_hashes = {str(path.relative_to(PROJECT)): digest(path) for path in sources}
    with (out / "test.log").open("w") as log:
        process = subprocess.run(command, cwd=PROJECT, env=env, stdout=log, stderr=subprocess.STDOUT)
    evidence = out / "evidence.json"
    valid = (process.returncode == 0 and "1 passed; 0 failed; 0 ignored;" in (out / "test.log").read_text()
             and validate_report(evidence, mode, config_hash)
             and (not args.config or digest(args.config) == config_hash)
             and all(digest(path) == source_hashes[str(path.relative_to(PROJECT))] for path in sources))
    summary = {"schema": 1, "mode": mode, "passed": valid, "exit_code": process.returncode,
               "command": command, "corpus_sha256": digest(CORPUS), "config_sha256": config_hash,
               "sources": source_hashes}
    if valid:
        report = json.loads(evidence.read_text())
        summary["groups"] = {origin: {"total": len(rows), "first_correct": sum(row["first_correct"] for row in rows),
                                      "assisted_correct": sum(row["assisted_correct"] for row in rows)}
                             for origin in sorted({row["candidate_origin"] for row in report["cases"]})
                             for rows in [[row for row in report["cases"] if row["candidate_origin"] == origin]]}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"passed": valid, "mode": mode, "groups": summary.get("groups", {})}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
