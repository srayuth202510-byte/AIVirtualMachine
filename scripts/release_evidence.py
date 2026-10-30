"""Bind source/config/artifact identity and validate canonical task outcomes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROJECT = Path(__file__).resolve().parent.parent
AUDIT_FIELDS = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id", "state", "action", "resource", "decision", "policy", "capability", "result", "rule_matched", "state_transition", "hash_prev"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def decode_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def load(path):
    return decode_json(Path(path).read_text())


def validate_interpretation(trace, case, task):
    prompt = {"bug_report":case["description"], "source":case["buggy"]}
    if (not isinstance(trace, dict) or trace.get("advisory_only") is not True
            or not isinstance(trace.get("system"), str) or not trace["system"]
            or not isinstance(trace.get("prompt"), str) or decode_json(trace["prompt"]) != prompt):
        raise ValueError("interpretation input/advisory transcript missing or changed")
    parsed = trace.get("parsed")
    if parsed is not None:
        if (trace.get("error") is not None or not isinstance(parsed, dict)
                or set(parsed) != {"expected_behavior", "suspected_bug", "planned_change"}
                or any(not isinstance(value, str) or not value.strip() or len(value) > 512 for value in parsed.values())
                or decode_json(trace["raw"]) != parsed):
            raise ValueError("interpretation schema/raw transcript mismatch")
        suffix = "\nYour preliminary task interpretation (untrusted model proposal; verify it against the source and test results): "
        if suffix not in task or decode_json(task.split(suffix, 1)[1]) != parsed:
            raise ValueError("interpretation was not supplied to the repair task")
    elif not isinstance(trace.get("error"), str) or not trace["error"]:
        raise ValueError("missing interpretation failure diagnostic")


def source_identity(project=PROJECT):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=project)
    files = {}
    for raw in sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = project / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular file: {name}")
        files[name] = digest(path)
    return {"commit": git("rev-parse", "HEAD").decode().strip(),
            "clean": not git("status", "--porcelain", "-z"),
            "source_sha256": hashlib.sha256(canonical(files)).hexdigest(), "files": files}


def audit_records(path):
    previous = ""
    records = {}
    for number, line in enumerate(Path(path).read_text().splitlines()):
        row = json.loads(line)
        if (type(row.get("seq")) is not int or row["seq"] != number
                or row.get("hash_version") != 2 or row["hash_prev"] != previous):
            raise ValueError("audit identity/chain mismatch")
        encoded = json.dumps([row[key] for key in AUDIT_FIELDS], ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        actual = hashlib.sha256(encoded).hexdigest()
        if actual != row["hash_entry"]:
            raise ValueError("audit hash mismatch")
        previous = actual
        records[actual] = row
    if not records:
        raise ValueError("empty audit")
    return records


def audited_value(value, records, *, action, rule=None):
    if not isinstance(value, dict) or not isinstance(value.get("audit_id"), str):
        return False
    record = records.get(value["audit_id"])
    if not record or record["action"] != action or (rule and record["rule_matched"] != rule):
        return False
    recorded = json.loads(record["result"])
    return canonical({key: item for key, item in recorded.items() if key != "audit_id"}) == canonical({key: item for key, item in value.items() if key != "audit_id"})


def valid_outcome(outcome, task, receipt, records):
    """ข้อความสรุป/status เก่าไม่มีสิทธิ์ยกระดับผล; ตรวจ start → receipt → outcome."""
    if not isinstance(task, dict) or not isinstance(outcome, dict):
        return False
    if (type(task.get("revision")) is not int or task["revision"] <= 0 or task.get("schema") != 1
            or outcome.get("schema") != 1 or outcome.get("task_id") != task.get("task_id")
            or outcome.get("task_revision") != task["revision"]
            or not audited_value(task, records, action="task", rule="task-start")
            or not audited_value(outcome, records, action="task", rule="task-outcome")):
        return False
    if outcome["verification"] != "passed":
        return not outcome.get("receipt_ids") or all(key in records for key in outcome["receipt_ids"])
    if (outcome.get("execution") != "completed" or not isinstance(receipt, dict)
            or receipt.get("status") != "verified" or type(receipt.get("exit_code")) is not int
            or receipt["exit_code"] != 0 or not audited_value(receipt, records, action="verification")
            or outcome.get("receipt_ids") != [receipt.get("audit_id")]
            or outcome.get("tested_workspace_digest") != f'sha256:{receipt.get("workspace_sha256")}'
            or outcome.get("current_workspace_digest") != outcome["tested_workspace_digest"]):
        return False
    start, proof, end = (records[key]["seq"] for key in (task["audit_id"], receipt["audit_id"], outcome["audit_id"]))
    return (start < proof < end and records[receipt["audit_id"]]["decision"] == "allow"
            and records[task["audit_id"]]["resource"] == records[outcome["audit_id"]]["resource"] == task["task_id"])


def candidate_config(path, artifacts=None):
    config = load(path)
    local = config.get("local")
    if config.get("provider") != "local" or not isinstance(local, dict):
        raise ValueError("release requires a pinned local worker config")
    entries = {"model": (local["model_path"], local["model_sha256"]),
               "worker": (local["worker_path"], local["worker_sha256"])}
    if local.get("controller_path"):
        entries["controller"] = local["controller_path"], local["controller_sha256"]
    for name, (file, pin) in entries.items():
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin) or digest(file) != pin:
            raise ValueError(f"{name}: candidate pin mismatch")
        if artifacts is not None and name in ("model", "worker") and artifacts.get(name, {}).get("sha256") != pin:
            raise ValueError(f"{name}: host validation used another artifact")
    return config


def trace_config(path):
    """ตรวจสอบ pin ของ native trace collector (executable, python, clang) แบบ fail-closed."""
    raw = load(path)
    if not isinstance(raw, dict):
        raise ValueError("trace config must be a JSON object")
    trace = raw.get("repair", {}).get("trace") if isinstance(raw.get("repair"), dict) else raw
    if not isinstance(trace, dict):
        raise ValueError("trace config missing trace block")
    entries = {
        "executable": (trace.get("executable"), trace.get("sha256")),
        "python": (trace.get("python"), trace.get("python_sha256")),
        "clang": (trace.get("clang"), trace.get("clang_sha256")),
    }
    for name, (file, pin) in entries.items():
        if (not isinstance(file, str) or not Path(file).is_absolute()
                or not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin)
                or digest(file) != pin):
            raise ValueError(f"{name}: trace pin mismatch")
    return trace


def validate_benchmark(path, expected_source, config_sha256, *, allow_control=False, experiment_case_ids=None, trace_config_sha256=None):
    report = load(path)
    corpus_path = PROJECT / "examples/repair-benchmark.json"
    corpus = load(corpus_path)
    cases = report["cases"]
    corpus_cases = corpus["cases"]
    experimental = experiment_case_ids is not None
    if experimental:
        if (allow_control or not experiment_case_ids or len(set(experiment_case_ids)) != len(experiment_case_ids)
                or any(case_id not in {case["id"] for case in corpus_cases} for case_id in experiment_case_ids)):
            raise ValueError("invalid interpretation experiment selection")
        corpus_cases = [case for case in corpus_cases if case["id"] in experiment_case_ids]
    if not allow_control and report.get("build_profile") != "release":
        raise ValueError("fresh-model performance evidence requires release profile")
    expected_mode = "interpretation_experiment" if experimental else "reference_control" if allow_control else "fresh_model"
    if (report.get("schema") != (3 if experimental else 2) or report.get("mode") != expected_mode
            or report.get("source_identity") != expected_source
            or report.get("model_config_sha256") != config_sha256
            or report.get("trace_config_sha256") != trace_config_sha256
            or report.get("corpus_sha256") != digest(corpus_path)
            or type(report.get("completed")) is not int or type(report.get("total")) is not int
            or report["completed"] != report["total"] or report["total"] != len(corpus_cases)
            or [row["id"] for row in cases] != [case["id"] for case in corpus_cases]):
        raise ValueError("benchmark identity, mode, source, or completeness mismatch")
    successes, cost = 0, 0
    totals = {"model_calls":0,"patch_retries":0,"reported_input_tokens":0,"reported_output_tokens":0,
              "unreported_usage_calls":0,"client_initialization_ms":0,"inference_ms":0,"sampled_tree_peak_rss_bytes":0}
    for case, row in zip(corpus_cases, cases):
        if (row.get("infrastructure_failure") or row.get("revision") != case["revision"]
                or row.get("baseline_reproduced") is not True or row.get("protected_verifier") is not True
                or row.get("verifier_unchanged") is not True or row.get("reproduction_test_origin") != "operator"
                or (trace_config_sha256 is not None) != isinstance(row.get("effective_config", {}).get("repair", {}).get("trace"), dict)):
            raise ValueError("benchmark case has incomplete reproduction/protection evidence")
        root = Path(path).parent / row["id"]
        if digest(root / "audit.jsonl") != row["audit_sha256"]:
            raise ValueError("benchmark audit file mismatch")
        records = audit_records(root / "audit.jsonl")
        baseline = row["baseline"]
        if (len(baseline) != 4 or any(part.get("ok") is not True for part in baseline[:3])
                or baseline[3].get("ok") is not False):
            raise ValueError("baseline did not compile and reproduce the bug")
        red = baseline[3].get("verification")
        red_files = [("README.md", hashlib.sha256(case["description"].encode()).hexdigest()),
                     ("src/main.c", hashlib.sha256(case["buggy"].encode()).hexdigest()),
                     ("verify.c", hashlib.sha256(case["verifier"].encode()).hexdigest())]
        red_digest = hashlib.sha256(json.dumps(red_files, separators=(",", ":")).encode()).hexdigest()
        if (not audited_value(red, records, action="verification") or red.get("status") != "failed"
                or type(red.get("exit_code")) is not int or red["exit_code"] != 1 or red["workspace_sha256"] != red_digest
                or records[red["audit_id"]]["seq"] >= records[row["task_contract"]["audit_id"]]["seq"]):
            raise ValueError("baseline receipt is missing, stale, or not a reproduced failure")
        if not any(record["action"] == "write" and record["decision"] == "deny" and record["resource"].endswith("/verify.c") for record in records.values()):
            raise ValueError("protected verifier write-denial evidence missing")
        run = row.get("agent_run") or {}
        if experimental:
            validate_interpretation(row.get("task_interpretation"), case, run.get("task", ""))
        receipt = run.get("verification") if not allow_control else row["independent_final_check"][-1].get("verification")
        # reference control มี receipt ของ task ก่อน final independent invocation
        if allow_control:
            ids = row["outcome"]["receipt_ids"]
            if ids and ids[0] not in records:
                raise ValueError("unknown reference-control receipt")
            receipt = json.loads(records[ids[0]]["result"]) if ids else None
            if receipt is not None:
                receipt["audit_id"] = ids[0]
        if not valid_outcome(row["outcome"], row["task_contract"], receipt, records):
            raise ValueError("canonical outcome/audit mismatch")
        origin = "operator_patch" if allow_control else "model_repair"
        successful = (row["outcome"]["execution"] == "completed" and row["outcome"]["verification"] == "passed"
                      and row["outcome"]["solution_origin"] == origin and row.get("source_changed") is True
                      and row.get("patch_oracle_correct") is True)
        if row.get("task_success") is not successful:
            raise ValueError("benchmark score contradicts canonical outcome")
        artifact = row["artifact"]
        patch = root / "patch.diff"
        if (not audited_value(artifact, records, action="artifact", rule="artifact-published")
                or artifact["workspace_digest"] != row["outcome"]["current_workspace_digest"]
                or artifact["task_id"] != row["task_contract"]["task_id"] or artifact["task_revision"] != row["task_contract"]["revision"]
                or artifact["task_digest"] != row["task_contract"]["task_digest"] or artifact["revision"] != 1
                or artifact["kind"] != "patch" or artifact["bytes"] != patch.stat().st_size
                or artifact["content_digest"] != f"sha256:{digest(patch)}"
                or not artifact["evidence_ids"] or any(key not in records for key in artifact["evidence_ids"])):
            raise ValueError("artifact task/revision/hash/evidence mismatch")
        source = root / "source.c"
        expected_files = [("README.md", hashlib.sha256(case["description"].encode()).hexdigest()),
                          ("src/main.c", digest(source)), ("verify.c", hashlib.sha256(case["verifier"].encode()).hexdigest())]
        workspace_digest = "sha256:" + hashlib.sha256(json.dumps(expected_files, separators=(",", ":")).encode()).hexdigest()
        if digest(source) != row["source_sha256"] or row["outcome"]["current_workspace_digest"] != workspace_digest:
            raise ValueError("reviewed source/protected verifier does not match tested workspace")
        elapsed = row["cost"]["total_elapsed_ms"]
        if type(elapsed) is not int or elapsed < 0:
            raise ValueError("invalid task cost")
        successes += successful
        cost += elapsed
        metrics = row["cost"]
        model = metrics["model"]
        fields = {"model_calls":model["calls"], "patch_retries":metrics["patch_retries"],
            "reported_input_tokens":model["input_tokens_reported"],"reported_output_tokens":model["output_tokens_reported"],
            "client_initialization_ms":metrics["client_initialization_ms"],"inference_ms":model["inference_ms"],
            "unreported_usage_calls":model["calls"]-model["usage_reported_calls"]}
        if any(type(value) is not int or value < 0 for value in fields.values()):
            raise ValueError("invalid model usage/cost accounting")
        for key, value in fields.items(): totals[key] += value
        peak = metrics["sampled_tree_peak_rss_bytes"]
        if type(peak) is not int or peak < 0: raise ValueError("invalid RAM observation")
        totals["sampled_tree_peak_rss_bytes"] = max(totals["sampled_tree_peak_rss_bytes"], peak)
    expected_cost = cost / successes if successes else None
    if (type(report.get("task_successes")) is not int or report["task_successes"] != successes
            or report.get("cost_per_success_ms") != expected_cost):
        raise ValueError("aggregate score/cost mismatch")
    totals["total_elapsed_ms"] = cost
    per_success = {key: value/successes if successes else None for key, value in totals.items()
                   if key != "sampled_tree_peak_rss_bytes"}
    return {"successes": successes, "total": len(cases), "cost_per_success_ms": expected_cost,
            "cost_totals":totals,"cost_per_success":per_success,
            "token_totals_complete":totals["unreported_usage_calls"] == 0}
