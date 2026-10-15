#!/usr/bin/env python3
"""Exercise partial writes, a cross-poll burst, and rotation in a real watcher process."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parents[1]
FIELDS = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id", "state",
          "action", "resource", "decision", "policy", "capability", "result", "rule_matched",
          "state_transition", "hash_prev"]


def sealed(row, previous):
    row = {**row, "hash_prev": previous}
    row["hash_entry"] = hashlib.sha256(json.dumps([row[key] for key in FIELDS],
                                      separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return row


def encoded(rows):
    return ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path)
    args = parser.parse_args()
    template = [json.loads(line) for line in (PROJECT / "examples/audit-review/burst.jsonl").read_text().splitlines()]
    rows = []
    previous = ""
    for i, row in enumerate(template):
        if i == 0:
            row.update(resource="/etc/passwd", rule_matched="path-traversal")
        row = sealed(row, previous)
        rows.append(row)
        previous = row["hash_entry"]
    seal = sealed({**rows[-1], "seq": 20, "timestamp": rows[-1]["timestamp"] + 1,
                   "action": "seal", "state": "AUDIT", "decision": "allow", "resource": "audit.jsonl",
                   "rule_matched": "", "result": "tip:" + previous}, previous)
    next_row = sealed({**rows[0], "seq": 0, "timestamp": seal["timestamp"] + 1,
                       "decision": "allow", "resource": "/workspace/src/main.rs",
                       "rule_matched": "outcome", "result": "success"}, seal["hash_entry"])
    reports = []
    with tempfile.TemporaryDirectory(prefix="aivm-watch-smoke-") as directory:
        root = Path(directory)
        source = root / "audit.jsonl"
        archive = root / "audit.old.jsonl"
        source.write_bytes(encoded(rows[:10]))
        command = [sys.executable, str(PROJECT / "scripts/qwen-audit-watch.py"), str(source),
                   "--interval", "0.05", "--model-every", "600"]
        if args.model:
            command += ["--model", str(args.model.resolve())]
        with (root / "stderr.log").open("w+") as errors:
            process = subprocess.Popen(command, cwd=PROJECT, stdout=subprocess.PIPE,
                                       stderr=errors, bufsize=0, start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            buffer = b""
            phase = "initial"
            model_done = args.model is None
            stopped = False
            deadline = time.monotonic() + 300
            try:
                while time.monotonic() < deadline:
                    if not selector.select(timeout=1):
                        if process.poll() is not None:
                            break
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        report = json.loads(line)
                        reports.append(report)
                        if report["type"] == "monitor_error":
                            raise RuntimeError(report["error"])
                        if phase == "initial" and report["type"] == "events":
                            assert report["new_event_ids"] == list(range(10))
                            with source.open("ab") as file:
                                file.write(encoded(rows[10:])[:-20])
                            phase = "partial"
                        elif phase == "partial" and report["type"] == "waiting_for_complete_record":
                            with source.open("ab") as file:
                                file.write(encoded(rows[10:])[-20:])
                            phase = "burst"
                        elif phase == "burst" and any(a["category"] == "deny_burst" for a in report.get("rule_alerts", [])):
                            with source.open("ab") as file:
                                file.write(encoded([seal]))
                            source.rename(archive)
                            source.write_bytes(encoded([next_row]))
                            phase = "rotation"
                        elif phase == "rotation" and report["type"] == "events" and report["generation"] == 1:
                            phase = "done"
                        if report["type"] == "model_review":
                            model_done = True
                        if phase == "done" and model_done and not stopped:
                            process.send_signal(signal.SIGINT)
                            stopped = True
                code = process.wait(timeout=5)
                if code:
                    errors.seek(0)
                    raise RuntimeError("watcher failed: " + errors.read()[-2000:])
                assert phase == "done", "streaming scenario did not finish"
                assert source.read_bytes() == encoded([next_row]), "watcher changed live log"
                assert archive.read_bytes() == encoded(rows + [seal]), "watcher changed archived log"
            finally:
                selector.close()
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                process.stdout.close()
    alerts = [alert for report in reports for alert in report.get("rule_alerts", [])]
    assert [a["category"] for a in alerts].count("boundary_violation") == 1
    assert [a["category"] for a in alerts].count("deny_burst") == 1
    model_results = [row["model_review"] for row in reports if row["type"] == "model_review"]
    result = {"passed": True, "source_unchanged_by_watcher": True,
              "rule_categories": [a["category"] for a in alerts],
              "rotations": sum(row["type"] == "rotation" for row in reports),
              "model_status": model_results[0]["status"] if model_results else "not_requested",
              "reports": reports}
    print(json.dumps(result, indent=2))
    return 0 if not args.model or result["model_status"] == "validated_structure" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
