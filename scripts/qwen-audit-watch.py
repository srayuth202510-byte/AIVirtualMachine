#!/usr/bin/env python3
"""Poll an append-only audit log; emit grounded JSONL alerts without taking action."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
import subprocess
import uuid

spec = importlib.util.spec_from_file_location("audit_reviewer", Path(__file__).with_name("qwen-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
WATCH_ID = uuid.uuid4().hex


class Watcher:
    def __init__(self, path, verify, max_events=32):
        self.path = Path(path)
        self.verify = verify
        self.max_events = max_events
        self.file = None
        self.accepted = b""
        self.file_records = 0
        self.last_record = None
        self.anchor = None
        self.generation = 0
        self.next_id = 0
        self.history = []
        self.history_alerts = []
        self.tracker = audit.RuleTracker()
        self.last_timestamp = None
        self.last_wait = None

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def open(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("audit source must be a regular file")
        self.file = os.fdopen(fd, "rb")

    @staticmethod
    def evidence(row):
        return {"event_id": row["seq"], "generation": row["_generation"],
                "source_seq": row["_source_seq"], "timestamp": row["timestamp"],
                "hash_entry": row["hash_entry"]}

    def waiting(self, kind, **details):
        state = (kind, tuple(details.items()))
        if state != self.last_wait:
            self.last_wait = state
            return [{"type": kind, "generation": self.generation, **details}]
        return []

    def poll(self):
        if self.file is None:
            try:
                self.open()
            except FileNotFoundError:
                yield from self.waiting("waiting_for_log")
                return
        self.file.seek(0)
        raw = self.file.read(audit.MAX_BYTES + 1)
        if len(raw) > audit.MAX_BYTES:
            raise ValueError("per-file 1 MiB limit reached; rotate the audit log")
        complete_at = raw.rfind(b"\n") + 1
        complete, pending = raw[:complete_at], raw[complete_at:]
        if not complete.startswith(self.accepted):
            raise ValueError("processed audit prefix was truncated or rewritten")
        if complete != self.accepted:
            records = audit.load_records(complete)
            self.verify(complete)
            if self.anchor is not None and records[0]["hash_prev"] != self.anchor:
                raise ValueError("rotation chain gap: new file does not continue the prior tip")
            new = records[self.file_records:]
            timestamp = self.last_timestamp
            for row in new:
                if timestamp is not None and row["timestamp"] < timestamp:
                    raise ValueError("audit timestamp regressed; correlation continuity is uncertain")
                timestamp = row["timestamp"]
            mapped = [{**row, "seq": self.next_id + i, "_source_seq": row["seq"],
                       "_generation": self.generation} for i, row in enumerate(new)]
            basis = self.history + mapped
            recent = [row for row in basis if row["timestamp"] >= timestamp - 60]
            if len(recent) > 4096:
                raise ValueError("60-second correlation window exceeds 4096 records")
            alerts = self.tracker.feed(mapped)
            combined_alerts = self.history_alerts + alerts
            events = audit.model_events(basis, combined_alerts)
            selected = events[-self.max_events:]
            evidence_ids = {row["seq"] for row in mapped}
            evidence_ids.update(seq for alert in alerts for seq in alert["event_ids"])
            # Model input also has an exact source reference even if it spans rotation.
            evidence_ids.update(row["id"] for row in selected)
            evidence = [self.evidence(row) for row in basis if row["seq"] in evidence_ids]
            recent_ids = {row["seq"] for row in recent}
            self.history = recent
            self.history_alerts = [alert for alert in combined_alerts
                                   if any(seq in recent_ids for seq in alert["event_ids"])]
            self.accepted = complete
            self.file_records = len(records)
            self.last_record = records[-1]
            self.last_timestamp = timestamp
            self.next_id += len(mapped)
            self.last_wait = None
            yield {"type": "events", "generation": self.generation,
                   "initial_backfill": bool(mapped and mapped[0]["seq"] == 0),
                   "new_event_ids": [row["seq"] for row in mapped],
                   "rule_alerts": alerts, "evidence": evidence,
                   "model_coverage": {"records": len(selected), "context_total": len(basis),
                                      "truncated": len(selected) < len(basis)},
                   "_model_events": selected}
        if pending:
            yield from self.waiting("waiting_for_complete_record", pending_bytes=len(pending))
        try:
            current = self.path.stat()
        except FileNotFoundError:
            yield from self.waiting("waiting_for_log")
            return
        held = os.fstat(self.file.fileno())
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            # A seal can arrive after our read but before the rename. Drain
            # that verified inode next poll instead of reporting a false gap.
            if held.st_size > len(raw):
                return
            if pending:
                raise ValueError("rotation left an incomplete record in the previous file")
            if not self.last_record or not (
                self.last_record["action"] == "seal"
                and self.last_record["state"] == "AUDIT"
                and self.last_record["decision"] == "allow"
                and self.last_record["result"] == "tip:" + self.last_record["hash_prev"]
            ):
                raise ValueError("audit file replaced without a verified rotation seal")
            anchor = self.last_record["hash_entry"]
            self.close()
            self.anchor = anchor
            self.accepted = b""
            self.file_records = 0
            self.last_record = None
            self.generation += 1
            self.last_wait = None
            yield {"type": "rotation", "generation": self.generation,
                   "expected_previous_hash": anchor}
            # The new file is checked on the next poll before processing any event.


def emit(report):
    print(json.dumps({"advisory_only": True, "watch_id": WATCH_ID, **report}, ensure_ascii=False), flush=True)


def model_job(binary, root, model, batch):
    try:
        result = audit.review_with_model(binary, root, model, batch["_model_events"])
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        result = {"status": "unavailable", "advisory_only": True, "findings": [], "error": str(error)}
    new_ids = set(batch["new_event_ids"])
    relevant = [finding for finding in result["findings"] if new_ids.intersection(finding["event_ids"])]
    result["prior_only_findings_omitted"] = len(result["findings"]) - len(relevant)
    result["findings"] = relevant
    return {"type": "model_review", "batch_event_ids": batch["new_event_ids"],
            "evidence": batch["evidence"], "model_coverage": batch["model_coverage"],
            "model_review": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", type=Path)
    parser.add_argument("--model", type=Path, help="Optional local GGUF reviewer")
    parser.add_argument("--interval", type=float, default=2, help="Poll interval, 0.05..60 seconds")
    parser.add_argument("--model-every", type=float, default=30, help="Minimum seconds between model jobs (1..600)")
    parser.add_argument("--max-events", type=int, default=32, choices=range(1, 65), metavar="N")
    parser.add_argument("--polls", type=int, default=0, help="Stop after N polls; 0 watches until Ctrl+C")
    args = parser.parse_args()
    if not 0.05 <= args.interval <= 60 or not 1 <= args.model_every <= 600 or args.polls < 0:
        raise ValueError("invalid interval/model-every/polls")
    model = args.model.resolve(strict=True) if args.model else None
    if model and not model.is_file():
        raise ValueError("model must be a regular GGUF file")
    build = ["cargo", "build", "-q", "-p", "aivm-cli"]
    if model:
        build += ["--features", "llama"]
    subprocess.run(build, cwd=audit.PROJECT, check=True, timeout=600)
    with tempfile.TemporaryDirectory(prefix="aivm-audit-watch-") as directory:
        root = Path(directory)
        binary = root / "aivm"
        shutil.copy2(audit.PROJECT / "target/debug/aivm", binary)
        def verify(raw):
            snapshot = root / "snapshot.jsonl"
            snapshot.write_bytes(raw)
            audit.invoke(binary, root, "verify-audit", str(snapshot))
        watcher = Watcher(args.audit, verify, args.max_events)
        future = None
        last_job = float("-inf")
        status = 0
        emit({"type": "watch_started", "poll_interval": args.interval,
              "memory": "in-process 60-second window; restart replays the current file"})
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                count = 0
                while args.polls == 0 or count < args.polls:
                    if future and future.done():
                        emit(future.result())
                        future = None
                    for batch in watcher.poll():
                        if batch["type"] != "events":
                            emit(batch)
                            continue
                        now = time.monotonic()
                        ready = model and future is None and now - last_job >= args.model_every
                        model_status = ("pending" if ready else "not_requested" if model is None
                                        else "skipped_busy" if future else "skipped_cooldown")
                        emit({key: value for key, value in batch.items() if not key.startswith("_")}
                             | {"model_status": model_status})
                        if ready:
                            future = pool.submit(model_job, binary, root, model, batch)
                            last_job = now
                    count += 1
                    if args.polls == 0 or count < args.polls:
                        time.sleep(args.interval)
            except KeyboardInterrupt:
                emit({"type": "watch_stopped", "reason": "interrupted"})
            except (OSError, ValueError, TypeError, RuntimeError) as error:
                emit({"type": "monitor_error", "error": str(error)})
                status = 2
            finally:
                watcher.close()
            if future:
                emit(future.result())
        return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        emit({"type": "monitor_error", "error": str(error)})
        sys.exit(2)
