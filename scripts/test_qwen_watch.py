"""Streaming behavior tests; cryptographic verification is covered by CLI smoke."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("qwen_watch", Path(__file__).with_name("qwen-audit-watch.py"))
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
FIXTURES = Path(__file__).resolve().parents[1] / "examples/audit-review"


def seal(row, previous=""):
    row = {**row, "hash_prev": previous}
    fields = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id",
              "state", "action", "resource", "decision", "policy", "capability", "result",
              "rule_matched", "state_transition", "hash_prev"]
    row["hash_entry"] = hashlib.sha256(json.dumps([row[key] for key in fields],
                                      separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return row


def encode(rows):
    return ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode()


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "audit.jsonl"
        self.verified = []
        self.watcher = watch.Watcher(self.path, self.verified.append)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.watcher.close)

    def rows(self):
        return watch.audit.load_records((FIXTURES / "burst.jsonl").read_bytes())

    def batches(self):
        return [row for row in self.watcher.poll() if row["type"] == "events"]

    def test_partial_record_waits_and_idle_does_not_repeat_alerts(self):
        raw = (FIXTURES / "boundary.jsonl").read_bytes()
        self.path.write_bytes(raw[:-1])
        self.assertEqual(list(self.watcher.poll())[0]["type"], "waiting_for_complete_record")
        self.assertEqual(self.verified, [])
        with self.path.open("ab") as file:
            file.write(b"\n")
        batch = self.batches()[0]
        self.assertEqual(batch["rule_alerts"][0]["category"], "boundary_violation")
        self.assertEqual(batch["evidence"][0]["source_seq"], 0)
        self.assertEqual(list(self.watcher.poll()), [])
        self.assertEqual(len(self.verified), 1)

    def test_deny_burst_spans_polls_and_is_not_rearmed_on_every_append(self):
        rows = self.rows()
        self.path.write_bytes(encode(rows[:10]))
        self.assertEqual(self.batches()[0]["rule_alerts"], [])
        with self.path.open("ab") as file:
            file.write(encode(rows[10:]))
        alerts = self.batches()[0]["rule_alerts"]
        self.assertEqual(alerts[0]["category"], "deny_burst")
        self.assertEqual(alerts[0]["event_ids"], list(range(20)))
        next_row = seal({**rows[-1], "seq": 20, "timestamp": rows[-1]["timestamp"] + 1}, rows[-1]["hash_entry"])
        with self.path.open("ab") as file:
            file.write(encode([next_row]))
        self.assertEqual(self.batches()[0]["rule_alerts"], [])

    def test_rotation_keeps_window_and_disambiguates_source_sequence(self):
        rows = self.rows()
        self.path.write_bytes(encode(rows[:10]))
        self.batches()
        sealing = seal({**rows[10], "seq": 10, "action": "seal", "state": "AUDIT",
                        "decision": "allow", "result": "tip:" + rows[9]["hash_entry"]}, rows[9]["hash_entry"])
        with self.path.open("ab") as file:
            file.write(encode([sealing]))
        self.path.rename(self.path.with_name("audit.old.jsonl"))
        rotated = []
        previous = sealing["hash_entry"]
        for i in range(10):
            row = seal({**rows[i], "seq": i, "timestamp": sealing["timestamp"] + 1 + i}, previous)
            rotated.append(row)
            previous = row["hash_entry"]
        self.path.write_bytes(encode(rotated))
        reports = list(self.watcher.poll())
        self.assertEqual(reports[-1]["type"], "rotation")
        batch = self.batches()[0]
        self.assertEqual(batch["rule_alerts"][0]["category"], "deny_burst")
        self.assertEqual(len(set(batch["rule_alerts"][0]["event_ids"])), 20)
        seq_zero = [row for row in batch["evidence"] if row["source_seq"] == 0]
        self.assertEqual({row["generation"] for row in seq_zero}, {0, 1})

    def test_truncation_rewrite_and_unsealed_replacement_stop_monitor(self):
        raw = (FIXTURES / "boundary.jsonl").read_bytes()
        self.path.write_bytes(raw)
        self.batches()
        self.path.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "truncated or rewritten"):
            list(self.watcher.poll())
        self.path.write_bytes(raw.replace(b"/etc/passwd", b"/etc/shadow"))
        with self.assertRaisesRegex(ValueError, "truncated or rewritten"):
            list(self.watcher.poll())
        self.path.write_bytes(raw)
        self.path.rename(self.path.with_name("old.jsonl"))
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "without a verified rotation seal"):
            list(self.watcher.poll())

    def test_rotation_chain_gap_is_rejected(self):
        row = self.rows()[0]
        row = seal({**row, "action": "seal", "state": "AUDIT", "decision": "allow", "result": "tip:"})
        self.path.write_bytes(encode([row]))
        self.batches()
        self.path.rename(self.path.with_name("old.jsonl"))
        self.path.write_bytes(encode([self.rows()[0]]))
        list(self.watcher.poll())
        with self.assertRaisesRegex(ValueError, "rotation chain gap"):
            list(self.watcher.poll())

    def test_seal_arriving_between_read_and_rotation_check_is_drained(self):
        row = self.rows()[0]
        self.path.write_bytes(encode([row]))
        sealing = seal({**row, "seq": 1, "timestamp": row["timestamp"] + 1,
                        "action": "seal", "state": "AUDIT", "decision": "allow",
                        "result": "tip:" + row["hash_entry"]}, row["hash_entry"])
        next_row = seal({**row, "timestamp": row["timestamp"] + 2}, sealing["hash_entry"])
        def rotate_after_read(raw):
            self.watcher.verify = self.verified.append
            with self.path.open("ab") as file:
                file.write(encode([sealing]))
            self.path.rename(self.path.with_name("old.jsonl"))
            self.path.write_bytes(encode([next_row]))
        self.watcher.verify = rotate_after_read
        first = list(self.watcher.poll())
        self.assertEqual([row["type"] for row in first], ["events"])
        second = list(self.watcher.poll())
        self.assertEqual(second[-1]["type"], "rotation")
        self.assertEqual(self.batches()[0]["generation"], 1)

    def test_missing_source_and_capacity_limits_are_explicit(self):
        self.assertEqual(list(self.watcher.poll())[0]["type"], "waiting_for_log")
        self.path.write_bytes(b"x" * (watch.audit.MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "1 MiB limit"):
            list(self.watcher.poll())

    def test_action_named_seal_is_not_enough_to_accept_replacement(self):
        row = seal({**self.rows()[0], "action": "seal", "decision": "allow"})
        self.path.write_bytes(encode([row]))
        self.batches()
        self.path.rename(self.path.with_name("old.jsonl"))
        self.path.write_bytes(encode([row]))
        with self.assertRaisesRegex(ValueError, "without a verified rotation seal"):
            list(self.watcher.poll())

    def test_failed_verification_never_advances_cursor(self):
        self.path.write_bytes((FIXTURES / "boundary.jsonl").read_bytes())
        def fail(raw):
            raise RuntimeError("hash mismatch")
        self.watcher.verify = fail
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            list(self.watcher.poll())
        self.assertEqual(self.watcher.next_id, 0)
        self.assertEqual(self.watcher.accepted, b"")

    def test_clock_regression_is_not_silently_correlated(self):
        rows = self.rows()
        self.path.write_bytes(encode(rows[:1]))
        self.batches()
        with self.path.open("ab") as file:
            file.write(encode([seal({**rows[1], "timestamp": rows[0]["timestamp"] - 1}, rows[0]["hash_entry"])]))
        with self.assertRaisesRegex(ValueError, "timestamp regressed"):
            list(self.watcher.poll())


if __name__ == "__main__":
    unittest.main()
