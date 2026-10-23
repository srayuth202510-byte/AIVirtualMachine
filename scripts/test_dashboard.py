"""Dashboard regression checks: retained audit data and real HTTP responses."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("aivm_dashboard", Path(__file__).with_name("aivm-dashboard.py"))
DASHBOARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DASHBOARD)


class Socket:
    def __init__(self, path):
        self.input = io.BytesIO(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        self.output = bytearray()

    def makefile(self, *args):
        return self.input

    def sendall(self, data):
        self.output.extend(data)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "audit.jsonl"
        self.database = self.root / "private/events.db"
        self.store = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(self.store.close)

    def record(self, seq, **extra):
        return dict(timestamp=1700000000 + seq, action="read", resource=f"file-{seq}",
                    decision="deny", result="policy denied", **extra)

    def write(self, records):
        self.log.write_text("".join(json.dumps(record) + "\n" for record in records))

    def request(self, path):
        server = type("Server", (), {"store": self.store})()
        connection = Socket(path)
        with patch.object(DASHBOARD.DashboardHandler, "log_message"):
            DASHBOARD.DashboardHandler(connection, ("127.0.0.1", 1000), server)
        header, body = bytes(connection.output).split(b"\r\n\r\n", 1)
        return header.decode(), body

    def test_retention_deduplication_private_storage_and_read_only_source(self):
        self.write([self.record(index) for index in range(8)])
        before = hashlib.sha256(self.log.read_bytes()).hexdigest()
        self.store.sync()
        self.store.sync()
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["total"], 3)
        self.assertEqual([entry["path"] for entry in snapshot["entries"]], ["file-7", "file-6", "file-5"])
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(hashlib.sha256(self.log.read_bytes()).hexdigest(), before)
        self.log.unlink()
        self.store.sync()
        self.assertFalse(self.store.snapshot()["audit_read_success"])
        self.assertEqual(self.store.snapshot()["total"], 3)

    def test_deny_is_not_lost_between_polls_when_allow_traffic_exceeds_retention(self):
        self.write([])
        self.store.sync()
        records = [self.record(1)]
        for index in range(2, 12):
            record = self.record(index)
            record.update(decision="allow", result="success")
            records.append(record)
        self.write(records)
        self.store.sync()
        snapshot = self.store.snapshot()
        self.assertEqual([entry["path"] for entry in snapshot["entries"]], ["file-1"])
        self.assertTrue(snapshot["coverage_complete"])

    def test_byte_budget_resumes_at_cursor_and_reports_backlog_and_partial_writes(self):
        self.write([self.record(index) for index in range(8)])
        with patch.object(DASHBOARD, "MAX_AUDIT_BYTES", 300):
            self.store.sync()
            self.assertGreater(self.store.snapshot()["backlog_bytes"], 0)
            self.assertFalse(self.store.snapshot()["coverage_complete"])
            for _ in range(12):
                self.store.sync()
        self.assertEqual([entry["path"] for entry in self.store.snapshot()["entries"]],
                         ["file-7", "file-6", "file-5"])
        self.assertTrue(self.store.snapshot()["coverage_complete"])
        line = json.dumps(self.record(8)).encode()
        with self.log.open("ab") as output:
            output.write(line[:30])
        self.store.sync()
        self.assertGreater(self.store.snapshot()["pending_bytes"], 0)
        with self.log.open("ab") as output:
            output.write(line[30:] + b"\n")
        self.store.sync()
        self.assertEqual(self.store.snapshot()["entries"][0]["path"], "file-8")
        self.assertTrue(self.store.snapshot()["coverage_complete"])

    def test_rotation_drains_held_inode_and_checks_continuity(self):
        first = self.record(1, hash_prev="", hash_entry="first")
        self.write([first])
        self.store.sync()
        seal = self.record(2, hash_prev="first", hash_entry="seal")
        seal.update(action="seal", decision="allow", result="tip:first")
        with self.log.open("a") as output:
            output.write(json.dumps(self.record(3)) + "\n" + json.dumps(seal) + "\n")
        archive = self.log.with_suffix(".old")
        self.log.rename(archive)
        self.write([self.record(4, hash_prev="seal", hash_entry="next")])
        self.store.sync()
        self.assertIn("file-3", [entry["path"] for entry in self.store.snapshot()["entries"]])
        self.assertFalse(self.store.snapshot()["coverage_complete"])
        self.store.sync()
        self.assertEqual(self.store.snapshot()["entries"][0]["path"], "file-4")
        self.assertTrue(self.store.snapshot()["coverage_complete"])
        # ข้าม archive หนึ่งช่วงต้องไม่รายงาน coverage ว่าครบ
        self.log.rename(self.log.with_suffix(".next"))
        self.write([self.record(5, hash_prev="unseen-seal", hash_entry="last")])
        self.store.sync()
        self.store.sync()
        self.assertGreater(self.store.snapshot()["coverage_gaps"], 0)
        self.assertFalse(self.store.snapshot()["coverage_complete"])

    def test_same_inode_rewrite_reports_gap_and_imports_available_records(self):
        self.write([self.record(1), self.record(2)])
        self.store.sync()
        self.write([self.record(3)])
        self.store.sync()
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["entries"][0]["path"], "file-3")
        self.assertGreater(snapshot["coverage_gaps"], 0)
        self.assertFalse(snapshot["coverage_complete"])

    def test_import_failure_rolls_back_cursor_before_retry(self):
        self.write([self.record(1), self.record(2)])
        ingest = self.store._ingest
        calls = 0
        def fail_second(line):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.OperationalError("database is locked")
            ingest(line)
        with patch.object(self.store, "_ingest", side_effect=fail_second):
            self.store.sync()
        self.assertFalse(self.store.snapshot()["audit_read_success"])
        self.assertEqual(self.store.snapshot()["total"], 0)
        self.store.sync()
        self.assertEqual(self.store.snapshot()["total"], 2)
        self.assertTrue(self.store.snapshot()["coverage_complete"])

    def test_restart_preserves_latest_retention_and_committed_cursor(self):
        self.write([self.record(index) for index in range(8)])
        self.store.sync()
        before = self.store.snapshot()["entries"]
        reopened = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(reopened.close)
        reopened.sync()
        self.assertEqual(reopened.snapshot()["entries"], before)
        self.assertTrue(reopened.snapshot()["coverage_complete"])
        with self.log.open("a") as output:
            output.write(json.dumps(self.record(8)) + "\n")
        reopened.sync()
        self.assertEqual([row["path"] for row in reopened.snapshot()["entries"]],
                         ["file-8", "file-7", "file-6"])

    def test_backfill_of_an_existing_database_without_cursor_preserves_source_order(self):
        self.write([self.record(index) for index in range(8)])
        self.store.sync()
        expected = self.store.snapshot()["entries"]
        # จำลอง DB รุ่นเดิมที่เก็บ events แล้วแต่ยังไม่มี persistent cursor
        with self.store.conn:
            self.store.conn.execute("DELETE FROM import_cursors")
        migrated = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(migrated.close)
        migrated.sync()
        self.assertEqual(migrated.snapshot()["entries"], expected)

    def test_cursor_write_failure_rolls_back_events_before_restart(self):
        self.write([self.record(index) for index in range(8)])
        with patch.object(self.store, "_save_cursor", side_effect=sqlite3.OperationalError("disk full")):
            self.store.sync()
        self.assertFalse(self.store.snapshot()["audit_read_success"])
        self.assertEqual(self.store.snapshot()["total"], 0)
        reopened = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(reopened.close)
        reopened.sync()
        self.assertEqual([row["path"] for row in reopened.snapshot()["entries"]],
                         ["file-7", "file-6", "file-5"])
        self.assertTrue(reopened.snapshot()["coverage_complete"])

    def test_restart_follows_saved_seal_and_reports_an_unobserved_rotation(self):
        self.write([self.record(1, hash_prev="", hash_entry="first")])
        self.store.sync()
        seal = self.record(2, hash_prev="first", hash_entry="seal")
        seal.update(action="seal", decision="allow", result="tip:first")
        with self.log.open("a") as output:
            output.write(json.dumps(seal) + "\n")
        self.store.sync()
        self.log.rename(self.log.with_suffix(".old"))
        self.write([self.record(3, hash_prev="seal", hash_entry="current")])
        resumed = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(resumed.close)
        resumed.sync()
        self.assertTrue(resumed.snapshot()["coverage_complete"])
        self.log.rename(self.log.with_suffix(".next"))
        self.write([self.record(4, hash_prev="unseen-seal", hash_entry="latest")])
        missed = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(missed.close)
        missed.sync()
        self.assertFalse(missed.snapshot()["coverage_complete"])
        self.assertGreater(missed.snapshot()["coverage_gaps"], 0)
        again = DASHBOARD.EventStore(self.database, self.log, max_entries=3)
        self.addCleanup(again.close)
        again.sync()
        self.assertEqual(again.snapshot()["coverage_gaps"], missed.snapshot()["coverage_gaps"])
        self.assertFalse(again.snapshot()["coverage_complete"])

    def test_rotation_with_backlog_does_not_skip_budget_split_records(self):
        self.write([])
        self.store.sync()  # เปิด inode เก่าก่อน rotate
        records = [self.record(index) for index in range(1, 9)]
        seal = self.record(9, hash_entry="seal", hash_prev="previous")
        seal.update(action="seal", decision="allow", result="tip:previous")
        with self.log.open("a") as output:
            output.writelines(json.dumps(record) + "\n" for record in records + [seal])
        self.log.rename(self.log.with_suffix(".old"))
        self.write([self.record(10, hash_prev="seal", hash_entry="current")])
        with patch.object(DASHBOARD, "MAX_AUDIT_BYTES", 300):
            for _ in range(16):
                self.store.sync()
        snapshot = self.store.snapshot()
        self.assertEqual([entry["path"] for entry in snapshot["entries"]],
                         ["file-10", "file-8", "file-7"])
        self.assertTrue(snapshot["coverage_complete"])

    def test_malformed_partial_and_oversized_lines_cannot_crash_or_inject_fragments(self):
        self.log.write_text('[]\nnull\n{"timestamp":"bad"}\n{"timestamp":NaN}\n')
        self.store.sync()
        self.assertEqual(self.store.snapshot()["total"], 0)
        valid = json.dumps(self.record(1)).encode()
        self.log.write_bytes(b"x" * (DASHBOARD.MAX_LINE_BYTES + 1) + valid + b"\n" + valid)
        self.store.sync()
        self.assertEqual(self.store.snapshot()["total"], 0)
        with self.log.open("ab") as output:
            output.write(b"\n")
        self.store.sync()
        self.assertEqual(self.store.snapshot()["total"], 1)
        large_timestamp = self.record(2)
        large_timestamp["timestamp"] = 10 ** 100
        self.write([large_timestamp])
        self.store.sync()
        self.assertEqual(self.store.snapshot()["total"], 2)

    def test_http_html_escapes_every_audit_field_and_routes_are_explicit(self):
        record = self.record(1)
        record.update(action='<script>alert("category")</script>', resource="<img src=x>", result="<script>reason</script>")
        self.write([record])
        header, body = self.request("/?refresh=1")
        self.assertIn("200 OK", header)
        self.assertIn("text/html", header)
        self.assertIn(b'<div class="container">', body)
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b"<img", body)
        self.assertIn(b"&lt;script&gt;reason&lt;/script&gt;", body)
        self.assertIn("404", self.request("/unknown")[0])

    def test_metrics_use_prometheus_gauges_with_escaped_labels_and_json_is_separate(self):
        record = self.record(1)
        record["action"] = 'read"\\\ncategory'
        self.write([record])
        header, body = self.request("/metrics")
        self.assertIn("text/plain; version=0.0.4", header)
        self.assertIn(b"# TYPE aivm_dashboard_events gauge\n", body)
        self.assertIn(b"aivm_dashboard_events 1\n", body)
        self.assertIn(b'category="read\\"\\\\\\ncategory"', body)
        self.assertTrue(body.endswith(b"\n"))
        header, body = self.request("/metrics.json")
        self.assertIn("application/json", header)
        self.assertEqual(json.loads(body)["total"], 1)
        with patch.object(DASHBOARD, "render_graph", side_effect=ImportError):
            header, body = self.request("/graph")
        self.assertIn("503", header)
        self.assertNotIn("image/png", header)

    def test_legacy_database_migration_and_cli_environment_overrides(self):
        path = self.root / "legacy.db"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, type TEXT, path TEXT, reason TEXT)")
            connection.execute("INSERT INTO events (timestamp,type) VALUES (1,'legacy')")
        store = DASHBOARD.EventStore(path, self.log)
        self.addCleanup(store.close)
        self.assertEqual(store.snapshot()["categories"], {"legacy": 1})
        with patch.dict(os.environ, {"AIVM_DASHBOARD_PORT": "9001", "AIVM_DASHBOARD_DB": str(path)}):
            args = DASHBOARD.parse_args(["--port", "9002", "--log", str(self.log)])
        self.assertEqual(args.port, 9002)
        self.assertEqual(args.db, path)
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            DASHBOARD.parse_args(["--port", "99999"])


if __name__ == "__main__":
    unittest.main()
