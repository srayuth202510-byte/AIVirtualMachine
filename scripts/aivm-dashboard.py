#!/usr/bin/env python3
"""Read-only local audit dashboard with SQLite retention and Prometheus metrics."""

import argparse
import hashlib
import html
import http.server
import io
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from urllib.parse import urlsplit


MAX_AUDIT_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024


class EventStore:
    def __init__(self, database, audit_log, max_entries=500):
        if not 1 <= max_entries <= 10000:
            raise ValueError("max_entries must be between 1 and 10000")
        self.audit_log = Path(audit_log)
        self.database = Path(database)
        self.max_entries = max_entries
        self.started = time.monotonic()
        self.last_refresh = 0.0
        self.audit_read_success = False
        self.last_error = ""
        self.lock = threading.Lock()
        self.source = None
        self.cursor_tail = b""
        self.discarding = False
        self.backlog_bytes = 0
        self.pending_bytes = 0
        self.coverage_gaps = 0
        self.coverage_warning = ""
        self.last_hash = None
        self.last_action = None
        self.check_anchor = False
        self.expected_anchor = None
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # DB อาจมีข้อมูลจาก audit จึงสร้าง private ตั้งแต่เปิด ไม่ทำ I/O ตอน import
        fd = os.open(self.database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.geteuid():
                raise ValueError("dashboard database must be an owned regular file with one link")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL, type TEXT NOT NULL, path TEXT,
                reason TEXT, fingerprint TEXT UNIQUE);
            CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp);
            CREATE TABLE IF NOT EXISTS import_cursors (
                source TEXT PRIMARY KEY, state TEXT NOT NULL);
        """)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(events)")}
        if "fingerprint" not in columns:
            self.conn.execute("ALTER TABLE events ADD COLUMN fingerprint TEXT")
        self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprint ON events(fingerprint)")
        self.source_key = str(self.audit_log.absolute())
        cursor = self.conn.execute("SELECT state FROM import_cursors WHERE source = ?",
                                   (self.source_key,)).fetchone()
        self.resume_state = json.loads(cursor[0]) if cursor else None
        self._purge()
        self.conn.commit()

    def close(self):
        if self.source is not None:
            self.source.close()
        self.conn.close()

    def _purge(self):
        # subquery ต้องเลือก IDs ก่อน aggregate; คำสั่งเดิมไม่เคยลบแถวเกินเพดาน
        self.conn.execute("DELETE FROM events WHERE event_id NOT IN "
                          "(SELECT event_id FROM events ORDER BY event_id DESC LIMIT ?)",
                          (self.max_entries,))

    def _open_source(self):
        # ห้ามตาม symlink และเปิดแบบไม่รอ เพื่อให้ FIFO ปลอมไม่ทำให้ dashboard ค้าง
        fd = os.open(self.audit_log, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("audit source must be a regular file")
        self.source = os.fdopen(fd, "rb")
        self.cursor_tail = b""
        self.discarding = False
        self.check_anchor = True
        if self.resume_state is not None:
            state, self.resume_state = self.resume_state, None
            self.coverage_gaps = state["coverage_gaps"]
            self.coverage_warning = state["coverage_warning"]
            position = state["offset"]
            tail = bytes.fromhex(state["tail"])
            metadata = os.fstat(self.source.fileno())
            if (type(position) is not int or position < 0 or len(tail) > 128
                    or len(tail) > position):
                raise ValueError("invalid persisted audit cursor")
            if ((metadata.st_dev, metadata.st_ino) == (state["device"], state["inode"])
                    and metadata.st_size >= position
                    and os.pread(self.source.fileno(), len(tail), position-len(tail)) == tail):
                # inode เดิมอย่างเดียวไม่พอ: เทียบท้ายข้อมูลด้วยเพื่อจับการเขียนทับที่ขนาดเท่าเดิม
                self.source.seek(position)
                self.cursor_tail = tail
                self.discarding = state["discarding"]
                self.check_anchor = state["check_anchor"]
                self.expected_anchor = state["expected_anchor"]
                self.last_hash = state["last_hash"]
                self.last_action = state["last_action"]
            elif (state["sealed_end"] and state["last_hash"]
                  and (metadata.st_dev, metadata.st_ino) != (state["device"], state["inode"])):
                self.expected_anchor = state["last_hash"]
            else:
                self._gap("Persisted audit cursor no longer matches the source; replaying available data.")

    def _save_cursor(self):
        # cursor กับ events ต้อง commit พร้อมกัน ป้องกัน replay เก่าเบียด retention หลัง restart
        position = self.source.tell()
        metadata = os.fstat(self.source.fileno())
        tail = os.pread(self.source.fileno(), min(position, 128), max(0, position-128))
        state = dict(device=metadata.st_dev, inode=metadata.st_ino, offset=position,
                     tail=tail.hex(), discarding=self.discarding, check_anchor=self.check_anchor,
                     expected_anchor=self.expected_anchor, last_hash=self.last_hash,
                     last_action=self.last_action, coverage_gaps=self.coverage_gaps,
                     coverage_warning=self.coverage_warning,
                     sealed_end=(position == metadata.st_size and not self.discarding
                                 and self.last_action == "seal"))
        self.conn.execute("INSERT INTO import_cursors (source, state) VALUES (?, ?) "
                          "ON CONFLICT(source) DO UPDATE SET state=excluded.state",
                          (self.source_key, json.dumps(state)))

    def _gap(self, warning):
        # แจ้ง coverage แยกจากการเปิดอ่านสำเร็จ ไม่อ้างว่าเก็บครบเมื่อมีช่วงที่ไม่ทราบ
        self.coverage_gaps += 1
        self.coverage_warning = warning

    def _ingest(self, line):
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError):
            self._gap("Malformed audit records were skipped.")
            return
        if not isinstance(record, dict):
            self._gap("Non-object audit records were skipped.")
            return
        if self.check_anchor:
            previous = record.get("hash_prev", "")
            if self.expected_anchor is not None:
                if previous != self.expected_anchor:
                    self._gap("Audit rotation continuity could not be established.")
            elif previous:
                self._gap("Audit source starts after genesis; earlier history was not imported.")
            self.check_anchor = False
            self.expected_anchor = None
        self.last_hash = record.get("hash_entry")
        self.last_action = record.get("action")
        timestamp = record.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            return
        try:
            timestamp = float(timestamp)
            if not math.isfinite(timestamp):
                return
        except OverflowError:
            return
        decision = record.get("decision", "")
        result = record.get("result", "")
        if not isinstance(decision, str) or not isinstance(result, str):
            return
        if decision.lower() != "deny" and not any(word in result.lower() for word in ("budget", "quarantine")):
            return
        action, resource = record.get("action", "unknown"), record.get("resource", "")
        reason = result or record.get("rule_matched", "")
        if not all(isinstance(value, str) for value in (action, resource, reason)):
            return
        fingerprint = hashlib.sha256(line.rstrip(b"\r\n")).hexdigest()
        # backfill ของ DB รุ่นเดิมต้องจัดลำดับซ้ำตาม source ก่อน purge มิฉะนั้นแถวเก่า
        # ที่ถูก reinsert จะเบียดแถวล่าสุดซึ่งถูก IGNORE เพราะ fingerprint ยังมีอยู่
        self.conn.execute("INSERT OR REPLACE INTO events "
                          "(timestamp, type, path, reason, fingerprint) VALUES (?, ?, ?, ?, ?)",
                          (timestamp, action[:256], resource[:4096], reason[:4096], fingerprint))

    def sync(self):
        with self.lock:
            try:
                if self.source is None:
                    self._open_source()
                position = self.source.tell()
                metadata = os.fstat(self.source.fileno())
                witness = os.pread(self.source.fileno(), len(self.cursor_tail), position - len(self.cursor_tail))
                if metadata.st_size < position or witness != self.cursor_tail:
                    self._gap("Audit source was truncated or rewritten; replaying the available file.")
                    self.source.seek(0)
                    self.cursor_tail = b""
                    self.discarding = False
                    self.check_anchor = True
                    self.expected_anchor = None
                remaining = MAX_AUDIT_BYTES
                self.pending_bytes = 0
                checkpoint = (self.source.tell(), self.discarding, self.check_anchor,
                              self.expected_anchor, self.last_hash, self.last_action)
                try:
                    self._consume(remaining)
                except (OSError, ValueError, sqlite3.Error):
                    # DB rollback ต้อง rollback cursor ด้วย มิฉะนั้น poll ถัดไปจะข้าม events
                    (position, self.discarding, self.check_anchor, self.expected_anchor,
                     self.last_hash, self.last_action) = checkpoint
                    self.source.seek(position)
                    raise
                position = self.source.tell()
                held = os.fstat(self.source.fileno())
                self.backlog_bytes = max(0, held.st_size - position)
                self.cursor_tail = os.pread(self.source.fileno(), min(position, 128), max(0, position - 128))
                current = self.audit_log.stat()
                if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                    if position >= held.st_size or self.pending_bytes:
                        if self.pending_bytes or self.discarding:
                            self._gap("Audit rotation left an incomplete record.")
                        anchor = self.last_hash if self.last_action == "seal" else None
                        if not anchor:
                            self._gap("Audit source was replaced without an observed rotation seal.")
                        self.source.close()
                        self.source = None
                        self.expected_anchor = anchor
                        self._open_source()
                        self.pending_bytes = 0
                    # อ่านไฟล์ใหม่ครั้งถัดไปหลัง drain inode เก่าแล้ว
                    self.backlog_bytes += current.st_size
                self.audit_read_success = True
                self.last_error = ""
                self.last_refresh = time.time()
            except (OSError, ValueError, sqlite3.Error) as error:
                self.audit_read_success = False
                detail = getattr(error, "strerror", None) or str(error)
                self.last_error = f"Audit log could not be imported: {detail}"

    def _consume(self, remaining):
        with self.conn:
            # เดิน cursor ต่อทุก poll; retention จำกัดเฉพาะ events ที่ผ่าน filter แล้ว
            while remaining > 0:
                position = self.source.tell()
                line = self.source.readline(min(MAX_LINE_BYTES + 1, remaining))
                if not line:
                    break
                remaining -= len(line)
                complete = line.endswith(b"\n")
                if self.discarding:
                    # หลัง restart ก็ต้องทิ้งบรรทัดที่ยาวเกินต่อจนจบ ห้ามตีความเศษท้ายเป็น event
                    self.discarding = not complete
                    continue
                if len(line) > MAX_LINE_BYTES:
                    self._gap("Oversized audit records were skipped.")
                    self.discarding = not complete
                    continue
                if not complete:
                    # เก็บ partial line ไว้อ่านใหม่เมื่อ writer เขียนจบ
                    self.source.seek(position)
                    if os.fstat(self.source.fileno()).st_size <= position + len(line):
                        self.pending_bytes = len(line)
                    break
                self._ingest(line)
            self._purge()
            self._save_cursor()

    def snapshot(self):
        with self.lock:
            rows = self.conn.execute("SELECT type, path, reason, timestamp FROM events "
                                     "ORDER BY event_id DESC LIMIT ?", (self.max_entries,)).fetchall()
            categories = dict(self.conn.execute("SELECT type, COUNT(*) FROM events GROUP BY type"))
            return {
                "total": sum(categories.values()), "categories": categories,
                "last_refresh": self.last_refresh, "uptime_seconds": time.monotonic() - self.started,
                "audit_read_success": self.audit_read_success, "error": self.last_error,
                "backlog_bytes": self.backlog_bytes, "pending_bytes": self.pending_bytes,
                "coverage_gaps": self.coverage_gaps, "coverage_warning": self.coverage_warning,
                "coverage_complete": self.audit_read_success and self.coverage_gaps == 0
                                     and self.backlog_bytes == 0 and not self.discarding
                                     and not (self.check_anchor and self.expected_anchor is not None),
                "entries": [{"type": kind, "path": path or "", "reason": reason or "", "time": timestamp}
                            for kind, path, reason, timestamp in rows],
            }


def prometheus_metrics(snapshot):
    # ตัวนับหน้าต่าง retention ลดลงได้ จึงเป็น gauge ไม่ใช่ cumulative counter
    lines = [
        "# HELP aivm_dashboard_events Retained audit DENY or budget events.",
        "# TYPE aivm_dashboard_events gauge",
        f"aivm_dashboard_events {snapshot['total']}",
        "# HELP aivm_dashboard_events_by_category Retained events per audit action.",
        "# TYPE aivm_dashboard_events_by_category gauge",
    ]
    for category, count in sorted(snapshot["categories"].items()):
        escaped = category.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(f'aivm_dashboard_events_by_category{{category="{escaped}"}} {count}')
    lines += [
        "# HELP aivm_dashboard_audit_read_success Whether the last audit read succeeded.",
        "# TYPE aivm_dashboard_audit_read_success gauge",
        f"aivm_dashboard_audit_read_success {int(snapshot['audit_read_success'])}",
        "# HELP aivm_dashboard_last_refresh_timestamp_seconds Last successful import time.",
        "# TYPE aivm_dashboard_last_refresh_timestamp_seconds gauge",
        f"aivm_dashboard_last_refresh_timestamp_seconds {snapshot['last_refresh']:.6f}",
        "# HELP aivm_dashboard_uptime_seconds Dashboard process uptime.",
        "# TYPE aivm_dashboard_uptime_seconds gauge",
        f"aivm_dashboard_uptime_seconds {snapshot['uptime_seconds']:.6f}",
    ]
    for key in ("backlog_bytes", "pending_bytes", "coverage_gaps", "coverage_complete"):
        lines += [f"# TYPE aivm_dashboard_{key} gauge",
                  f"aivm_dashboard_{key} {int(snapshot[key])}"]
    return "\n".join(lines) + "\n"


def render_page(snapshot):
    category_rows = "".join(f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>"
                            for category, count in sorted(snapshot["categories"].items(), key=lambda pair: -pair[1]))
    event_rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(event[key]))}</td>"
                                         for key in ("type", "path", "reason")) + "</tr>"
                         for event in snapshot["entries"][:20])
    warnings = [snapshot["error"], snapshot["coverage_warning"]]
    if snapshot["backlog_bytes"]:
        warnings.append(f"Audit import pending: {snapshot['backlog_bytes']} bytes.")
    warning = "".join(f'<p role="alert">{html.escape(message)}</p>' for message in warnings if message)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIVM Monitoring Dashboard</title>
<style>
body{{font-family:sans-serif;margin:2rem;background:#f5f5f5;color:#333}}
.container{{background:white;padding:1.5rem;border-radius:8px;margin-bottom:1.5rem;overflow:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:.5rem;border:1px solid #ddd;text-align:left}}
th{{background:#f0f0f0}}td{{overflow-wrap:anywhere}}[role=alert]{{color:#a11}}
</style></head><body><h1>AIVM Monitoring Dashboard</h1>{warning}
<div class="container"><h2>Statistics</h2><table>
<tr><th>Retained DENY/Budget events</th><td>{snapshot['total']}</td></tr>{category_rows}
<tr><th>Uptime (seconds)</th><td>{int(snapshot['uptime_seconds'])}</td></tr></table></div>
<div class="container"><h2>Recent Events (last 20)</h2><table>
<tr><th>Type</th><th>Path</th><th>Reason</th></tr>{event_rows}</table></div>
<div class="container"><h2>Graph</h2><p><a href="/graph">PNG chart of retained events</a></p></div>
<div class="container"><p><a href="/metrics">Prometheus metrics</a> · <a href="/metrics.json">JSON metrics</a></p></div>
</body></html>"""


def render_graph(snapshot):
    # backend แบบ headless; matplotlib เป็น optional และไม่คืน PNG ปลอมเมื่อไม่มี
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure
    figure = Figure(figsize=(6, 4))
    axes = figure.subplots()
    categories = sorted(snapshot["categories"].items(), key=lambda pair: -pair[1])[:20]
    axes.barh([pair[0] for pair in categories], [pair[1] for pair in categories], color="#4c72b0")
    axes.set_xlabel("retained events")
    axes.set_title("AIVM Audit — Events per Category")
    output = io.BytesIO()
    FigureCanvasAgg(figure).print_png(output)
    return output.getvalue()


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path not in {"/", "/metrics", "/metrics.json", "/graph"}:
            self.send_error(404)
            return
        store = self.server.store
        store.sync()
        snapshot = store.snapshot()
        if path == "/metrics":
            self.respond(200, "text/plain; version=0.0.4; charset=utf-8", prometheus_metrics(snapshot).encode())
        elif path == "/metrics.json":
            data = {key: value for key, value in snapshot.items() if key != "entries"}
            self.respond(200, "application/json; charset=utf-8", json.dumps(data, allow_nan=False).encode())
        elif path == "/graph":
            try:
                image = render_graph(snapshot)
            except ImportError:
                self.respond(503, "text/plain; charset=utf-8", b"Chart unavailable. Metrics and recent events are available.\n")
                return
            self.respond(200, "image/png", image)
        else:
            self.respond(200, "text/html; charset=utf-8", render_page(snapshot).encode())

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


class DashboardServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, address, store):
        self.store = store
        super().__init__(address, DashboardHandler)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=os.environ.get("AIVM_AUDIT_LOG", "./audit.jsonl"))
    parser.add_argument("--db", type=Path, default=os.environ.get("AIVM_DASHBOARD_DB", "./.aivm-dashboard/events.db"))
    parser.add_argument("--host", default=os.environ.get("AIVM_DASHBOARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=os.environ.get("AIVM_DASHBOARD_PORT", "8000"))
    parser.add_argument("--max-entries", type=int, default=os.environ.get("AIVM_DASHBOARD_MAX_ENTRIES", "500"))
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    if not 1 <= args.max_entries <= 10000:
        parser.error("max-entries must be between 1 and 10000")
    return args


def main(argv=None):
    args = parse_args(argv)
    store = None
    try:
        store = EventStore(args.db.expanduser(), args.log.expanduser(), args.max_entries)
        with DashboardServer((args.host, args.port), store) as server:
            print(f"Dashboard: http://{args.host}:{server.server_port}", flush=True)
            print(f"Audit log: {store.audit_log}; DB: {store.database}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Dashboard failed: {error}")
        return 1
    finally:
        if store is not None:
            store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
