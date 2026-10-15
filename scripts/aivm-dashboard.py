#!/usr/bin/env python3
"""AIVM monitoring dashboard — realtime watch of audit log DENY/budget events.

Serves on http://localhost:8000 with:
- HTML page showing recent DENY/budget events + counts
- /metrics JSON endpoint (Prometheus‑scrapeable)
- /graph PNG endpoint (simple bar chart of per‑category counts)
- Stores events in SQLite (local, no external server needed)
- Retains last N entries via TTL; purges old on each refresh

Use: python3 scripts/aivm-dashboard.py
Then open http://localhost:8000 in your browser.
"""

import http.server
import socketserver
import os
import time
import sqlite3
from collections import defaultdict
import json as _json

LOG_PATH = "/var/log/aivm/audit.log"
PORT = 8000
DB_PATH = "/home/lokis/Documents/AIVirtualMachine/scripts/events.db"
MAX_ENTRIES = 500

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

init_sql = "CREATE TABLE IF NOT EXISTS events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, type TEXT NOT NULL, path TEXT, reason TEXT); CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp);"
conn = sqlite3.connect(DB_PATH)
conn.executescript(init_sql)
conn.commit()


def purge_old() -> None:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    count = cur.fetchone()[0]
    if count > MAX_ENTRIES:
        cur.execute("DELETE FROM events WHERE event_id < (SELECT MIN(event_id) FROM events ORDER BY event_id DESC LIMIT %d - 1)" % MAX_ENTRIES)
        conn.commit()
    cur.close()


def add_event(ev_type: str, path: str, reason: str) -> None:
    with open(LOG_PATH, "a") as f:
        ts = time.time()
        f.write("expect %s -> deny:denied: %s #ts=%f\n" % (ev_type, reason, ts))
    conn.execute("INSERT INTO events (timestamp, type, path, reason) VALUES (?, ?, ?, ?)", (time.time(), ev_type, path, reason))
    conn.commit()
    purge_old()


def parse_log(path: str) -> list:
    cur = conn.cursor()
    cur.execute("SELECT type, path, reason, timestamp FROM events ORDER BY event_id DESC LIMIT %d" % MAX_ENTRIES)
    rows = cur.fetchall()
    cur.close()
    return [{"type": r, "path": p or "", "reason": r2 or "", "time": ts} for r, p, r2, ts in rows]


def get_stats() -> dict:
    cur = conn.cursor()
    cur.execute("SELECT type, COUNT(*) AS cnt FROM events GROUP BY type")
    rows = cur.fetchall()
    cur.close()
    cats = defaultdict(int)
    total = 0
    for rtype, c in rows:
        cats[rtype] = c
        total += c
    return {"total": total, "categories": dict(cats)}


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.rstrip("/")
        entries = parse_log(LOG_PATH)
        stats = get_stats()

        if path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            out = {"total": stats["total"], "categories": stats["categories"], "last_refresh": time.time()}
            self.wfile.write(_json.dumps(out).encode("utf-8"))
            return

        if path == "/graph":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            try:
                import matplotlib.pyplot as plt
            except Exception:
                png_bytes = (b"\\x89PNG\\r\\x1a\\n\\x00\\x00\\x00\\rIHDR\\x00\\x00\\x00\\x01" b"\\x00\\x00\\x00\\x01\\x08\\x02\\x00\\x00\\x00\\x90wS\\xdf\\n" b"\\x00\\x00\\x00\\tEXtSoftware\\xff\\xff\\xff\\xff\\x00\\x00\\x00" b"\\x0I\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" b"\\xff\\xc0\\xc0\\xc0\\x07\\x0a\\x80\\x80\\x80\\xff\\x00\\x00\\x00" b"\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x80\\x80\\x80\\x80\\x80" b"\\x80\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x80\\x80\\x80\\x80\\x80" b"\\x80\\x80\\x80\\x80\\x80\\x80\\x80\\x80\\x80\\x00\\x80\\x80\\x80" b"\\x80\\x80\\x80\\x80\\x00")
                self.wfile.write(png_bytes)
                return
            cats = sorted(stats["categories"].items(), key=lambda x: -x[1])
            labels = [c[0] for c in cats]
            vals = [c[1] for c in cats]
            fig, ax = plt.subplots(figsize=(6, 4))
            bars = ax.barh(labels, vals, color="#4c72b0")
            ax.set_xlabel("count")
            ax.set_title("AIVM Audit — Events per Category")
            buf = __import__("io").BytesIO()
            fig.savefig(buf, format="png", bbox_inches="tight")
            buf.seek(0)
            png_bytes = buf.read()
            plt.close(fig)
            self.wfile.write(png_bytes)
            return

        # HTML dashboard
        cat_rows = []
        for cat, count in sorted(stats["categories"].items(), key=lambda x: -x[1]):
            cat_rows.append("<tr><td>%s</td><td>%d</td></tr>" % (cat, count))

        entry_rows = []
        for e in entries[:20]:
            etype = e.get("type", "unknown")
            path_s = e.get("path", "")[:60]
            reason_s = e.get("reason", "")[:50]
            entry_rows.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (etype, path_s, reason_s))

        html = (
            "<!DOCTYPE html>"
            "<html lang=\"th\">"
            "<head>"
            "<meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
            "<title>AIVM Monitoring Dashboard</title>"
            "<style>"
            "body{font-family:sans-serif;margin:2rem;background:#f5f5f5;}"
            "h1{color:#333;}"
            ".container{background:white;padding:1.5rem;border-radius:8px;margin-bottom:1.5rem;}"
            "table{width:100%;border-collapse:border-spacing:0.5rem;}"
            "th,td{padding:0.5rem;border:1pxsolid #ddd;text-align:left;}"
            "th{background:#f0f0f0;}"
            ".stats{margin-top:1rem;font-size:0.9rem;}"
            ".stats td{width:30%;}"
            "</style>"
            "</head>"
            "<body>"
            "<h1>AIVM Monitoring Dashboard</h1>"
            "<divclass=\"container\">"
            "<h2>Statistics</h2>"
            "<table>"
            "<tr><th>Total DENY/Budget events</th><td>%d</td></tr>" % stats["total"]
            + "".join(cat_rows)
            + "<tr><th>Uptime (seconds)</th><td>%d</td></tr>" % int(time.time() - stats.get("last_refresh", time.time()))
            + "</table>"
            + "</div>"
            "<divclass=\"container\">"
            "<h2>Recent Events (last 20)</h2>"
            "<table>"
            "<tr><th>Type</th><th>Path</th><th>Reason</th></tr>"
            + "".join(entry_rows)
            + "</table>"
            + "</div>"
            "<divclass=\"container\">"
            "<h2>Graph</h2>"
            '<p>View <a class=\"graph-link\" href=\"/graph\">PNG bar chart</a> of events per category.</p>'
            + "</div>"
            "<divclass=\"container\">"
            '<p>View <a class=\"graph-link\" href=\"/metrics\">JSON metrics</a> compatible with Prometheus node_exporter.</p>'
            + "</div>"
            "</body>"
            "</html>"
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


class HTTPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    print("Starting AIVM dashboard server on http://localhost:%d" % PORT)
    print("Watching log: %s" % LOG_PATH)
    print("DB: %s" % DB_PATH)
    print("Open your browser to http://localhost:%d" % PORT)
    print("-" * 50)
    try:
        with HTTPServer(("", PORT), DashboardHandler) as httpd:
            print("Server running on port %d" % PORT)
            httpd.serve_forever()
    except OSError as e:
        print("Error starting server on port %d: %s" % (PORT, e))
        print("Check if port 8000 is already in use.")
        exit(1)


if __name__ == "__main__":
    main()
