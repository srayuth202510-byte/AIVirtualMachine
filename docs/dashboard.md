# Audit dashboard

Dashboard อ่าน audit JSONL และเก็บเฉพาะ DENY/budget/quarantine events ลง SQLite
เพื่อแสดงผล ไม่เปลี่ยน log ต้นฉบับ ไม่ให้สิทธิ์และไม่สั่ง containment
ตัว dashboard ไม่ตรวจ hash chain; ใช้ `aivm audit` หรือ audit watcher สำหรับ integrity

```bash
python3 scripts/aivm-dashboard.py \
  --log ./vms/coder/audit.jsonl \
  --db ./.aivm-dashboard/events.db \
  --host 127.0.0.1 --port 8000 --max-entries 500
```

เริ่มต้น bind เฉพาะ `127.0.0.1:8000` และสร้าง DB ใต้ `.aivm-dashboard`
ซึ่งถูก ignore ใน Git ไฟล์ DB เป็น `0600` และ directory ที่สร้างใหม่เป็น `0700`
นำ DB รุ่นเดิมกลับมาใช้ได้ด้วย `--db ./scripts/events.db`; fingerprint column
จะถูก migrate เมื่อเปิด การ import Python module ไม่สร้าง directory หรือ DB

| CLI | Environment | ค่าเริ่มต้น |
|---|---|---|
| `--log` | `AIVM_AUDIT_LOG` | `./audit.jsonl` |
| `--db` | `AIVM_DASHBOARD_DB` | `./.aivm-dashboard/events.db` |
| `--host` | `AIVM_DASHBOARD_HOST` | `127.0.0.1` |
| `--port` | `AIVM_DASHBOARD_PORT` | `8000` |
| `--max-entries` | `AIVM_DASHBOARD_MAX_ENTRIES` | `500` |

CLI มีลำดับเหนือ environment; `--port 0` ให้ระบบเลือก port ว่างและพิมพ์ URL

| Endpoint | ผล |
|---|---|
| `/` | HTML statistics และ 20 events ล่าสุด พร้อม escape ทุก audit field |
| `/metrics` | Prometheus text exposition (`text/plain; version=0.0.4`) |
| `/metrics.json` | สถิติ JSON สำหรับ client ที่ต้องการรูปแบบเดิม |
| `/graph` | PNG chart เมื่อมี optional `matplotlib`; ถ้าไม่มีคืน HTTP 503 |

`/metrics` เปลี่ยนจาก JSON เป็น text; client JSON เดิมต้องใช้ `/metrics.json`
รูปแบบอ้างอิง [Prometheus exposition specification](https://prometheus.io/docs/instrumenting/exposition_formats/)
จำนวน events เป็น **gauge** เพราะ retention ทำให้ลดลงได้ ไม่ใช่ cumulative counter
มี metrics สำหรับ audit read success, last refresh timestamp และ uptime จริง

อ่านเฉพาะท้าย audit ไม่เกิน 4 MiB และไม่เกินจำนวน lines ตาม `max-entries`
ข้าม malformed records, partial writes และ lines เกิน 1 MiB
DB เก็บสูงสุด `max-entries` events และ deduplicate ด้วย fingerprint ของ record
ถ้า log หาย/อ่านไม่ได้ ยังแสดงข้อมูลเดิมพร้อมข้อความแจ้งและ read-success = 0
ตัวเลขนี้จึงเป็นหน้าต่างข้อมูลที่เก็บไว้ ไม่ใช่จำนวน events ตลอดอายุ VM

ทดสอบ regression ด้วย `python3 -m unittest discover -s scripts -p 'test_dashboard.py'`
ครอบคลุม HTTP responses, HTML escaping, metrics labels, retention/dedup,
partial/oversized input, private storage และ schema migration
