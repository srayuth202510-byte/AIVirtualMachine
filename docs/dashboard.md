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
| `--refresh-interval` | `AIVM_DASHBOARD_REFRESH_INTERVAL` | `0.5` วินาที |
| `--max-clients` | `AIVM_DASHBOARD_MAX_CLIENTS` | `8` |
| `--request-timeout` | `AIVM_DASHBOARD_REQUEST_TIMEOUT` | `5` วินาที |

CLI มีลำดับเหนือ environment; `--port 0` ให้ระบบเลือก port ว่างและพิมพ์ URL
refresh interval รับ 0.05–60 วินาที, max clients รับ 1–128 และ request timeout
รับ 0.1–60 วินาที Timeout จำกัดเวลาที่ socket รออ่าน/เขียนโดยไม่มีความคืบหน้า
เมื่อ handler slots เต็มจะตอบ HTTP 503 พร้อม `Retry-After: 1` โดยไม่สร้าง thread เพิ่ม

| Endpoint | ผล |
|---|---|
| `/` | HTML statistics และ 20 events ล่าสุด พร้อม escape ทุก audit field |
| `/metrics` | Prometheus text exposition (`text/plain; version=0.0.4`) |
| `/metrics.json` | สถิติ JSON สำหรับ client ที่ต้องการรูปแบบเดิม |
| `/graph` | PNG chart เมื่อมี optional `matplotlib`; ถ้าไม่มีหรือกำลัง render อยู่คืน HTTP 503 |

`/metrics` เปลี่ยนจาก JSON เป็น text; client JSON เดิมต้องใช้ `/metrics.json`
รูปแบบอ้างอิง [Prometheus exposition specification](https://prometheus.io/docs/instrumenting/exposition_formats/)
จำนวน events เป็น **gauge** เพราะ retention ทำให้ลดลงได้ ไม่ใช่ cumulative counter
มี metrics สำหรับ audit read success, last refresh timestamp และ uptime จริง

Importer thread เดียวอ่านจากต้นไฟล์แล้วเดิน cursor ต่อครั้งละไม่เกิน 4 MiB โดยไม่จำกัด
จำนวน ALLOW lines ก่อนกรอง DENY/budget/quarantine จึงไม่ทำเหตุการณ์ที่ต้องเก็บ
หลุดเพราะมี ALLOW จำนวนมากระหว่าง polls `max-entries` จำกัดเฉพาะ events ใน DB
และ deduplicate ด้วย fingerprint ของ record ไม่ใช่จำนวนบรรทัดที่อ่าน

Importer เริ่มพร้อม server และทำงานแม้ไม่มี HTTP clients โดยตรวจทุก
`refresh-interval` วินาที และระบาย backlog ต่อทุก 0.01 วินาทีเมื่อยังมีข้อมูลครบ
ให้ประมวลผล HTTP อ่าน snapshot ใน memory พร้อม 20 events ล่าสุด จึงไม่รอ
SQLite busy timeout หรือ import batch และไม่สร้าง SQL transaction ตามจำนวน requests
snapshot กับ graph cache ใช้ lock แยกจาก DB และกราฟมีผู้ render ได้ครั้งละหนึ่งราย
cache กราฟนาน 5 วินาที; ถ้าหมวดหมู่และจำนวนไม่เปลี่ยนจะใช้ภาพเดิมต่อได้

JSON/Prometheus เพิ่ม `snapshot_age_seconds`, `snapshot_stale`, `importer_running`
และ `import_in_progress` อายุข้อมูลนับจาก import ที่สำเร็จล่าสุดด้วย monotonic clock
ก่อนสำเร็จครั้งแรกอายุเป็น JSON `null` / Prometheus `NaN` snapshot ถือว่า stale
เมื่อยังไม่เคยอ่านสำเร็จ, import ล้ม, importer หยุด หรืออายุเกิน
`max(2, 3 × refresh-interval)` วินาที เมื่อ stale จะรายงาน `coverage_complete = false`
หน้าเว็บแสดงอายุข้อมูลและคำเตือน ขณะ DB ติด lock ยังตอบ snapshot ก่อนหน้าได้
และจะ retry import โดยใช้ cursor เดิมหลังปลด lock

partial line รอจนเขียนจบ ส่วน malformed/oversized records (เกิน 1 MiB) ถูกข้าม
พร้อม coverage warning เมื่อ rotate จะอ่าน inode เก่าที่เปิดไว้ให้จบก่อนเปลี่ยน
ไปไฟล์ปัจจุบัน และเทียบ seal hash กับ `hash_prev` ของไฟล์ใหม่เพื่อตรวจช่วงที่อาจหาย
การ truncate/rewrite ที่พบจากขนาดไฟล์หรือ bytes ก่อน cursor ทำให้แจ้ง gap และ replay
ไฟล์ที่ยังมีอยู่ การตรวจนี้ไม่ใช่การตรวจ hash chain หรือ authentication

JSON/Prometheus มี `backlog_bytes`, `pending_bytes`, `coverage_gaps` และ
`coverage_complete` แยกจาก `audit_read_success` ข้อมูลที่ยังอ่านไม่ทันหรืออ่านไม่ครบ
จะแสดงคำเตือนบนหน้าเว็บ DB failure จะ rollback cursor เพื่อ retry โดยไม่ข้าม events
cursor (inode/offset และ bytes ก่อน cursor) กับ events ถูก commit ใน SQLite
transaction เดียวกัน เมื่อ restart จึงอ่านต่อโดยไม่ replay events เก่าที่ถูก purge
กลับมาเบียด events ล่าสุด หากพบ seal ก่อนหยุด จะใช้ hash นั้นตรวจ continuation
หลัง restart ได้ ส่วน cursor ที่ไม่ตรงกับไฟล์หรือ rotation ที่ข้ามไปจะแจ้ง gap
coverage gaps/warnings ถูกเก็บข้าม restart ด้วย
DB รุ่นเดิมที่ยังไม่มี cursor จะ backfill และจัดลำดับ retained events ตาม source
ก่อน purge เพื่อรักษารายการล่าสุดเมื่ออ่าน backlog ครบแล้ว

coverage หมายถึง source ที่เคยสังเกตได้ด้วย DB นี้ ไม่รับรองประวัติที่ไม่เคย import
และไม่ตาม archive ย้อนหลัง หากเริ่มใหม่โดยไม่มี cursor แล้ว active file เป็น
continuation จะแจ้งว่าไม่ได้ import ประวัติก่อนหน้า

ถ้า log หาย/อ่านไม่ได้ ยังแสดงข้อมูลเดิมพร้อมข้อความแจ้งและ read-success = 0
จำนวน events เป็นหน้าต่างข้อมูลตาม retention ไม่ใช่จำนวนตลอดอายุ VM

ทดสอบ regression ด้วย `python3 -m unittest discover -s scripts -p 'test_dashboard.py'`
ครอบคลุม HTTP responses, HTML escaping, metrics labels, retention/dedup,
partial/oversized input, private storage, schema migration, traffic ระหว่าง polls,
cursor/backlog, DB retry, truncation, rotation ระหว่างมี backlog และ restart
หลัง retention purge/transaction failure

ทดสอบ concurrency บน host ที่เปิด localhost socket ได้ด้วย `make test-dashboard-http`
ครอบคลุม SQLite lock จริงขณะตอบ HTTP, slow header timeout, HTTP 503 เมื่อเต็ม,
การคืน slots และกราฟที่ช้า CI เปิดชุดนี้แยกจาก unit tests ปกติ

ผลทดสอบ HTTP server จริงต่อเนื่อง 30 นาที พร้อม restart 5 รอบและ live rotation
14 รอบ อยู่ใน [รายงาน soak 24 ตุลาคม 2026](dashboard-soak-2026-10-24.md)

ผลหลังแยก importer และเพิ่ม bounded HTTP อยู่ใน
[รายงาน async validation](dashboard-async-validation-2026-10-24.md): traffic 2 นาที,
DB lock latency, restart/rotation และ recovery หลัง `SIGKILL`
