# Dashboard หลังแยก importer — 24 ตุลาคม 2026

**ผ่าน** บน working tree หลัง commit `d03a8b764f6519998652b2e6ce03e3857bce383d`
ทดสอบ background importer, snapshot ใน memory และ HTTP handlers ที่จำกัดจำนวน
dashboard source ที่ทดสอบมี SHA-256
`0669f3e947483a05c3f03e9f99d955c5a41eaf142c6f2992bf463e620c84fc62`
และไม่เปลี่ยนระหว่างรัน

## พฤติกรรมที่ตรวจ

- HTTP อ่าน snapshot โดยไม่รอ SQLite; แสดงอายุข้อมูลและ stale เมื่อ importer ล้ม/ค้าง
- Importer ทำงานได้โดยไม่มี HTTP clients และ commit cursor กับ events ใน transaction เดิม
- จำกัด handlers พร้อมกัน 8 รายตามค่าเริ่มต้น; เมื่อเต็มตอบ 503 พร้อม Retry-After
- Socket idle timeout และการปิด server คืน handler slots และ join threads ได้
- Graph cache แยก lock จาก importer/HTTP snapshot และมีผู้ render ครั้งละหนึ่งราย

## ผลตรวจ

`CARGO_NET_OFFLINE=true make verify test-dashboard-http check-ci` exit 0:
format, strict clippy, workspace/Python tests, demo 14/14 และ CI parity ผ่าน
dashboard suite มี **36 tests** รวม real HTTP 5 tests ซึ่งเปิดด้วย
`AIVM_DASHBOARD_HTTP_TESTS=1` บน host ที่อนุญาต localhost sockets

Exercise ใช้ HTTP server จริงบน `127.0.0.1` กับ audit สังเคราะห์,
retention 200 และค่า refresh/timeout/concurrency เริ่มต้น
ระหว่าง traffic มี clients อ่าน HTML, Prometheus และ JSON พร้อมกัน
ตรวจ cursor ที่ persist แล้วเทียบ inode/offset กับ EOF และ retained rows กับ oracle
ก่อนถือว่าแต่ละ batch อ่านครบ จึงรองรับการ import แบบ asynchronous

| รายการ | ผลจริง |
|---|---|
| Traffic | 120.002 วินาที, 78 batches |
| เวลารวม setup/fault injection/verification | 130.244 วินาที |
| Audit สังเคราะห์ | 32,022 records, 9 ไฟล์ |
| HTTP requests | 9,338; unexpected errors 0 |
| ระหว่าง SQLite write lock | 178 requests; HTTP latency สูงสุด **1.64 ms** |
| SQLite lock failure/retry | แสดง stale และ error แล้วอ่านต่อครบหลังปลด lock |
| Graceful restart ระหว่าง traffic | 3 รอบ ผ่านทั้งหมด |
| Rotation ระหว่าง traffic | 5 รอบ ผ่านทั้งหมด |
| Crash recovery | append 32 DENY แล้ว `SIGKILL`; เปิดใหม่และกู้ retained window ได้ครบ |
| จงใจข้ามไฟล์กลาง | หยุด consumer ด้วย SIGSTOP ระหว่าง rotation; ตรวจพบ gap 1 ครั้ง |
| ตรวจ retained rows แยกหลังจบ | 200 แถวตรง oracle; 200 fingerprints ไม่ซ้ำ |
| SQLite / audit chain | `integrity_check = ok`; CLI ตรวจ v2 chain ผ่านครบทุกไฟล์ |
| HTTP latency p50 / p95 / max ทั้งรอบ | 1.16 / 1.92 / 16.23 ms |
| Peak sampled dashboard RSS | 29,112 KiB ประมาณ 28.4 MiB |

Burst ก่อน traffic มี 12,000 records รวม 5,701,735 bytes และอ่านครบตาม oracle
poll แรกยังไม่เห็น backlog (`backlog_seen = false`) จึงใช้ cursor/EOF และผล DB
ยืนยันการอ่านครบ; byte-budget/backlog behavior มี unit regression แยกอยู่แล้ว

รอบเดิมที่ [soak 30 นาที](dashboard-soak-2026-10-24.md) request รอ SQLite lock
นาน 5.01 วินาที รอบนี้ HTTP ตอบ snapshot เดิมได้ระหว่าง importer รอ lock
ผลรอบใหม่นี้ครอบคลุม workload หลังแก้เป็นเวลา 2 นาที

## หลักฐาน

เก็บใน `target/dashboard-async-validation-2026-10-24/` ซึ่งถูก Git ignore:

- `final-checks.log`: required verification, dashboard HTTP tests และ CI parity
- `dashboard-soak.py`, `soak.log`: harness และผล exercise
- `run/results.json`: cases, HTTP latency, RSS/coverage samples และ source/harness hashes
- `run/source-dashboard.py`, `run/source.patch`: source และ diff ตอนเริ่ม exercise
- `run/audit*.jsonl`, `run/private/events.db`, `run/audit-verification.log`: fixture และผลตรวจ
- `independent-checks.json`: ผลเทียบ DB กับ audit ทุกไฟล์โดยแยกจาก oracle ใน harness
- `final-source.patch`, `final-test-dashboard.py`, `manifest.json`: diff/tests หลังตรวจครบและ hashes

ทำซ้ำบน host ที่เปิด localhost ได้ โดยใช้ output directory ใหม่:

```bash
python3 target/dashboard-async-validation-2026-10-24/dashboard-soak.py \
  --out target/dashboard-async-validation-2026-10-24/repeat --duration 120
```
