# Dashboard soak 30 นาที — 24 ตุลาคม 2026

**ผ่าน** บน commit `f9ea8d3eee83fd0bf1a87d3aede0fbeaff4a5ac1`
โดยเริ่มจาก working tree สะอาดและใช้ dashboard source เดิมตลอดการทดสอบ
รัน HTTP server จริงบน `127.0.0.1` ด้วย audit สังเคราะห์และ SQLite แยกใน
`target/dashboard-soak/2026-10-24-f9ea8d3-30m/`

## วิธีทดสอบ

ใช้ harness จาก [รอบ 23 ตุลาคม](host-validation-2026-10-23.md)
เพิ่มช่วง traffic เป็น 1,800 วินาที, restart ทุก 300 วินาที,
rotation ทุก 120 วินาที และบันทึก progress ทุกประมาณ 30 วินาที
HTTP clients สามตัวอ่าน `/`, `/metrics` และ `/metrics.json` พร้อมกัน
writer เติมครั้งละ 256 records โดยมี DENY ทุก 40 records และตรวจ SQLite
เทียบรายการ DENY ล่าสุด 200 รายการตามลำดับหลังทุก batch

เมื่อ restart จะหยุด clients ชั่วคราว ปิด server แล้วเปิดใหม่ด้วย DB เดิม
ตรวจ persistent cursor และ retained rows ก่อนกลับมารับ traffic
writer อยู่ใน controller เดียวกับที่สั่ง restart จึงหยุดเขียนระหว่างช่วงนี้ด้วย
ผล restart ครอบคลุมการอ่านต่อและ retention หลังเปิดใหม่

ก่อนช่วง traffic ทดสอบ burst เกิน byte budget, partial write, SQLite write lock
จริงนานจนถึง busy timeout และ rotation ที่ยังมีข้อมูลใน inode เก่า
หลัง traffic จงใจ rotate สองครั้งโดยไม่อ่านไฟล์กลางหนึ่งช่วง แล้วตรวจว่า
dashboard แจ้ง gap พร้อมตรวจ audit chain ของ fixture ทุกไฟล์ด้วย CLI

## ผล

| รายการ | ผลจริง |
|---|---|
| Traffic ต่อเนื่อง | 1,800.002 วินาที, 1,774 batches |
| เวลารวม setup/fault injection/verification | 1,824.242 วินาที |
| Audit สังเคราะห์ทั้งหมด | 466,184 records, 18 ไฟล์ |
| HTTP requests | 106,261; unexpected errors 0 |
| Restart ระหว่างช่วง traffic | 5 รอบ ผ่านทั้งหมด |
| Rotation ระหว่างช่วง traffic | 14 รอบ ผ่านทั้งหมด |
| Burst ก่อน traffic | 12,000 records, 5,701,735 bytes; พบ backlog แล้วอ่านจนหมด |
| Partial write | รอจนบรรทัดครบและ import ได้ครั้งเดียว |
| SQLite write lock | แจ้ง import failure แล้ว retry หลังปลด lock ได้ครบ |
| Retention | 200 events ล่าสุดตรงต้นทางทั้งรายการและลำดับทุก batch |
| จงใจข้ามไฟล์กลาง | แจ้ง coverage gap 1 ครั้งตามที่คาด |
| Audit v2 hash chain | CLI ตรวจครบทุกไฟล์ผ่าน |
| SQLite integrity check หลังจบ | `ok` |
| DB permissions / directory | `0600` / `0700` |
| Dashboard RSS จาก 1,800 samples | 28,072–28,524 KiB (ประมาณ 27.4–27.9 MiB) |
| HTTP latency p50 / p95 | 1.51 / 2.11 ms |
| HTTP latency สูงสุด | 5.01 วินาที ระหว่างจงใจล็อก SQLite |
| Dashboard regression suite ก่อน soak | 24 tests ผ่าน |

ตัวตรวจหลักฐานอีกชุดอ่าน audit ทุกไฟล์ตามลำดับ แยก DENY ที่จงใจไม่ให้
consumer เห็น แล้วสร้างรายการล่าสุดใหม่โดยไม่ใช้ deque ของ harness
ผลตรงกับ SQLite 200 แถว มี fingerprints ไม่ซ้ำ 200 ค่า และ persisted cursor
มี gap หนึ่งครั้งตามการฉีดความผิดพลาด ขณะ traffic ทุกจุดตรวจมี coverage ครบ

ผลนี้ครอบคลุม dashboard กับ workload สังเคราะห์บน host นี้เป็นเวลา 30 นาที
ค่า latency และ RSS เป็นค่าที่วัดได้ระหว่าง exercise นี้

## หลักฐานและการทำซ้ำ

ไฟล์หลักฐานอยู่ใต้ `target/dashboard-soak/2026-10-24-f9ea8d3-30m/`
ซึ่งถูก Git ignore:

- `preflight.json`: commit, clean status, Python/platform และ source/harness hashes
- `dashboard-soak.py`: harness ที่ใช้จริง พร้อมระยะเวลา restart/rotation
- `runner-host.log`: รายการเคสที่ผ่านและ progress ระหว่างรัน
- `run-host/results.json`: ผลรวม, latency, RSS/coverage samples และ hashes
- `run-host/source-dashboard.py`, `run-host/source-test-dashboard.py`, `run-host/source.patch`: source snapshot
- `run-host/audit*.jsonl`, `run-host/private/events.db`: fixture และ DB หลังจบ
- `run-host/audit-verification.log`, `run-host/aivm-verifier`: ผล CLI และ binary ที่ใช้ตรวจ
- `verify-evidence.py`, `independent-checks.json`: ตัวตรวจแยกและผลหลังจบ
- `manifest.json`: ขนาดและ SHA-256 ของไฟล์หลักฐาน

ความพยายามแรกภายใน restricted chat sandbox เปิด socket ไม่ได้ (`Operation
not permitted`) จึงเก็บผลนั้นใน `run/` และ `runner.log` จากนั้นรันรอบจริง
นอก sandbox ใน `run-host/` จน exit 0 โดยใช้เฉพาะ localhost และ fixture แยก

```bash
python3 target/dashboard-soak/2026-10-24-f9ea8d3-30m/dashboard-soak.py \
  --out target/dashboard-soak/2026-10-24-f9ea8d3-30m/repeat \
  --duration 1800
```

ใช้ output directory ใหม่ทุกครั้ง และ host ที่อนุญาต localhost socket
ตัวตรวจหลักฐาน `verify-evidence.py` ผูกกับ `run-host/` ของรอบนี้
dashboard source SHA-256 ที่ใช้คือ
`a28437cc3faa8b940131784bd13507d872d1212c0542721000dc7f143b910b7e`

