# Host validation และ dashboard load test — 23 ตุลาคม 2026

Worker/model validation รันบน host จริงที่ commit
`50b5d0e4a3e2fd6def5198b60c8fb6c7095eaacd` โดยเริ่มจาก working tree สะอาด
เริ่มเวลา 14:44 น. Asia/Bangkok ผล core/model **ผ่านครบ** แต่ dashboard
ของ commit นี้ **ไม่ผ่าน restart/retention** จึงแก้เพิ่มใน working tree
และทดสอบซ้ำจนผ่าน แยกผลก่อนแก้กับหลังแก้ไว้ชัดเจน

หลักฐานอยู่ใน `target/host-validation/2026-10-23-50b5d0e/`
มี commands, elapsed times, raw logs, source/artifact hashes และ fixture สังเคราะห์
ผล dashboard หลังแก้ไม่ใช่การรับรอง dashboard เดิมที่ commit `50b5d0e`

## Host และ fixture ที่ใช้

- Host `MondayBtype`, Linux `7.0.0-38-generic`, x86_64; รันนอก restricted chat sandbox
- KVM, user/network/PID namespaces, Firecracker และ container helper พร้อม
- ตรวจ cgroup delegation ด้วย transient user service ก่อนรัน container tests
  ค่า cgroup writable/quotas ใน probe นอก delegated service เป็น false ตามขอบเขตสิทธิ์
  ผล container tests มาจาก service ที่ delegate CPU/memory/PIDs จริง
- ใช้ GGUF เดิม `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf`, 1,117,320,768 bytes
- Approved model SHA-256:
  `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`
- ใช้ boot pins เดิมที่ `/home/lokis/.local/share/aivm/microvm/pins.json`
  ตรวจ model/kernel/rootfs/Firecracker เทียบ trusted pins ก่อนรัน

## ผล real-model validation

| ชุดทดสอบ | ผล | เวลารวม command/setup |
|---|---|---:|
| Protected loader หลังสลับ/แก้ source model | ผ่าน exact host test | 56.69 วินาที |
| Worker process namespace | ผ่าน exact host test | 102.68 วินาที |
| Timeout/memory failure และ recovery — process namespace | ผ่าน exact host test และ evidence 4 records | 110.18 วินาที |
| Worker container | ผ่าน exact host test | 99.48 วินาที |
| Timeout/memory failure และ recovery — container | ผ่าน exact host test และ evidence 4 records | 106.67 วินาที |
| Worker MicroVM | ผ่าน exact host test | 156.48 วินาที |
| Timeout/memory failure และ recovery — MicroVM | ผ่าน exact host test และ evidence 4 records | 146.47 วินาที |

ทั้ง 7 รายการมี summary `1 passed; 0 failed; 0 ignored` ไม่มี skip
wrapper `validate-model-host.py` exit 0 รวม build/probe ด้วยเป็น 9 successful commands
baseline worker tests ตรวจ wrong hash แล้วไม่มี token, verified inference,
streamed output ตรง final output และยกเลิกหลัง delta ได้จริง

failure suites ตรวจ request deadline 100 ms และ memory budget 128 MiB
พร้อม verified inference ใหม่ด้วย client/pins เดิมหลัง failure แต่ละครั้ง
ทั้ง 12 evidence records ยืนยัน descendants reaped และ staging clean

| Tier | Timeout elapsed รวม staging/cleanup | Memory failure ที่ยืนยันได้ |
|---|---:|---|
| Process namespace | 5,766 ms | allocation-failure, 33,248 ms |
| Container | 5,462 ms | allocation-failure, 31,766 ms |
| MicroVM | 14,635 ms | ram-backed-staging-capacity, 17,082 ms |

100 ms เป็น worker request deadline ซึ่งไม่รวม staging/boot preparation
จึงไม่ใช่หลักฐานว่า latency รวมเท่ากับ 100 ms ส่วน memory failure ของ MicroVM
เกิดจาก RAM-backed staging เต็มก่อน inference ไม่ใช่หลักฐาน inference/kernel OOM

model/kernel/rootfs/Firecracker/pins และ worker hashes ก่อน–หลัง validation ตรงกัน
`model/integrity.json` ระบุ `artifacts_unchanged: true` และ validation source hashes
ยังตรงกับ source ที่ใช้เริ่มรัน ไม่มีการ download หรือเปลี่ยน artifact pins

## Dashboard: ข้อผิดพลาดที่พบและการแก้เพิ่ม

ใช้ dashboard server จริงบน `127.0.0.1` พร้อม HTTP clients 3 ตัวอ่าน HTML,
Prometheus และ JSON ระหว่างเขียน audit สังเคราะห์ที่มี v2 hash chain
กำหนด retention 200 events และตรวจรายการใน SQLite เทียบกับ source order

รอบแรกที่ `50b5d0e` ผ่าน burst/partial write/SQLite lock/rotation แต่ล้มตอน restart
หลังประมาณ 66 วินาที: DENY 14 รายการในหน้าต่างล่าสุดหาย และมี events เก่ากว่า
เข้ามาแทน สาเหตุคือ cursor อยู่ใน memory และ `INSERT OR IGNORE` ทำให้ fingerprint
ของแถวที่ยังเหลือใน DB ไม่ได้จัดลำดับใหม่ แต่แถวเก่าที่ถูก purge ถูก reinsert
ด้วย event IDs ที่ใหม่กว่า แล้ว purge กลับไปลบรายการที่ควรเก็บ

แก้ใน [dashboard](../scripts/aivm-dashboard.py) ดังนี้:

1. เก็บ cursor, inode/offset, witness bytes และ continuity/coverage state ใน SQLite
   transaction เดียวกับ events เมื่อ restart จึงอ่านต่อจากจุดที่ commit แล้ว
2. ตรวจ cursor ก่อน resume; ใช้ seal/continuation เชื่อมการ rotate หรือแจ้ง gap
   เมื่อไม่สามารถยืนยันได้ และรักษา gap warning ข้าม restart
3. สำหรับ DB รุ่นเดิมที่ไม่มี cursor จัดลำดับ duplicate events ตาม source ระหว่าง
   backfill ก่อน purge เพื่อรักษารายการล่าสุดหลังอ่านครบ
4. เพิ่ม regression สำหรับ restart หลัง purge, DB รุ่นเดิม, cursor-write rollback,
   restart หลัง seal และการรักษา coverage gap ข้าม restart

เพิ่มการทดสอบจาก 11 เป็น **15 tests** ผ่านทั้งหมด
เก็บ migration regression ที่ล้มก่อนแก้ไว้ใน `dashboard-migration-before.log`
ผล soak รอบแรกอยู่ใน `dashboard/` ส่วนรอบสุดท้ายอยู่ใน `dashboard-final/`
จึงตรวจย้อนผลล้มเหลวได้โดยไม่ถูกเขียนทับ

## ผล dashboard รอบสุดท้าย

| รายการ | ผล |
|---|---|
| Workload รวม | 42,478 records สังเคราะห์ |
| ช่วง traffic ต่อเนื่อง | 120 วินาที มี restart และ live rotation |
| เวลารวม exercise | 127.70 วินาที รวม fault injection/verification |
| HTTP requests | 7,121; unexpected HTTP errors 0 |
| Burst เกิน 4 MiB และมี ALLOW มากกว่า retention | ไม่พลาด DENY ที่ต้องเก็บ; backlog แสดงถูกต้อง |
| Partial line | รอจนเขียนครบ แล้ว import ได้หนึ่งครั้ง |
| SQLite write lock จริง | read/import failure ถูกแจ้ง; retry หลังปลด lock ไม่ข้าม event |
| Restart/retention/live rotation | รายการล่าสุดตรง source order ทุก checkpoint |
| จงใจ rotate สองครั้งโดย consumer ไม่ได้อ่านไฟล์กลาง | รายงาน gap; ไม่อ้าง coverage ว่าครบ |
| Audit สังเคราะห์ทั้ง archive และ active log | `aivm audit` ตรวจ v2 chain ผ่าน |
| Peak sampled dashboard RSS | 28,344 KiB ประมาณ 27.7 MiB |
| HTTP latency p50 / p95 | 1.33 / 2.46 ms |
| HTTP latency สูงสุด | 5.01 วินาที ตรงกับ SQLite busy timeout ที่จงใจทดสอบ |

latency และ memory ข้างต้นเป็นค่าจาก exercise นี้ซึ่งรันร่วมกับ model validation
ไม่ใช่ benchmark หรือการยืนยันความเสถียรระยะยาว การเทียบ seal hash ของ dashboard
ตรวจ continuity ที่สังเกตได้ ไม่ได้ authenticate audit records

## Gate หลังแก้และผลที่ยังอธิบายไม่ได้

`make verify` รอบสุดท้ายผ่าน: format, strict clippy, Rust default 349 passed,
3 ignored, Python รวม 119 tests (skipped 2), evaluation และ demo 14/14
Dashboard suite ผ่าน 15 tests

เก็บความล้มเหลวของ gate รอบแรกไว้ด้วย: test
`response_does_not_allow_worker_to_outlive_deadline` ล้มที่ assertion ว่า error
ต้องมีคำว่า deadline แต่ assertion เดิมไม่พิมพ์ error จริง จึงยังระบุสาเหตุไม่ได้
exact test เดิมรันซ้ำผ่าน และ diagnostic ที่ใช้ fake worker/response/request
เดียวกันรันต่อเนื่อง 100 รอบ ได้ exit-deadline errors ถูกต้องทั้ง 100 รอบ
จากนั้น `make verify` ซ้ำผ่านทั้งชุด โดยไม่มีการแก้ Rust worker หรือ test นี้
ผลเหล่านี้ไม่ใช่หลักฐานว่าได้แก้ต้นเหตุของความล้มเหลวครั้งแรกแล้ว

ดู `verify-after-dashboard-fix.log`, `deadline-exact.log`,
`deadline-diagnostic.log` และ `verify-after-dashboard-fix-retry.log`
สำหรับผลทั้งหมด ไม่ได้นำผล retry ไปแทนที่ log ที่ล้ม

## หลักฐานและการตรวจซ้ำ

- `source-baseline.json`: commit, clean status และ source hashes ก่อนเริ่ม
- `model/host.json`, `validation-sources.json`, `results.json`: source identity/commands/results
- `model/artifacts-before.json`, `artifacts-after.json`, `integrity.json`: artifact integrity
- `model/failure-recovery-<tier>.json`: timeout, memory failure และ verified recovery/cleanup
- `dashboard/results.json`: ผลล้มของ dashboard เดิม
- `dashboard-final/results.json`: ผลรอบสุดท้าย, samples, source/harness/verifier hashes
- `dashboard-final/source-dashboard.py` และ `source.patch`: source ที่ใช้ทดสอบหลังแก้
- `dashboard-soak-before.py`, `dashboard-soak-final.py`: reproducible exercise ก่อน/หลังแก้
- `dashboard-regressions.log`, `verify-after-dashboard-fix.log`: regression และ gate หลังแก้
- `summary.json`, `manifest.json`: สรุปสถานะและรายการ hashes ของหลักฐาน

คำสั่ง host validation ใช้เหมือน [รายงาน 21 ตุลาคม](host-validation-2026-10-21.md)
โดยเปลี่ยน `--out` ไป directory ใหม่ ส่วน dashboard ตรวจซ้ำด้วย:

```bash
python3 target/host-validation/2026-10-23-50b5d0e/dashboard-soak-final.py \
  --out target/host-validation/2026-10-23-50b5d0e/dashboard-repeat \
  --duration 120
```

ใช้ output directory ที่ยังไม่มีอยู่เพื่อไม่เขียนทับหลักฐานก่อนหน้า
การแก้ dashboard เพิ่มในรอบนี้อยู่ใน commit เดียวกับรายงานฉบับนี้
