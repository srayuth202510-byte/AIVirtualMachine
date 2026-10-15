# Audit watcher: ตรวจ log ต่อเนื่องแบบแจ้งเตือนเท่านั้น

ต่อจาก [audit reviewer](audit-reviewer.md) โดยอ่านข้อมูลที่เพิ่มเข้ามาเป็นช่วง
จำประวัติสำหรับกฎตรวจ DENY ถี่ และให้ Qwen ทบทวนเบื้องหลัง ไม่มีการกัก,
หยุด process, grant/revoke หรือแก้ policy อัตโนมัติ

## เริ่มใช้

```bash
python3 scripts/qwen-audit-watch.py path/to/audit.jsonl \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

ไม่ระบุ `--model` จะใช้เฉพาะกฎ กด Ctrl+C เพื่อหยุด ตัวอย่างที่มีไฟล์อยู่แล้ว:

```bash
python3 scripts/qwen-audit-watch.py examples/audit-review/boundary.jsonl \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --polls 2
```

`--polls N` หยุดหลังอ่าน N รอบ (ค่าเริ่มต้น 0 = เฝ้าต่อ) ตอนจบจะรอ model job
ที่กำลังรันให้เสร็จหรือ timeout จึงอาจใช้เวลานานกว่าจำนวนรอบ × interval
สคริปต์ไม่แก้ audit ต้นฉบับ; ไฟล์ snapshot/config/binary อยู่ใน temp directory

## ลำดับการทำงาน

1. build/copy CLI ครั้งเดียว แล้วเริ่มด้วย `watch_started`
2. อ่านทุก 2 วินาที (`--interval 0.05..60`) และใช้ Rust ตรวจ hash chain ของ
   prefix ที่เขียนเสร็จแล้วก่อนนำเหตุการณ์มาใช้
3. เทียบ prefix กับ bytes ที่เคยอ่านแล้ว หากข้อมูลเดิมถูกแก้หรือตัดทิ้งจะหยุด
4. ป้อนเฉพาะ records ใหม่เข้ากฎที่จำหน้าต่างเวลา 60 วินาทีข้าม poll ได้
5. ส่งรายงานกฎออกทันที ส่วน Qwen มี worker หนึ่งตัวและไม่มีคิวสะสมไม่จำกัด
6. Qwen รับเฉพาะ normalized events และเสนอความเห็นแยกจาก rule alerts

แต่ละบรรทัด stdout เป็น JSON พร้อม `advisory_only: true` และ `watch_id`
ซึ่งใช้แยกการรันแต่ละครั้ง การแจ้งเตือนไม่ถูกส่งออกบริการภายนอก

## รายงานที่พบ

| type | ความหมาย |
|---|---|
| `watch_started` | เริ่มเฝ้าดู; ยังไม่ได้รับรองไฟล์หรือความปลอดภัย |
| `events` | พบ records ใหม่ที่ตรวจ chain ผ่าน มี `rule_alerts` และหลักฐาน |
| `waiting_for_complete_record` | ยังไม่มี newline ปิด record ท้ายไฟล์ จึงยังไม่ตีความ |
| `waiting_for_log` | ไฟล์ยังไม่ปรากฏ/อยู่ในช่วง rename; ยังรอ ไม่ได้รายงานว่า log ปกติ |
| `rotation` | พบ seal ที่ตรวจผ่านและเตรียมตรวจรอยต่อไฟล์ใหม่ |
| `model_review` | ผลของ model job ที่เสร็จแล้ว ผูกกับ batch/event IDs ของมัน |
| `monitor_error` | ความต่อเนื่อง/ความถูกต้อง/ขนาดเกินขอบเขต; หยุด watcher ด้วย exit 2 |
| `watch_stopped` | ผู้ใช้หยุดด้วย Ctrl+C |

ตอนเริ่มโปรแกรมจะอ่านจากต้นไฟล์ปัจจุบัน `initial_backfill: true` แสดง batch
แรกซึ่งอาจเป็นประวัติเก่า ไม่ได้หมายความว่าเหตุการณ์เกิดขึ้นขณะเริ่ม watcher
รอบที่ไม่มีข้อมูลใหม่จะไม่ส่ง rule alerts เดิมซ้ำ

## หลักฐานและการหมุนไฟล์

event ID ใน watcher เพิ่มต่อเนื่องภายในหนึ่ง `watch_id` ไม่รีเซ็ตเมื่อ rotate
ใน `evidence` มี generation, source_seq, timestamp และ hash_entry ให้ย้อนกลับ
หา record จริงได้ แม้ `seq: 0` จะปรากฏซ้ำในไฟล์ใหม่

ถือ fd ของไฟล์เดิมไว้เพื่ออ่าน seal ที่เพิ่งเขียน ไม่อาศัยชื่อ archive
เมื่อเปลี่ยน inode ต้องมี `action: seal` ที่ท้ายไฟล์เดิมและตรวจ hash ผ่าน
record แรกของไฟล์ใหม่ต้องต่อ `hash_prev` กับ tip นั้นก่อนใช้ข้อมูล
DENY ในไฟล์เก่าและใหม่จึงยังนับในหน้าต่างเดียวกันได้
seal ต้องตรงรูปแบบที่ AuditWriter สร้างด้วย: state `AUDIT`, decision `allow`
และ result อ้าง tip ก่อน seal การมี action ชื่อ `seal` เพียงอย่างเดียวไม่พอ

หากมีหลาย rotations จน watcher ไม่เห็นไฟล์กลาง, chain ขาด, copytruncate,
ไฟล์ถูกสลับโดยไม่มี seal หรือมี record ค้างในไฟล์เดิม จะรายงาน error
และหยุด แทนการข้ามข้อมูลโดยไม่แจ้ง ต้องให้ operator ตรวจ chain/ประวัติที่ขาด

## Qwen และขอบเขตการมองเห็น

- กฎเดินต่อระหว่าง Qwen inference; โมเดลไม่มีอำนาจปรับหรือลบ rule alerts
- เริ่ม model job ได้ไม่ถี่กว่า 30 วินาที (`--model-every 1..600`)
- ถ้า worker ไม่ว่าง batch ใหม่จะมี `model_status: skipped_busy`; ถ้ายังอยู่ใน
  cooldown เป็น `skipped_cooldown` ข้อมูล batch เหล่านี้ไม่ถูกเข้าแถวรออัตโนมัติ
- โมเดลเห็น context ท้ายสุด 32 events (`--max-events 1..64`)
  `model_coverage` บอกส่วนที่ไม่ได้เห็น จึงห้ามตีความว่าผล Qwen ครอบคลุมทุก batch
- ตัวโมเดลยังตรวจ schema และ event IDs เหมือน reviewer เดิม ข้อเสนอที่อ้าง
  เฉพาะ events เก่าโดยไม่มี event ของ batch ใหม่จะไม่ส่งซ้ำ
- `unavailable`/`invalid_response` ไม่ทำให้ rule alerts หาย และไม่ถือว่าปลอดภัย

ความจำอยู่ใน process เท่านั้น ไม่ persist ลง VM หรือฝึกโมเดลเพิ่ม
restart จะเริ่มจากต้นไฟล์ปัจจุบันและอาจเตือนเรื่องเดิมอีก; `watch_id` ใหม่ช่วยแยก
ผล ไม่ได้กู้หน้าต่างเวลาจากไฟล์ก่อน restart

## ขีดจำกัดและ trust

รองรับ v2 audit เท่านั้น สูงสุด 1 MiB / 4096 records ต่อไฟล์
ควร rotate ก่อนถึงเพดาน และมี records ในหน้าต่าง 60 วินาทีไม่เกิน 4096
หาก timestamp ย้อนหลังจะหยุด เพราะยังไม่สามารถรับรองการ correlate เวลาได้
สัญญาณกฎไม่ใช่ข้อพิสูจน์เจตนาโจมตี และโมเดลอาจพลาดหรือแจ้งเกินจริง

การตรวจ hash เป็นความสอดคล้องภายใน stream ที่เห็น ไม่ใช่ external authentication
ไม่ยืนยันประวัติก่อนเริ่ม watcher และไม่กันผู้ควบคุม host ที่แก้ log พร้อมคำนวณ
hash ใหม่ได้ การไม่พบคำเตือนไม่ใช่ผลอนุญาตให้ดำเนินการ

## ตรวจซ้ำ

```bash
python3 -m unittest discover -s scripts -p 'test_qwen_*.py'
python3 scripts/smoke-qwen-watch.py
python3 scripts/smoke-qwen-watch.py \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

smoke สร้าง log ชั่วคราว เติม DENY ทีละส่วนจนข้าม threshold แล้วหมุนไฟล์
ตรวจว่ามี boundary alert และ burst alert อย่างละครั้ง และตรวจ byte contents
ของทั้งไฟล์ปัจจุบันและ archive ว่า watcher ไม่เปลี่ยนข้อมูล
fixture ต้นฉบับใน repository ไม่ถูกแก้

บน host นี้ผ่านทั้ง rules-only และ Qwen จริง: ตรวจพบ burst ขณะ model job
ยังทำงาน (`skipped_busy`), รอ record ที่เขียนไม่จบได้, ตาม rotation หนึ่งครั้งได้
และ Qwen คืนผลที่ผ่าน schema/evidence validation
หลักฐานอยู่ใน `target/host-validation/logs/aivm-watch-qwen-smoke.json`

Python regression tests รวมทั้งหมด 22 ข้อผ่าน, rules-only streaming smoke
ผ่าน และ `make ci` ผ่าน โดย CLI smoke ตรวจด้วยว่า log ที่ถูกแก้ย้อนหลัง
ทำให้ watcher ส่ง `monitor_error` และไม่ emit events จากข้อมูลนั้น
