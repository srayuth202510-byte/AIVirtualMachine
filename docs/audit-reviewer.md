# Audit reviewer: กฎตรวจพื้นฐาน + Qwen แบบอ่านอย่างเดียว

หากต้องการติดตาม records ที่เพิ่มเข้ามาและ correlate ข้าม poll/rotation
ดู [audit-watcher.md](audit-watcher.md)

วิเคราะห์ snapshot ของ audit JSONL แล้วแจ้งเหตุการณ์ที่ควรตรวจต่อ
ไม่มีคำตอบแบบ ALLOW/DENY จากตัว reviewer และไม่มีการ grant/revoke/execute
ตามคำแนะนำของโมเดล Policy/Gateway ของ VM เดิมยังเป็นผู้บังคับใช้

## วิธีใช้

ใช้เฉพาะกฎได้โดยไม่ต้องโหลดโมเดล:

```bash
python3 scripts/qwen-audit.py path/to/audit.jsonl
```

เพิ่มความเห็นจาก local Qwen:

```bash
python3 scripts/qwen-audit.py path/to/audit.jsonl \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

หรือทดลองกับ fixture ที่รู้คำตอบ:

```bash
python3 scripts/qwen-audit.py examples/audit-review/boundary.jsonl \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

สคริปต์ build CLI อัตโนมัติและใช้ temporary directory ที่แยกจาก VM เดิม
ผล JSON ออก stdout; build/model error แยกจากข้อมูลคำเตือน
ต้นฉบับ audit เปิดเพื่ออ่านเท่านั้น ไม่ instantiate Runtime ของ VM ต้นฉบับ
ไม่มีการเขียน audit, state หรือ config กลับเข้า VM นั้น

## สิ่งที่ตรวจ

| category | สัญญาณจาก audit |
|---|---|
| `boundary_violation` | DENY ที่มี rule path-traversal, symlink-escape หรือ boundary-write |
| `sensitive_access` | คำขอที่ถูก DENY และมีพาธข้อมูลอ่อนไหว หรือ rule เกี่ยวกับ secret/lease/HITL |
| `deny_burst` | อย่างน้อย 20 denied records ของ agent/session เดียวกันภายใน 60 วินาที |
| `prompt_injection` | intent มีคำชี้นำให้ข้ามคำสั่งเดิมหรือปิด policy ตามรูปแบบที่กำหนด |

สิ่งเหล่านี้เป็น **สัญญาณให้ตรวจต่อ** ไม่ใช่ข้อพิสูจน์ว่ามีผู้โจมตี
lease หมดอายุหรือการขอสิทธิ์ที่ไม่มีอาจเป็นงานปกติ และ keyword matching
ไม่ครอบคลุม prompt injection ทุกรูปแบบ จำนวน burst นับ records ไม่ใช่ requests

Qwen เห็นเฉพาะ event ID, actor ที่แปลงเป็นหมายเลข, timestamp, action/decision
จากรายการที่กำหนด และ signal categories ที่กฎพบ ไม่ส่ง raw resource paths,
agent/session names, intent text, rule/result strings เข้าโมเดล
จึงลดช่องให้ข้อมูลจาก audit กลายเป็นคำสั่งหรือเปิดเผยข้อความลับ
โมเดลทำหน้าที่ทบทวนข้อมูลที่แปลงรูปแบบแล้ว และอาจเสนอ `anomaly` ให้คนตรวจต่อ
ไม่ได้อ่านเนื้อหาไฟล์ต้นทางหรือค้นหาการโจมตีจากข้อความดิบ

## การรักษาขอบเขต

- ใช้ `aivm reason --config ... --prompt ...` ซึ่งเรียก model โดยตรง
  ไม่มี ToolGateway และไม่ parse คำตอบเป็น intent สำหรับรันเครื่องมือ
- Input ต้องเป็น v2 audit records และผ่าน `aivm verify-audit <snapshot>`
  หากข้อมูลเสีย, hash ไม่ตรง, JSON ไม่สมบูรณ์ หรือเป็น legacy v1 จะหยุดด้วย error
- ตรวจ duplicate JSON fields, schema, categories, severity และ event IDs
  ของคำตอบ Qwen ปฏิเสธเลขเหตุการณ์ที่ไม่มีจริงและ category ที่ไม่ตรง signal
  เหตุผลแบบข้อความยังเป็นข้อเสนอของโมเดล ไม่ได้ผ่านการพิสูจน์เชิงความหมาย
  รองรับ Markdown `json` fence เฉพาะกรณีที่ครอบ JSON ทั้งคำตอบ ไม่มี prose ภายนอก
- กฎกับโมเดลอยู่คนละส่วนในรายงาน (`rule_alerts` / `model_review`)
  โมเดลละเว้นหรือลด severity ก็ไม่ลบคำเตือนเดิมจากกฎ
- Model JSON ผิดรูปแบบจะ retry ได้อีกหนึ่งครั้ง หากยังผิดจะรายงาน
  `invalid_response`; inference error เป็น `unavailable` แต่ยังคืน rule alerts
- `validated_structure` หมายถึงรูปแบบและการอ้าง event ถูกต้องเท่านั้น
  ความเห็นโมเดลอาจพลาดภัยหรือแจ้งเตือนเกินจริงได้

## ขอบเขตข้อมูลและผลลัพธ์

อ่าน snapshot สูงสุด 1 MiB / 4096 records กฎตรวจทั้ง snapshot ส่วนโมเดล
ดูท้ายไฟล์ 32 records เป็นค่าเริ่มต้น เปลี่ยนได้ด้วย `--max-events 1..64`
รายงาน `model_coverage.truncated` แสดงว่ามีข้อมูลที่โมเดลไม่ได้เห็นหรือไม่
เหตุการณ์เก่าที่ยังเข้าเงื่อนไขจะยังอยู่ใน `rule_alerts`

การตรวจ chain ยืนยันความสอดคล้องภายใน snapshot ไม่ใช่การรับรองผู้เขียน
หรือการยืนยันว่าไม่มีการตัดท้ายไฟล์ ไม่มี external hash anchor ในเครื่องมือนี้
รองรับครั้งละไฟล์ สำหรับข้ามรอยต่อไฟล์ rotate ให้ตรวจด้วย `aivm audit <vm>`
ต่างหาก Burst ข้ามรอยต่อ snapshot ยังไม่ถูกนำมารวมกัน

exit 0 หมายถึงสร้างรายงานได้ ไม่ได้หมายความว่าปลอดภัยหรือโมเดลตรวจครบ
exit 2 หมายถึง input/build/runtime error ที่ทำให้สร้างรายงานไม่ได้
รายงานไม่มีอำนาจเปลี่ยนสิทธิ์ และยังต้องมี operator ตรวจเหตุการณ์

## ทดสอบและวัดผล

```bash
python3 -m unittest discover -s scripts -p 'test_qwen_*.py'
python3 scripts/eval-qwen-audit.py
python3 scripts/eval-qwen-audit.py \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

ชุดตัวอย่าง 6 กรณี: read ปกติ, ข้ามขอบเขต, อ่านข้อมูลอ่อนไหว,
DENY ถี่, instruction-override cue และ DENY ครั้งเดียวที่ไม่เข้าเกณฑ์
กฎต้องตรงกับ labels ทั้ง 6 และ evaluator ตรวจว่าต้นฉบับไม่เปลี่ยน
fixtures ผ่านตัวตรวจ hash ของ Rust ด้วย ไม่ใช้เพียง JSON ที่ไม่มี chain

คะแนน `rules_passed` กับ `model_passed` แยกกัน คำตอบโมเดลที่ผิด schema
หรือ inference ใช้ไม่ได้ไม่นับเป็นคำตอบถูก แม้กฎจะพบเหตุการณ์แล้วก็ตาม
evaluator exit 1 เมื่อผลไม่ตรง labels; exit 2 เมื่อการประเมินเกิด error
คะแนนเปรียบเทียบชุด category เท่านั้น ไม่ได้วัดความถูกต้องของ severity หรือเหตุผล

นี่เป็นชุดทดสอบขนาดเล็กที่โมเดลได้รับ signal labels จากกฎด้วย
ใช้ตรวจพฤติกรรมและข้อผิดพลาดของ pipeline ไม่ใช่ benchmark ความแม่นยำ
ด้านความปลอดภัยหรือหลักประกันว่าจะตรวจพบการโจมตีจริงทุกแบบ

## ผลทดสอบบนเครื่องนี้

- Python regression tests รวมตัวช่วยอ่านไฟล์เดิม: 12 ผ่าน
- Rules-only evaluation: category ตรง 6/6 กรณี
- Qwen2.5 Coder 1.5B Q4_K_M: category ตรง 6/6 กรณีในรอบสุดท้าย
  หลังปรับคำสั่งให้ชัดและรองรับ JSON fence ทั้งคำตอบ
- การทดลองก่อนปรับมีทั้งการพลาด category และการตอบผิดรูปแบบ จึงคง
  rule alerts แยกจากโมเดลเสมอ ไม่ให้คะแนนชุดเล็กนี้เพิ่มอำนาจตัดสินแก่ Qwen
- ลองกับ audit จริงของ local test VM จำนวน 6 records: ไม่พบ signals ตามกฎ
  หรือข้อเสนอเพิ่มจากโมเดล; hash ต้นฉบับก่อนและหลังตรงกัน
- `make ci`, strict Clippy แบบ all-features และ CLI smoke ผ่าน
  smoke ตรวจด้วยว่า model-only inference ไม่เพิ่ม audit/ไม่สร้างไฟล์ตาม intent
  และตัวตรวจ audit ปฏิเสธ snapshot ที่แก้ฟิลด์ย้อนหลัง

เก็บผลใน `target/host-validation/logs/aivm-qwen-audit-eval.json`,
`aivm-audit-rules-eval.json`, `aivm-audit-real-review.json`,
`aivm-audit-review-ci.log` และ `aivm-audit-review-clippy.log`
artifacts เหล่านี้ไม่อยู่ใน Git และถูกลบเมื่อ `cargo clean`
