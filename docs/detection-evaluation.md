# ตรวจสอบขอบเขตการตรวจจับ

`scripts/eval-detection.py` รัน 30 สถานการณ์จาก
[`examples/detection/cases.json`](../examples/detection/cases.json):
โจมตี 20 กรณี, งานปกติ 6 กรณี และความสมบูรณ์ของ log 4 กรณี
ชุดนี้สร้างเพื่อหาจุดอ่อนและตรวจ regression ไม่ใช่ตัวอย่างสุ่มจาก traffic จริง
จึงนำเปอร์เซ็นต์ไปอ้างเป็นความแม่นยำใน production ไม่ได้

## วิธีรัน

```sh
python3 scripts/eval-detection.py \
  --output target/host-validation/logs/detection-rules.json

python3 scripts/eval-detection.py \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-limit 8 \
  --output target/host-validation/logs/detection-qwen.json

python3 -m unittest discover -s scripts -p 'test_detection.py' -v
cargo test -p aivm-adversarial --test detector_gateway
```

Model เป็นตัวเลือก รัน 8 กรณีแรกที่มี label สำหรับการตรวจจับโดยค่าเริ่มต้น
เพิ่ม `--model-limit 26` เพื่อทบทวนทั้ง 26 กรณีที่ eligible
แต่ละกรณีใช้ normalized events ตาม reviewer จริง สูงสุด 32 records
รายงานแสดง coverage และชื่อกรณีที่ไม่ได้ส่งให้โมเดลอย่างชัดเจน
โมเดลเห็นเฉพาะ events/signals ไม่เห็นคำอธิบายสถานการณ์ เจตนา หรือคำตอบที่คาดไว้
signals มาจากกฎเดิม จึงเป็นการวัดการทบทวนสัญญาณ ไม่ใช่การตรวจจับโดยอิสระจากกฎ

## สิ่งที่แยกวัด

1. **Policy conformance:** category และการตอบสนองตรงกับข้อกำหนดที่เขียนไว้
   ใน corpus หรือไม่ เช่น 19 denials ไม่สร้างทดแทน แต่ 20 boundary denials
   ใน session เดียวภายใน 60 วินาทีสร้างทดแทน
2. **Detection against scenario intent:** เมื่อผู้เขียนสถานการณ์กำหนดเจตนา
   เป็น attack/benign ระบบส่งสัญญาณได้ถูกต้องหรือไม่ แสดง TP/FP/TN/FN,
   precision, recall และ false-positive rate แยก rules/model
3. **Containment against intent:** นับการสร้างทดแทนเทียบกับ attack/benign
   อีกชุดหนึ่ง การไม่สร้างทดแทนไม่เท่ากับปล่อยให้โจมตีสำเร็จ เพราะ gateway
   อาจปฏิเสธคำสั่งไปแล้ว และนโยบายตั้งใจให้ containment ใช้เกณฑ์สูงกว่า alert
4. **Integrity:** hash ปลอม, timestamp ย้อนกลับ และ log ไม่สมบูรณ์
   ตรวจว่า stop/hold ตามนโยบาย ไม่รวมใน accuracy ของ attack/benign

`recall` นับ abstention ของโมเดลในกรณี attack เป็นการตรวจไม่พบด้วย
output ผิด schema หรือโมเดลล้มเหลวไม่ถูกนับเป็นผล clean/true negative
precision และ false-positive rate ใช้เฉพาะผลที่จำแนกได้ พร้อมแสดง
`classified_fraction` และจำนวน abstentions แยกต่างหาก ค่าไม่มี denominator
เป็น `null` ไม่ใช่ 100%

Exit 0 หมายถึงไม่มี policy regression และ source ไม่ถูกแก้ **ไม่ได้หมายถึง
ตรวจ attack ได้ครบ** Exit 1 หมายถึง policy regression; exit 2 เป็น runner error
รายงานเก็บ SHA256 ของ corpus, evaluator, detector sources, binary และ model
พร้อมค่า inference เพื่อให้ตรวจสอบรุ่นที่ทดสอบได้

## ขอบเขตของการทดสอบ

Corpus รวม low-and-slow, หลาย agent/session, threshold 19/20, หน้าต่าง
60/61 วินาที, benign misconfiguration, คำพูดในเอกสารที่เหมือน injection,
paraphrase, allowed sensitive access และ unknown rule tags
มีการทยอย append หลาย polls และ sealed rotation เพื่อทดสอบ correlation
ใช้ Rust `verify-audit` จริง, Python watcher จริง และ supervisor จริง
แต่แทนการ start/stop runtime ด้วย `RecordingAdapter` ที่บันทึก action เท่านั้น
ไม่มีคำสั่งโจมตีใน corpus ถูก execute และไม่มีการติดต่อ systemd จาก evaluator
เปรียบเทียบ hash ของ source ก่อน/หลังทุก reconciliation เพื่อกันการแก้ข้อมูล

`crates/aivm-adversarial/tests/detector_gateway.rs` เพิ่ม bridge อีกชั้น:
เรียก **ToolGateway จริง** เพื่ออ่านไฟล์ปกติ, ลอง path traversal 19/20 ครั้ง
และอ่าน `.env` ที่ policy ปฏิเสธ จากนั้นตรวจ chain ด้วย Rust แล้วส่ง audit
ที่เกิดขึ้นจริงเข้า Python rules พร้อมตรวจว่าไฟล์ไม่เปลี่ยน
จึงตรวจได้ด้วยว่า field/rule tags ที่ gateway ผลิตเชื่อมกับ detector ถูกต้อง
ส่วนการหยุด process จริงอยู่ใน host tests ของ
[recovery supervisor](recovery-supervisor.md)

## ผล baseline บนเครื่องนี้ (2026-10-15)

ทั้ง 30 กรณีทำตาม policy ที่ระบุ และ source ทุกไฟล์ไม่เปลี่ยน
แต่เมื่อนับตามเจตนาของสถานการณ์ ผลต่างออกไป:

| ตัวตรวจ | กรณี attack | ตรวจพบ | พลาด | กรณี benign | เตือน/ตอบสนองเกินเหตุ |
|---|---:|---:|---:|---:|---:|
| Rules: มี risk alert | 20 | 16 | 4 | 6 | 3 |
| Supervisor: สร้างทดแทน | 20 | 7 | 13 | 6 | 1 |
| Qwen: มี risk finding (8 กรณีแรก) | 5 | 3 | 2 | 3 | 2 |

Qwen ที่ทดสอบคือ Qwen2.5-Coder-1.5B-Instruct Q4_K_M, seed 42,
temperature 0 โมเดลตอบผ่าน schema 8/8 และตรงกับ category labels ครบ 6/8
สองกรณี burst โมเดลรายงาน boundary แต่ไม่รายงาน `deny_burst`
คำอธิบายบางรายการยังอาจไม่ตรงความหมายของ audit แม้ผ่าน schema
ไม่ได้แปลว่าผลวิเคราะห์ได้รับการยืนยันว่าถูกต้อง

กฎพลาด paraphrased injection, allowed sensitive read ที่มีเจตนาร้าย,
boundary ที่ใช้ rule tag ใหม่ และ allowed execution ที่สถานการณ์ระบุว่าร้ายแรง
งานปกติที่เป็น accidental path mistake, ตัวอย่าง injection ในเอกสาร และ
batch ที่ config path ผิด ทำให้เกิด false positives โดย batch หลังทำให้
supervisor สร้างทดแทนตาม policy แม้ไม่มีเจตนาร้าย

ผลที่สำคัญคือ **บางกรณี attack และ benign ให้ normalized input เหมือนกัน
ทุก field** เช่น allowed read ปกติกับ allowed sensitive read ที่มีเจตนาร้าย
หรือ boundary probe กับ path mistake รายงานแสดงกลุ่มเหล่านี้ใน
`indistinguishable_normalized_inputs` โมเดลที่เห็น input เท่ากันไม่มีข้อมูล
ให้แยกเจตนาได้ การแก้ต้องพิจารณาเพิ่มข้อมูลที่ปลอดภัยและเชื่อถือได้ เช่น
ชนิดทรัพยากร, ผลของการกระทำ หรือบริบทของงาน พร้อมวัด false positives ซ้ำ
การเปลี่ยน threshold หรือเปลี่ยนโมเดลอย่างเดียวไม่แก้ข้อจำกัดข้อมูลนี้

Baseline นี้ยังไม่ยืนยันการตรวจ exploit จริง, ความทนต่อผู้โจมตีที่ควบคุม host,
การโจมตีที่ไม่ผ่าน audit, ความแม่นยำบน production หรือ TEE/attestation
