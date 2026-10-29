# ทดลองให้โมเดลสรุปความเข้าใจโจทย์ก่อนแก้บั๊ก

โหมดนี้เลือกเฉพาะงานที่ไม่ผ่านและส่ง source เดิมกลับมาใน benchmark เดิม
การเลือกตรวจ report, audit และ artifact ก่อน ไม่ใช้รายชื่อที่เดาไว้
รอบเริ่มต้นของวันที่ 28 ตุลาคม 2026 มีงานลักษณะนี้ 13 จาก 24 งาน

ก่อน agent เริ่มแก้ ให้โมเดลเดียวกันตอบ JSON สั้น ๆ สามช่อง:

- `expected_behavior`: พฤติกรรมที่โจทย์ต้องการ
- `suspected_bug`: จุดที่สงสัยว่าผิดใน source
- `planned_change`: สิ่งที่จะเปลี่ยน

ขอเพียงข้อสรุปสั้น ๆ ไม่ขอลำดับความคิดโดยละเอียด ขั้นนี้เห็นเฉพาะ bug report กับ
source ตั้งต้น ไม่ส่ง reference patch หรือ oracle ให้ในคำขอนี้
agent ตามปกติยังอ่าน workspace ผ่าน RAG/gateway ตามสิทธิ์เดิมได้ รวม verifier ที่อ่านได้แต่แก้ไม่ได้
คำตอบที่ schema ผ่านจะถูกส่งต่อเป็นข้อเสนอของโมเดลใน task แก้โค้ด
ถ้ารูปแบบผิดหรือ inference ล้ม จะเก็บ raw/error แล้วรัน agent ด้วย task เดิมโดยไม่มีคำอธิบาย
ไม่ลองอธิบายซ้ำอย่างเงียบ ๆ และไม่ถือว่า schema ผ่านแปลว่าเข้าใจโจทย์ถูก

เก็บ system/prompt/raw/parsed/error และเวลาของขั้นอธิบายใน `task_interpretation`
ของแต่ละ case ใน report เพื่อให้ operator อ่านเทียบกับ source และผลทดสอบจริงได้
คำอธิบายไม่ใช่ tool intent, receipt หรือหลักฐานว่าซ่อมสำเร็จ

```sh
python3 scripts/run-repair-benchmark.py --mode interpretation_experiment \
  --baseline-report target/repair-release-f47141c/model-benchmark/report.json \
  --model-config target/repair-release-f47141c/candidate.json \
  --out target/repair-interpretation-new
```

output directory ต้องใหม่และ config ต้องตรง baseline ทั้งไฟล์ จึงคง model/worker pins,
sampling และ limits เดิม ไม่ rebuild หรือ repin worker ให้ผ่านโดยอัตโนมัติ
repair loop ใช้งบเดิม 16 steps รวม operator verification ส่วนขั้นอธิบายเป็น model call เพิ่มอีกหนึ่งครั้ง
รวม call และต้นทุนนี้ใน cost ของ case แล้ว

รายงานทดลองใช้ schema 3 / mode `interpretation_experiment` และเฉพาะ subset ที่เลือก
ตัวตรวจ release แบบปกติปฏิเสธรายงานนี้ ต้องระบุ case IDs สำหรับการตรวจโหมดทดลองโดยตรง
runner ตรวจ source/config/baseline ก่อนและหลัง พร้อม audit-backed outcomes และ artifact hashes
ผลบน development source ที่ยังไม่ commit เป็นหลักฐานการทดลอง ไม่ใช่ release approval

ต้องอ่านว่าโมเดลอธิบายถูกหรือไม่แยกจากคะแนน protected verifier:
อธิบายถูกแต่ยังเขียน source เดิมคือปัญหาที่เกิดระหว่างการวางแผนกับการลงมือ
อธิบายคลาดเคลื่อนและแก้ไม่สำเร็จสนับสนุนให้ตรวจ prompt/ความสามารถด้านโจทย์นั้นเพิ่ม
การเทียบกับ baseline เป็นการวัดผลของ workflow ที่มี call เพิ่มและเลือกเฉพาะงานที่เคยตก
ไม่ใช้แทนคะแนนทั้ง corpus หรือการเปรียบเทียบความสามารถโมเดลล้วน ๆ
