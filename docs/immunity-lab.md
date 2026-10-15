# Immunity lab: ทดลองกฎก่อนเพิ่มการตรวจจับ

`scripts/immunity-lab.py` เพิ่มวงจรสร้างตัวอย่างดัดแปลง → เสนอกฎ → วัดผล
→ ออกรุ่นสำหรับ shadow → ย้อนกลับได้ เป็นการสร้าง rule artifacts แบบ offline
ไม่ได้ fine-tune น้ำหนัก Qwen หรือปรับ policy ของ gateway/supervisor โดยอัตโนมัติ

ห้องทดลองนี้สร้าง audit สังเคราะห์ใน directory ชั่วคราวและตรวจ chain ด้วย
Rust CLI จริง ไม่มีการ execute ข้อความโจมตีหรือบูต guest จากตัวอย่างเหล่านี้
การทดสอบ Gateway/Container/MicroVM จริงยังใช้ชุดทดสอบของ backend ตามเดิม

## วงจรที่เพิ่ม

1. `generate`: สร้าง training 18 กรณีและ holdout 19 กรณีแบบทำซ้ำได้
   ดัดแปลงคำสั่ง override ด้วยตัวพิมพ์ใหญ่ ช่องว่าง และ Unicode fullwidth
   พร้อม benign quotations, sensitive access ที่มีเจตนาต่างกัน และผู้โจมตี
   ที่ปลอม prefix ว่าเป็นตัวอย่างในเอกสาร
2. `propose`: Qwen เห็นเฉพาะ **training labels และ feature enums**
   ไม่เห็น holdout, raw path/intent, ชื่อ agent หรือข้อมูลลับ โมเดลเรียกผ่าน
   model-only `reason` ไม่มี gateway หรือสิทธิ์เรียก tool
3. `evaluate`: ทดสอบ training, holdout และ regression 26 กรณี attack/benign
   จาก corpus เดิม แยกผล baseline กับ baseline+candidate พร้อม false positives
   และ misses; integrity 4 กรณียังคงอยู่ในชุดทดสอบ detection เดิม
4. `release`: ประเมินใหม่ก่อนสร้าง content-addressed bundle และเปลี่ยน
   `active.json` แบบ atomic รุ่นที่ออกมีสิทธิ์เพียง `emit_alert` และ mode `shadow`
5. `shadow`: อ่าน audit จริงผ่าน verified watcher เดิม ส่ง JSONL แยก
   `baseline_alerts` กับ `shadow_findings` ต่อเนื่องได้โดยไม่มีการสั่ง runtime
6. `rollback`: ตรวจ hash, engine และประเมินรุ่นเก่าใหม่ก่อนเปลี่ยน pointer
   ประวัติรุ่นที่ใหม่กว่ายังคงอยู่

ค่าเริ่มต้น `propose` ที่ไม่ระบุ model ใช้กฎจาก operator seed เพื่อทดลอง plumbing
รายงานระบุ `operator_seed` ชัดเจน การระบุ `--model` จึงจะเรียก Qwen จริง
ถ้าโมเดลตอบผิด grammar หลัง 2 attempts จะจบด้วย error ไม่มี fallback เป็น
กฎ seed ที่แอบอ้างว่าได้จากโมเดล

## ขอบเขตภาษากฎและข้อมูล

แต่ละ candidate มี 1..4 กฎ แต่ละกฎมี `id`, `category` และ `all` ที่ประกอบด้วย
2..5 เงื่อนไข equality จาก enums เท่านั้น ไม่รับ code, regex, shell command,
เส้นทางไฟล์, grant/revoke/kill หรือ field เพิ่มเติม ปฏิเสธ ID และ predicates ซ้ำ

```json
{
  "id": "intent-override",
  "category": "prompt_injection",
  "all": {
    "action": "intent",
    "intent_cue": "override",
    "intent_context": "unmarked"
  }
}
```

Feature extractor เขียนและตรวจโดยคน: normalize NFKC/case/ช่องว่าง แล้วสกัด
`action`, `decision`, `resource_class`, `intent_cue`, `intent_context`
ประเภท resource และคำบ่งชี้ override มาจาก heuristic ที่กำหนดไว้ล่วงหน้า
Qwen เลือกเงื่อนไขภายในภาษานี้ ไม่ได้สร้าง feature ใหม่หรือเรียนรู้ความหมายเอง
prompt มีตัวอย่าง grammar ของกฎ seed จึงไม่ใช่การทดสอบว่าโมเดลค้นพบกฎใหม่
โดยปราศจากคำแนะนำ

`intent_context=quoted` เป็นเพียง prefix heuristic จากข้อความที่ไม่น่าเชื่อถือ
ไม่ได้รับรองว่าเป็นเอกสารจริง จึงมี forged quotation ใน holdout เพื่อแสดงช่องโหว่นี้
ประเภท category ยังบังคับ predicates ที่สัมพันธ์กับหลักฐาน เช่น prompt injection
ต้องมี action=intent และ intent_cue=override

## เงื่อนไขผ่านและข้อจำกัด

- ต้องตรวจ attack เพิ่มจาก baseline ได้อย่างน้อย 1 กรณีทั้ง training และ holdout
- ต้องไม่เพิ่ม false positives ใน training, holdout และ regression
- Candidate เพิ่มได้เฉพาะ advisory alerts ไม่ลบ baseline alerts จึงยังคง
  false positives เดิมอยู่ ต้องอ่าน baseline/combined metrics ทั้งคู่
- Release ผูกกับ training hash, manifest, candidate, engine source hashes
  และ binary hash ไม่เชื่อ pass flag ที่ส่งเข้ามาจากผู้เสนอ
- ถ้าเปลี่ยน corpus, engine หรือ runtime binary ต้องประเมินและออกรุ่นใหม่
- ไม่มีขั้น promote ไปเป็น enforcement ในรุ่นนี้ supervisor เดิมไม่อ่าน registry นี้

Holdout แยกตระกูลวลีจาก training **สำหรับการเสนอของ Qwen** แต่ feature
extractor และ curriculum ถูกออกแบบโดยคนร่วมกัน จึงไม่ใช่การทดสอบแบบ blind
ต่อผู้พัฒนาหรือหลักฐานว่าใช้ได้กับภัยใหม่ทั้งหมด มี sensitive-access controls
ที่จงใจให้ข้อมูลเหมือนกันทั้งสอง splits เพื่อบังคับไม่ให้กฎเดาเจตนาจากข้อมูลที่ไม่พอ
ห้ามใช้ผล holdout ป้อนกลับเข้า prompt แล้วอ้างว่า holdout ยังไม่เคยถูกเห็น

กฎที่ผ่านกับข้อมูลสังเคราะห์ยังอาจเตือนผิดบน traffic จริง จึงออกได้เฉพาะ shadow
ต้องเก็บและตรวจผลจริงก่อนเพิ่มสิทธิ์ตอบสนองในงานพัฒนาขั้นต่อไป
ไม่มีการนำ log จริงมาปรับ labels หรือฝึกเองโดยอัตโนมัติ เพื่อไม่ให้ข้อความโจมตี
เปลี่ยนความหมายของ benign/attack ได้โดยตรง

Registry/curriculum ต้องอยู่ใน host directory ที่ agent เขียนไม่ได้ โหมด directory
ต้องเป็น 0700 และผู้ใช้เจ้าของเดียวกันเมื่อเขียน มี single-writer lock และ atomic
0600 files SHA256 ตรวจความสอดคล้องภายใน ไม่ใช่ลายเซ็นจากบุคคลภายนอก
ผู้ที่ควบคุม host/UID และแก้ artifacts ทุกส่วนได้ยังอยู่นอกขอบเขตการป้องกันนี้

## ทดลองใช้

```sh
python3 scripts/immunity-lab.py --lab target/immunity-demo generate

# เลือก seed เพื่อทดสอบ pipeline
python3 scripts/immunity-lab.py --lab target/immunity-demo propose \
  > target/immunity-proposal.json

# หรือให้ Qwen จริงเสนอ candidate จาก training features
python3 scripts/immunity-lab.py --lab target/immunity-demo propose \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  > target/immunity-proposal.json

IMMUNITY_CANDIDATE=$(python3 -c \
  'import json; print(json.load(open("target/immunity-proposal.json"))["candidate"])')

python3 scripts/immunity-lab.py --lab target/immunity-demo evaluate "$IMMUNITY_CANDIDATE"
python3 scripts/immunity-lab.py --lab target/immunity-demo release "$IMMUNITY_CANDIDATE"

# replay หนึ่งครั้ง (ค่าเริ่มต้น --polls 1)
python3 scripts/immunity-lab.py --lab target/immunity-demo shadow vms/NAME/audit.jsonl

# เฝ้าดูต่อเนื่องจน Ctrl+C
python3 scripts/immunity-lab.py --lab target/immunity-demo shadow \
  vms/NAME/audit.jsonl --polls 0 --interval 2

python3 scripts/immunity-lab.py --lab target/immunity-demo rollback VERSION_SHA256
```

Shadow watcher pin รุ่นหนึ่งไว้ตลอดการทำงาน ต้องเริ่ม watcher ใหม่เพื่อใช้รุ่น
ที่ release/rollback ล่าสุด รองรับ partial writes และ sealed rotation ตาม watcher เดิม
source ไม่ถูกเขียน และ event เดิมไม่ถูกแจ้งซ้ำขณะ process เดิมทำงาน
เมื่อ restart จะ replay ไฟล์ปัจจุบันพร้อม watch_id ใหม่และไม่อ้างว่ามี durable cursor

Exit 0 คือ operation สำเร็จหรือ evaluation ผ่าน; exit 1 คือ gate ไม่ผ่าน;
exit 2 คือ input/model/artifact/verification error การไม่มีผลลัพธ์ที่ valid
ไม่ถือเป็น clean report

## ทดสอบ

```sh
python3 -m unittest discover -s scripts -p 'test_immunity.py' -v
```

ครอบคลุม grammar hostile input, การปกปิด raw text/holdout จาก prompt,
การปฏิเสธผลโมเดลโดยไม่ fallback, gate ที่จับ false positives, กฎเงียบที่ไม่เพิ่ม
การตรวจพบ, การผูก training/candidate/report, release/rollback, artifact ที่ถูกแก้
และ shadow replay ผ่าน Rust verifier จริงโดยไม่เปลี่ยน source

## ผลทดลองบนเครื่องนี้ (2026-10-15)

Qwen2.5-Coder-1.5B-Instruct Q4_K_M เสนอ candidate จริงที่ผ่าน grammar
แต่ไปจับ quoted context ทำให้เพิ่ม false positives ใน training/holdout
และไม่เพิ่ม true positives ใน training ด่านประเมินจึงปฏิเสธการ release
ไม่มีการแทนกฎนี้ด้วย seed แล้วอ้างว่าเป็นความสำเร็จของ Qwen

ทดลองวงจรที่ผ่านด้วย operator seed แยกต่างหาก ได้ผลดังนี้:

| ชุดจำลอง | ตรวจพบ attack เดิม | หลังเพิ่ม seed | False positives เดิม → ใหม่ |
|---|---:|---:|---:|
| Training (attack 9 / benign 9) | 2 | 8 | 2 → 2 |
| Holdout (attack 10 / benign 9) | 0 | 8 | 0 → 0 |
| Regression (attack 20 / benign 6) | 16 | 17 | 3 → 3 |

Seed ผ่าน gate และทดสอบ release สองรุ่น, rollback กลับรุ่นแรก และ shadow
บน audit สังเคราะห์จริงผ่าน CLI ครบ source ไม่เปลี่ยน Shadow ผลิต finding
โดยไม่สั่งกักกัน instance ยังพลาด forged quotation และ sensitive access
ที่แยกเจตนาไม่ได้จาก features ที่มี ตัวเลขนี้จำกัดเฉพาะ corpus ที่สร้างไว้
ไม่ใช่ความแม่นยำบน traffic จริง

หลักฐานการทดลองอยู่ใน `target/host-validation/immunity-demo/summary.json`
พร้อม candidate/evaluation/release/shadow/rollback artifacts ใน directory เดียวกัน
directory นี้เป็น local build artifact และไม่ถูก commit
