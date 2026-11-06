# Availability inventory experiment — 6 November 2026

รอบนี้ปรับ **การถ่ายทอด availability ที่โค้ดคำนวณแล้ว** ให้โมเดลตอบถูกตั้งแต่
attempt แรก พร้อมวัดความครบถ้วนของรายการข้อมูลที่ขาด ไม่ใช้ผลนี้อ้างว่า
โมเดลเข้าใจเจตนาโจมตีดีขึ้นหรือ semantic grounding ของข้อความอิสระผ่านแล้ว

## สิ่งที่เปลี่ยน

- builder ระบุ `present_fact_ids` และ `missing_fact_ids` ชัดเจนตาม field presence
  และบริบทที่ caller ส่งมา ไม่อนุมานจากค่า 0, ลิสต์ว่าง หรือคำว่า hidden ในชื่อ field
- `trusted_context` รับได้เฉพาะ operator_intent, process_state และ task_contract
  พร้อมค่า enum ที่กำหนด ใช้ synthetic operator fixtures ในการทดลองเท่านั้น
  ไม่ใช่ telemetry จาก host และไม่เปิดให้ model output ตั้ง availability เอง
- validator ตรวจ catalog เทียบกับค่าจริงและ flags ซ้ำ ถ้าขัดกันให้ `QC-SOURCE`
  ส่วนข้ออ้างผิดยังถูกปฏิเสธเหมือนเดิม ไม่มีการแก้ค่าหรือตัด field ให้ผ่าน
- prompt ฉบับสุดท้ายวาง inventory เดิมใกล้จุดตอบ และให้ `concern_source`
  ที่โค้ดคำนวณเป็น tag แสดง availability โมเดลต้องคัดลอก source fields ให้ตรง
  ไม่ใช้ label, case ID หรือ expected containment สร้างข้อมูลนี้
- grammar และ output contract `concern-claims-v1` เดิม ไม่จำกัดคำตอบที่เลือกได้
  ด้วยค่าของแต่ละเคส จึงยังตรวจความผิดพลาดจาก output ดิบทุก attempt ได้

นี่เป็นงานถ่ายทอดข้อมูลที่มี source อยู่แล้ว ไม่ใช่การให้โมเดลค้นหา missing facts
เอง ข้ออ้าง actor/count ที่เลือกเพิ่มยังต้องตรวจค่ากับ facts ก่อนรับ

## เกณฑ์ที่ตรึงไว้ก่อน holdout

คงเกณฑ์เดิมทั้งหมด รวมการนับ grounding violations ทุก attempt แม้ retry แก้ได้
เพิ่มสอง gate ที่เปิดใช้ชัดเจนในการทดลอง:

1. `--require-availability-complete`: missing_evidence ต้องตรง missing_fact_ids
   ครบทุกชื่อและไม่มีเกิน การตอบรายการว่างเมื่อยังมี missing IDs ไม่ผ่าน
2. `--require-first-attempt`: ทุกเคสต้องผ่าน validator ตั้งแต่ model invocation แรก
   schema error ที่ retry แก้สำเร็จก็ยังไม่ผ่าน gate นี้

การผ่านทั้งสองเงื่อนไขยืนยันการตอบครบและตรงตั้งแต่ครั้งแรกในชุดทดลอง
ไม่รวม abstention, rejected output หรือ unavailable เป็นผล clean

## ชุดข้อมูลและวิธีวัด

dev มี **4 matched pairs / 8 views** ใน `concern-availability-dev-v1.json`
แต่ละคู่มี audit เดียวกัน เปลี่ยนเฉพาะบริบทที่ให้/ไม่ให้ รวมค่าศูนย์,
ลิสต์ว่าง, actor ที่ถูกตัดจาก context และ paced-boundary counterexample
ที่เปิดผลไปแล้วและนำมาเป็น dev อย่างเปิดเผย

holdout ใหม่มี **6 matched pairs / 12 views** ใน
`concern-availability-holdout-v1.json` audit shapes ใหม่ทั้งหกไม่ซ้ำกับชุดที่
เปิดผลแล้วหรือ dev และ context-aware inputs ทั้งสิบสองไม่ซ้ำกัน
แต่ละคู่คง audit และ baseline response เดิมเมื่อเปลี่ยน availability
จึงไม่ถือว่านี่เป็นสิบสอง audit scenarios ที่เป็นอิสระกัน

ใช้ Qwen2.5-Coder-1.5B Q4_K_M เดิม, SHA256
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`,
seed 42, temperature 0, top_k 1, สี่ threads, context 4096, output 256 tokens
ไม่เปลี่ยน weights, grammar หรือเกณฑ์ยอมรับข้ออ้างระหว่าง dev candidates
วัดบน commit `15c45d7` พร้อม working-tree changes จึงผูก source snapshots/hashes ด้วย

## ผล dev และการเลือก prompt

| Candidate | รายการ missing ครบและถูก | ผ่าน validator ตั้งแต่แรก | Attempts | Gate รวม |
|---|---:|---:|---:|---|
| v1: inventory ใน facts | 2/8 | 7/8 | 9 | ไม่ผ่าน |
| v2: ย้ำ inventory ใกล้จุดตอบ | 6/8 | 6/8 | 10 | ไม่ผ่าน |
| v3: inventory + code-derived tag source | 8/8 | 8/8 | 8 | ผ่าน |

v1 ยังตอบ missing_evidence ว่างทั้งที่ขาด context ส่วน v2 คัดลอกรายการได้
แต่เลือก tag missing-context ผิดในสองเคสที่ข้อมูลครบแล้ว
v3 แยก field ที่เป็นการแสดงผลแบบ deterministic ให้โค้ดระบุ source ชัดเจน
แล้วให้โมเดลคัดลอก แทนการให้โมเดลเลือก tag จากเงื่อนไขเอง

v3 ผ่านทุก gate โดยไม่ต้อง retry ไม่มี schema/grounding rejects หรือ unavailable
รวม actor/count claims ที่ตรวจแล้ว 2 ข้อ และมีหนึ่ง advisory ว่างที่ถูกต้อง
เพราะข้อมูลครบและไม่มีข้ออ้างเพิ่ม รายการ missing ในเคสที่ข้อมูลยังขาดต้องครบ
จึงไม่ใช่การผ่านเกณฑ์ด้วยการตอบว่างทุกเคส

ทั้งสามรายงานและ source snapshots อยู่ใน
`target/security-concern-availability-dev-v1/`, `-dev-v2/`, `-dev-v3/`
เลือก v3 ก่อนเรียกโมเดลบน holdout และไม่ใช้ผล holdout ปรับ prompt ต่อ
dev v3 transcripts SHA256:
`a0d5419bff1ac91ba311617abcbf07da99e9b4e0349f8a3f2d719e2aca753a86`

## ผล holdout หลังตรึง v3

**ผ่านทุก gate: 12/12 views ถูกตั้งแต่ attempt แรก** รวม 12 invocations
ไม่มี retry, schema/grounding rejects, timeout หรือ unavailable
missing_evidence ครบและตรงกับ source ทั้งสิบสองเคส (เทียบ set ของ IDs ไม่บังคับลำดับ)
รวม missing context IDs ที่ตรวจแล้ว 18 รายการ
ทุก tag ตรงกับ concern_source ที่โค้ดคำนวณด้วย

โมเดลไม่เสนอ actor/count claims เพิ่มใน holdout รอบนี้เลย (`verified_claims=0`)
จึงไม่ใช้ผลนี้อ้างว่าความสามารถเลือก actor/count claims ดีขึ้น
มี advisory ว่างที่ถูกต้องสามเคสซึ่ง context ครบทั้งหมด ส่วนอีกเก้าเคส
ต้องรายงาน missing IDs ให้ครบจึงจะผ่าน ไม่สามารถผ่านด้วยการตอบ [] ทุกเคส
นี่เป็นความแม่นของการถ่ายทอด inventory แบบปิดชุด ไม่ใช่การค้นพบหลักฐานใหม่
หรือการตัดสินความเสี่ยงโดยโมเดล

containment ตรง baseline **12/12** และยังเป็น TP=4, FP=2, TN=4, FN=2
ไม่ได้ลด false containment ของ maintenance job และไม่ได้คืนสิทธิ์จาก tag none
Court ยังคง shadow/dry-run การเปิด enforcement ยังต้องผ่าน improvement gate
และเงื่อนไข operational อื่นแยกจากการทดลองนี้

หลักฐานอยู่ใน `target/security-concern-availability-holdout-v1/`:

- `report.json`, `baseline.json`, `prompt-freeze.json`
- `freeze-verification.json`: ค่าที่ตรึงไว้ตรงกันครบ 12 รายการ รวมแหล่งโค้ด,
  prompt, binaries, model, corpus, contract และการเปิด gate ทั้งสองจริง
- `replay-verification.json`: ตรวจ output ดิบใหม่ครบ 12 attempts โดยไม่เรียกโมเดล
  และได้ advisory, tag, missing IDs และ containment ตรงกับที่บันทึกทั้งหมด
- raw transcripts อยู่คู่กับ pinned binaries/config ใน `jury-run-*`
  SHA256 `89d46283ef6ab0eb6364d01ac8bab81468248b9efd9d1876f946b5cb5cf3104f`

base prompt SHA256:
`f5f277eefd7b9f7e4e1ad25b56954eec1fdb4b5819fd6548f01afadea93c7763`

## Baseline และการตรวจโค้ด

`eval-detection.py` ใช้ Rust audit verifier และ watcher/supervisor จริงตรวจ
ครบ 12 views ไม่มี policy regression; baseline containment TP=4, FP=2, TN=4, FN=2
FP สองกรณีเป็น matched pair ของ maintenance job ที่ตั้งค่าผิดและเข้าเกณฑ์กฎ
ชุดข้อมูลเปลี่ยนจากรอบก่อน จึงไม่เทียบจำนวน FP/FN ข้ามชุดว่าเป็นผลปรับปรุง
labels เป็น synthetic intent labels และไม่ถูกส่งให้โมเดล

`make verify` ผ่านกับ implementation ฉบับสุดท้าย รวม format, clippy,
Python/Rust tests และ demo 14/14; ชุด `test_qwen_*.py` ผ่าน 103 tests
ครอบคลุม inventory ที่ถูกแก้, context/flags ขัดกัน, คำสั่งใน context,
ค่าศูนย์/ลิสต์ว่าง, gate ที่ไม่ยอมให้ตอบว่างทุกเคส, schema retry,
matched holdout novelty และการเปลี่ยน source fields ระหว่างคู่ context โดยไม่ค้างค่าเดิม
graph ของ source code อัปเดตแล้วด้วย AST extraction

## คำสั่ง reproduction

```sh
python3 scripts/eval-qwen-concerns.py --corpus path \
  --corpus-path examples/security-concerns/concern-availability-dev-v1.json \
  --variants grounded \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --require-availability-complete --require-first-attempt \
  --output target/availability-dev-reproduction/report.json

python3 scripts/eval-qwen-concerns.py --corpus path \
  --corpus-path examples/security-concerns/concern-availability-holdout-v1.json \
  --variants grounded \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --require-availability-complete --require-first-attempt \
  --output target/availability-holdout-reproduction/report.json
```

หลังเปิดผลแล้ว ชุด holdout นี้ใช้ reproduction ได้ แต่หากจูน prompt ต่อ
ต้องสร้าง holdout ใหม่ ห้ามเปลี่ยนเกณฑ์หรือเรียกการวัดซ้ำว่าเป็น fresh holdout
