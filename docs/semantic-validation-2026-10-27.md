# Semantic verification validation — 27 ตุลาคม 2026

Baseline `9e85010` หลักฐานอยู่ใน `target/semantic-verification-2026-10-27/`
เพิ่ม workflow ตาม [คู่มือ](semantic-verification.md) โดยไม่แก้ model weights,
worker/controller pins หรือ corpus คุณภาพเดิม 6+8 งาน

## ผลที่ตรวจแล้ว

| ชุด | Candidate เริ่มต้นถูก | ผลที่ใช้ verifier/helper ถูก |
|---|---:|---:|
| Replay คำตอบ Qwen เดิมที่ผิด 2 ข้อ | 0/2 | 2/2 |
| Frozen synthetic bad-candidate probes | 0/6 | 6/6 |

`replay-verified/evidence.json` และ audit logs ครบทั้ง 8 ข้อ ตรวจคะแนน/chain/receipt
ซ้ำจาก Python validator แล้ว ข้อมูล replay ไม่ใช่ผล Qwen รอบสด และ synthetic
initial candidates ตั้งใจใส่คำตอบผิดเพื่อทดสอบการปฏิเสธกับ fallback

- `semantic-sandbox-fixed-fixture.log`: regressions 4 tests ผ่าน รวม wrong answers,
  feedback repair, forged receipt, protected source และ budget/gateway denial
- `properties-seeded.log`: properties ของ sorting และ signed addition ผ่าน
  512 cases ต่อ property ด้วย `PROPTEST_RNG_SEED=20261027` พร้อม fixed regressions
- `runtime-regressions.log`: runtime/supervisor/CLI regressions ผ่าน
- `cli-smoke-final.log`: CLI create/source/transition/semantic/receipt/audit ผ่าน
  และ budget หมดไม่สามารถใช้ receipt ของรอบก่อนมารับรองผลได้
- `clippy-features.log`: Clippy รวม llama/microvm/hardware และ all targets ผ่าน
- `ci-final.log`: `RUST_TEST_THREADS=1 make ci` ผ่านครบ รวม `make verify`,
  Python evidence tests และ semantic CLI smoke ใหม่ ไม่ใช้ผลนี้อ้างว่า quota/staging
  race ที่อยู่ในส่วน 3 ของแผนได้รับการแก้แล้ว

รอบแรก fixture ตั้ง build artifact ใหม่แต่ไม่ได้อยู่ใน allowlist จึงถูก gateway
ปฏิเสธตามที่ควร แก้ fixture ให้ใช้ `build:tests` ที่อนุญาตอยู่เดิม ไม่เพิ่มสิทธิ์
รอบ validator แรกตั้ง genesis/sequence ของ audit ไม่ตรงระบบเดิม จึงปฏิเสธรายงาน
แก้ validator ให้ตรวจ hash chain version 2 ที่ seq เริ่ม 0 และ genesis ว่าง
เก็บ evidence/log รอบเดิมไว้ ไม่เปลี่ยนคำตอบเพื่อให้คะแนนผ่าน

## ผล Qwen รอบสด

`fresh-host/evidence.json` ครบทั้ง 8 ข้อและ validator ผ่าน รันจริง 756.48 วินาที

| ชุด Qwen สด | คำตอบแรกถูก | หลัง feedback/helper ถูก |
|---|---:|---:|
| สองข้อเดิมที่ผิด | 0/2 | 2/2 |
| หก synthetic edge probes | 0/6 | 6/6 |
| รวม | 0/8 | 8/8 |

คำตอบแรก 6/8 ข้อเป็น JSON/i32 schema ที่ผ่านแต่ความหมายผิด อีก 2 ข้อได้
`output_rejected` จึงไม่มี output สำเร็จและไม่นับว่ารูปแบบผ่าน หลัง feedback
โมเดลซ่อม `code-result` ได้ 1 ข้อ อีก 7 ข้อใช้ `tool_solver` แล้วตรวจผ่านจริง
รวม inference attempts 16 ครั้ง; ไม่มี model infrastructure error ถูกนับเป็นผลผ่าน

ชุดนี้เลือกสอง regression ที่ทราบว่าผิดกับหกกรณีขอบเขตของ sort/C addition
จึงไม่เทียบ 0/8 นี้ตรง ๆ กับคะแนน transfer เดิม 6/8 ซึ่งมีโจทย์คนละชุด
ผลหลังใช้เครื่องมือไม่ได้แสดงว่า weights หรือความสามารถโมเดลล้วนดีขึ้น

ใช้ Qwen2.5-Coder 1.5B Q4_K_M และ approved worker/controller เดิมจากส่วน 1
context 512, output 96, 2 threads, temperature 0, top-k 1, seed 42
เพิ่มได้หนึ่ง repair attempt หลังครั้งแรก แล้วใช้ helper เมื่อยังไม่ผ่าน
Source ของ operator เปลี่ยนตาม typed task ระหว่าง runs; โมเดลเขียน source นี้ไม่ได้

`fresh-sandbox/test.log` ไม่ผ่านเพราะเปิด pinned controller ใน sandbox ไม่สำเร็จ
และ `verify-sandbox.log` ติด PermissionDenied ใน test เดิมที่ execute worker snapshot
การขอ host ครั้งแรกติด usage limit ของระบบอนุมัติ จึงยังไม่รันทดสอบในครั้งนั้น
ภายหลังระบบอนุมัติกลับมาใช้งานได้และ `host-prerequisite.log` ผ่าน จึงรัน host CI
และ fresh evaluation แยกจากผลที่ล้มเหลวข้างต้น

Validator สุดท้ายเพิ่มการเก็บ source hashes ก่อนเริ่ม subprocess และปฏิเสธหาก source
เปลี่ยนระหว่างรัน ตรวจ fresh reports เดิมซ้ำกับ checker สุดท้ายใน
`evidence-final-revalidation.json` โดยไม่เปลี่ยน prompts, outputs หรือคะแนน
`semantic-changes.json` วิเคราะห์ผล raw/structured เดิมแยกต่างหาก: เคส sort
ที่เคยเรียงถูกแต่ครอบ Markdown กลายเป็น JSON ที่เรียงผิด แม้ strict oracle ตกทั้งคู่
การวิเคราะห์นี้ไม่ตัด fence เพื่อเพิ่มคะแนนและไม่เปลี่ยน oracles เดิม

ผล `verified` ยืนยันเฉพาะ typed task/inputs ที่กำหนดและสัญญาที่ผ่าน
รองรับ sort และ C addition ตามขอบเขตเท่านั้น ไม่ใช้ผลนี้รับรองคำตอบทั่วไป
