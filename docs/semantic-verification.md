# Semantic verification และตัวช่วยคำนวณ

Operator เลือก task ที่มีสัญญาชัดเจน แล้วให้โมเดลตอบ JSON, ตรวจคำตอบด้วย Rust
และ C ที่รันจริง, ส่ง feedback ให้แก้ได้ตาม budget และใช้ตัวช่วยเมื่อยังไม่ผ่าน
คำตอบที่ยอมรับต้องมี verification receipt จาก gateway และผ่านตัวตรวจของ task
ไม่มีฟิลด์ที่ให้โมเดลอ้าง receipt หรือแก้ expected answers เอง

รองรับสอง task แบบ opt-in:

- `sort`: array ของ i32 ไม่เกิน 64 ค่า ตรวจ ascending order และ multiset
  รวมจำนวนค่าซ้ำ รองรับค่าติดลบ, array ว่าง และขอบเขต i32
- `c_add`: ผลของ `int add(int a,int b){return a+b;}` สำหรับ input i32
  ตรวจ `checked_add` ก่อนรัน C และปฏิเสธ task ที่ผลรวมเกิน i32
  นี่เป็น contract ของฟังก์ชัน addition ที่กำหนด ไม่ใช่ arbitrary C evaluator

โจทย์ภาษาธรรมชาติและ typed task ต้องตรงกันโดย operator เป็นผู้กำหนด
ระบบไม่ได้แปลง prompt ใด ๆ เป็น task นี้โดยอัตโนมัติ

## Workflow และขอบเขตสิทธิ์

1. ตรวจ task, budget และ operator verifier template ซึ่งต้องมี `argv: []`,
   ไม่มี `stdout_contains` และมี `prepare` สำหรับ compile/link
2. ปฏิเสธเมื่อ write capability ของโมเดลครอบคลุม `workspace/semantic.c`
   อ่าน source ผ่าน gateway และตรวจ bytes ให้ตรงกับโปรแกรมที่สร้างจาก typed task
3. Compile ด้วย `-pipe` และ link ตาม `verification.prepare` ของ operator
   ทุก action ใช้ policy, capability, build slots และ sandbox เดิม
4. รับคำตอบโมเดลเป็นข้อมูล JSON, ตรวจ i32/schema และ properties ใน Rust
   แล้วเรียก C helper ด้วย argv แบบ literal เพื่อยืนยันคำตอบอีกครั้ง
5. เมื่อผิด บันทึก DENY และ feedback จากตัวตรวจ แล้วขอคำตอบใหม่ตาม budget
   ไม่ใช้ stdout ของโปรแกรมเป็น instruction ของโมเดล
6. เมื่อโมเดลยังไม่ผ่าน Rust สร้าง candidate แล้วให้ C ที่รันจริงยืนยันผล
   โหมด sort ใช้ C `qsort`; โหมด c_add เรียกฟังก์ชัน C จริง
   ตรวจ marker ของ output รวม newline และเรียก verifier แยกอีก invocation

ตัวตรวจ Rust ของ sort ใช้ order และความครบของสมาชิก แยกจาก C qsort
ผลที่คืนจาก Rust จะรับได้เมื่อ C ยืนยันผลตรงกันเท่านั้น ไม่มีการอ่าน exit code
จากข้อความ stdout เพื่อสร้าง receipt Gateway ใช้ structured sandbox outcome เดิม
Receipt ผูกกับ argv ของ candidate, compile plan, binary และ workspace digest
ซึ่งมี source ของ operator รวมอยู่ด้วย

โมเดลไม่ได้เพิ่ม capability, allowlist หรือ state guard ให้ตัวเอง
การเปิด workflow นี้ไม่เปลี่ยนค่าเริ่มต้นของ `reason` หรือ agent loop เดิม
Compiler/solver ที่ policy ไม่อนุญาต, source ไม่ตรง, build ล้ม หรือ budget หมด
จบเป็น `failed` และไม่คืน output ที่ verified

ค่าเริ่มต้นคือ model attempts รวมครั้งแรก 2 ครั้ง, gateway actions 12 ครั้ง,
output 96 tokens และระยะเวลา 300 วินาที Action budget นับ source read,
compile/link และแต่ละ solver/verifier invocation ด้วย Deadline รวมตรวจที่ขอบเขต
แต่ละ phase; worker ยังคุม hard deadline ราย inference ตาม config เดิม
ไม่ได้เพิ่ม watchdog ที่ interrupt backend ใด ๆ ได้เองจาก trait `Model`

## ลองผ่าน CLI

ตัวอย่างใช้ Echo เพื่อทดลอง fallback โดยไม่ต้องดาวน์โหลดโมเดล ตัว helper ยังคง
ต้อง compile/run และมี receipt จริง ตรวจ CRT paths ด้วย `cc -print-file-name=crt1.o`
แล้วปรับ [config](../examples/semantic.yaml) ให้ตรง host ก่อนใช้

```bash
aivm create semantic --config examples/semantic.yaml
aivm semantic-source --task examples/semantic-sort.json > vms/semantic/workspace/semantic.c
aivm transition semantic ANALYZE
aivm transition semantic MODIFY --confidence 0.95
aivm semantic semantic --task examples/semantic-sort.json \
  --prompt 'Sort [3,-2,3,0] ascending. Return JSON only.' --json
aivm audit semantic
```

`semantic-source` เป็นคำสั่ง operator; source ต้องอยู่นอก write scope ของโมเดล
เปลี่ยนโจทย์เป็น [c_add](../examples/semantic-add.json) โดยให้ operator สร้าง source
ใหม่จาก task เดียวกันก่อนรัน `semantic` พร้อม prompt ที่ตรงกัน
CLI คืน exit code ไม่เป็นศูนย์ถ้าผลสุดท้ายไม่ verified

API คือ `Runtime::run_semantic(task, prompt, budget)` หรือ
`Supervisor::run_semantic(name, task, prompt, budget)` ซึ่งถือ VM lifecycle lease
ผล `SemanticRun` แยก `model_with_verifier`, `model_repair_with_verifier` และ
`tool_solver` พร้อม raw successful outputs, format/schema/task correctness,
infrastructure status, termination, actions และ receipts

## การทดสอบและการรายงาน

Proptest 1.11.0 เป็น dev dependency แบบ `std` ใช้สร้าง inputs สำหรับตัวตรวจ/runtime
512 กรณีต่อ property ไม่เรียกโมเดลจริงหลายร้อยรอบ Failure persistence ของ Proptest
เก็บ seed ใน `proptest-regressions` เพื่อ replay; เคสผิดเดิมเก็บเป็น regression โดยตรง
ทดสอบซ้ำด้วย seed ของรอบนี้ได้ด้วย `PROPTEST_RNG_SEED=20261027`

```bash
cargo test -p aivm-runtime --test semantic_properties
cargo test -p aivm-runtime --test coding_workflow semantic_
python3 -m unittest discover -s scripts -p test_semantic_quality.py
python3 scripts/smoke-semantic.py

# Replay คำตอบเดิม 2 ข้อและ bad candidates ของ synthetic probes อีก 6 ข้อ
python3 scripts/eval-semantic-quality.py --out target/new-semantic-replay

# Qwen รอบสด; ใช้ Cargo target directory แยกจาก worker binary ที่ config pin ไว้
python3 scripts/eval-semantic-quality.py --config /absolute/path/to/pinned-config.json \
  --out target/new-semantic-fresh
```

Inputs/oracles ใน [semantic corpus](../examples/semantic-quality.json) ตรึงก่อนประเมิน
Validator ตรวจคะแนนซ้ำจาก output, task/config/corpus identity, SHA-256 และ audit chain
รวมทั้งตรวจ final receipt กับ entry จริง รายงาน replay/probes แยกจาก fresh model
Model infrastructure error ไม่ถูกนับเป็นผลประเมินสดผ่าน แม้ helper จะตอบถูกได้
ชุดนี้เป็น targeted synthetic probes ไม่ใช่ independent production benchmark

ดู [ผลการตรวจ 27 ตุลาคม](semantic-validation-2026-10-27.md)
