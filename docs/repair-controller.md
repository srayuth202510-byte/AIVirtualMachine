# Repair controller: unresolved failures ข้ามทุก retry

Supervisor ถือ VM lease ตลอด `run_agent` และใช้ controller ใน runtime ผ่าน policy
เดียวกับ `Runtime::run_agent` โดยตรง ทั้งสองเส้นทางยังส่งทุก read/write/exec ผ่าน gateway
โมเดลแก้ controller, policy หรือ verifier contract ไม่ได้ผ่าน intent

## Ledger ที่ไม่ถูกย่อพร้อม observations

`AgentRun.repair_state` แยก `verification_failures` กับ `tool_errors`
failure ถูกเพิ่มจาก failed gateway verifier record เท่านั้น ไม่รับรายการที่โมเดลประกาศเอง
ถ้า stdout ของ verifier มีบรรทัดนี้ จะเก็บ input/expected/actual แบบมีโครงสร้าง:

```text
AIVM_CASE_FAILURE {"input":{"b":-3,"e":1},"expected":-3,"actual":9}
```

ถ้าไม่มี diagnostic ที่อ่านได้ เก็บ generic failure พร้อมข้อความและ receipt แทน
counterexample เป็นข้อมูลสำหรับซ่อม ไม่ใช่ verification authority
identity ของ failure ผูกกับ contract/input/expected; actual และ receipt ของ observation ล่าสุดอัปเดตได้

ทุกรอบที่เรียกโมเดลจะแนบ ledger นอกส่วน RAG/observations ที่ถูกล้างหรือย่อได้
tool error ใหม่ไม่แทนที่รายการ failure และ RAG query เลือก unresolved failure ก่อน tool error
tool errors เก็บสี่เหตุการณ์ล่าสุดใน context พร้อมจำนวนที่ย่อออก; audit snapshots เก็บประวัติเดิมไว้
unresolved failures ไม่ถูกตัดออกเพื่อให้ context พอดี ถ้าเต็มเพดานจะหยุดพร้อม overflow evidence
backend ที่รับ context ไม่ไหวต้องคืน error ตามปกติ ไม่ตัด failure เงียบ ๆ

สถานะ failure เปลี่ยนเป็น `resolved` หลัง canonical outcome ที่ gateway สร้างยืนยันว่า
full verifier ผ่านกับ workspace ปัจจุบันเท่านั้น ผูก `resolved_by` กับ outcome audit ID
การผ่าน probe, compile สำเร็จ หรือโมเดลส่ง `done` ไม่คลี่คลายข้อผูกพันเอง

## คำอธิบายผูกกับ patch ที่ใช้จริง

หลังมี structured counterexample ค่าเริ่มต้นขอคำตอบ JSON ในรูปนี้:

```json
{
  "failure_ids": ["failure:<host-issued-id>"],
  "path": "src/main.c",
  "change": "Initialize the accumulator to one so the counterexample does not multiply once too many.",
  "old_text": "int r=b;",
  "new_text": "int r=1;"
}
```

ขอเพียงข้อสรุปสั้น ๆ ไม่ขอลำดับความคิด โมเดลใช้ output mode JSON เดิมของ worker
จึงไม่เพิ่ม tool หรือเปลี่ยน worker protocol

controller ตรวจว่า failure IDs ยัง unresolved, path เป็น relative, old/new ต่างกัน และ payload มีขอบเขต
ผูกแผนกับ workspace digest ก่อน inference จากนั้นอ่าน source ผ่าน gateway
`old_text` ต้องพบเพียงจุดเดียว รวมถึงไม่อนุญาต overlapping matches ที่กำกวม
host ใช้ replacement หนึ่งจุดแล้วส่ง `filesystem.write` ผ่าน gateway ตามสิทธิ์เดิม
path อ่านไม่ได้/เขียนไม่ได้, fragment ไม่ตรง, workspace เปลี่ยน, patch ซ้ำ หรือ JSON ผิด จะถูกปฏิเสธและ audit

คำอธิบายไม่ได้พิสูจน์ว่า patch แก้ถูก ต้องให้ verifier ตรวจต่อ
`last_plan` พร้อม `last_plan_applied` แยกแผนที่เสนอจากแผนที่เขียนสำเร็จ

## ตรวจเฉพาะเคสก่อนชุดเต็ม

หลัง source เปลี่ยนเป็น candidate ใหม่ controller ใช้ operator prepare steps เดิมเพื่อ build
หากตั้ง case check ไว้ จะรันทุก unresolved structured input ก่อน full verifier
case check ไม่ผ่านจะหยุดลำดับก่อนชุดเต็ม ถ้าผ่านทั้งหมดจึงรัน full verifier ต่อ
probe ไม่ได้สร้างอำนาจยืนยันงานสำเร็จให้โมเดล และไม่เปลี่ยน failure เป็น resolved

เพิ่ม fragment นี้ใน `verification` ที่มี `prepare` และ build slots ตั้งไว้แล้ว:

```yaml
counterexample:
  executable: build:tests
  argv: [--case]
```

โปรแกรมของ operator จะได้รับ input JSON เป็น argv literal ตัวสุดท้าย เช่น:

```text
build:tests --case '{"b":-3,"e":1}'
```

โปรแกรมต้องตรวจ input และคำนวณ oracle ของเคสนั้นเอง ส่วน full invocation ใช้ argv เดิม
รองรับเฉพาะ declared build artifact และต้องมี allowlist/capability เดิมครบ
config ไม่เพิ่มสิทธิ์ และไม่อนุญาต probe ที่มี shape ชนกับ full verifier invocation
หากไม่ได้ตั้ง `counterexample` controller จะใช้ full verifier ตามเดิม ไม่อ้างว่าได้แยกทดสอบเคสนั้นแล้ว
ตัวอย่าง driver ที่ทดสอบจริงอยู่ใน `tests/support/repair_controller.rs`

## หยุดเมื่อไม่คืบหน้า

```yaml
repair:
  max_no_progress_steps: 6
  max_failed_candidates: 3
  max_failures: 8
  require_plan: true
```

- candidate ที่ bytes เหมือนเดิมหรือเคยตรวจ/เสนอแล้วไม่ทำให้เริ่ม operator verification ซ้ำโดยอัตโนมัติ
- การอ่านซ้ำ, เสนอ plan ที่ใช้ไม่ได้, ส่ง patch ซ้ำ และ tool errors ไม่รีเซ็ตตัวนับความคืบหน้า
- source digest ใหม่เป็นเพียง candidate ใหม่ ไม่ใช่หลักฐานว่าซ่อมดีขึ้น
- หลาย candidate ที่ล้มโดยยังไม่มี counterexample ใหม่ที่ตรวจผ่าน จะหยุดตาม `max_failed_candidates`
- probe ที่เคยผ่านแล้วไม่รีเซ็ตตัวนับนี้ซ้ำตลอดไป; full verifier ยังเป็นเกณฑ์สำเร็จ
- งบ `max_steps` ยังนับ model proposal/patch และ operator build/probe/full steps ทั้งหมด

`max_no_progress_steps` รับ 2–64, `max_failed_candidates` รับ 2–32, `max_failures` รับ 1–16
เกินขอบเขตปฏิเสธ config; ledger เต็มหยุดแทนการลบ unresolved evidence
`require_plan: false` คงทาง tool intents เดิมสำหรับการใช้งานที่ต้องการ แต่ไม่ปิดการรักษา failure,
การตรวจ candidate ซ้ำ, no-progress guards หรือ canonical verification

managed build ไม่ส่งโมเดลกลับไปขั้นที่บังคับให้เรียก compiler หลัง duplicate patch
tool errors ยังคงเป็นเหตุการณ์แยกและ failure เดิมยังถูกแนบใน retry ถัดไป

## หลักฐานหลังหยุด

ทุกการเปลี่ยน ledger ถูก audit เป็น `repair-state` ผูกกับ task ที่ host ออก
เมื่อผ่าน Supervisor จะเก็บ `agent-run-<task-id>.json` นอก workspace แบบ atomic/0600
แม้งานจบแบบ stalled/budget exhausted รายงานมี ledger, plan/hunk ล่าสุด, steps และ canonical outcome
source candidate สุดท้ายยังอยู่ใน workspace; benchmark runner เก็บ full diff/artifact ตามเดิม

state นี้รักษาข้อมูลข้าม retry และ context compaction ภายใน task เดียวกัน
restart/new task ไม่ได้รับ authority ของ receipt เดิม ต้องตรวจใหม่ตาม task contract เดิมของระบบ

```sh
cargo test -p aivm-runtime --test coding_workflow repair_controller::
cargo test -p aivm-runtime --lib repair::
make verify
```
