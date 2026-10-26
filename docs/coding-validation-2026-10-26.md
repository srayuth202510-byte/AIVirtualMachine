# Coding completion validation — 26 ตุลาคม 2026

**โมเดลจริงแก้ source แล้ว runtime build/test ผ่าน gateway จนได้ `verified`**
พร้อม operator ตรวจ patch ซ้ำแยกอีกรอบผ่าน 289 input pairs
หลักฐานอยู่ใน `target/agent-quality-2026-10-26/`

## ผลของรอบสุดท้าย

`agent-quality-operator-contract.json` ใช้ Qwen2.5-Coder 1.5B Q4_K_M เดิมบน CPU
ผ่าน pinned process-namespace worker; model/worker/controller pins ตรงกับ baseline
model config อยู่ใน `agent-final-config.json` ปิด sealed cache และใช้ quota root แยก

| ก้าว | ผู้กำหนด action | ผล |
|---|---|---|
| 1 | Model: อ่าน `src/main.c` | ผ่าน |
| 2 | Model: แก้ `a - b` เป็น `a + b` | ผ่าน |
| 3 | Operator contract: GCC `-pipe -c` source | ผ่าน |
| 4 | Operator contract: GCC `-pipe -c` protected verifier | ผ่าน |
| 5 | Operator contract: GNU ld link | ผ่าน |
| 6 | Operator contract: `build:tests` | exit 0 พร้อม verification receipt |

`agent_verified=true`, `task_correct=true`, `stopped=done`, `agent_error=null`
ใช้ 6 จาก budget สูงสุด 8 ก้าว `AgentStep.origin` แสดงบทบาทชัดเจน
โมเดลไม่ได้เป็นผู้เลือกคำสั่ง compiler/linker ในรอบนี้
เวลาของ snapshot นี้: client boot 71.992 วินาที และ agent run 97.776 วินาที
ไม่ได้ใช้รอบเดียวนี้รับรอง performance หรือ success rate ของงาน repository จริง

Oracle ของ operator ถูกเก็บใน `verify.c` นอก write scope ของโมเดล:
ก่อนแก้ source ทดสอบ known-broken baseline ต้องออก 1;
หลังรันโมเดล compile/link/test ซ้ำผ่าน gateway อีกครั้งจึงได้ `task_correct=true`
ตรวจว่า agent เขียน verifier ไม่ได้, bytes ของ verifier ไม่เปลี่ยน และ audit chain ผ่าน

## การแก้

- เพิ่ม `verification.prepare` แบบ opt-in ให้ operator ระบุ build steps
  ตาม [ตัวอย่าง](build-workflow.md#operator-managed-verification-build)
  หลัง filesystem write runtime ส่งทุก prepare step และ final verifier ผ่าน gateway ปกติ
- ไม่เปิด `/tmp` หรือ random temporary files; GCC compile ใช้ `-pipe`
  และเขียนเฉพาะ output slots ที่จองไว้
- คำสั่งล้มเหลวหยุดลำดับแล้วส่ง diagnostics กลับขั้น repair;
  เมื่อโมเดลแก้ source จึงเริ่ม build ใหม่ Budget นับทุก action รวม operator steps
- `done` ของงานที่ร้องขอแก้และทดสอบถูกปฏิเสธจนกว่าจะมี receipt
  แม้โมเดลจะยังไม่เคยแก้ไฟล์ ไม่เปลี่ยน Cube operator guards จากผล agent
- Observation เก็บ argv/outputs ที่ร้องขอแบบจำกัดความยาว
  ไม่แสดง environment ของ secret broker

`prepare` ไม่ได้เพิ่ม capability หรือข้าม allowlist/policy/sandbox
เมื่อไม่กำหนด `prepare` ใช้ workflow เดิม และ serialization ของ contract เดิม
ไม่เพิ่ม field ว่าง จึงไม่เปลี่ยน digest โดยไม่จำเป็น

## การตรวจ

- `verify-operator-contract.log`: `make verify` ผ่าน fmt, strict Clippy,
  workspace Rust tests, Python tests และ demo 14/14
- `operator-verifier-final-tests.log`: runtime library 57 tests, coding integration
  9 tests และ tools library 37 tests ผ่าน; live model test เรียกแยกโดยตรงข้างต้น
- Regression ยืนยันว่าไม่มี `-pipe` ยังสร้าง temp file ไม่ได้,
  failed verifier ส่งกลับให้ repair และรอบต่อมาสร้าง receipt ได้,
  operator prepare ที่ร้องขอ `/bin/sh` ยังถูก gateway ปฏิเสธ
- ใช้ Cargo target directory แยกสำหรับ gate เพื่อไม่แทนที่ pinned worker
  และใช้ `RUST_TEST_THREADS=1` ใน gate สุดท้าย

มี staging recovery test ล้มหนึ่งครั้งระหว่าง parallel workspace run
(`final-regressions.log`); exact test และ serialized workspace run ต่อมาผ่าน
ไม่ได้อ้างว่ารอบล้มเหลวนั้นผ่าน หรือเปลี่ยน staging production code ในงานนี้

## รอบทดลองก่อนสำเร็จ

เก็บผลเดิมครบใน `agent.log`, `agent-host.log`, `agent-phased.log`, `agent-final.log`
และ JSON ที่คู่กัน รอบ sandbox ติด worker verification; รอบที่ส่ง build recipe
ทั้งหมดให้โมเดลอ้างสำเร็จทั้งที่ไม่แก้ source; รอบแบ่งขั้นแก้ source/compile ได้
แต่โมเดลวนคำสั่ง; รอบคำแนะนำคำสั่งถัดไปยังวน write จน stalled
ไม่ใช้ผล `task_correct=true` ของ operator เพียงอย่างเดียวแทน `agent_verified`

แนวทางสุดท้ายใช้ operator-owned verifier preparation เป็นลำดับ deterministic
ส่วนโมเดลทำ source edit และ repair ไม่ได้เพิ่มอำนาจการอนุมัติให้โมเดล
ผลคุณภาพคำตอบ 14 งานรายงานแยกใน [model quality](model-quality-2026-10-26.md)
