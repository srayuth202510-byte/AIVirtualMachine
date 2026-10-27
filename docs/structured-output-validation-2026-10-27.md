# Structured output validation — 27 ตุลาคม 2026

Baseline source: `aee1c18` พร้อม README และแผนงานที่ยังไม่ได้ commit
หลักฐานของรอบนี้อยู่ใน `target/structured-output-2026-10-27/`
ดูวิธีใช้และ protocol migration ใน [structured output](structured-output.md)

## ขอบเขตที่เปลี่ยน

- เพิ่มโหมด text/JSON/agent intent ต่อ request; model-only default ยังคง text
- Local llama ใช้ GBNF ก่อน sampling และ Serde ตรวจผลอีกครั้งทั้ง worker/control plane
- Agent ใช้ schema ร่วมกับ worker และยัง audit invalid-intent ก่อนปฏิเสธ
- Structured protocol version 2 ตรวจ mode และ grammar ID; text version 1 คง wire format เดิม
- Structured streaming ส่งหนึ่งผลหลัง final validation/cleanup ไม่ส่ง partial JSON
- เพิ่ม `aivm reason --output-mode` และการเทียบ raw/structured บน corpus เดิม

ไม่ได้แก้ semantic verifier, เพิ่ม Proptest หรือแก้ staging lifecycle ในชุดงานนี้

## การตรวจและข้อจำกัด

- `verify-fourth.log`: native parallel `make verify` ผ่าน fmt, strict Clippy,
  Rust/Python tests และ demo 14/14
- `clippy-llama.log` และ `llama-tests.log`: llama/microvm feature lint/tests ผ่าน
- `grammar-host-absolute.log`: ใช้ pinned Qwen vocabulary จริง ตรวจ positive/negative
  grammar, Unicode, truncated JSON, unknown/duplicate fields และการสร้าง state ใหม่
- `structured-protocol-tests.log`: ทดสอบ worker ที่ส่ง version/mode/grammar ผิด,
  ผลผิด schema, partial streams, deadline และ cancellation
- `graph-update-host.log`: code graph ปรับใหม่สำเร็จด้วย AST ไม่มี LLM

Sandbox ปฏิเสธการ execute pinned worker snapshot ในรอบแรก (`initial-tests.log`)
exact host recheck ผ่าน (`staging-host-recheck.log`) จึงรัน gate ที่ต้อง execute บน host
Grammar host test ครั้งแรกให้ config path แบบ relative ซึ่ง Cargo resolve จาก crate
แล้วไม่พบไฟล์; รอบ absolute path ผ่าน เก็บ log เดิมไว้ครบ

Parallel CI (`ci-final.log`) พบ test เดิม
`empty_inherited_probe_lock_waits_until_release_instead_of_reporting_corruption`
หมดเวลา admission queue ที่บรรทัดตั้งต้น ก่อนสร้าง probe lock ของตัวเอง
exact test ผ่านใน `quota-exact.log` ผลนี้ยังไม่อธิบายหรือแก้สาเหตุ flake
`RUST_TEST_THREADS=1 make ci` ผ่านครบใน `ci-serial.log` รวม dashboard HTTP,
CLI end-to-end, llama, MicroVM และ hardware feature gates โดยไม่ได้ใช้ผลนี้อ้างว่า
parallel flake ถูกแก้แล้ว และไม่ได้รวม ignored model host tests เป็นผลผ่าน

Host streaming รอบแรกชน host quota กับ quality evaluation และได้
`resources_unavailable` (`structured-stream-host.log`) จึงยังไม่ใช่ผลผ่านของ
กรณี token exhaustion รอบแยกหลัง evaluation จบผ่านใน
`structured-stream-host-isolated.log` (76.63 วินาที): งบ 1 token คืน `invalid_output`
โดยไม่มี callback และ request ถัดมาบน client เดิมคืน JSON ที่ verified แล้ว
ผ่าน callback เพียงครั้งเดียว ไม่มี ignored test ถูกนับแทนการรันจริง

## โมเดลและผลคุณภาพ

ใช้ Qwen2.5-Coder 1.5B Q4_K_M เดิมบน CPU และ model SHA-256 เดิม
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`
Worker/controller ของการทดสอบสร้างใน `worker-build` ด้วย features `llama,microvm`
และ pin `3f5658e9062cb79e6c4aabd4605b4ee533e82714d8b0048ce9dfb931078ca90c`
ไม่แทนที่ `target/debug` หรือแก้ production config

raw/structured ใช้ config, weights, sampling, prompts และ oracles เดียวกัน
context 512, output 96, CPU 2 threads, temperature 0, top-k 1, seed 42
ปิด sealed cache และใช้ quota root ใหม่ Results อยู่ใน `comparison/`
ชุด 8 งานยังเป็น synthetic transfer probes ไม่ใช่ independent benchmark

รายงานครบทั้งสี่รันและ infrastructure ผ่านทั้งหมด ตรวจซ้ำด้วย validator สุดท้ายแล้ว
ใน `quality-revalidation.json` ซึ่งเก็บทั้ง producer/validator hashes
Validator เพิ่มการตรวจ output/schema หลังเริ่มรัน จึงตรวจ reports เดิมซ้ำโดยไม่แก้
คำตอบ, prompts, config หรือ oracles

| Corpus | Task ถูก: text | Task ถูก: structured | JSON format/schema: text | JSON format/schema: structured |
|---|---:|---:|---:|---:|
| Baseline | 4/6 | 6/6 | 3/5 | 5/5 |
| Synthetic transfer | 3/8 | 6/8 | 3/7 | 7/7 |

Extraction สองงานใช้ text ตามโจทย์ จึงไม่รวมในตัวหาร JSON ทั้ง 12 งาน
Strict-oracle regressions เป็นศูนย์ แต่ยังมี semantic change ระหว่างคำตอบที่ตกทั้งคู่
ไม่ใช้จำนวน JSON ที่ผ่านแทน task correctness และไม่ใช้ผลชุดนี้แทน accuracy ของงานจริง

Median wall time ต่อ case ของ baseline คือ text 59.921 วินาที และ structured 49.542
วินาที; transfer คือ 35.903 และ 35.831 วินาทีตามลำดับ ช่วงแรกมี CI/grammar checks
รันร่วม จึงไม่สรุปว่ารูปแบบนี้ทำให้เร็วขึ้น Resource limits: RAM 4096 MiB,
CPU 120 วินาที, staging 5120 MiB, request timeout 120 วินาทีและ total timeout
180 วินาที ไม่ได้วัด peak RSS เพื่อรับรอง resource performance

เคส `sort-negative-duplicates` แสดงข้อจำกัดชัดเจน: raw คืนค่าที่เรียงถูก
`[-2, 0, 3, 3]` แต่ครอบ Markdown ขณะที่ structured คืน `[0, -2, 3, 3]`
ซึ่งรูปแบบผ่านแต่เรียงผิด ทั้งสองคำตอบตก strict oracle จึงไม่อยู่ใน `regressed`
ของ summary ต้องอ่าน output/failure kind ประกอบ ไม่ใช้คะแนนรวมกลบ semantic change นี้
เคส `code-result` ยังตอบ `11` แทน `-5` ทั้งสองโหมด แม้ JSON number ผ่าน parser
จึงยังต้องทำ semantic verifier + Proptest ตามส่วน 2 ของแผน
