# Structured output: GBNF + Serde

Caller เลือก `text`, `json` หรือ `agent_intent` ต่อ request ได้ ค่าเริ่มต้นของ
model-only inference ยังเป็น `text` ส่วน agent loop ขอ `agent_intent` โดยตรง
และยังส่งทุก tool ผ่าน gateway, capability, policy และ audit ตามเดิม

```bash
aivm reason --config model.yaml --prompt 'Sort [3,-2,3,0]. Return JSON.' --output-mode json
aivm reason --config model.yaml --prompt 'Return a read intent for src/seed.txt.' --output-mode agent_intent --stream
```

`--stream` ของ CLI ยังต้องใช้ `model.local.worker_path` โหมด structured ส่งผล
หนึ่งก้อนหลัง final validation และ cleanup เสร็จ; text mode ยังคงส่ง delta ตามเดิม
JSON ที่ผ่าน schema อาจยังคำนวณผิด, เรียงผิด หรือเลือก path ผิดได้
การผ่าน schema จึงไม่ใช่ verification receipt หรือการอนุมัติให้ execute

## API และ protocol

- `Model::reason_with_mode(context, max_output_tokens, mode)`
- `Model::reason_stream_with_mode(context, max_output_tokens, mode, callback)`
- `Model::reason_with_system_mode(system, context, mode)`
- `InferenceRequest.output_mode` และ `OutputMode::protocol_version()` สำหรับ worker client

Local llama backend ต่อ grammar sampler ก่อน sampling และสร้าง grammar state ใหม่
ต่อ inference ใช้ GBNF คงที่ `aivm-json-v1` หรือ `aivm-agent-intent-v1`
ไม่มี expected answers ของ corpus อยู่ใน grammar Backend อื่นที่ใช้ default trait
method ตรวจคำตอบสุดท้ายด้วย parser/schema แต่ไม่ได้เพิ่ม constrained sampling ให้ provider

Text requests คง protocol version 1 และไม่ serialize `output_mode` เมื่อเป็นค่าเริ่มต้น
Structured requests ต้องใช้ version 2 พร้อมโหมดที่เลือก Responses ต้องยืนยัน version,
request ID, `output_mode` และ `grammar_id` ที่ตรงกัน ก่อน control plane จะตรวจ output ซ้ำ
การเพิ่ม field อย่างเดียวใน request version 1 ถูกปฏิเสธ เพื่อไม่ให้ worker เก่า ignore เงียบ ๆ

**ต้อง build worker/controller ใหม่และให้ operator อัปเดต SHA-256 pins ก่อนใช้
agent หรือ structured requests กับ deployment เดิม** ห้ามเปลี่ยน production pins
จากผล worker ที่ไม่ได้ตรวจ โค้ดทดสอบใช้ binary/config/quota root แยกจากของเดิม

`agent_intent` แชร์ typed Serde schema กับ runtime: ปฏิเสธ unknown/duplicate fields,
tool ที่ไม่รู้จัก, `done:false`, และชนิด content ที่ผิด tool ส่วน argv/outputs/secret
ยังต้องผ่าน gateway ที่ตรวจนโยบายจริง การ generate ใช้ลำดับ field คงที่
แต่ parser รับลำดับอื่นได้ ตัว parser compatibility `parse_intent` ยังอ่าน exact JSON
fence เดิมได้; การเรียกโมเดลจาก agent ตรวจ structured schema ก่อนถึง parser นี้
จึงไม่รับ Markdown จาก model ใน agent loop

Grammar โหลดไม่ได้, JSON/schema ไม่ผ่าน หรือ local generation ใช้งบโทเคนหมดก่อน
จบ generation จะเป็น `invalid_output` ไม่มี fallback เป็น text Structured completion
ที่อ้าง termination `length` ถูกปฏิเสธ แม้ output ที่ส่งมาจะ parse ได้
Error diagnostics ไม่สะท้อนข้อความของ worker กลับให้ผู้เรียกโดยตรง
Partial structured output จะไม่เข้า callback เมื่อ schema, protocol, deadline,
cancellation หรือ cleanup ล้มเหลว

## การตรวจ

Gate ปกติใช้ `make verify`; llama backend ใช้ `make check-llama test-llama`
และ CI parity ใช้ `make ci` การรันจริงด้านล่างเป็น ignored host tests ที่ต้องเรียกแยก
อย่านับ ignored tests ใน gate ปกติเป็นผล host validation ผ่าน

```bash
# ต้องเป็น absolute path; Cargo เรียก test จาก directory ของ crate
export AIVM_WORKER_HOST_CONFIG=/absolute/path/to/pinned-model-config.json

cargo test -p aivm-model --features llama,microvm --test structured_grammar \
  real_vocabulary_grammars_reject_invalid_tokens_and_reset_per_request -- --exact --ignored
cargo test -p aivm-model-worker --test worker \
  real_model_structured_stream_and_incomplete_budget -- --exact --ignored

# ใช้ Cargo target directory แยกจาก binary ที่ config pin ไว้
python3 scripts/eval-model-quality.py --config "$AIVM_WORKER_HOST_CONFIG" \
  --out target/new-structured-comparison --structured --test-features microvm
```

Quality runner คง inputs/oracles เดิมทั้ง 6+8 งาน: extraction ยังคง text,
intent ใช้ agent schema และงานตัวเลข/array/JSON ใช้ JSON value grammar
รายงาน `format_valid`, `schema_valid`, `task_correct`, termination และ raw successful
outputs แยกกัน Validator ตรวจคะแนนและ schema ซ้ำจาก output ไม่เชื่อ boolean ใน report
ผลที่ถูกปฏิเสธเก็บ error code และไม่มี output สำเร็จ; ไม่มีการเรียก partial output ว่าผ่าน
Latency จาก host run เป็นหลักฐานของรอบนั้น ไม่ใช่ performance benchmark

ส่วน semantic verifier + Proptest และ staging recovery + nextest/strace อยู่ใน
[แผนงาน](structured-output-quality-test-plan.md) แยกจากการบังคับรูปแบบนี้
