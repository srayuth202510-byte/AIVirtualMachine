# Typed concern claims

Concern mode ใช้คอนแทรกต์ `concern-claims-v1` และ output mode `concern_claims`
โมเดลเลือกข้ออ้างจากชนิดที่กำหนด โค้ดตรวจค่ากับ facts ก่อนรับ advisory
ข้อความสรุป `verified_summary` สร้างจากข้ออ้างที่ผ่านเท่านั้น ไม่มีข้อความอิสระ
ที่ผ่าน schema แล้วถูกตีความต่อว่าเป็นข้อเท็จจริงที่ตรวจแล้ว

```json
{
  "concern": "Concern: missing context",
  "claims": [
    {"kind": "actor_count", "value": 1},
    {"kind": "actor_exists", "actor_id": 1},
    {"kind": "count", "fact_id": "denied_total", "value": 0}
  ],
  "cited_event_ids": [0],
  "missing_evidence": ["operator_intent"]
}
```

ตัวอย่างนี้รับได้เมื่อ facts ยืนยัน actor count/ID และ denied_total ตามค่าที่อ้าง
พร้อมระบุว่า operator intent ยังไม่มี ผู้ตรวจไม่เปลี่ยนค่าที่ผิดให้ถูกเอง
คำตอบที่ถูกปฏิเสธเก็บดิบใน transcript และ retry ได้อีกครั้งโดยให้ feedback
เฉพาะ validator ไม่บอก labels ของสถานการณ์

## การตรวจแต่ละชั้น

1. **GBNF ใน local llama worker** ใช้ grammar คงที่ `aivm-concern-claims-v1`
   บังคับ concern ให้เป็นหนึ่งใน `Concern: none`, `Concern: facts to review`,
   `Concern: missing context` จึงบังคับ prefix ตอน generation ด้วย
   ชื่อ field, ชนิดข้ออ้าง, fact IDs และเพดาน arrays ถูกจำกัดใน grammar
2. **Rust/Serde หลัง generation** ปฏิเสธ JSON ไม่ครบ, duplicate/unknown fields,
   booleans/floats ที่ปลอมเป็น integers, ข้ออ้างซ้ำ และ arrays ที่เกินขอบเขต
   นี่เป็นการตรวจโครงสร้าง ยังไม่ตรวจว่าข้ออ้างตรงกับเคสจริง
3. **Python fact validator** ตรวจ actor/count/missing-evidence เทียบกับ view
   ที่โค้ดสร้างจาก audit; ปฏิเสธทั้ง advisory ถ้ามีข้ออ้างผิดแม้เพียงหนึ่งข้อ
4. **Trusted renderer** สรุปจากค่าที่ตรวจแล้วด้วย template คงที่ ไม่ใช้ข้อความ
   อธิบายอิสระจากโมเดล สรุปนี้ไม่ใช่ verdict หรือคำอนุมัติ action

ทุก array มีได้ไม่เกินสามรายการ integer อยู่ในช่วง 0..999999999 และ actor ID
ต้องเป็นบวก ไม่รับ string, float หรือ boolean แทน integer

| ชนิด | เงื่อนไขการรับ |
|---|---|
| `actor_count` | `value` ตรงกับ `facts.counts.actors_total` |
| `actor_exists` | `actor_id` อยู่ใน `facts.actor_ids_visible` |
| `count` | `fact_id` อยู่ใน registry และ `value` ตรงค่าที่โค้ดคำนวณ |
| `missing_evidence` | fact ID เป็นบริบทที่รู้จัก และ `context_availability` ระบุว่าไม่มี |
| `cited_event_ids` | ID ไม่ซ้ำและอยู่ใน `events_visible` |

numeric registry ครอบคลุม records_total/visible/hidden, denied/allowed/other totals,
window_seconds, denials_required_same_actor, window_denied_total,
max_denied_one_actor_in_window, max_denied_one_actor_in_window_with_policy_signal
และ denied_one_actor_hidden_from_context ส่วน actors_total ใช้ชนิด actor_count
ห้ามใช้ fact ID หรือคำอธิบายใหม่โดยไม่ได้เปลี่ยนคอนแทรกต์

**ศูนย์และลิสต์ว่างยังเป็นข้อมูลที่มีอยู่** จึงห้ามอ้างว่า denied_total=0 หรือ
actor_ids_visible ว่างแปลว่าขาดข้อมูล บริบทที่รองรับคือ operator_intent,
process_state และ task_contract ค่าเริ่มต้นยังระบุทั้งสามว่าไม่มี เพราะยังไม่มี
collector จริงของข้อมูลเหล่านี้ การทดลองส่ง `trusted_context` แยกจาก audit/model output
โดยใช้ synthetic operator fixtures ที่มีค่า enum แบบปิดชุดเท่านั้น
builder ส่ง `context_values`, `context_availability` และแหล่งที่มาให้ตรวจย้อนหลังได้
บริบทที่ส่งมาแล้วต้องไม่ถูกอ้างว่าขาดหาย
ไม่ใช้ชื่อ context อิสระจากโมเดลเป็นหลักฐานว่าอะไรขาดหาย

`facts.fact_availability` แสดง `present_fact_ids` และ `missing_fact_ids` ที่โค้ด
คำนวณจาก field ที่มีอยู่และ context values/flags โดยตรวจความสอดคล้องซ้ำ
ก่อนรับ advisory ศูนย์และลิสต์ว่างไม่ถูกย้ายไปฝั่ง missing
prompt นำ inventory เดิมมาแสดงใกล้จุดตอบ พร้อม `concern_source` ที่โค้ดคำนวณ
จากการมี/ไม่มี missing IDs เพื่อให้โมเดลคัดลอก tag ได้ตรงกัน
tag นี้บอก availability เท่านั้น ไม่ใช่ความเสี่ยงหรือ verdict

การวัด [availability แบบคู่เปรียบเทียบ](archive/security-concern-availability-evaluation-2026-11-06.md)
เพิ่ม `--require-availability-complete` และ `--require-first-attempt`
จึงต้องรายงาน missing IDs ครบและถูกต้องตั้งแต่ครั้งแรก ไม่ผ่านด้วยการตอบ []
ทุกเคสเมื่อข้อมูลยังขาด ส่วน validator ของคอนแทรกต์ยังตรวจความจริงเหมือนเดิม
โดยไม่ได้เติมหรือแก้ output ให้โมเดลย้อนหลัง

## ขอบเขตและความเข้ากันได้

Grammar ไม่ใส่ actor/count หรือ expected answers ของเคส ดังนั้น actor_id=2
ยังเป็น JSON ที่โครงสร้างถูกได้ แต่ถูก fact validator ปฏิเสธในเคส actor เดียว
การตัด context จะไม่เปิดให้โมเดลเดา event IDs หรืออ้าง actor ที่ไม่ปรากฏใน view
actors_total ยังคำนวณจาก audit ทั้งหมด ขณะที่ actor_exists จำกัดเฉพาะตัวที่มองเห็น

โมเดลยังอาจเลือกข้ออ้างที่ไม่ตรง facts หรือให้ advisory ว่างได้ จึงรายงาน
attempt kinds, accepted advisories, verified claims และ empty advisories แยกกัน
`no_fabricated_facts` ยังนับ attempts ที่ผิดข้อเท็จจริงแม้ retry แก้สำเร็จ
ไม่ยุบการปฏิเสธให้เป็นผลผ่านหรือข้อมูลว่าปลอดภัย

`LegacyQwenJury` และ validator แบบข้อความเดิมคงไว้สำหรับ regression ของ
คอนแทรกต์เก่าเท่านั้น evaluator ทั้งสองตัวใช้ `QwenJury` แบบ typed เป็น default
และไม่มี fallback รับ schema ข้อความเดิมเมื่อ typed validation ล้มเหลว

Structured protocol ยังเป็น version 2 พร้อม mode/grammar ID ใหม่ ต้อง rebuild
CLI/worker และ pin artifacts ที่ตรวจแล้วก่อนใช้ mode นี้กับ deployment เดิม
การทดลองใช้สำเนา binaries/config/quota root แยกต่างหาก ไม่แก้ production pins
providers ที่ไม่มี constrained sampling ยังต้องผ่าน final schema และ fact validation

containment ยังคำนวณด้วยกฎ `supervisor-rule` โมเดลมีน้ำหนักศูนย์และไม่มีโหวต
invalid advisory ไม่ยกเลิก containment ที่กฎต้องทำ และ valid `Concern: none`
ไม่คืนสิทธิ์หรือปล่อย instance Court ยังคง shadow/dry-run

## การตรวจ

```sh
python3 -m unittest discover -s scripts -p 'test_qwen_*.py'
make verify
make check-llama test-llama

# ใช้ ModelConfig ที่มี local.model_path และ approved model_sha256
AIVM_WORKER_HOST_CONFIG=/absolute/path/model-config.json \
  cargo test --locked -p aivm-model --features llama --test structured_grammar \
  real_vocabulary_grammars_reject_invalid_tokens_and_reset_per_request -- --exact --ignored
```

ผลจริงของ dev/holdout ใหม่อยู่ใน
[รายงาน typed claims](archive/security-concern-claims-evaluation-2026-11-06.md)
