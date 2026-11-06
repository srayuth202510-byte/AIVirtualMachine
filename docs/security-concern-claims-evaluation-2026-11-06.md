# Typed concern claims — 6 November 2026

ผลต่อเนื่องด้านคุณภาพทุก attempt:
[explicit availability inventory และ matched holdout ใหม่](security-concern-availability-evaluation-2026-11-06.md)
เพิ่มเกณฑ์ความครบถ้วนและ first-attempt โดยยังเก็บผลคอนแทรกต์เดิมด้านล่างไว้ตามจริง

**ตัวตรวจปฏิเสธข้ออ้างผิดจากโมเดลจริงได้แล้ว แต่ยังไม่เปิด enforcement**
ใน holdout โมเดลยังอ้างว่าข้อมูลที่ให้มาแล้วขาดหาย จึงถูกปฏิเสธและไม่ผ่าน
เกณฑ์คุณภาพทุก attempts การคง containment ของกฎไม่ขึ้นกับ advisory

รอบนี้เปลี่ยนคอนแทรกต์เป็น [typed claims](concern-claims.md) และให้โค้ดสร้าง
ข้อความสรุปจากค่าที่ตรวจแล้ว จึงไม่ใช้คะแนนนี้อ้างว่าแก้ semantic grounding
ของข้อความอิสระได้ทั่วไป คอนแทรกต์เดิมเคยรับคำว่า “second actor” ในเคส
actor เดียวเพราะไม่มีตัวเลข แต่คอนแทรกต์ใหม่ไม่มีช่องข้อความอิสระให้แฝงข้ออ้างนั้น

## ผล dev

**ผ่าน 10/10 เคสตั้งแต่ attempt แรก** รวมข้ออ้างที่ตรวจแล้ว 27 ข้อ
ไม่มี advisory ว่าง ไม่มี grounding/schema rejects และไม่มี timeout/unavailable
containment ตรง baseline ครบสิบเคส และทุก gate รวม
`all_accepted_claims_verified` ผ่าน

รายงานอยู่ที่ `target/security-concern-claims-dev-v1/report.json`
พร้อม `candidate-lock.json` และ `source-snapshot/` ที่เก็บ Python/Rust sources
transcript SHA256:
`269017d7d39bfa6d6fca7159871d341c55edff7091087056f113ab71f08046af`

## ผล holdout หลังตรึงคอนแทรกต์

| ตัวชี้วัด | ผล |
|---|---:|
| เคสที่รับ advisory ได้ | 11/12 |
| Model invocations | 13 |
| ข้ออ้างใน advisory ที่ตรวจผ่าน | 30 |
| Advisory ว่าง | 0 |
| Grounding rejects (`grounded_missing`) | 2 attempts ในหนึ่งเคส |
| Prefix `Concern:` ถูกต้องใน output ดิบ | 13/13 |
| Schema rejects / timeout / unavailable | 0 |
| Containment ตรง baseline | 12/12 |

`all_accepted_claims_verified=true` และทุกข้ออ้างที่รับเข้ามาตรวจตรงกับ facts
แต่ `no_fabricated_facts=false`, `all_calls_resolved=false` จึงยังได้
`pass=false` และ exit 1 จาก `--require-pass` ไม่ใช่ความล้มเหลวของ runner

เคส `claims-holdout-paced-boundary` มี facts ให้
`denied_one_actor_hidden_from_context=0` และ
`max_denied_one_actor_in_window=27` แล้ว แต่โมเดลใส่สองชื่อ field นี้ใน
missing_evidence ทั้งคำตอบแรกและ retry (invocations 6 และ 7)
ตัวตรวจจึงปฏิเสธทั้ง advisory ด้วย `QC-MISSING` และเก็บ concern ที่รับเป็น null
ไม่แก้หรือตัด field ที่ผิดทิ้งแล้วนำส่วนที่เหลือมาใช้
กฎยังเสนอ containment ของเคสนี้ตาม baseline แม้ advisory ใช้ไม่ได้

ผลนี้แสดงว่าตัวตรวจข้ออ้างจับความผิดที่คอนแทรกต์ข้อความเดิมเคยปล่อยผ่านได้
ไม่ใช่หลักฐานว่าโมเดลหยุดแต่งข้อเท็จจริงทุก attempt
ข้ออ้างแบบ `actor_exists`/`actor_count` ที่ผิดและ legacy/free-prose bypass
ถูกปฏิเสธใน adversarial tests ส่วนข้อผิดพลาดจากโมเดลจริงในรอบนี้เป็นเรื่อง
missing-evidence ไม่มี false actor claim ที่รับผ่าน

โมเดลเลือก tag `Concern: none` ในคำตอบที่รับทั้งหมด และไม่ได้เสนอ
missing context ที่ผ่านเลย จึงยังไม่มีหลักฐานว่าช่วยค้นบริบทใหม่หรือแยก
attack/benign ดีขึ้น ข้ออ้างที่รับไม่ว่าง แต่เป็นการเลือก facts ที่มีอยู่แล้ว
containment ยังเป็น TP=4, FP=1, TN=5, FN=2 ตามกฎเดิม

## หลักฐานและขอบเขตการอนุมัติ

วัดบน commit `8b22086` พร้อม working-tree changes ของรอบนี้ ใช้ source hashes
และ snapshot ระบุโค้ดที่วัด ไม่ถือว่า commit ID อย่างเดียวครอบคลุม implementation

หลักฐานอยู่ใน `target/security-concern-claims-holdout-v1/`:

- `report.json`, `baseline.json`, `prompt-freeze.json`
- `freeze-verification.json` ยืนยันค่าที่ตรึงไว้ตรงกันครบ 11 รายการ
  รวม prompt, Python/Rust sources, model, CLI, worker, corpus, mode และ variant
- `replay-verification.json` อ่าน output ดิบมาตรวจใหม่โดยไม่เรียกโมเดล
  รับได้ 11 คำตอบ ปฏิเสธ 2 คำตอบ และตรงกับ advisory/error ที่บันทึกครบทุก attempt
- raw transcripts อยู่คู่กับ pinned binaries/config ใน `jury-run-*`
  SHA256 `6f8904c8369f01604ac86d4851082c3ddf97aea7274ad2631a8599d32f3402b5`

base prompt SHA256:
`e12d1771ef9e7ff6619c4f49898da15220f840d7309026f068ea73f60830e62c`

grammar และ fact validator ทำงานในขอบเขตคอนแทรกต์ปิดชุดแล้ว แต่คุณภาพ
ทุก attempts ของโมเดลยังไม่ผ่าน จึงคง shadow/dry-run และไม่เปิด enforcement
การลด false containment ยังต้องเพิ่มหลักฐานอิสระและผ่าน paired improvement gate

## ขอบเขตการทดลอง

- dev 10 เคสใน `concern-claims-dev.json`: แปดรูปแบบเดิม และสองเคสเพิ่ม
  รวม counterexample actor เดียวที่เคยเปิดผลแล้ว ซึ่งย้ายมาเป็น dev โดยเปิดเผย
- holdout ใหม่ 12 เคสใน `concern-claims-holdout-v1.json`: ไม่มี input หลัง
  normalization ซ้ำกับ dev หรือ holdout ที่เปิดผลไปแล้ว และไม่ซ้ำกันเอง
- ตรึง variant `grounded`, คอนแทรกต์, prompt, sources, model/CLI/worker
  และ corpus hash ก่อนเรียกโมเดลบน holdout วัดครั้งเดียว ไม่ใช้ผลปรับ prompt ต่อ
- ใช้ model pin เดิม Qwen2.5-Coder-1.5B Q4_K_M,
  `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`,
  seed 42, temperature 0, top_k 1, context 4096, สี่ threads และ output 256 tokens
- Budget, output contract และชุด dev เปลี่ยนจากรอบข้อความเดิม จึงไม่ตีความ
  ความต่างของคะแนนว่าเป็นผลของ grammar เพียงอย่างเดียว

## การตรวจความปลอดภัยและโค้ด

`make verify` ผ่าน รวม format, clippy, Python/Rust tests และ demo 14/14
`make check-llama test-llama` ผ่านเช่นกัน การรันที่ต้องใช้ host namespaces
หรือ container/KVM ตามเงื่อนไขของ test ยังเป็น ignored ไม่ได้นับว่า host validation ผ่าน
graph ของ source code อัปเดตแล้วโดย AST extraction

เรียก ignored grammar test แยกโดยใช้ vocabulary ของ GGUF ที่ตรวจ model hash จริง
ได้ผลผ่าน ครอบคลุม prefix ที่หาย, free prose นอก enum, boolean แทนจำนวน,
fact ID ที่ไม่รู้จัก และ arrays ที่ยาวเกิน ขณะที่ actor_id=2 ยังผ่าน grammar ได้
เพื่อยืนยันว่า grammar ไม่แอบใส่ expected actor/count ของเคส

Python regression tests ตรวจ actor ที่ไม่มีจริง, จำนวนนับผิด, missing-evidence
ที่จริงให้มาแล้ว (รวมศูนย์/ลิสต์ว่าง), context ที่ collector ระบุว่ามี,
unknown/duplicate fields, boolean/float/string แทน integers, คำสั่ง,
การอ้าง hidden event/actor, free-prose/legacy bypass และการเก็บคำตอบผิดดิบ
ทุก advisory ที่ถูกปฏิเสธไม่เปลี่ยน containment ที่กฎคำนวณ
ชุด `test_qwen_*.py` ผ่าน 93 tests หลังเพิ่มการตรวจ source facts ที่ไม่ครบ
และยืนยันว่า retry ที่แก้สำเร็จไม่ล้าง grounding violation เดิมออกจากคะแนน

## Baseline ของ holdout ใหม่

`eval-detection.py` ใช้ Rust audit verifier และ watcher/supervisor จริงในการจำลอง
ตรวจครบ 12 เคส ไม่มี policy regression; containment TP=4, FP=1, TN=5, FN=2
FP เป็น maintenance job ที่ตั้งค่าผิดแต่เข้าเงื่อนไขกฎเดิม
labels เป็น synthetic intent labels ไม่ใช่ production accuracy

## คำสั่ง reproduction

```sh
python3 scripts/eval-qwen-concerns.py --corpus path \
  --corpus-path examples/security-concerns/concern-claims-dev.json --variants grounded \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --output target/concern-claims-dev-reproduction/report.json

python3 scripts/eval-detection.py \
  --corpus examples/security-concerns/concern-claims-holdout-v1.json \
  --output target/concern-claims-holdout-reproduction/baseline.json

# ชุดนี้เปิดผลแล้ว: ใช้ reproduction เท่านั้น ห้ามใช้จูนแล้วเรียกว่า fresh holdout
python3 scripts/eval-qwen-concerns.py --corpus path \
  --corpus-path examples/security-concerns/concern-claims-holdout-v1.json --variants grounded \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --output target/concern-claims-holdout-reproduction/report.json
```
