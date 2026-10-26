# Model quality comparison — 26 ตุลาคม 2026

ประเมิน Qwen2.5-Coder 1.5B Q4_K_M บน CPU ผ่าน pinned process-namespace worker
ใช้โมเดลเดิม SHA-256 `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`
และ worker/controller SHA-256 `f126b1332bc8da31a7c9932233a89e35fa8a37bc18acc145c54ad26cf5d8c06f`
ไม่ได้เปลี่ยน weights หรือ sampling ระหว่างรัน raw/strict

หลักฐานอยู่ใน `target/agent-quality-2026-10-26/comparison-final/`
ทั้งสี่รันผ่าน infrastructure checks พร้อม records ครบและตรวจคะแนนซ้ำจาก output
คำตอบของ quality corpus เป็นข้อมูลเท่านั้น ไม่ execute intents ที่โมเดลเสนอ

## ผล

| Corpus | จำนวน | Prompt เดิม | เพิ่มคำกำกับรูปแบบ | Strict-oracle regressions |
|---|---:|---:|---:|---:|
| Baseline เดิม | 6 | 4/6 | 5/6 | 0 |
| Synthetic transfer ใหม่ | 8 | 3/8 | 3/8 | 0 |

คำกำกับใน `examples/model-quality-format.json` ช่วยโจทย์ `sort` ของ baseline
ให้คืน JSON array โดยไม่ครอบ Markdown แต่ไม่ได้เพิ่มคะแนนใน corpus ใหม่
**ผลนี้สนับสนุนการปรับรูปแบบเฉพาะบางงาน ยังไม่ยืนยันว่าคุณภาพดีขึ้นทั่วไป**
จึงไม่เปิด suffix นี้เป็น default ของ model clients

ข้อผิดพลาดที่ยืนยันได้:

- Baseline `strict-read-intent` และ transfer tasks ที่ขอ read intent/typed JSON
  ยังครอบ Markdown แม้โจทย์ห้ามไว้
- `code-result` คืน `11` แทน `-5` สำหรับ `add(-8, 3)` ทั้งสองรัน
- `sort-negative-duplicates` ใน raw มีค่าถูกแต่ครอบ Markdown; strict เอา Markdown
  ออกแต่เรียงเป็น `[0, -2, 3, 3]` ผิด ความเปลี่ยนแปลงนี้ไม่เพิ่มคะแนนทั้งสองฝั่ง
  และเป็นตัวอย่างว่าการผ่านรูปแบบไม่ได้ยืนยันความถูกต้องของคำตอบ

`regressed` ใน summary หมายถึงเคสที่เคยผ่าน strict oracle แล้วกลับไม่ผ่าน
จึงไม่แสดงการเปลี่ยนชนิดความผิดพลาดระหว่างสองคำตอบที่ตกอยู่แล้ว
ต้องอ่าน `failure_kind` และ output ราย case ด้วย ไม่ใช้คะแนนรวมแทนการวิเคราะห์

## สิ่งที่เพิ่มและการตรวจ

- `examples/model-quality.json` คงโจทย์และ oracle เดิมทั้งหกงาน
- `examples/model-quality-holdout.json` เพิ่มแปดงาน: จำนวนติดลบ, nested extraction,
  read intent คนละ path, prompt injection, sorting ที่มีค่าซ้ำ/ติดลบ, empty array,
  ผลลัพธ์ C และ JSON types
- `scripts/eval-model-quality.py` รัน A/B, เก็บ config/corpus/profile hashes,
  prompt/output จริง, latency และรายชื่อเคสที่คะแนนดีขึ้นหรือถดถอย
- Validator ปฏิเสธหลักฐานขาด, hash/profile/prompt ไม่ตรง, คะแนนที่ไม่ตรง output
  และ JSON types ผิด เช่น `false` เทียบกับ `0`
- Rust oracle ยังปฏิเสธ Markdown และ extra fields; การลองตัด fence
  ใช้วิเคราะห์ `failure_kind` เท่านั้น ไม่ช่วยคะแนน

Corpus ใหม่เขียนหลังเห็น baseline จึงเป็น synthetic transfer probes
ไม่ใช่ independent holdout หรือ production benchmark ไม่ใช้ 5/6 แทน accuracy ของงานโค้ดจริง

## ทำซ้ำ

```bash
python3 scripts/eval-model-quality.py \
  --config target/agent-quality-2026-10-26/quality-config.json \
  --out target/quality-comparison-new-run
```

ใช้ worker build/pins เดิมและ output directory ใหม่ ดู prerequisites และข้อจำกัด
ใน [model control hardening](model-control-hardening.md)
Config ของ A/B ใช้ context 512, output สูงสุด 96 tokens, 2 threads,
temperature 0, top-k 1, seed 42 และปิด sealed cache; มีสำเนา config ใน evidence directory

รอบทดลองก่อนหน้าเก็บไว้ใน `comparison/` และ `comparison-host/`:
รอบแรกสร้าง controller ใน sandbox ไม่ได้ รอบ host แรกใช้ quota root ร่วมกับ
policy ที่ตั้ง cache ไว้ต่างกันจึงถูกปฏิเสธ แก้โดยแยก quality quota root
ไม่ใช้รอบเหล่านี้เป็นผลผ่าน และไม่เปลี่ยน model/worker pins เพื่อหลบการตรวจ
