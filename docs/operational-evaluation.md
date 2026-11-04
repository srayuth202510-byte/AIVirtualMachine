# การประเมินระดับการปฏิบัติจริง (Operational evaluation) — 4 November 2026

รองรับข้อ 5 ของลำดับความสำคัญใน
[open-weight-security-roadmap](open-weight-security-roadmap.md):
replay/evaluation ครอบคลุม prompt injection, artifact tampering,
resource exhaustion และความไม่ตรงกันระหว่าง summary กับผลจริง

`scripts/eval-operational.py` รวมหลักฐานเดิมที่มีอยู่แล้วเป็นรายงานเดียว
ทำซ้ำได้แบบ deterministic รันได้ทุกเครื่อง (ไม่ต้องมี KVM หรือโมเดลจริง)
ต่างจาก `validate-model-host.py` ที่ชุด failure-recovery ต่อ tier (timeout/
memory + recovery-after) ต้องมีโมเดลพร้อม pin และ KVM

```sh
python3 scripts/eval-operational.py            # ทั้ง 4 มิติ exit 0 เมื่อผ่านทุก stage
python3 scripts/eval-operational.py --stages tamper,summary
python3 -m unittest discover -s scripts -p 'test_operational.py'
```

## กฎที่ harness บังคับ

- **ผลรวม fail-closed:** ไฟล์หาย, stage ขาดหลักฐาน, exit 0 ที่เทสต์วิ่งไป 0 ตัว
  (ชื่อพิมพ์ผิด) หรือ summary ไม่ ok/0 failed/0 ignored ต้องแปลงเป็น failed
  ไม่ใช้เพียง return code เดียวเป็นผ่าน
- **คุมชื่อเทสต์:** ทุกชื่อที่ขอต้องปรากฏเป็น `test <ชื่อ> ... ok` ใน log
  (เทียบชื่อสุดท้ายของ module path) กันกรณี filter จับกันเอง (prefix matching)
  จนคิดว่าเทสต์วิ่งครบโดยไม่ใช่
- **การเก็บผล detection:** ยกเมตริกจาก `rules_risk_metrics` ของ
  `eval-detection.py` (โหมดไม่มีโมเดล) มาเป็น tp/fp/tn/fn/abstention/
  precision/recall/FPR/classified-fraction และต้องไม่มี `policy_regressions`
  พร้อม provenance hash ของ corpus/evaluator/detector จากไฟล์รายงานจริง
- **Provenance ของ harness:** commit, hash ของ log/รายงานย่อยทุก stage,
  `release_evidence.source_identity()` — เทียบรุ่นหรือรันซ้ำได้

## Baseline บนเครื่องนี้ (2026-11-04, commit `5f51fa6`)

| Stage | Result | รายละเอียดที่วัดได้ |
|---|---|---|
| detection (rules-only) | Passed | 26 cases: tp 16 / fp 3 / tn 3 / fn 4, precision 0.842, recall 0.80, FPR 0.50, classified_fraction 1.0, abstain 0 |
| artifact tamper | Passed | 5 gate tests ปฏิเสธตั้งแต่ประตู: kernel/rootfs ปลอม, alt artifact ปลอม, fc pin ผิด, kernel ขยะ, artifact หาย |
| summary-vs-reality | Passed | 4 verifier tests: budget/gateway deny ไม่ถูกนับ verified, แหล่งที่มา mismatch, operator ต้อง build+verify จริง, generated tests ห้ามสร้าง/อ่านไฟล์นอกขอบเขต |
| resource exhaustion | Passed | fuzz seeds: input ประมาณถือคง deny และ input ธรรมดาต้องได้ decision ไม่ crash |

ผลรวม: **all green** แต่ corpus สังเคราะห์ไม่ใช่ความแม่นยำบน production traffic
ดูคำนิยามเมตริกและขอบเขตใน [detection-evaluation](detection-evaluation.md)
การล้มเหลวจริงต่อ tier (timeout/memory/recovery ของ process/container/microvm)
ยังวัดด้วย `validate-model-host.py` — harness นี้ไม่แทนชุดนั้น

## ขอบเขต

- detection ใช้สัญญาณกฎเดิม จึงเป็นการวัดการทบทวนสัญญาณ ไม่ใช่การตรวจจับ
  แบบอิสระจากกฎ (เดียวกับข้อจำกัดของ eval-detection)
- exhaustion ชุดนี้ครอบคลุมขั้น deterministic เช่นการกัก quota และทรัพยากรย่อย
  ไม่ครอบคลุมการใช้ทรัพยากรจริงบน isolation tier ทั้งหมด
- summary-vs-reality ครอบคลุมผู้ยืนยันผลและ gateway แต่ไม่ใช่ความถูกต้อง
  ของงานซ่อมโค้ดบน compiler จริง (ชุด benchmark ของงานซ่อมแยกอยู่)
