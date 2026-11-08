# Paired Security Court evaluation — 5 November 2026

ผลรอบนี้ **ยังไม่แสดงว่า Court ลด false containment โดยไม่เพิ่ม misses**
ใช้ baseline corpus เดิม 30 สถานการณ์ (attack 20, benign 6, integrity 4)
และ holdout เดิมอีก 12 สถานการณ์ (attack 7, benign 5) แยกคะแนนกัน
ไม่แก้ labels, ไม่ปรับ threshold รายเคส และไม่เปิด enforcement

ผลการเรียก Qwen จริงแบบสามบทบาทแยกไว้ใน
[Real Qwen role-jury evaluation](security-court-qwen-evaluation-2026-11-05.md)
ตัวเลขในเอกสารนี้ยังเป็น deterministic controls ไม่ใช่คะแนนของ Qwen

## วิธีรันและอ่านผล

```sh
python3 scripts/eval-security-court.py
python3 scripts/eval-security-court.py --require-improvement
python3 -m unittest discover -s scripts -p 'test_security_court_evaluation.py'
```

รายงานเต็มอยู่ที่ `target/security-court-evaluation/report.json` (ไม่ commit)
หรือเลือก `--output <path>`; `--corpus <path>` วัด corpus อื่นเพียงชุดเดียว
Exit 0 หมายถึงการวัดครบและ baseline ไม่เกิด policy regression ไม่ได้แปลว่า
Court ดีขึ้น; `--require-improvement` จะ exit 1 ถ้าไม่มีหลักฐานปรับปรุง
runner/input/provenance error จะ exit 2 ไม่ถูกนับเป็นผล clean

ผลนี้วัดจาก committed baseline `30cfc00` พร้อม working-tree changes ของ
evaluator รอบนี้ รายงานมี commit, สถานะ dirty/clean, SHA256 ของ corpus,
binary และ evaluator/detector sources 6 ไฟล์ รวม baseline provenance
และ latency เฉพาะ judge + translator ไม่รวม Rust verifier/watcher/การสร้าง fixture
มี model calls 0 และ `enforcement_enabled: false`

## รูปแบบการทดลองที่กำหนดไว้

ใช้ watcher/controller และ Rust `verify-audit` จริงตาม detection evaluator เดิม
ส่วน runtime effects บันทึกผ่าน `RecordingAdapter` ไม่ติดต่อ systemd หรือรัน
คำสั่งโจมตี Court ใช้ deterministic judge/translator และ juror กฎหนึ่งเสียง
ที่รับสัญญาณ containment ซึ่ง supervisor สังเกตจาก audit จริงในการจำลอง
ยังไม่ได้วัดคุณภาพลูกขุน Qwen หรือการลงมือของ receiver/runtime บน host

Predictor รับเฉพาะ audit event hashes, อายุ ณ นาฬิกาจำลองของ corpus และ
สัญญาณ containment ไม่รับ scenario ID, label, description หรือ expected action
ID ของคดีมาจาก hash ของ observation; labels ถูกใช้ภายหลังเพื่อ scoring เท่านั้น
เทสต์สลับ attack/benign, เปลี่ยนชื่อและคำอธิบายทุกเคส แล้วตรวจว่า predictor
คืน bundle/verdict/directive เดิม ทั้งนี้ labels เป็น synthetic labels เดิมที่
มนุษย์ออกแบบร่วมกับ corpus ไม่ใช่ blind labels จาก production traffic

| Profile | แหล่งหลักฐานขั้นต่ำ | Quorum | ข้อมูลที่มีจริง |
|---|---:|---:|---|
| `audit_parity` | 1 | 1 | Audit stream เดียว เป็น control สำหรับเทียบพฤติกรรมเดิม |
| `corroboration_required` | 2 | 1 | Audit stream เดียว จึงยังขาดแหล่งอิสระอีกแหล่ง |

Watcher กับกฎที่อ่าน stream เดียวกันไม่นับเป็นหลักฐานสองแหล่ง และไม่สร้าง
เสียงจากโมเดลที่ไม่ได้เรียกจริง Profiles นี้เป็นการทดลอง offline ไม่ใช่การแก้
deployment policy ของผู้ใช้ Bundle ใช้ identity จำลองและแยกประเมินทีละคดี
รายงานนี้จึงไม่ใช่ ledger สำหรับส่งเข้า Court receiver ของ deployment จริง

## ผล containment เทียบเจตนาของสถานการณ์

นับ `restrict` ขึ้นไปเป็น proposed containment; baseline นับการสร้างทดแทน
FN ในตารางหมายถึง attack ที่ไม่มี containment ไม่ได้หมายความว่าโจมตีสำเร็จ
เพราะ gateway อาจปฏิเสธไปแล้ว Integrity 4 เคสไม่รวมใน TP/FP/TN/FN

| Corpus | ระบบ/แผน | TP | FP | TN | FN | Court งดตัดสิน |
|---|---|---:|---:|---:|---:|---:|
| Baseline (26 eligible) | Supervisor เดิม | 7 | 1 | 5 | 13 | — |
| Baseline | Court `audit_parity` | 7 | 1 | 5 | 13 | 18 |
| Baseline | Court `corroboration_required` | 0 | 0 | 6 | 20 | 26 |
| Holdout (12 eligible) | Supervisor เดิม | 1 | 0 | 5 | 6 | — |
| Holdout | Court `audit_parity` | 1 | 0 | 5 | 6 | 11 |
| Holdout | Court `corroboration_required` | 0 | 0 | 5 | 7 | 12 |

ตารางเป็นผลของ action: TN หมายถึง benign ที่ไม่มี containment ไม่ได้แปลว่า
Court ยืนยันว่าปลอดภัย รายงานแยก `court_classification` อีกชุดโดยนับ
`insufficient-evidence` เป็น abstention และไม่เพิ่ม TN; profile ที่ต้องการ
สองแหล่งมี classification coverage 0 ทั้งสอง corpus จึงไม่อ้าง FPR = 0
ในความหมายของการจำแนก ส่วน `audit_parity` มี coverage 8/26 และ 1/12

Risk alerts เป็นคนละตัวชี้วัดกับ containment: rules เดิมยังมี TP 16 / FP 3 /
TN 3 / FN 4 ใน baseline และ TP 4 / FP 2 / TN 3 / FN 3 ใน holdout
Court รอบนี้ไม่ได้เพิ่ม detector หรือแก้ alerts เหล่านั้น

## เหตุใดเกณฑ์ปรับปรุงจึงไม่ผ่าน

`audit_parity` ไม่เปลี่ยน containment ทุกกรณี รวม false containment เดิม
`benign-misconfiguration-burst` จึงยังไม่มี FP reduction
ส่วน `corroboration_required` ยกเลิกแผน containment ทั้งหมดเพราะหลักฐานไม่พอ
ทำให้เสีย containment ของ attack ที่ baseline เคยตอบสนองได้ 7 กรณี และ
holdout อีก 1 กรณี ไม่ใช่การเพิ่มความแม่นยำ

Gate ต้องมี false containment ลดลงอย่างน้อยหนึ่งชุด โดยทุกชุดต้องไม่มี
attack containment เดิมหาย, ไม่มี false containment ใหม่ และไม่มีเคสที่
baseline จะ containment แล้ว Court เปลี่ยนเป็น unresolved นับแบบจับคู่รายเคส
จึงไม่ให้ตรวจ attack ใหม่หนึ่งเคสมาหักล้างการพลาด attack เดิมอีกเคส
ทั้งสอง profiles ได้ `improvement_gate: false`

มีคู่ข้อมูลที่สังเกตได้เหมือนกันทุก field แต่เจตนาต่างกัน เช่น
`severe-boundary` กับ `benign-misconfiguration-burst` และ allowed sensitive
read ที่เป็น attack/benign ทั้งใน baseline และ holdout Predictor ให้ผลเดียวกัน
กับ inputs เดียวกันตามที่ควรเป็น การเพิ่มขั้นพิจารณาโดยไม่เพิ่มข้อมูลจึงยัง
ไม่มีหลักฐานว่าช่วยแยกสองกรณีนี้ได้

ระบบที่บังคับใช้อยู่ยังใช้ baseline เดิม: `effective_containment_risk_metrics`
คงเดิมเสมอในรายงานนี้ Court shadow ไม่ระงับ containment ของ supervisor
ไม่คืนสิทธิ์ และไม่เปลี่ยน gateway งานถัดไปคือเพิ่มบริบทที่ตรวจสอบได้จาก
แหล่งอิสระ เช่น task contract ที่ผู้ดูแลรับรอง หรือสัญญาณ process/resource
จาก collector อีกตัว แล้ววัดด้วย labels แยกและ paired gate เดิมอีกครั้ง
