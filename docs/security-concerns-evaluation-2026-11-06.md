# Concern mode — 6 November 2026

**ยังไม่ผ่าน semantic grounding และยังคง shadow/dry-run**: คำตอบที่ผ่าน
schema ยังอ้างว่าจำนวนนับที่ให้มาแล้วขาดหาย และใน holdout ยังกล่าวถึง
“second actor” ทั้งที่ facts ยืนยันว่ามี actor เดียว คะแนนอัตโนมัติด้านรูปแบบ
จึงไม่ใช่เกณฑ์อนุมัติ enforcement

ต่อจาก [ผลระยะ 10 เดิม](security-court-qwen-evaluation-2026-11-05.md#ต่อเนื่อง-concern-mode-ระยะ-10--qwen-ไม่โหวต-ไม่นับ-ไม่ตัดสิน)
รอบนี้ปรับ prompt บน dev เท่านั้น และเตรียม holdout ใหม่ 12 เคส
ใน `examples/security-concerns/concern-holdout-2026-11-06.json`
ไม่มี input หลัง normalization ซ้ำกับ dev, holdout เดิม หรือกันเอง
ตรวจด้วย regression test ที่เทียบ `input_sha256` ของสิ่งที่โมเดลเห็นจริง

## ผล dev ของฉบับสุดท้าย

| Variant | เคสที่ได้ concern ผ่าน | Invocations | Schema rejects | Grounding rejects ที่ตรวจได้ | Gate รวม |
|---|---:|---:|---:|---:|---|
| grounded | 7/8 | 9 | 2 | 0 | ไม่ผ่าน |
| policy | 6/8 | 10 | 4 | 0 | ไม่ผ่าน |
| missing-context | 7/8 | 9 | 2 | 0 | ไม่ผ่าน |

รวม 28 invocations ผ่าน schema 20 ครั้ง ไม่มี timeout/unavailable ในรอบนี้
ทุก variant ตรงกับ containment baseline ครบแปดเคส แต่ `all_calls_resolved`
ไม่ผ่าน: `dev-single-generic-denial` ขาด `Concern:` ทั้งคำตอบแรกและ retry
ในทุก variant ส่วน policy มี `dev-nineteen-boundary-probes` ที่
missing_evidence ยาวเกิน 160 ตัวอักษรทั้งสอง attempts เพิ่มอีกหนึ่งเคส
จึงยังไม่ผ่านระยะ 10 แม้ gate ตรวจตัวเลข/citations/commands จะผ่าน

เลือก grounded ตามจำนวนเคสที่ผ่านและลำดับตัดสินกรณีเสมอที่กำหนดไว้
เก็บ `candidate-lock.json`, `source-snapshot/` และรายงานใน
`target/security-concerns-dev-final-2026-11-06/`
transcripts SHA256:
`a1cd832d6d65e3ed55ffb2fd3f9627bee495aab22a1d8370855547e234f956ef`

ตัวอย่าง semantic mismatch ที่ schema ยอมรับ: `dev-generic-burst-no-signal`
มี `facts.counts.actors_total=1`, `denied_total=20` และ
`policy_inputs.actors` ระบุ actor/denied_in_window แต่ concern ของ grounded
กลับระบุว่าข้อมูลไม่บอกจำนวน actors หรือ denied events ทั้งที่ข้อมูลอยู่ใน input
การอ้าง event IDs ที่มีจริงไม่ได้ยืนยันข้อความนี้

## ผล holdout ใหม่หลังตรึง prompt

เลือก grounded และรันเพียงครั้งเดียว: **9/12 เคสได้ concern ที่ผ่านรูปแบบ**
จาก 15 invocations (validated 9, schema rejects 6) ไม่มี timeout/unavailable
แต่ `all_calls_resolved=false` จึงได้ `pass=false` และ exit 1 เมื่อใช้
`--require-pass` ไม่ใช่ความล้มเหลวของ runner หรือ provenance

สามเคสที่ยังขาด `Concern:` ทั้งคำตอบแรกและ retry:

- `fresh-clean-mixed-actions`
- `fresh-sustained-boundary-burst`
- `fresh-separated-session-bursts`

containment ตรง baseline **12/12 เคส**, ไม่มี attack containment เดิมหาย
และไม่มี false containment เพิ่ม คะแนนยังเป็น TP=4, FP=1, TN=5, FN=2
ตามกฎเดิม ไม่ใช่การลด false positives ด้วย Qwen

manual counterexample ใน `fresh-truncated-allow-history` (invocation 11):
`facts.counts.actors_total=1` และ audit ทั้งหมดเป็น actor/session เดียว
แต่ concern ที่ผ่าน schema กล่าวถึง “the second actor in the window”
ทั้งที่ไม่มี actor ที่สอง เป็นข้อผิดพลาดที่ `no_fabricated_facts=true`
ของ validator เดิมยังจับไม่ได้ เก็บข้อความดิบ, input hash ที่ตรงกัน และ
ผล `semantic_grounding_pass=false` ใน `manual-assessment.json`
นี่เป็น counterexample ที่ตรวจด้วยคน ไม่ใช่คะแนน semantic แบบ exhaustive

หลักฐานอยู่ใน `target/security-concerns-holdout-2026-11-06/`:

- `report.json` และ `baseline.json` แยกผลโมเดลจากการตรวจ supervisor จริง
- `prompt-freeze.json` บันทึก variant, dev report/transcript hashes, corpus,
  prompt, source, model, CLI และ worker hashes ก่อน model call แรกของ holdout
- `freeze-verification.json` ยืนยันตรงกับค่าที่ตรึงไว้ครบเก้ารายการ
- `jury-run-095c5f31356e4911a9716c21e7c7f212/transcripts.jsonl`
  มี SHA256 `fc403476d0d7bb98ecacf5047d2b4e41134f2930ffd8da0d5f7fa761f8723a59`

base prompt SHA256:
`a1b1ed6650ed78af9cde6476e491a8b4fbf9c75f8ae19449d5d22ff65da2273d`
fresh corpus SHA256:
`e05906471e399dbe6a41e940b8cd70aa50315de394ddc02816219e99941814cb`

## การตรวจโค้ดและงานถัดไป

`make verify` ผ่านกับโค้ดฉบับสุดท้าย รวม fmt, clippy, Python/Rust tests
และ demo 14/14; ชุด `test_qwen_*.py` ผ่าน 80 tests หลังปรับ regression test
ให้ทดสอบการปฏิเสธ actor ตัวเลขและรอโมเดลแก้จริงแทนการเช็กข้อความใน prompt
รอบใน session sandbox ติด executable-staging `PermissionDenied`
จึงตรวจซ้ำบน host แล้วผ่าน โดยไม่เปลี่ยนกฎ isolation ของ AIVM

ยังไม่ผ่านระยะ 10 และไม่เปิด enforcement งานถัดไปต้องแยกการบังคับ prefix
ออกจากการตรวจข้ออ้างเรื่อง actor/counts ให้เทียบกับ typed facts ได้จริง
แล้วปรับบน dev และสร้าง holdout ชุดใหม่ ส่วนการลด false containment
ยังต้องเพิ่มบริบทจากแหล่งอิสระตามผล paired Court evaluation เดิม

## สิ่งที่แก้

- คำสั่งแยก actor identifier ที่เป็นตัวเลขออกจากข้อความ ให้ใช้คำว่า
  `the observed actor` / `different actors` และใส่เลข event เฉพาะ citations
- ย้ำ prefix `Concern:` ภายในค่า string หลัง input อีกครั้ง โดยปรับจาก
  prompt เดิมและไม่ให้ตัวอย่างคำตอบสำเร็จรูปที่โมเดลอาจลอกเป็นคำตอบตายตัว
- retry ส่งคำตอบดิบก่อนหน้ากลับเป็นข้อมูลที่ไม่เชื่อถือ พร้อม feedback
  จาก validator เท่านั้น ไม่เติม prefix หรือแก้ output ด้วยโค้ด
- ตัวนับ grounding ตรวจ error ทุกตัวในข้อความรวม ทำให้ schema error แรก
  ไม่บดบัง `QC-DIGITS` ที่ตามมา
- evaluator build release CLI จาก source ปัจจุบันก่อนเก็บสำเนา
  แก้กรณีเดิมที่ build debug แต่ copy release เก่า พร้อม regression test

คง validator เดิม: concern ยาวไม่เกิน 256 ตัวอักษร ขึ้นต้น `Concern:`,
ไม่มีตัวเลข/คำสั่ง, citations ต้องมีจริง, missing_evidence ไม่เกินแปดรายการ
และแต่ละรายการไม่เกิน 160 ตัวอักษร ไม่ขยาย acceptance เพื่อให้คะแนนผ่าน
Qwen ไม่มีโหวตและน้ำหนักต่อ containment เป็นศูนย์ กฎ supervisor เป็นผู้ตัดสิน
ไม่เปิด Court enforcement และไม่เปลี่ยน gateway หรือ policy ของ deployment

## วิธีทดลอง

ใช้ Qwen2.5-Coder-1.5B Q4_K_M เดิม, SHA256
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`,
seed 42, temperature 0, top_k 1, สี่ threads, context 4096, output 192 tokens
เรียกผ่าน pinned CLI/worker และ process-namespace isolation ของ AIVM
วัดบน commit `3bd151f` พร้อม working-tree changes ของรอบนี้ จึงใช้ source
hashes/snapshot ประกอบ ไม่ถือว่า commit ID อย่างเดียวระบุโค้ดที่วัดครบถ้วน

dev มีแปดเคส รัน `grounded`, `policy`, `missing-context` แยก invocation
เลือก variant จาก dev ก่อนดูผล holdout โดยให้ความสำคัญกับเกณฑ์ผ่านทั้งหมด
ตามด้วยจำนวนเคสที่ได้ concern ผ่าน และจำนวน grounding violations ที่น้อยกว่า
หากเท่ากันใช้ลำดับ `grounded`, `policy`, `missing-context`
การเลือก variant ที่ยังไม่ผ่านเป็นเพียงการวัดข้อจำกัด ไม่ใช่อนุมัติใช้งาน

ก่อนเรียกโมเดลบน holdout ตรวจ audit ด้วย Rust CLI และใช้ watcher/supervisor
ผ่าน `eval-detection.py` จริง ผล baseline ทั้ง 12 เคสตรงกับ response ใน corpus
ไม่มี policy regression; containment TP=4, FP=1, TN=5, FN=2
FP คือ maintenance job ที่ตั้งค่าผิดแต่มี audit pattern เข้าเงื่อนไขกฎ
ผลนี้เป็น synthetic intent labels ไม่ใช่ production accuracy หรือหลักฐานว่าโจมตีสำเร็จ

การลอง prompt ก่อนฉบับสุดท้ายใช้ dev เท่านั้น:

- รอบใน session sandbox เริ่ม controller ไม่ได้ทั้ง 24 invocations
  (`target/security-concerns-dev-2026-11-06/report.json`) จัดเป็น unavailable
  ไม่ใช่ผลคุณภาพโมเดล แล้วจึงรันบน host โดยคง AIVM worker isolation
- candidate แรกที่มีตัวอย่าง JSON ส่วนต้นทำให้คำตอบยาว/ผิด schema ในเคสแรก
  หยุดหลังสี่ attempts ที่บันทึกครบและอีก invocation ถูกขัดจังหวะ
  เก็บใน `target/security-concerns-dev-host-2026-11-06/aborted.json`
- candidate ฉบับสั้นพร้อมตัวอย่าง JSON สมบูรณ์ตอบ `none` โดยไม่มี prefix
  ซ้ำทุก attempt ที่บันทึกครบ 19 ครั้ง จึงตัดออกโดยไม่ให้คะแนนเต็มชุด
  เก็บใน `target/security-concerns-dev-v2-2026-11-06/aborted.json`
- ฉบับสุดท้ายกลับมาใช้ prompt เดิมเป็นฐาน เพิ่มคำสั่ง actor/prefix และ
  retry ที่แนบคำตอบจริง เก็บ source snapshot และ candidate lock ก่อน holdout

CLI release ที่ build ถูกต้องรอบนี้มี hash ต่างจากผลวันที่ห้า ขณะที่ worker
มี hash เดิม จึงไม่สรุปว่าความแตกต่างข้ามวันเกิดจาก prompt อย่างเดียว
การเทียบ candidates ภายในรอบนี้ใช้ CLI/worker ชุดเดียวกัน

## ขอบเขตการแปลผล

`no_fabricated_facts` เป็นชื่อ gate เดิมที่ตรวจตัวเลข, citations และ commands
ใน attempts เท่านั้น ไม่ใช่ semantic verifier ของข้อความทุกประโยค
คำตอบที่ไม่มีตัวเลขก็อาจอ้างผิดว่าข้อมูล actor หรือ policy ไม่ได้ให้มา
จึงต้องอ่าน transcripts ประกอบและไม่อ้างว่าผ่าน gate นี้เท่ากับไม่มี hallucination
containment ที่ตรง baseline ยืนยันเพียงว่า advisory ไม่เปลี่ยนการตัดสิน
ไม่ใช่หลักฐานว่าคุณภาพ detector ดีขึ้นหรือ false containment ลดลง

## คำสั่งทำซ้ำ

```sh
python3 -m unittest discover -s scripts -p 'test_qwen_*.py'
make verify

python3 scripts/eval-qwen-concerns.py --corpus dev \
  --variants grounded,policy,missing-context \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --output target/security-concerns-dev-reproduction/report.json

python3 scripts/eval-detection.py \
  --corpus examples/security-concerns/concern-holdout-2026-11-06.json \
  --output target/security-concerns-holdout-reproduction/baseline.json

# Reproduction เท่านั้น: ชุดนี้ถูกเปิดผลแล้ว ไม่ใช่ holdout ใหม่สำหรับจูนต่อ
python3 scripts/eval-qwen-concerns.py --corpus path \
  --corpus-path examples/security-concerns/concern-holdout-2026-11-06.json \
  --variants grounded \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --require-pass --output target/security-concerns-holdout-reproduction/report.json
```

holdout รอบนี้ใช้วัดครั้งเดียว ไม่ใช้ผลปรับ prompt ต่อ การรันซ้ำภายหลัง
เป็น reproduction และหากจะปรับ prompt ต้องสร้าง holdout ชุดใหม่อีกครั้ง
