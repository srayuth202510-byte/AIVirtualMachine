# แผนงาน: ศาลจำลองสำหรับการตอบสนองด้านความปลอดภัย

สถานะ: **ระยะ 1–7 เสร็จ (ศาลจำลอง + ท่อแปล directive + supervisor dry-run)**
— อัปเดต 2026-11-06; ตัวรับใน external Python supervisor ยังไม่เปลี่ยน runtime
และยังไม่เปิด enforcement ใน Rust supervisor/gateway

การวัดระยะ 8 ทำแล้ว: [paired baseline/holdout evaluation](archive/security-court-evaluation-2026-11-05.md)
ยังไม่ผ่านเกณฑ์ลด false containment โดยไม่เพิ่ม misses จึงคง shadow/dry-run

ติดตามระยะ 10 วันที่ 2026-11-06: [ปรับ concern prompt/retry และวัด holdout ใหม่](archive/security-concerns-evaluation-2026-11-06.md)
dev ของฉบับสุดท้ายได้ grounded/missing-context ผ่าน 7/8 เคส และ policy 6/8 เคส
ส่วน holdout ใหม่ของ grounded ผ่านรูปแบบ 9/12 เคสและ containment ตรง baseline 12/12
จึงยังไม่ผ่านเกณฑ์ครบชุด อีกทั้งคำตอบที่ผ่าน schema ยังกล่าวถึง actor ที่สอง
ในเคสที่ facts ยืนยันว่ามี actor เดียว ระยะ 10 มี harness แล้วแต่คุณภาพ
semantic grounding ยังไม่ผ่าน จึงคง shadow/dry-run

คอนแทรกต์ใหม่ [typed claims + grammar](archive/security-concern-claims-evaluation-2026-11-06.md):
dev ผ่าน 10/10 เคส; holdout ใหม่รับ advisory ได้ 11/12 เคส รวมข้ออ้างที่ตรวจแล้ว
30 ข้อ และ containment ตรง baseline 12/12 ตัวตรวจปฏิเสธ false missing-evidence
ทั้งคำตอบแรกและ retry ในอีกหนึ่งเคส ทุก output มี prefix ถูกต้องจาก grammar
แต่ gate คุณภาพทุก attempts ยังไม่ผ่าน คอนแทรกต์นี้ปิดชุดข้ออ้างและให้โค้ด
สร้างข้อความสรุป จึงไม่อ้างว่าแก้ semantic grounding ของ free prose ได้ทั่วไป
และยังไม่อนุมัติ Court enforcement

ผลล่าสุดของ [availability inventory แบบคู่เปรียบเทียบ](archive/security-concern-availability-evaluation-2026-11-06.md):
โค้ดระบุ present/missing IDs และ tag source ให้โมเดลถ่ายทอดอย่างชัดเจน
dev 4 คู่/8 views และ holdout ใหม่ 6 คู่/12 views ผ่านครบตั้งแต่ attempt แรก
รวม gate ความครบถ้วนและ first-attempt ไม่มี retry หรือ rejects ในฉบับสุดท้าย
holdout ไม่ได้เสนอ actor/count claims เพิ่ม จึงยืนยันเฉพาะงานถ่ายทอด availability
และไม่อ้างว่าคุณภาพโมเดลผ่านทั่วไปหรือช่วยลด false containment; คง shadow/dry-run

วัดซ้ำบน [holdout ชุดใหม่ v2](archive/security-concern-availability-holdout-v2-2026-11-09.md)
เมื่อ 2026-11-09: audit shape ใหม่ 6 pairs/12 views ที่ไม่ซ้ำกับ dev/v1
ผ่านทุก gate ตั้งแต่ attempt แรก รวม missing_evidence ครบ 12/12 และไม่มี
fabricated facts (verified_claims=0) โดยไม่เปลี่ยน prompt; containment ตรง baseline
12/12 (TP=4, FP=0, TN=2, FN=6 ของชุดนี้) นี่คือหลักฐาน generalization ของงาน
ถ่ายทอด inventory เท่านั้น ไม่ได้ลด false containment และไม่เปลี่ยนสถานะ shadow/dry-run

ระยะ 9 เรียก Qwen จริงครบ 114 รอบแล้ว:
[สามบทบาทและเสียงข้างมาก](archive/security-court-qwen-evaluation-2026-11-05.md)
เสนอ containment ทุก 38 เคส รวม benign 11 เคส จึงยังไม่ผ่าน improvement gate

เป้าหมายคือเพิ่มกระบวนการพิจารณาที่มีกฎเป็นหลัก มีการทักท้วงและตรวจหลักฐาน
ก่อนเสนอการตอบสนองต่อความเสี่ยง เริ่มจาก shadow mode และวัดผลเทียบกับ
watcher/supervisor เดิม โดยเฉพาะกรณี config ผิดที่ทำให้เกิด containment เกินเหตุ

## หลักที่ต้องรักษา

- กฎสูงสุดคือ invariants ของระบบ: ทุก external action ผ่าน gateway,
  deny-by-default, agent แก้สิทธิ์ตัวเองไม่ได้ และต้องมี audit
- คะแนนโหวตและคำอธิบายของโมเดลไม่มีสิทธิ์ข้ามกฎสูงสุดหรือเพิ่ม permissions
- ผู้พิพากษาเป็น deterministic policy evaluator ที่ตรวจสอบและ replay ได้
  Qwen ทำหน้าที่ช่วยวิเคราะห์และเสนอความเห็นภายใต้ schema ที่จำกัด
- การตัดสินต้องตอบว่า “หลักฐานไม่พอ” ได้ การงดออกเสียงหรือ timeout
  ไม่ถูกนับเป็นหลักฐานว่าเป็นอันตรายหรือปลอดภัย
- กฎป้องกันที่บังคับใช้อยู่ยังทำงานได้ทันที กระบวนการศาลต้องไม่เปิดทาง
  ให้คำสั่งที่ gateway ปฏิเสธ หรือทำให้การควบคุมฉุกเฉินเดิมต้องรอโมเดล
- Immunity Lab เสนอร่างกฎได้ แต่ไม่มีสิทธิ์แก้กฎสูงสุดหรือประกาศใช้เอง

## บทบาทที่เสนอ

| บทบาท | หน้าที่ | ขอบเขตสิทธิ์ |
|---|---|---|
| ผู้รวบรวมหลักฐาน | อ่าน audit/runtime signals พร้อมตรวจ provenance และความต่อเนื่อง | อ่านและส่ง evidence references |
| ฝ่ายกล่าวหา | ระบุข้อสงสัยและกฎที่เกี่ยวข้อง | เสนอข้อกล่าวหาพร้อม event IDs |
| ฝ่ายทักท้วง | หาเหตุอธิบายอื่น เช่น config ผิด ข้อมูลเก่า หรือหลักฐานไม่ครบ | เสนอข้อคัดค้านและข้อมูลที่ยังขาด |
| ลูกขุน | ประเมินหลักฐานแยกกันและลงความเห็น | โหวตพร้อมเหตุผล/หลักฐาน หรืองดออกเสียง |
| ผู้พิพากษา | ตรวจข้อกำหนด หลักฐาน และเกณฑ์คะแนน | ออกข้อเสนอที่อยู่ในขอบเขตของกฎ |
| Supervisor | ตรวจอำนาจและเงื่อนไขการลงมืออีกชั้น | ดำเนินการเฉพาะ action ที่ได้รับอนุญาต |

ลูกขุนควรผสมกฎที่ตรวจซ้ำได้, สัญญาณจาก runtime และการวิเคราะห์ของโมเดล
การเรียก Qwen ตัวเดิมหลายรอบไม่ถือว่าเป็นหลักฐานอิสระหลายแหล่ง
ต้องระบุแหล่งข้อมูลร่วมกันเพื่อไม่ให้นับหลักฐานชิ้นเดียวซ้ำเป็นหลายเสียง

## กฎและมาตรฐานหลักฐานที่ต้องออกแบบ

จัดลำดับกฎสูงสุด → นโยบายตอบสนอง → ข้อกำหนดเฉพาะ deployment
ทุกระดับมี schema, version, hash และกติกาการเปลี่ยนรุ่นที่ชัดเจน
ความขัดแย้งกับกฎระดับสูงกว่าต้องถูกปฏิเสธ

แต่ละเหตุและ action ต้องระบุ:

- ข้อกำหนดที่เกี่ยวข้องและระดับหลักฐานขั้นต่ำ
- แหล่งข้อมูลที่ยอมรับ ความสดใหม่ และ instance/session ที่หลักฐานผูกอยู่
- การตรวจ chain และ provenance โดยไม่อ้างว่า hash chain เป็น external authentication
- จำนวนแหล่งหลักฐานอิสระที่ต้องมี, quorum, เงื่อนไข veto และ abstention
- deadline, ขีดจำกัดทรัพยากร และผลเมื่อข้อมูลขาด/โมเดลล้มเหลว
- การตอบสนองที่อนุญาต ระยะเวลา และวิธีทบทวนหรือย้อนกลับ

ผลพิจารณาที่เสนอ: หลักฐานไม่พอ, เฝ้าดู, จำกัดสิทธิ์, กักกัน, สร้างทดแทน
ต้องแยก “เสี่ยงพอให้กักกันชั่วคราว” จาก “ยืนยันว่าถูกยึดระบบ”
เกณฑ์คะแนนและระดับหลักฐานยังไม่กำหนด ต้องเขียนและตรวจทานก่อนทดลอง
ไม่ให้โมเดลเลือกหรือเปลี่ยน threshold ระหว่างพิจารณา

## ลำดับการพัฒนา

- [x] **ระยะ 1 — นิยามกฎและสัญญาข้อมูล**
  กำหนด schemas ของ case, evidence, allegation, objection, vote และ verdict
  พร้อม decision table และตัวอย่างที่ควรอนุญาต/ปฏิเสธ
  (ทำแล้วใน `scripts/security-court.py` + `scripts/test_security_court.py`:
  `decision-table`, unanimous-override ปฏิเสธ, หลักฐานเสียถูกแยก, replay ซ้ำได้)
- [x] **ระยะ 2 — ผู้พิพากษาแบบ deterministic**
  เริ่มจากลูกขุนจำลอง ทดสอบกฎสูงสุด, หลักฐานขาด, คะแนนเท่ากัน,
  timeout, ข้อมูลซ้ำ และโหวตเอกฉันท์ที่ขัดกฎ
  (ทำแล้วใน `scripts/security-court.py`: `simulate_jury` แปลงช้าเกินเป็น
  timeout, tie ลดหนึ่งระดับ, โหวตซ้ำ/งดออกเสียง/timeout ไม่นับซ้ำฝั่งใด)
- [x] **ระยะ 3 — ฝ่ายทักท้วงและลูกขุนหลายแหล่ง**
  เชื่อมกฎ/runtime/Qwen แบบ advisory ตรวจ schema และ evidence IDs
  ไม่ส่งคำสั่งจากข้อความโมเดลเข้า runtime
  (ทำแล้ว: `advisory_to_votes` ตรวจ schema/อ้าง event นอกเคส/ข้อความคำสั่ง
  ทิ้งทั้งชิ้น ที่ปรึกษาซ้ำนับครั้งเดียว)
- [x] **ระยะ 4 — Shadow evaluation**
  บันทึกคำตัดสินโดยไม่เปลี่ยน runtime เทียบ baseline เดิมกับ corpus,
  mutations และข้อมูลจริงที่ผู้ดูแลให้ label แยกจากผู้เสนอ
  (ทำแล้ว: `shadow` รัน `examples/security-court/` 3 bundles + `labels.json`
  ตรวจ mismatch + `diff_runs` เทียบสองรัน replay ได้)
- [x] **ระยะ 5 — ทบทวนก่อนเชื่อม enforcement**
  สรุปผลและข้อจำกัด กำหนด deployment policy, kill switch, rollback,
  budget และช่องทางทบทวน ก่อนพิจารณาเปิดการตอบสนองจริงในงานถัดไป
  (ทำแล้ว: `validate_policy`/`apply_policy`/`review` — kill switch หยุดทุก
  action, เพดานกด action ลง, law รุ่นผิด fail-closed, review ไม่คืนสิทธิ์เอง)
- [x] **ระยะ 6 — ท่อแปลคำตัดสินเป็น directive (ยังไม่ผูก gateway จริง)**
  แปล verdict → directive ที่ "จำกัดได้เท่านั้น" พร้อม ledger ตรวจย้อนกลับได้
  และ replay/idempotent; การบังคับใช้ใน Rust supervisor/gateway ยังเป็นงาน
  ถัดไปโดย design (ต้องมี adversarial case ก่อนเปิด exec surface ใหม่)
  (ทำแล้ว: `enforce` — `enforcement_table`, `enforcement_directive`,
  `enforce_run`; ตรวจ law_hash ซ้ำกับ case, ผูก `bundle_sha256` กับข้อมูลคดี
  ทั้งชุดและ replay verdict ก่อนแปล, evidence refs ต้องอยู่ใน bundle,
  action ห้ามเกิน `case.requested_action` หรือ `policy.max_action`,
  kill switch = ไม่มี directive, quarantine/restrict/replace ปล่อยสิทธิ์
  ผ่าน policy review เท่านั้น (deadline ใช้แค่กำหนดทบทวน), ledger ห้าม
  case_id ซ้ำและ replay ได้ bytes เดิม; ถือ lock ข้ามโปรเซสตั้งแต่อ่านจนเขียน
  ledger เสร็จ; เทสต์ใน `EnforcementTests`)
- [x] **ระยะ 7 — Receiver แบบ dry-run ใน external supervisor**
  `scripts/aivm-supervisor.py --court-ledger … --court-corpus … --court-policy …`
  replay directive ทุกฟิลด์กับ bundle, ตรวจ instance จาก controller state,
  session จาก audit ล่าสุด และอายุหลักฐานจาก timestamp ของ audit ที่ Rust
  ตรวจ chain แล้ว ใช้ hash ของ audit record เป็น event ID; ตรวจ kill switch
  และ action cap ปัจจุบันอีกครั้ง บันทึก `court-preview.json` พร้อม provenance
  และ `applied: false` เสมอ แถวใดผิดต้อง blocked ทั้งรอบ ไม่เรียก reconcile,
  systemd หรือ gateway; CLI ปฏิเสธ `--apply`, `--watch` และ `--drain`
  ดู [วิธีใช้และข้อจำกัด](recovery-supervisor.md#security-court-dry-run)
- [x] **ระยะ 8 — วัด Court เทียบ baseline และ holdout แบบจับคู่**
  `scripts/eval-security-court.py` ใช้ labels เดิมเพื่อ scoring เท่านั้น;
  Court ที่ใช้ audit เดิมให้ containment เท่า baseline ส่วน profile ที่ต้องการ
  สองแหล่งยังงดตัดสินทุกเคสเพราะมี stream เดียว จึงไม่ผ่าน improvement gate
  รายงาน FP/FN, abstentions, coverage, cases ที่เปลี่ยน และ provenance แยก
  baseline/holdout; ผลนี้ยังไม่อนุมัติ enforcement
- [x] **ระยะ 9 — Qwen จริงแบบฝ่ายเดียวและสามบทบาท**
  เพิ่ม `--model`/`--model-sha256` ใน evaluator และ `qwen-court-jury.py`
  แต่ละฝ่ายเรียก pinned process-namespace worker แยก context ไม่เห็นคำตอบกัน
  เก็บ prompt/output/error/citations พร้อม provenance 114 invocations;
  เป็นโมเดลเดียวหลายบทบาทและยังมีหลักฐาน stream เดียว ไม่ปลอมเป็นหลายแหล่ง
  ผล majority: baseline TP 20 / FP 6, holdout TP 7 / FP 5 — เลือก containment
  ทุกเคส จึงยังไม่พิสูจน์ประโยชน์ในการแยกแยะ รายละเอียดและข้อจำกัดอยู่ใน
  [รายงาน Qwen](archive/security-court-qwen-evaluation-2026-11-05.md)
- [x] **ระยะ 10 — concern mode: facts โค้ดคำนวณ + กฎเป็นผู้ตัดสิน**
  เขียน `qwen-court-jury.py` ใหม่เป็น schema `{"concern", "cited_event_ids",
  "missing_evidence"}` (ไม่มี verdict/โหวต) และ `rule_decision()` ให้กฎ
  `deny-burst-with-boundary-or-sensitive-access` ตัดสิน containment เสมอ
  (โหวตเดียวจาก `supervisor-rule`, `min_sources:1/quorum:1`); facts
  (จำนวนนับ/ช่วงเวลา 60 วินาที/actor-session/hidden-from-context) คำนวณด้วยโค้ด
  ส่งให้โมเดลโดยตรงและบังคับ grounding: ห้ามตัวเลขในข้อความ
  (Thai digits รวม), อ้าง event เฉพาะที่มีจริง (≤32 ตัว), ห้ามคำสั่ง/code fence
  และห้ามลอกคำ placeholder ของตัวอย่าง, retry บอกเฉพาะ schema พร้อมย้ำ
  คงเนื้อหาเดิม; `eval-qwen-concerns.py` รันชุด `concern-dev` (8 เคส
  ใช้ปรับ prompt) และ `concern-holdout` (9 เคส วัดครั้งเดียว) ตรวจ dev∩holdout
  ซ้ำกันจะไม่ผ่าน, แยก attempt kinds (schema / grounded_digits /
  grounded_citation / grounded_command / timeout / unavailable) และเกณฑ์ผ่าน
  `no_fabricated_facts`, `no_false_positives_beyond_baseline`,
  `no_lost_baseline_attacks`, `containment_matches_baseline`,
  `all_calls_resolved`; ผล Qwen2.5-Coder-1.5B (GGUF pin ที่รู้จัก):
  **dev ผ่านทุกเกณฑ์** (9 calls / 8 cases, ลอก placeholder ถูกจับแล้ว
  แก้ด้วย anti-echo validation + prompt ย้ำคงเขียนของตัวเอง), **holdout ไม่ผ่าน
  2 เกณฑ์** (1 attempt มีตัวเลขในข้อความ = grounded_digits, และ 2 เคสไม่ได้
  concern ที่ผ่านหลัง retry เนื่องทิ้งคำนำหน้า `Concern:`; ส่วน
  `containment_matches_baseline` ผ่านครบ 9 เคส — กฎไม่เสียการตัดสินเพียงชั้นเดียว)
  ขั้นถัดไป: ปรับ prompt ต่อบน dev เท่านั้น เช่น ย้ำรูปแบบคำนำหน้ากับชื่อ actor
  แล้ววัดใหม่บน holdout ที่แตกเคสใหม่ (ห้ามถอดไปปรับจากเคสเดิม)


## การเปลี่ยนเป็น court-law-v2

รุ่น v2 แก้การนับโหวตซ้ำและเพิ่ม `bundle_sha256` ใน verdict และ directive:

- นับหนึ่งเสียงต่อ `(voter, origin)` สำหรับทุกผล รวม not-guilty, abstain และ
  timeout; ถ้าผู้โหวตเดียวกันให้ผลขัดกัน ให้ปฏิเสธทั้งคดีโดยไม่เลือกรับตามลำดับ
- hash ครอบคลุม case, evidences, allegations, objections และ votes ทั้งชุด
  รวม instance/session และหลักฐานที่ถูกคัดออก ใช้ canonical JSON ที่เรียง keys;
  ลำดับรายการเป็นส่วนหนึ่งของข้อมูลที่ผูกไว้
- `enforcement_directive` รับ bundle เต็มแทน case อย่างเดียว ตรวจ digest
  และ replay ผลตัดสินก่อนสร้าง directive จึงไม่รับ verdict เก่ากับ bundle
  ที่เปลี่ยน VM/session หรือหลักฐานแล้ว hash นี้ตรวจการจับคู่ข้อมูล
  ภายใต้ trusted custody เดิม ไม่ใช่ลายเซ็นรับรองผู้ส่ง
- `enforce` ใช้ไฟล์ `<ledger>.lock` กับ `flock` ครอบการอ่าน ตรวจ case ซ้ำ
  append, flush/fsync และเก็บ hash ของ ledger; ไม่ลบไฟล์ lock หลังใช้งาน
  เพื่อให้ทุก writer ล็อก inode เดียวกัน การเขียนพร้อมกันจึงไม่เพิ่ม case ซ้ำ
- case ID เดิมที่ผูก bundle คนละ hash ถูกปฏิเสธก่อน append ทุกแถวในรอบนั้น
  การ replay bundle เดิมไม่เพิ่ม record และคง bytes ของ ledger เดิม

policy ต้องระบุ `law_version: court-law-v2` ส่วน verdict และ ledger รุ่นเก่า
ที่ไม่มี bundle hash จะถูกปฏิเสธ ไม่เติม hash ให้โดยอนุมานย้อนหลัง:
เก็บ ledger เก่าไว้เป็นหลักฐาน สร้าง verdict ใหม่ด้วย `judge`/`shadow` จาก
bundle ต้นฉบับที่ตรวจทานแล้ว และใช้ ledger ใหม่สำหรับ v2 การตรวจนี้ยังไม่เชื่อม
กับ enforcement ใน Rust supervisor/gateway

## Adversarial gate ก่อนเชื่อม supervisor (2026-11-05)

รัน `python3 -m unittest discover -s scripts -p 'test_security_court.py'`
ได้ 38 tests (รวม subtests หลาย inputs ต่อ test) โดยเพิ่มการตรวจต่อไปนี้:

- หลักฐานผิด instance/session, หมดอายุ, chain เสีย หรือ event แต่งขึ้น:
  แม้โหวต guilty เอกฉันท์ ก็ต้องเหลือ `none` เมื่อแหล่งอิสระไม่พอ
  ตรวจทั้ง verdict และ ledger ที่เขียนผ่าน `enforce_run`
- ขอบเขตอายุหลักฐาน: เท่ากับเพดานยังใช้ได้; เกินหนึ่งวินาทีถูกคัดออก
  อายุในขั้นนี้ยังเป็น `age_secs` ที่ bundle ให้มา ไม่ใช่การตรวจเวลาปัจจุบัน
  ของ supervisor ตอนรับ directive
- สำเนาหลักฐานสิบชิ้นจากแหล่งเดียวไม่นับเป็นสิบแหล่งอิสระ
- ฟิลด์เพิ่มสิทธิ์ (`grant`, `capabilities`, `permissions`) ในทุกส่วนของ
  bundle ถูกปฏิเสธ แม้คำนวณ bundle hash ใหม่; `grant` ใน verdict,
  policy หรือ ledger ก็ถูกปฏิเสธก่อนเขียนผลใหม่
- allegation ที่แรงเกิน case ถูกปฏิเสธ; ตรวจ action × policy cap ครบ
  25 คู่ และ directive จำกัดสิทธิ์ต้องคง `policy-review`
- verdict แถวท้ายเสียต้องไม่เพิ่มแถวก่อนหน้าเข้า ledger เดิมบางส่วน
  ส่วนการส่งซ้ำและการชนกันข้ามโปรเซสยังใช้ regression tests เดิมคุม
- boolean ต้องไม่แทน integer ใน thresholds, อายุหลักฐาน, budget,
  เวลาลูกขุน หรือ `independent_sources` โดยเฉพาะ `true` ที่ Python
  เทียบเท่ากับ `1` ซึ่งเดิมผ่านการเทียบ verdict กับผล replay ได้

ชุดนี้ยืนยันขอบเขตของ Python judge/translator เท่านั้น ไม่ได้ยืนยันการรับ
directive ของ Rust supervisor, การกัน session เปลี่ยนระหว่างตรวจและลงมือ,
การตรวจ freshness ณ เวลาลงมือ หรือผลลด false positives เทียบ baseline
ต่อยอดด้วย `CourtPreviewTests` ใน `scripts/test_supervisor.py` แล้ว:
มี replay ของ directive ที่ถูกแก้, VM/session ผิด, session เปลี่ยน,
event ข้าม actor, audit หาย/เสีย/anchor ขาด, อายุจริงเกินเพดาน,
review deadline, policy cap/kill switch, duplicate, budget, input ไม่ถูกต้อง
และ CLI ที่ต้องไม่เปลี่ยน controller state/audit หรือเปิด apply mode
เทสต์ใช้ controller/adapter จำลอง แต่ตรวจ audit ผ่าน Rust CLI จริง

วัด paired baseline/holdout แล้วใน [รายงานระยะ 8](archive/security-court-evaluation-2026-11-05.md)
ยังไม่พิสูจน์การลด false containment โดยไม่เพิ่ม misses และ Qwen จริงรอบนี้
ยังแต่งข้อเท็จจริง/โหวตขัดเหตุผลได้แม้ schema ผ่าน ขั้นถัดไปต้องตรวจ grounding
และความสอดคล้องของ output รวมทั้งเพิ่มบริบทที่ตรวจสอบได้แล้ววัดใหม่
ก่อนพิจารณา enforcement จริง
ซึ่งยังต้องตรวจ process/session ณ เวลาลงมือและทำ transaction/recovery เพิ่มเติม

## เกณฑ์พิสูจน์ก่อนขยับแต่ละระยะ

- โหวตเอกฉันท์ต้องไม่อนุญาต action ที่ขัดกฎหรือมีหลักฐานต่ำกว่าเกณฑ์
- เหตุการณ์ปลอม/ซ้ำ, หลักฐานผิด instance, stale evidence, prompt injection
  และโมเดลสร้าง event ID เอง ต้องไม่เพิ่มอำนาจในการลงมือ
- การพิจารณาเดิมภายใต้กฎรุ่นเดิมและ inputs เดิมต้อง replay คำตัดสินได้
  เก็บผลโมเดลที่ใช้จริงไว้ประกอบการ replay โดยไม่ต้องเรียกโมเดลใหม่
- วัด false positives, misses, abstentions, coverage และ latency แยกกัน
  พร้อมรายงานต้นทุนและจำนวนกรณีที่คำตัดสินเปลี่ยนจาก baseline
- ต้องลด containment ผิดในชุดทดสอบที่ตกลงไว้โดยไม่เพิ่ม misses ในชุดนั้น
  ถ้ายังแยกไม่ได้เพราะ inputs เหมือนกัน ต้องรายงานว่าข้อมูลไม่พอ
- ทดสอบความล้มเหลวของแต่ละบทบาทและตรวจว่าขอบเขต gateway เดิมยังคงอยู่
- ทุก verdict อ้าง case ID, law version/hash, evidence references,
  votes/objections, เงื่อนไขที่ผ่าน/ไม่ผ่าน และเหตุผลของ action ที่เสนอได้
- ทบทวนด้วยหลักฐานใหม่ได้ แต่การทบทวนไม่คืนสิทธิ์หรือปล่อย instance
  ที่ถูกกักกันโดยอัตโนมัติ ต้องผ่านนโยบายที่กำหนดอีกครั้ง
- directive ทุกใบต้องจำกัดสิทธิ์เท่านั้น ห้ามมีช่องเพิ่ม capability/permission,
  ต้องไม่เกิน `case.requested_action`/`policy.max_action` และ replay แล้ว
  ledger ต้องได้ bytes เดิม (case_id ซ้ำไม่ได้)

ฐานที่ใช้ต่อยอด: [detection evaluation](detection-evaluation.md),
[recovery supervisor](recovery-supervisor.md) และ [Immunity Lab](immunity-lab.md)
