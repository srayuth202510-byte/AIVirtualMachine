# แผนงาน: ศาลจำลองสำหรับการตอบสนองด้านความปลอดภัย

สถานะ: **ระยะ 1–6 เสร็จ (ศาลจำลอง + ท่อแปล directive)** — อัปเดต 2026-11-04;
ยังไม่ผูก supervisor/gateway จริง (งานถัดไปต้องมี adversarial case ก่อน)

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
