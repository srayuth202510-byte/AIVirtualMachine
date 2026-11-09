# Availability inventory holdout v2 — 9 November 2026

รอบนี้เป็น **การวัดซ้ำบน holdout ชุดใหม่ชุดที่สอง** หลัง prompt/source ถูกตรึงไว้
ตั้งแต่ต้นเดือน วัตถุประสงค์คือตรวจว่า contract `concern-claims-v1` ที่ให้โค้ด
คำนวณ availability แล้วให้โมเดลคัดลอก ยังคงทำงานได้บน audit shape ใหม่
ที่ไม่เคยใช้ใน dev หรือ holdout ชุดก่อนหน้า ไม่ใช่การปรับ prompt จากผล holdout

## สิ่งที่ทำ

- ตรวจ dev เดิม (`concern-availability-dev-v1.json`) ก่อนแตะ holdout:
  ผ่านทุก gate 8/8 views ตั้งแต่ attempt แรก ไม่มีการแก้ prompt
- สร้าง holdout ชุดใหม่ `examples/security-concerns/concern-availability-holdout-v2.json`
  เป็น 6 matched pairs / 12 views โดย audit shape ทั้งหกไม่ซ้ำกับ
  `concern-dev.json`, `concern-holdout.json`, และ availability v1
  และ context-aware inputs ทั้งสิบสองไม่ซ้ำกัน
- label `response` ของทุกเคสคำนวณยืนยันกับกฎจริง (`rule_decision`) ก่อนรัน
  ไม่ได้ปรับ label จากผลโมเดล
- รันโมเดลจริงครั้งเดียวหลัง freeze: Qwen2.5-Coder-1.5B Q4_K_M เดิม,
  SHA256 `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`,
  seed 42, temperature 0, top_k 1, สี่ threads, context 4096, output 256 tokens

shape ใหม่ที่ใช้: leased-secret burst, hidden-agent flood ที่ actor ผู้ก่อเหตุ
ถูกตัดจาก 32-event context, allow/execute mix, split boundary agents
ที่แต่ละ actor ต่ำกว่า threshold, generic backlog ผสม allow,
และ sensitive signal ที่หมดอายุแล้วตามด้วย generic burst ปัจจุบัน

## ผล

**ผ่านทุก gate: 12/12 views ถูกตั้งแต่ attempt แรก** รวม 12 invocations
ไม่มี retry, schema/grounding rejects, timeout หรือ unavailable

- `missing_evidence` ครบและตรงกับ `missing_fact_ids` ทั้ง 12 เคส
- advisory ทั้ง 12 ผ่าน typed claims validator (`verified_claims=0`,
  ไม่มี actor/count claim เพิ่ม; มี advisory ว่างที่ถูกต้อง 3 เคสเมื่อ context ครบ)
- ไม่มี fabricated facts, lost baseline attacks หรือ added false containment
- containment ตรง baseline 12/12 (TP=4, FP=0, TN=2, FN=6)

ตัวเลข FP=0/FN=6 เป็นของ corpus ชุดนี้ ไม่ได้แปลว่าการตรวจจับดีขึ้น
และไม่สามารถเทียบจำนวนข้ามชุดกับรายงาน v1 ที่มี FP=2 ได้

## หลักฐาน

อยู่ใน `target/security-concerns-availability-holdout-v2/`:

- `report.json`
- `jury-run-*/` พร้อม pinned binaries/config และ raw transcripts

ค่าที่ตรึง:

- corpus SHA256: `c4dd301e99759145c1da6bbfc1fbaeac4bbfcf5f2735827e6a31d118eddff461`
- base prompt SHA256: `f5f277eefd7b9f7e4e1ad25b56954eec1fdb4b5819fd6548f01afadea93c7763`
  (เหมือนรายงาน v1 — ไม่มีการเปลี่ยน prompt)
- transcripts SHA256: `4115db7c9d6acd1a49939f5f63dfb447add66d97df71576e2e006c71bff5c198`
- commit: `ff59bd4a42cc937fc4b4a91e5719ff7fd47bfa69`
- validation contract: `concern-claims-v1`

## ขอบเขตข้อสรุป

นี่คือความแม่นของการ **ถ่ายทอด inventory ที่โค้ดคำนวณแล้ว** บนชุดทดลองปิด
ไม่ใช่หลักฐานว่าโมเดลเข้าใจเจตนาโจมตีหรือ semantic grounding ของ free prose
และไม่ได้ช่วยลด false containment ของ maintenance job จึงยังคง shadow/dry-run
และยังไม่อนุมัติ Court enforcement การเปิด enforcement ต้องผ่าน improvement gate
และเงื่อนไข operational อื่นแยกจากการทดลองนี้
