# แผน: Structured output, semantic verification และ staging recovery

สถานะ: **ส่วน 1–2 เสร็จและตรวจแล้ว รวม Qwen รอบสด; ส่วน 3 ยังไม่ได้ implement** — อัปเดต 27 ตุลาคม 2026
ผลและข้อจำกัด: [structured output](structured-output-validation-2026-10-27.md), [semantic verification](semantic-validation-2026-10-27.md)
Baseline: `aee1c18` พร้อมผล [coding validation](coding-validation-2026-10-26.md)
และ [model quality](model-quality-2026-10-26.md)

เป้าหมายคือใช้ backend และ verifier เดิมให้มากที่สุด แบ่งงานเป็นสามชุด
ที่ review และตรวจผลแยกกันได้: GBNF + Serde, verifier + Proptest,
และ staging reproduction + nextest/strace

## ลำดับทำงาน

1. เก็บ baseline และแยก build/evidence directories
2. บังคับ structured output และตรวจ schema ก่อนใช้ผล
3. เพิ่ม semantic verification และ property-based tests
4. พิสูจน์และแก้ staging race พร้อมเพิ่ม test runner ที่แยก process
5. รัน gate รวมและบันทึกผลจริงของทั้งสามส่วน

## 0. Baseline และหลักฐานร่วม

- [x] เก็บ commit, source diff/hash, tool versions, model/config/corpus hashes
  และคำสั่งที่รันใน evidence directory ใหม่ ไม่เขียนทับผลวันที่ 26 ตุลาคม
- [x] ใช้ Cargo target directory แยกระหว่าง gate กับ pinned worker host tests
  ไม่ build worker คนละ features ทับ binary ที่กำลัง validate
- [x] คง approved model/boot pins เดิม หากแก้ worker ให้ผูก test config กับ hash
  ของ build ใหม่ที่สร้างจาก source นี้ และเก็บ build identity ชัดเจน
- [x] บันทึก failure เดิมทุกครั้ง ไม่มีการ retry แล้วลบประวัติรอบที่ล้ม

## 1. JSON: GBNF + Serde

### งานที่จะทำ

- [x] เพิ่ม output mode ที่ caller เลือกอย่างชัดเจน เช่น text, JSON value
  และ agent intent; ใช้ text เป็นค่าเริ่มต้นสำหรับ caller เดิม
  งาน extract ข้อความไม่ถูกบังคับเป็น JSON ทั้งหมด
- [x] กำหนด protocol version/capability ให้ worker เก่าที่ไม่รองรับโหมดใหม่
  ถูกปฏิเสธ ห้ามอาศัย field ใหม่ที่ worker เก่าอาจ ignore เงียบ ๆ
- [x] ต่อ `LlamaSampler::grammar` ที่มีใน `llama-cpp-2` รุ่นที่ repo ใช้อยู่
  เข้ากับ sampling chain ก่อนเลือก token และสร้าง grammar state ใหม่ต่อ inference
- [x] เริ่มจาก GBNF คงที่ที่ควบคุมได้: JSON value และ schema ของ agent intents
  ยังไม่ทำตัวแปลง arbitrary JSON Schema หรือเพิ่ม framework server ใหม่
- [x] ตรวจ final output ด้วย JSON parser และ typed Serde schema อีกครั้ง
  สำหรับ agent คงการปฏิเสธ unknown fields/tools และตรวจ content ของแต่ละ tool
  ผ่าน gateway ตามเดิม Schema ไม่ได้ออก capability ให้โมเดล
- [x] Grammar โหลดไม่ได้, output ขาด, token budget หมดก่อน JSON ครบ
  หรือ schema ไม่ตรง ต้องคืน failure/incomplete ที่ระบุได้ ไม่มี fallback เป็น raw text
- [x] Structured streaming ต้องไม่ส่ง partial JSON เข้า dispatcher;
  รับเป็นผลสำเร็จได้หลัง final validation เท่านั้น และทดสอบ streaming แยก
- [x] เพิ่ม evidence ว่า request ใช้ output mode/grammar รุ่นใดจริง

จุดแก้หลัก: `crates/aivm-model/src/lib.rs`, `src/worker.rs`, worker entrypoint,
worker protocol/quality tests และ agent integration ที่ใช้ intent schema

### เกณฑ์ผ่าน

- [x] ทุก successful response ในโหมด structured ผ่าน parser/schema ที่กำหนด
  ไม่มี Markdown รอบ JSON; incomplete output ไม่ถูกนับว่า format ผ่าน
- [x] Negative cases ครอบคลุม extra/duplicate fields, tool ผิด, malformed/truncated JSON,
  Unicode, grammar state ข้าม request และ budget/deadline/cancellation
- [x] Text mode เดิมและ gateway must-deny cases ผ่าน regression
- [x] รัน model corpus เดิม 6 + 8 งานโดยไม่เปลี่ยน oracle
  เลือก mode ตามรูปแบบงาน ไม่ใช้ค่า oracle เป็น grammar ที่ล็อกคำตอบถูกไว้
- [x] รายงาน format/schema validity แยกจาก task correctness
  ไม่ใช้การสร้าง JSON สำเร็จแทนข้อสรุปว่าคำตอบถูก

## 2. ความหมาย: verifier + Proptest

### งานที่จะทำ

- [x] ใช้ `verification.prepare` และ protected operator verifier เดิม
  สำหรับ compile/link/test; งานคำนวณหรือ sort ที่ใช้โปรแกรมช่วยต้องมี
  executable/arguments ที่อนุญาตและวิ่งผ่าน gateway ปกติ
- [x] เพิ่ม Proptest เป็น dev dependency เพื่อสร้างและย่อกรณีทดสอบที่ล้ม
  เก็บ seed/minimal regression case ให้ replay ได้
- [x] เพิ่ม properties ของ sorting: เรียงตามลำดับ, สมาชิกและจำนวนซ้ำคงเดิม,
  ครอบคลุม array ว่าง ค่าติดลบและค่าซ้ำ ไม่ทดสอบด้วยตัวอย่างบวกเพียงชุดเดียว
- [x] เพิ่ม verifier cases ของ arithmetic/code execution ที่มีเครื่องหมายลบ
  และกำหนดขอบเขต/นโยบาย overflow ชัดเจน ไม่ใช้ C undefined behavior เป็น oracle
- [x] ใช้ generated cases กับ verifier/runtime tests ที่รันเร็ว
  ไม่เรียกโมเดลจริงหลายร้อยครั้งใน unit gate
- [x] แยก metrics อย่างน้อยเป็น `format_valid`, `schema_valid`, `task_correct`,
  infrastructure status และ termination reason พร้อม raw output
- [x] รายงาน semantic changes ของเคสที่ strict oracle ตกทั้งสองฝั่งด้วย
  เช่นเดิม sort ถูกแต่ครอบ fence กลายเป็น JSON ถูกแต่เรียงผิด
- [x] เพิ่มชุดประเมินแยกที่ไม่ใช้ปรับ prompt และ freeze inputs/oracles ก่อนทดลอง
  คงผลเดิมให้เทียบย้อนหลังได้

จุดแก้หลัก: `crates/aivm-runtime/tests/coding_workflow.rs`, verifier tests,
`crates/aivm-model-worker/tests/quality.rs`, `scripts/eval-model-quality.py`
และ dependency/test configuration

### เกณฑ์ผ่าน

- [x] Known-broken implementations และคำตอบผิดในรายงานเดิมถูก verifier ปฏิเสธ
  ขณะที่ implementation ที่ถูกต้องผ่าน properties และ regression cases
- [x] Agent เขียน verifier/expected answers ไม่ได้ และ model summary
  ไม่สามารถสร้าง verification receipt เอง
- [x] หลักฐานขาด คะแนนไม่ตรง output หรือใช้ corpus/config คนละชุด
  ถูก validator ปฏิเสธ
- [x] ผล model-only และผลที่ใช้โปรแกรมช่วยถูกรายงานแยกกัน
  ไม่อ้างว่า Proptest หรือ tool assistance ทำให้โมเดลตอบถูกทุกเรื่อง

## 3. Test ไม่เสถียร: reproduction + nextest + strace

### งานที่จะทำ

- [ ] ทำซ้ำ `recovery_skips_active_leases_and_removes_abandoned_requests`
  ทั้งแบบเดี่ยวและขนาน เก็บ failure แรกพร้อม process/fd/lease metadata
- [ ] ใช้ strace ติดตาม fork/exec, open/close, flock และ remove
  เพื่อพิสูจน์สาเหตุ สมมติฐานเรื่อง fd ที่ถูกสืบทอดยังไม่ถือเป็นข้อสรุป
- [ ] ให้ staging tests รับ temporary root ของตัวเองผ่าน argument/helper
  ไม่แก้ environment `TMPDIR` ร่วมกันระหว่าง threads
- [ ] สร้าง regression ด้วย subprocess และ pipe/barrier ระบุจังหวะถือ lease,
  process exit และ recovery ไม่ใช้ fixed sleep หรือเพิ่ม retry เพื่อกลบ failure
- [ ] แก้ production lifecycle เฉพาะเมื่อหลักฐานแสดงว่า implementation ผิด
  ถ้าสัญญาของ test ผิด ให้แก้ test โดยยังพิสูจน์ ownership/lifetime จริง
- [ ] เพิ่ม cargo-nextest แบบ pin รุ่นและระบุวิธีเตรียมเครื่อง/CI
  ใช้ process-per-test ช่วยแยกสภาพแวดล้อม พร้อมกำหนดกลุ่ม host tests ให้เหมาะสม
- [ ] คงการตรวจด้วย `cargo test --workspace` แบบขนานด้วย
  nextest/serial run ต้องไม่กลายเป็นวิธีซ่อน production race
- [ ] คง doctest gate แยกตามความสามารถของ runner และอัปเดต Makefile/CI parity

จุดแก้หลัก: `crates/aivm-model/src/worker/staging.rs`, process/helper tests,
nextest configuration, Makefile, CI และเอกสารทดสอบ

### เกณฑ์ผ่าน

- [ ] มี deterministic reproducer หรือหลักฐานที่อธิบาย failure เดิมได้
  ไม่ปิดงานเพียงเพราะรันครั้งต่อมาผ่าน
- [ ] Lease ที่ยังมีเจ้าของต้องไม่ถูก recovery ลบ; เมื่อ descriptors ปิดครบแล้ว
  abandoned staging ถูกกู้ได้โดยไม่กระทบ active requests
- [ ] Stress แบบขนานเริ่มที่ 1,000 รอบต่อ test case บน host เดิม
  เก็บจำนวนรอบ, concurrency, failures และ residuals; จำนวนรอบอย่างเดียวไม่แทน proof
- [ ] ผ่านทั้ง native Cargo runner และ nextest โดยไม่ต้อง serialize ทั้ง suite
  และไม่มี automatic retry เปลี่ยนผลล้มเหลวให้เป็นผลผ่านเงียบ ๆ

## Gate ปิดงานและผลส่งมอบ

- [ ] `make verify` และ CI parity ผ่านบน source สุดท้าย
- [ ] Lint/tests ของ `llama` และ worker protocol ผ่าน
  เพิ่ม feature/host checks ตามเส้นทางที่เปลี่ยนจริง
- [ ] Model host evaluation มี complete structured evidence และไม่มี skipped test
  ถูกนับเป็น host validation ผ่าน
- [ ] รายงาน JSON format, semantic quality, latency/resource usage และ staging
  stability แยกกัน พร้อมข้อจำกัดและ failure logs
- [ ] แยก implementation เป็นสาม commits/PRs ตามส่วน 1–3
  แต่ละส่วนมี regression และหลักฐานก่อนปิดงาน

## แหล่งอ้างอิง

- [llama.cpp GBNF และ JSON Schema subset](https://github.com/ggml-org/llama.cpp/blob/master/grammars/README.md)
- [Proptest](https://proptest-rs.github.io/proptest/intro.html)
- [nextest process-per-test](https://nexte.st/docs/design/why-process-per-test/)
- [strace](https://man7.org/linux/man-pages/man1/strace.1.html)
- [flock lifetime และ inherited descriptors](https://man7.org/linux/man-pages/man2/flock.2.html)
