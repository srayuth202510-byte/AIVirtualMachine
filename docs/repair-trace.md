# Native trace helper

`scripts/run-repair-trace.py` รับ C source, ชื่อฟังก์ชันและ JSON input แล้วใช้ Clang AST
หาตำแหน่ง parameter, initializer, assignment, ++/--, branch/loop condition และ return
จากนั้นสร้างสำเนาที่เก็บค่าจากการรันจริง ไม่ให้โมเดลสร้าง script หรือคาดเดา state

```sh
python3 scripts/run-repair-trace.py \
  --source target/repair-plain-integer-power-2026-10-29/evidence/integer_power/source.c \
  --function integer_power --input '{"b":-3,"e":1}' \
  --out target/native-power-trace
```

ต้องมี Clang สำหรับอ่าน AST และ GCC/binutils สำหรับ native collector
runner ใช้ operator-only ignored test ใน coding_workflow เพื่อส่ง compile/link/run
ผ่าน gateway, sandbox, build slots และ audit เดิม ไม่มี model tool หรือ capability ใหม่
ไม่ได้เรียก debugger, shell หรือ Python จากโมเดลเพื่อรัน target

ขอบเขตแรกคือหนึ่ง standalone function ที่คืน int, มี named int parameters ไม่เกินแปดตัว
และ initialized int locals รองรับ if/for/while/do, arithmetic, assignments และ ++/--
ยังไม่รองรับ headers/macros, globals, function calls/recursion, pointers, arrays,
storage qualifiers และชนิดตัวเลขอื่น สิ่งที่ไม่รองรับจะปฏิเสธก่อน native execution
ใช้กับ C ที่มี defined integer behavior; ไม่ได้พิสูจน์ absence of undefined behavior

สำเนา instrumented ต้องคืนค่าเท่ากับ source เดิมใน input ที่เลือกจึงออก `trace.json`
ความเท่ากันนี้เป็นเพียงการตรวจหนึ่ง input ไม่ใช่การพิสูจน์ว่า instrumentation
รักษาพฤติกรรมทุกกรณี `++/--` เก็บ new value แต่รักษา expression value ของ postfix
และ initializer/assignment/return expressions ถูกประเมินเพียงครั้งเดียว

เก็บได้ 32 events โดยปริยาย ตั้งได้ 4–64 เมื่อเกินจะจบด้วย exit 75 และ marker
`AIVM_TRACE_TRUNCATED` ซึ่ง runner ปฏิเสธเป็น complete trace
มี timeout/resource limits ผ่าน sandbox และ process-group timeout รอบ cargo
หาก sandbox ใช้ไม่ได้จะไม่ fallback ไปรัน target ตรงบน host

Output directory ต้องใหม่เพื่อรักษาหลักฐาน:

- `source.c`, `original.c`, `traced.c`, `bundle.json`: source/payload/parser identity และจุดเก็บค่า
- `measurement/`: native results พร้อม task/outcome/receipt และ audit ของ original/traced แยกกัน
- `trace.json`: observations ที่ผูกกับ source SHA256 และ input
- `context.txt`: ข้อความสั้นสำหรับแนบกับคำขอ repair
- `runner.json`: ผลการเก็บ trace และ source identity ก่อนหลัง

`--prepare-only` สร้าง source bundle โดยไม่รัน target และไม่สร้างหลักฐาน observed trace
`runner.passed` หมายถึง trace collection สมบูรณ์เท่านั้น `repair_verified` เป็น false เสมอ
measurement driver ที่ exit 0 ไม่ได้เป็น verifier ของโจทย์ ต้องตรวจ patch ด้วย protected verifier เดิม
หลัง source เปลี่ยน trace เดิมเป็นข้อมูล historical และต้องเก็บใหม่เพื่อใช้อธิบาย candidate ปัจจุบัน

helper นี้ยังเป็น operator workflow แยกจาก automatic retry loop
การแนบ `context.txt` ควรรักษา unresolved input/expected/actual จาก repair ledger เดิมครบ
ทดสอบผลกับโมเดลโดยคง plain-language request เดิม แล้วเพิ่มเฉพาะ trace เป็นการทดลองถัดไป
