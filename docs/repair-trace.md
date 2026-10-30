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

ขอบเขตปัจจุบันคือหนึ่ง standalone function ที่คืน `int`, `unsigned int` หรือ `void` (สำหรับฟังก์ชันที่แก้ไข array in-place แล้วเก็บผลตรวจจาก checksum ของ array), มี named parameters ไม่เกินแปดตัว (`int`, `unsigned`, `const int *`, `int *`, `const char *`, `char *`) และ initialized scalar locals รองรับ `if`/`for`/`while`/`do`, ternary (`?:`), arithmetic, bitwise (`&`, `|`, `^`, `<<`, `>>`, `~`), array subscript (`a[i]`), assignments, `++/--` และ explicit casts (`CStyleCastExpr`)
ยังไม่รองรับ headers/macros ใน source ที่เก็บ trace, globals, function calls/recursion, struct/union, pointer arithmetic นอกเหนือจาก subscript และชนิด `float`/`double` สิ่งที่ไม่รองรับจะปฏิเสธก่อน native execution
ใช้กับ C ที่มี defined behavior; ไม่ได้พิสูจน์ absence of undefined behavior

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

## เปิด automatic repair trace

ตัวช่วย standalone ด้านบนยังใช้ตรวจทีละเคสได้ ส่วน runtime รองรับ automatic trace
แบบ opt-in สำหรับ operator โดยไม่ต้องเรียก cargo/test harness ระหว่าง agent ทำงาน:

```sh
cargo build --release -p aivm-cli
target/release/aivm enable-repair-trace \
  --config examples/build-c.yaml --output target/build-c-with-trace.json
target/release/aivm create coding-trace --config target/build-c-with-trace.json
```

คำสั่งนี้ pin SHA256 ของ collector CLI ปัจจุบัน, Python และ Clang ลง `repair.trace`
โปรแกรมต้องอยู่ภายนอก model workspace และเป็น native executables ที่ pin ตรง
เมื่อ rebuild collector ให้สร้าง config ใหม่ ไฟล์ output ต้องยังไม่มีอยู่
config JSON ที่ได้ใช้กับ CLI/Supervisor เหมือน YAML เดิม

ต้องมี protected verifier/prepare plan ที่รายงาน `AIVM_CASE_FAILURE` พร้อม input JSON
และ `repair.require_plan: true` เมื่อ verifier fail runtime จะ:

1. อ่าน `source_path` ผ่าน gateway เดิม และเลือก structured counterexample ล่าสุด
2. เรียก worker ของ operator ด้วย source/input เป็น JSON ใน stdin มี deadline,
   process group และ output/resource bounds ไม่มี command หรือ script จากโมเดล
3. worker ใช้ Python ที่ pin ไว้กับ preparer code ที่ฝังใน collector binary
   เพื่อหา AST จาก Clang แล้ว compile/run original และ instrumented copy ผ่าน gateway
   ใน private runtime แยกสองชุด ตรวจค่าคืนตรงกันและผูก output snapshots กับ audit
4. แนบ trace ที่ตรงกับ source SHA256/input ปัจจุบัน พร้อมทุก unresolved failure
   ให้โมเดลตอบ complete C function Host ผูก path/failure IDs/old fragment เอง
   เก็บ comments/เนื้อหานอก function span เดิม และใช้ patch ผ่าน gateway
5. ให้ counterexample/full verifier ของ parent task ตัดสินผลตามเดิม

การเก็บ trace ไม่เปลี่ยนสถานะ failure และไม่รีเซ็ต no-progress counter
source เดิม/input เดิมใช้ cache ภายใน task; source เปลี่ยนจะไม่แนบ trace เก่า
ประวัติและ artifact paths อยู่ใน `AgentRun.repair_state.trace_history` และ private report
worker artifacts อยู่ภายนอก model workspace ข้อมูล historical ไม่กลับเข้า model prompt

ค่าปริยายเมื่อเปิดใช้: source `src/main.c`, ไม่เกิน 3 collections/task, 32 events,
deadline 20 วินาที/collection การเก็บ native trace เพิ่มได้ 6 gateway execs/collection
นอกงบ agent steps และบันทึกเวลาใน trace history ให้ประเมินต้นทุนเพิ่มได้
worker มี CPU/memory bounds ของ operator; native targets ใช้ sandbox และ quota แยก

automatic whole-function repair จำกัด source 2048 bytes ถ้าไม่รองรับ, pin ผิด,
worker timeout, trace truncated/เกินขนาด หรือหมด collection budget จะใช้ JSON hunk
repair เดิม โดยคง counterexample ทุกข้อไว้ ไม่มี fallback ไปรัน target นอก sandbox
หาก source/workspace เปลี่ยนระหว่าง collection จะปฏิเสธ trace/patch ที่ผูกกับ snapshot เก่า

`argument_order` เป็น optional list ของชื่อ input keys ตามลำดับ parameters เช่น
`--argument-order b,e` สำหรับ verifier ที่ใช้ keys b/e แม้ implementation เปลี่ยนชื่อ parameter
หากไม่ตั้งจะต้องตรงกับชื่อ parameters ที่ Clang ตรวจพบ ไม่เดาการจับคู่ให้เอง

หากตั้ง `preseed_baseline: true` ใน `repair.trace` (ใช้ในโหมด benchmark ที่ทราบว่า source ตั้งต้นล้มเหลว)
controller จะรัน operator verifier plan ตั้งต้นตั้งแต่ต้น task เพื่อบันทึก structured counterexample
และเก็บ native trace ก่อนเรียกโมเดลครั้งแรก จึงเข้าสู่ whole-function repair ได้ตั้งแต่ model call แรก
เมื่อโมเดลส่งคำตอบที่ซ้ำหรือถูกปฏิเสธซ้ำ `FunctionRepair` จะยกระดับคำแนะนำจาก counterexample
และสรุปพฤติกรรมลูป/การเปลี่ยนค่าตัวแปรจาก `NativeTrace.events` โดยอัตโนมัติ

ปิด automatic trace ด้วยการไม่ตั้ง `repair.trace` จึงคงพฤติกรรม config เก่าได้
การเปิดผ่าน config ยังจำกัดตามขอบเขต C ข้างต้น ผลการซ่อมต้องวัดแยกจาก trace availability
