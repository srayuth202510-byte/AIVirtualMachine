# Build และ test ผ่าน agent runtime

`make test-coding` ทดสอบวงจรอ่าน source → แก้ bug → compile → link → รัน test binary จริง ด้วย GCC, GNU as และ GNU ld ใน process sandbox โมเดลเป็น scripted model เพื่อให้ตรวจ runtime ได้แบบ deterministic โดยไม่ใช้ API key หรือ KVM

เมื่อ task เป็นงานโค้ด agent จะแบ่ง prompt เป็น subtask `inspect → implement → verify → repair` แล้วส่งให้โมเดลทีละช่วง พร้อมคำแนะนำ tool ตามขั้น หลังแก้ไฟล์ agent จะเข้าสู่ verify ซึ่งบังคับให้เรียก `process.exec`; หลัง build/test ล้มเหลวจะเข้าสู่ repair เมื่อ test artifact ผ่านด้วย status 0 agent จะจบงานเอง การเรียก action เดิมซ้ำหรือเรียก tool นอก verify จะถูก audit และหากโมเดลยังวนซ้ำ agent จะหยุดด้วยสถานะ `stalled`

โมเดลบางตัวส่งคำสั่ง build เป็นข้อความต่อท้าย executable ใน `process.exec.path` หรือส่งเนื้อหา source เป็น array ของบรรทัด Runtime แปลงกรณีเหล่านี้เป็น argv และข้อความตามลำดับโดยไม่เรียก shell จากนั้นยังส่งผ่าน `ToolGateway` และตรวจ executable, capability, output slots และ policy ตามปกติ

ทดสอบ baseline ก่อน: `add(2, 3)` คืนค่าผิด ทำให้ test binary ออกด้วย status 1 จากนั้น agent แก้ `a - b` เป็น `a + b` ผ่าน filesystem gateway แล้ว build ใหม่ ผล test binary ต้องเป็น status 0 Audit chain ต้องตรวจผ่านและ quota ของ artifacts ต้องไม่เกินที่กำหนด ผล test จาก agent ไม่เปลี่ยน `tests_passed` ของ Cube; การเปลี่ยน state ยังต้องใช้หลักฐานจาก operator

## เปิดพื้นที่ output

ค่าเริ่มต้นปิด ต้องเปิดใน config โดย operator ดูตัวอย่างเต็มที่ `examples/build-c.yaml`:

```yaml
build:
  enabled: true
  max_files: 4
  max_bytes: 1048576
tools:
  allow: [cc, as, ld, "build:tests"]
verification:
  executable: "build:tests"
  argv: []
```

- Gateway เตรียม output slots ไว้ใต้ `<workspace>/.aivm-build` ไฟล์มี permission 0700 และ directory เป็น 0700
- แบ่ง byte budget เท่ากันระหว่าง `max_files` ตัวอย่างนี้แต่ละไฟล์ไม่เกิน 256 KiB ผลรวม logical sizes ของ artifacts ไม่เกิน 1 MiB
- ก่อน build ตรวจว่า source size + byte budget ที่จองไว้ไม่เกิน `resources.storage`
- รายชื่อไฟล์รวมข้ามคำสั่งต้องไม่เกิน `max_files` ถ้าเต็มจะ DENY ก่อนสร้าง slot เพิ่ม ต้องให้ operator จัดการ artifacts
- Compiler เขียนเฉพาะ slots ที่ประกาศในคำขอนั้น และไม่ได้สิทธิ์เขียน source หรือสร้างไฟล์ทั่วไป ไฟล์ที่ประกาศถูก truncate ก่อนเริ่มคำสั่ง รวมถึงกรณี build ล้มเหลว
- `build:tests` ใน allowlist อนุญาตให้รัน artifact ชื่อ `tests` เท่านั้น ไม่ได้อนุญาตให้รัน output ทุกใบ ใช้ได้เมื่อมี execute capability ตาม state MODIFY/VALIDATE
- Artifact ที่รันผ่าน build profile มี workspace แบบ read-only ยกเว้นประกาศ output slots เพิ่มอย่างชัดเจน
- Artifact directory ไม่ถูกนำเข้า search/RAG และแก้ผ่าน filesystem.write ไม่ได้
- Path traversal, symlink roots, hard links, reserved filenames และการใช้ profile คู่กับ secret injection ถูกปฏิเสธ มี Landlock + seccomp + rlimit + deadline บังคับกับ subprocess tree

## รูปแบบ intent

`content` ต้องเป็น JSON string เช่น object นี้ก่อน encode เป็น intent:

```json
{"argv":["-pipe","-c","src/main.c","-o",".aivm-build/main.o"],"outputs":["main.o"]}
```

Gateway สร้าง `main.o` แล้วจึงรัน compiler Output ใน `argv` ต้องตรงกับ slot ที่ประกาศ มิฉะนั้น kernel จะปฏิเสธ write การ link ใช้ GNU ld โดยตรงและประกาศ output `tests` แบบเดียวกัน

เรียก test binary โดยไม่ต้องรู้ absolute path ของ workspace:

```json
{"tool":"process.exec","path":"build:tests","content":"[]"}
```

Tool result แสดง exit status, stdout และ stderr Agent observation ใช้ `FAIL` เมื่อคำสั่งออกด้วย nonzero status หรือ signal จึงเห็น diagnostics ของ compiler แทนข้อความ `OK` ที่ทำให้เข้าใจผิด

การยืนยัน completion ต้องผ่าน `verification` contract ด้วย ไม่อนุมานจากชื่อ
`build:tests` ดู [รูปแบบ receipt และข้อจำกัด](verification-and-transactions.md)

## ขอบเขตของ profile นี้

รองรับงานที่ระบุ output filenames ได้ล่วงหน้า (Known Output Profile) Workflow ที่ทดสอบเป็น C บน Linux x86_64/glibc ใช้ GCC compile ด้วย `-pipe` และ GNU ld link โดยตรง GCC driver ในขั้น link

**ข้อจำกัดที่รู้จัก (Known Limitations):**

- **Cargo และ build tools ที่สร้าง temporary files แบบชื่อสุ่ม (Random Temp Files) ยังไม่รองรับ** — profile นี้ออกแบบสำหรับ compiler/linker ที่เขียน output ไปยัง path ที่ระบุล่วงหน้าเท่านั้น ไม่มีการเปิด `/tmp` หรือให้สิทธิ์สร้างไฟล์กว้างเพื่อหลบข้อจำกัด
- เพื่อรองรับ Cargo จำเป็นต้องเพิ่ม "Temp Directory Profile" ใหม่: gateway จอง temp directory แบบ bounded (Landlock allow write เฉพาะ temp dir + rlimit fsize + auto-cleanup) และ tool 宣告ต้องระบุ `temp_dir: true` ใน intent — งานนี้ยังไม่ได้ implement (ดู `crates/aivm-tools/src/build.rs` และ `crates/aivm-sandbox/src/landlock.rs`)
- การรัน `make ci` รวม integration suite นี้ด้วย ต้องมี GCC/binutils และ C runtime startup objects ในเครื่อง เช่นเดียวกับ CI Ubuntu
