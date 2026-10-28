# Review fixes — 28 ตุลาคม 2026

แก้ข้อสังเกตสามรายการจาก review ของ commit `5610c74`

## Network response quota

`max_total_bytes` ของ network capability เป็นงบ application payload:
จองความยาว request body ก่อนส่ง และนับ response body ทุก chunk ที่ HTTP reader
คืนมาให้ gateway รวม response ที่ใหญ่เกิน, ไม่ใช่ UTF-8 หรือขาดกลางทาง
นับและ checkpoint ก่อนตรวจปฏิเสธ จึงไม่คืนงบหลัง error หรือ restart
ไม่ได้วัด TCP/TLS headers, retransmission, URL/HTTP headers หรือ transport read-ahead

เพดานการอ่านคือ min(response limit ที่เหลือ, cumulative budget ที่เหลือ)
พร้อม lookahead ไม่เกินหนึ่งไบต์เพื่อแยก EOF พอดีงบจาก oversized response
ไบต์ lookahead ถูกนับและบันทึกด้วย ดังนั้นยอดอาจเกินเพดานได้หนึ่งไบต์
หลังงบหมด capability จะปฏิเสธ request ใหม่ก่อน DNS โดยไม่ต้องมี max_calls
ไม่ได้ drain body ส่วนที่เหลือของ response ที่ถูกปฏิเสธ

Regression tests ตรวจ oversized response ซ้ำจนหมดงบ, ยอดใน state.json,
request ถัดไปที่ถูกปฏิเสธ, partial read error, read bound ตามงบที่เหลือ
และ response ที่จบตรงเพดานพอดี โดยป้อน stream ให้ production reader helper
ไม่ต้องเชื่อมบริการภายนอกหรือเปิดช่องยกเว้น private-IP policy

## RAG freshness

ก่อน model inference แต่ละรอบ เมื่อเปิด RAG จะอ่าน workspace ใหม่ผ่าน gateway
ที่ยังบังคับ policy/capability/quota/audit แล้วตรวจ SHA-256 ของเนื้อหาไฟล์
ล้าง read cache ก่อน snapshot เพื่อให้เห็น external edits และผลจาก compiler
เมื่อ hash/รายชื่อไฟล์เปลี่ยนจะ rebuild index ก่อน retrieval; ไฟล์ที่ลบหรือหมดสิทธิ์
จะไม่มี chunks เก่าค้างอยู่ ไม่เชื่อ seed index ที่ส่งเข้ามาโดยไม่มีการตรวจใหม่
query ใช้ task, path/คำหรือ symbols ที่เพิ่มในไฟล์ที่เปลี่ยนล่าสุด และ diagnostics
จาก process.exec ที่ล้มเหลวล่าสุด การรัน process สำเร็จจะล้าง failure diagnostic

การ refresh ใช้งบ filesystem read ตามปกติ เมื่อหมดสิทธิ์/งบจะไม่ใช้ chunks เก่าแทน
ขอบเขตเป็น snapshot ที่อ่านในรอบนั้น ไม่ใช่ atomic filesystem snapshot;
ไฟล์ที่เปลี่ยนหลังอ่านจะเห็นในการ refresh รอบถัดไป Observations ของรอบเก่า
อาจยังมีข้อความที่เคยอ่านไว้ ส่วน retrieval ใช้ snapshot ใหม่เท่านั้น

Regression tests ใช้ scripted model ตรวจ prompt รอบถัดไปจาก A เป็น B,
external edit ระหว่าง inference, การลบไฟล์/เพิกถอนสิทธิ์ และ query ที่มี symbols
กับ diagnostic จาก process ที่ exit ไม่สำเร็จจริง

## RAM admission defaults

บน Linux auto budget คือ 75% ของ min(MemTotal, hard limits ของ cgroup ที่ครอบ process)
รองรับ v2 `memory.max`, v1 `memory.limit_in_bytes`, unlimited, nested parents
และ mount root/mountpoint ที่ต่างกัน รวม mountinfo path escapes
อ่านจาก `/proc/self/cgroup` และ `/proc/self/mountinfo` แล้วเดินขึ้นถึง mount root
v2 ที่ไม่มี memory controller ต้องยังมี `cgroup.controllers` เพื่อยืนยันว่า directory มีอยู่
ข้อมูลเสีย, permission error หรือ map membership ไปยัง mount ไม่ได้ทำให้ auto budget
เป็น 0 และ admission ปฏิเสธ ไม่เดา fallback 4 GiB

operator override ด้วย `model.host_resources.memory_mb` ได้ และยังใช้ข้อกำหนด pool
เดิม: participating clients ที่ใช้ quota root เดียวกันต้องมี policy ตรงกัน
auto budget เป็น snapshot ตอนสร้าง defaults ไม่ใช่ available-memory measurement
หรือ OS-wide reservation; ไม่ได้นำ memory.current มาหักหรือรับประกันว่าไม่มี OOM
เมื่อเปลี่ยน service limits ต้อง reload config/clients พร้อมปรับ shared pool policy
parent ที่ถูกซ่อนเหนือ cgroup namespace/mount root อ่านจากใน container ไม่ได้
ต้องกำหนด budget จากขอบเขตจริงฝั่ง operator ในกรณีนั้น
อ้างอิง [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

Tests ใช้ host จำลอง 64 GiB: unlimited ได้ 48 GiB, parent จำกัด 8 GiB ได้ 6 GiB,
child จำกัด 4 GiB ได้ 3 GiB, parent จำกัด 1 GiB ได้ 768 MiB พร้อมตรวจ v1 sentinel,
subtree mounts, malformed/unreadable limits และ cgroup ที่หายไป

```sh
cargo test --locked -p aivm-tools network_ --lib
cargo test --locked -p aivm-runtime agent::tests::rag_ --lib
cargo test --locked -p aivm-model worker::resources::memory --lib
make verify
```

ผลตรวจวันที่ 28 ตุลาคม 2026: regression tests ใหม่ 12 รายการผ่าน และ `make verify`
ผ่านครบ (fmt, strict Clippy, Rust/Python tests, demo 14/14) บน host
เก็บ raw log ใน `target/review-p2-verify-host.log` ไม่ commit test artifacts
การตรวจนี้ไม่ได้รัน ignored GGUF/KVM tests ที่ต้องมี prerequisites เฉพาะ
