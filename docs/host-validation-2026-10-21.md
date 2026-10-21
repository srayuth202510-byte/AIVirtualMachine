# Protected model loading บน host จริง — 21 ตุลาคม 2026

ตรวจ baseline `44aba9eb01fc30ff40d69a82e62d01939e857652` พร้อม working-tree changes
ของรอบนี้ ได้แก่ real-loader/worker regressions, container security setup filter และ
snapshot staging ที่ไม่ต้องรอ entropy ผลนี้จึงไม่ใช่การรับรอง baseline ที่ไม่มี changes เหล่านั้น
แยกหลักฐานของรอบสุดท้ายใน `target/host-validation/2026-10-21-44aba9e/final/`
มี `host.json` ระบุ baseline/diff digest และ `validation-sources.json` ระบุ hash ของ source ที่ใช้

## สภาพแวดล้อมและ fixture

- รันนอก restricted chat sandbox บน Linux `7.0.0-38-generic`, x86_64
- Rust/Cargo 1.96.0; bubblewrap 0.11.1; container helper ที่ติดตั้งไว้เดิม
- Host probe: userns, PID namespace, seccomp, KVM และ Firecracker พร้อม
- Container ขอ `Delegate=cpu memory pids` ผ่าน transient user service; ไม่แก้ global host settings
- GGUF เดิม: `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf`, 1,117,320,768 bytes
- Approved model SHA-256: `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`
  ตรงกับ fixture ใน [รายงาน 16 ตุลาคม](host-validation-2026-10-16.md)
- ใช้ MicroVM pins เดิมที่ `~/.local/share/aivm/microvm/pins.json`; ไม่ download หรือ repin

Chat sandbox รายงาน namespace/KVM ไม่พร้อม แต่ host probe นอก sandbox ยืนยันว่าพร้อม
จึงใช้ผล host จริงในการเลือกทดสอบ ไม่ตีความ sandbox restriction เป็น host capability

## ผลการตรวจ

| รายการ | ผล |
|---|---|
| `make verify` | ผ่าน: Rust 330 tests, Python suite และ demo 14/14 |
| Clippy แบบ strict สำหรับ model/worker/sandbox พร้อม `llama,microvm` | ผ่าน |
| Model/worker feature regressions | 36 ผ่าน; host-only tests 2 รายการแยกรันโดยตรง |
| Loader จริงหลัง source tampering | ผ่าน 1 test, 54.58 วินาที |
| Worker `process_namespace` | ผ่าน 1 test, 99.43 วินาที |
| Worker `container` | ผ่าน 1 test, 99.07 วินาที |
| Worker `microvm` | ผ่าน 1 test, 153.28 วินาที |
| Container boundary/quotas หลังแก้ seccomp | ผ่าน 1 test, 1.17 วินาที |
| Model/boot artifacts/pins/worker hash ก่อนและหลัง | ตรงกันทั้งหมด |

Host tests ที่เลือกทั้ง 5 รายการรันจริงโดยไม่มี ignored/skip ในผล exact test
เวลาเป็นเวลารวม command/setup ไม่ใช่ benchmark; feature/default suites มี host-only
tests ที่ ignored ตามปกติและไม่เอามาปนกับผล host จริงข้างบน
Container boundary test ตรวจ filesystem/network/exec restrictions, CPU/RAM/PIDs,
timeout และ cleanup ตาม assertions ของชุดทดสอบเดิม

Worker SHA-256 ของ build ที่ทดสอบ:
`4cc9890c854fdaa0950da2f6bc9dbdeb7633a10d8bd7570584c33515ba0c7d08`
Kernel/rootfs/Firecracker ใช้ hashes เดียวกับ [รายงาน 16 ตุลาคม](host-validation-2026-10-16.md)
หลังจบไม่พบ transient test services หรือ Firecracker ค้างอยู่ และล้าง scratch ของ
disposable entropy diagnostic แล้ว เก็บ serial log และ source patch/hashes ไว้ใน evidence directory

Loader test copy fixture ไปเป็นสำเนาส่วนตัวก่อนตรวจ pin แล้วเขียนทับ inode เดิมและแทน
pathname ด้วย symlink ก่อน llama.cpp เปิด descriptor ของ snapshot; ไม่แก้ fixture ต้นฉบับ
Worker test แต่ละ tier ต้องปฏิเสธ pin ผิดด้วย hash-mismatch error โดยไม่ปล่อย token,
โหลด pin ถูกพร้อม output ที่ไม่ว่าง, ตรวจ streaming เทียบ final response,
ตรวจ verification/network evidence และยกเลิกได้หลัง delta แรก

สคริปต์นับผ่านเฉพาะ exact host test ที่รันจริง 1 รายการและไม่มี skip ไม่ใช้ exit 0
จากการไม่พบชื่อเทสต์หรือการข้าม prerequisite มาอ้างผลสำเร็จ

## ข้อผิดพลาดที่พบและแก้ระหว่าง validation

1. Container hybrid seccomp ฆ่า trusted helper ที่ `landlock_create_ruleset`
   และหลังผ่านจุดนั้นฆ่า worker ที่ติดตั้ง seccomp ของตัวเอง เพิ่มเฉพาะ container profile
   ให้ผ่าน Landlock setup สาม syscall และ `seccomp` ซึ่งเพิ่มข้อจำกัดได้เท่านั้น
   Generic process profile คงเดิม; regression เปรียบเทียบ verdict ของ syscall 0–1024,
   wrong architecture, x32 และ filesystem ioctls ที่ห้าม
2. MicroVM ที่เพิ่งบูตค้างที่ `getrandom` ขณะ `Uuid::new_v4()` สร้างชื่อ snapshot directory
   ยืนยันจาก disposable guest diagnostic: `wait_for_random_bytes` และ syscall 318
   เปลี่ยนชื่อเป็น PID/เวลา/counter โดยยังจอง directory แบบ atomic ด้วย mode `0700`,
   ใช้ `create_new`/`O_NOFOLLOW`, unlink snapshot และเปิด read-only ก่อนตรวจ hash
   ความปลอดภัยพึ่ง atomic creation/permissions ไม่พึ่งความลับของชื่อ
3. รอบแรกมี general verification build เปลี่ยน worker binary ระหว่างการทดสอบ ทำให้
   worker pin ปฏิเสธถูกต้อง รอบสุดท้ายแยกจาก build อื่นและตรวจ worker hash ก่อน/หลัง
4. Container boundary wrapper ยังส่ง `--ignored` หลัง test เลิกใช้ `#[ignore]` แล้ว
   จึงคืน exit 0 โดยเลือก 0 tests เอา flag เก่าออกและให้ wrapper ตรวจ exact test summary
   กับ skip lines ก่อนยอมรับผลผ่าน; ไม่นับรอบที่เลือก 0 tests เป็นหลักฐาน
   Payload ที่ต้องรอ timeout/cleanup เปลี่ยนจาก `pause()` ที่ seccomp ไม่อนุญาตเป็น
   `nanosleep()` ที่อนุญาตอยู่แล้ว เพื่อให้ตรวจ timeout และลูก process ที่ยังมีชีวิตจริง

เก็บ failed attempts และ diagnostic logs ที่ parent directory ของ `final/` เพื่อไม่ซ่อน
ความล้มเหลวรอบแรก ส่วนผลที่อ้างข้างบนใช้เฉพาะรอบสุดท้ายและ quality gates ที่ระบุ

## ตรวจซ้ำและ recurring workflow

```bash
python3 scripts/validate-model-host.py \
  --model "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf" \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --pins "$HOME/.local/share/aivm/microvm/pins.json" \
  --out target/model-host-validation/manual
```

อย่ารัน Cargo build/test อื่นที่เปลี่ยน `target/debug/aivm-model-worker` พร้อมกัน
เก็บ raw logs, commands, elapsed time, summaries และ artifact hashes ใน output directory
ไฟล์ใต้ `target` ถูก ignore และอาจหายเมื่อ `cargo clean`; รายงานนี้อยู่ใน Git

เพิ่ม [workflow](../.github/workflows/model-host-validation.yml) สำหรับ daily/manual
validation และ upload evidence ไว้แล้ว ยังไม่ได้ตั้ง repository variables หรือเปิด runner
ดู prerequisites/ตัวแปรใน [testing](testing.md#pinned-gguf-บน-host-จริง)

ผลนี้ยืนยัน protected loading และ worker contracts บน host/fixture ที่ระบุ ไม่ได้วัด
ความถูกต้องเชิงความหมายของคำตอบ, รับรอง host อื่น, พิสูจน์ TEE/attestation หรือปิด
ข้อจำกัด typed verifier และ audit crash consistency ที่ยังเหลือใน
[security review](system-review-2026-10-20.md)
