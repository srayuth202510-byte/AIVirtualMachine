# System test — 25 ตุลาคม 2026

ทดสอบ commit `1bd4df04bd399e49cbd0e9f089d1c903713211b4` บน Linux host จริง
ที่มี KVM, Firecracker, QEMU, bubblewrap และ systemd user delegation
โดยใช้โมเดลและ boot artifacts ที่มี pins อนุมัติไว้เดิม
**ชุดระบบที่รองรับบน host นี้ผ่านหลังเลือก QEMU pins ให้ถูกชุด**
คะแนนงานของโมเดลและข้อจำกัดของ detector รายงานแยกจาก infrastructure gates

หลักฐานทั้งหมดอยู่ที่ `target/system-test-2026-10-25-1bd4df0/`
มี commands, exit codes, elapsed time, raw logs, source hashes และ artifact hashes
ไม่ได้แก้ application code หรือค่า pins ระหว่างการทดสอบ รายงานนี้เพิ่มหลังตรวจ integrity แล้ว

## ผลทดสอบระบบ

| ชุด | ผล |
|---|---|
| `make --keep-going ci check-ci` ด้วย QEMU pins ที่ถูกต้อง | ผ่าน; รวม format, strict Clippy, Rust/Python, dashboard HTTP, CLI smoke, llama, MicroVM และ hardware feature suites |
| Clippy ทั้ง workspace/all targets/all features | ผ่าน `-D warnings` |
| Rust ทั้ง workspace/all features พร้อมกัน | 452 ผ่าน, 0 ล้ม, 8 ignored |
| Container boundary จริงผ่าน delegated service | ผ่าน exact test ไม่มี skip |
| Worker/controller hardening รวม namespace cases | 11/11 ผ่าน ไม่มี ignored |
| Worker protocol, exit evidence, CPU-limit และ cancellation | 17 ผ่าน; GGUF host case เรียกแยกใน model runner |
| Supervisor รวม opt-in systemd host tests | 26/26 ผ่าน ไม่มี skip |
| Firecracker sandbox boot: `/bin/true` และ `/bin/false` | ผ่าน exact test ไม่มี skip |
| MicroVM ผ่าน runtime/gateway พร้อม audit | ผ่าน exact test ไม่มี skip |
| Generic QEMU boot: `/bin/true` และ `/bin/false` | ผ่าน exact test ไม่มี skip |
| Pinned model host runner รวม quality/cache | 11/11 stages ผ่าน |
| Protected loader หลัง tamper source สำเนา | ผ่าน |
| Inference/streaming และ failure recovery ของ process namespace, container, MicroVM | ผ่านทั้งสาม tier |
| Qwen audit: rules และโมเดลจริง | 6/6 fixtures ตรง expected categories ทั้งสองแบบ |
| Audit watcher กับโมเดลจริง | ผ่าน partial writes, burst และ rotation; source ไม่เปลี่ยน |

รายการ ignored ใน Rust all-features เป็น host/model tests ที่เรียกแยกข้างต้น
และ rotation crash helper ที่ parent test เรียกเป็น subprocess อยู่แล้ว
container test ที่ข้ามเมื่อไม่มี delegated config ถูกตรวจซ้ำผ่าน host script โดยตรง
ส่วน supervisor host tests ที่ CI ปกติข้ามสองเคส เปิดด้วย `AIVM_SUPERVISOR_HOST_TEST=1`
เพื่อตรวจการเก็บ descendants, replacement และการรับช่วง workload ของ controller ใหม่
จำนวนต่างชุดมีการทดสอบซ้ำข้าม features จึงไม่บวกเป็นจำนวน unique test cases รวม

Failure/recovery ของแต่ละ model tier ตรวจ timeout, memory pressure, zero deltas
ของ failed load, PID/starttime ของ descendants, process/staging cleanup และ verified
healthy inference หลัง failure ด้วย client เดิม ไม่ใช้ exit code เพียงอย่างเดียวแทนหลักฐาน

## ความล้มเหลวรอบแรกและการแก้ configuration ทดสอบ

CI รอบแรกคืน code 2 เพราะคำสั่งทดสอบเลือก
`~/.local/share/aivm/hw-generic-pins.json` ซึ่งชี้ไปยัง Firecracker ELF kernel
QEMU ปฏิเสธก่อนเข้า guest ด้วย:

```text
qemu-system-x86_64: Error loading uncompressed kernel without PVH ELF Note
```

เลือกชุด QEMU-specific ที่เคยอนุมัติไว้ใน
`target/host-validation/hardware-generic-pins.json` ตามรายงาน host เดิม
ตรวจ kernel/rootfs/QEMU binary hashes ตรงทั้งหมด แล้วเก็บสำเนาเป็น `hardware-pins.json`
ใน evidence directory จากนั้น exact QEMU test, CI ทั้งชุด และ all-features ผ่าน
โดยไม่เปลี่ยนค่า pin หรือดาวน์โหลด kernel ใหม่

เก็บผลล้มเหลวเดิมใน `ci.log`, `hardware-repro.log` และ `hardware-pin-correction.json`
ผล CI ที่แก้ configuration อยู่ใน `ci-corrected.log` และ `post-results.json`
ผลจาก runner แรกยังคง exit 1 ตาม failure เดิม ไม่เขียนทับให้กลายเป็นผลผ่าน

## คุณภาพโมเดลและ cache

ใช้ local GGUF `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf` แบบ CPU
SHA-256 `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`
และ oracle คงที่หกงาน ไม่ execute intents ที่ได้จาก quality corpus

| รายการ | Cache ปิด | Sealed cache เปิด |
|---|---:|---:|
| Infrastructure checks | 6/6 | 6/6 |
| คำตอบตรง oracle | 4/6 | 4/6 |
| Client boot | 5.112 s | 35.028 s |
| Median request elapsed | 36.930 s | 33.905 s |
| Command elapsed ทั้งชุด | 229.58 s | 241.03 s |

Request ที่ใช้ cache มี median ต่ำกว่าใน snapshot นี้ แต่ค่า setup ทำให้ command
หกงานใช้เวลารวมมากขึ้น ผลชุดเล็กนี้ไม่ใช่ production accuracy หรือ performance guarantee

Live coding benchmark อ่านและแก้ source ผ่าน gateway สำเร็จ
operator verifier ที่ agent เขียนไม่ได้ตรวจ **289 input pairs ผ่าน**
known broken baseline ถูกปฏิเสธก่อนและ verifier bytes ไม่เปลี่ยน
รายงาน `infrastructure_passed=true`, `task_correct=true`
แต่ agent ยังเป็น **unverified** เพราะ compiler call ของ agent พยายามใช้ `/tmp`
แล้วถูก sandbox ปฏิเสธ ส่วน operator compile/link/test sequence แยกต่างหากผ่าน
ผลเหล่านี้ไม่ถูกใช้แทนกัน และไม่ได้อนุมาน success rate ของการแก้ repository จริงจากงานเดียว

Qwen audit 6/6 เป็นอีก corpus ของ synthetic fixtures แยกจากหก quality tasks
watcher ยืนยัน `validated_structure` ของ model review และไม่แก้ live/archive audit
คำแนะนำจากโมเดลยังเป็น advisory ไม่ได้อนุมัติ capability หรือเปลี่ยน policy

## Detection ยังมีข้อจำกัด

| Corpus | Cases | Rule FP / FN | Containment FP / FN | Policy regressions |
|---|---:|---:|---:|---:|
| Baseline | 30 | 3 / 4 | 1 / 13 | 0 |
| Synthetic holdout | 12 | 2 / 3 | 0 / 6 | 0 |

Baseline risk metrics นับ 26 labeled cases; detector evaluation นี้เป็น rules-only
ไม่ merge คะแนนกับ model audit fixtures และไม่ปรับ labels เพื่อทำผลให้ผ่าน
Known blind spots และ indistinguishable inputs ยังคงอยู่

## Integrity และขอบเขตผล

- Approved model, kernels, rootfs, Firecracker/QEMU binaries และ pins ไม่เปลี่ยน
- Tracked source hashes ตรงกับก่อนเริ่มทดสอบ และ working tree สะอาดก่อนเพิ่มรายงานนี้
- คืน worker build เป็น `llama,microvm` แล้ว hash ตรงกับ model host run
- Generic QEMU ใช้ `tee_type=generic`, `attestation_mode=none`; ไม่ยืนยัน SEV-SNP/TDX หรือ TEE attestation
- รอบนี้ใช้ CPU inference; ไม่ได้ตรวจ GPU inference หรือ live external cloud providers
- AWS backup/restore บน cloud ไม่ได้รัน; ไม่มี AWS CLI ใน host นี้

ผลนี้เป็น snapshot ของ host/configuration ที่ระบุ ไม่ใช่ security certification
หรือหลักฐานยืนยัน host อื่น รายละเอียด gate/status ทั้งหมดอยู่ใน `summary.json`,
`results.json`, `post-results.json`, `integrity.json`, `post-integrity.json`
และ `model/results.json` ภายใต้ evidence directory
