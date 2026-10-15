# ทดสอบบน host จริง — 15 ตุลาคม 2026

เริ่มทดสอบจาก commit `e67c96a` และแก้ container launcher เพิ่มตามผลทดสอบจริง
โดยออกจาก sandbox ของแชตเพื่อเข้าถึง KVM และโมเดล
ผล probe ภายใน sandbox ไม่ใช่สถานะอุปกรณ์ทั้งหมดของ host

## ผลจริง

| ส่วน | ผล |
|---|---|
| Qwen2.5 Coder 1.5B Q4_K_M | โหลด GGUF และสร้างข้อความจริงผ่าน CLI สำเร็จ |
| Qwen + agent tool | เรียก `filesystem.read src/seed.txt` ผ่าน gateway และอ่าน marker ถูกต้อง แต่ summary แต่งข้อความขึ้นเอง |
| Firecracker MicroVM | บูตจริง `/bin/true` → 0, `/bin/false` → 1 ผ่านทั้ง sandbox และ Runtime → Gateway |
| Hardware backend โหมด Generic | บูตจริงผ่าน QEMU/KVM; `/bin/true` → 0, `/bin/false` → 1 |
| Container | boundary test จริงผ่าน หลังติดตั้ง helper และแก้การส่ง COMMAND ให้ bubblewrap |
| TEE/attestation จริง | ยังไม่ได้ทดสอบ ไม่พบ SEV-SNP/TDX device; Generic ไม่ใช่การยืนยัน TEE |
| Cloud model | ไม่ได้เรียก API; ไม่มี API key ตั้งไว้ และใช้ Local model ในการทดสอบครั้งนี้ |

## Local model

ไฟล์ที่มีอยู่เดิม:

```text
/home/lokis/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf
```

รันทดสอบ:

```bash
sh scripts/llama-smoke.sh \
  /home/lokis/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  'Write one short sentence confirming you can generate text.'
```

ได้ข้อความ `I can write text.` และ `llama-smoke: all green`

ทดสอบ agent เพิ่มด้วย context 4096, CPU 4 threads, temperature 0, seed 42:

- สร้างไฟล์ `src/seed.txt` ที่มี `LOCAL_MODEL_TOOL_PROOF_20261015`
- รอบแรก tool read คืนข้อความตรงกับไฟล์ แต่ summary เป็น `This is a sample seed text.`
- ลองอีกครั้งด้วยคำสั่งให้คัดลอกเนื้อหาแบบ verbatim โมเดลจบโดยไม่เรียก tool
  และ summary ยังไม่ตรงกับไฟล์

ดังนั้น model backend และเส้นทาง tool ทำงานจริง แต่ยังไม่นับว่างาน agent
ที่ต้องสรุปข้อมูลอย่างถูกต้องผ่าน การตอบ `done` ของโมเดลไม่ใช่หลักฐานว่างานถูกต้อง

## MicroVM จริง

host เปิด `/dev/kvm` ได้และคืน KVM API version 12 มี Firecracker อยู่เดิม
พร้อม kernel/rootfs/pins ใน `~/.local/share/aivm/microvm`
ตรวจ SHA256 ของ kernel, rootfs และ Firecracker ตรงกับ pins ทั้งก่อนและหลังทดสอบ

```bash
AIVM_MICROVM_PINS="$HOME/.local/share/aivm/microvm/pins.json" make test-microvm
```

ผล: **125 ผ่าน, 1 ignored** โดย ignored คือ Container boundary test
`microvm::tests::real_boot_runs_true_and_false` และ
`microvm_real_boot_allow_through_gateway` รันจริงและผ่าน ไม่ได้ skip

Runtime test ยืนยัน decision allow ทั้ง exit 0/1 และตรวจ audit ว่ามี
`verdict:clean` กับ instance DNA

## QEMU/KVM โหมด Generic

การลองครั้งแรกใช้ ELF kernel ของ Firecracker แล้ว QEMU ปฏิเสธด้วย
`Error loading uncompressed kernel without PVH ELF Note` เป็นปัญหา artifact
ไม่ใช่หลักฐานว่าบูตสำเร็จหรือว่า TEE ใช้งานได้

เตรียม kernel ที่รองรับ QEMU โดย download **เฉพาะแพ็กเกจ** Ubuntu
`linux-image-7.0.0-38-generic=7.0.0-38.38` จาก APT repository ที่ host ตั้งไว้
ตรวจ SHA256 ตรงกับ metadata ใน APT:

```text
f268d635efaa2e19a18e12813ffdbc2e32db2390cf67d4416abd59292975e7aa
```

แตกแพ็กเกจใต้ `target/host-validation/kernel-package/extracted` ไม่ได้ install
หรือเปลี่ยน kernel ของ host ใช้ rootfs เดิมผ่านสำเนาที่ backend สร้าง
pins สำหรับ Generic อยู่ที่ `target/host-validation/hardware-generic-pins.json`

```bash
AIVM_HARDWARE_PINS="$PWD/target/host-validation/hardware-generic-pins.json" \
  make test-hardware
```

ผล: **126 ผ่าน, 1 ignored** โดย test บูต QEMU จริงรัน `/bin/true` และ
`/bin/false` สำเร็จ ชุดนี้ใช้ `tee_type: generic`, `attestation_mode: none`
จึงไม่ยืนยัน confidential computing หรือ quote verification

## Container: boundary test จริงผ่าน

สิ่งที่ตรวจแล้วบน host:

- bubblewrap 0.11.1 มีอยู่
- สร้าง user/mount/PID namespace ผ่าน `unshare` ได้
- transient user systemd service ที่กำหนด `Delegate=cpu memory pids`
  ได้ cgroup ที่เขียนได้และมีทั้งสาม controllers
- build release `aivm-container-init` สำเร็จ
- operator ติดตั้ง `/usr/libexec/aivm-container-init` เป็น root-owned แล้ว

ตัว backend บังคับ helper ต้อง root-owned และไม่เป็น setuid/group-writable
จึงยังไม่เปลี่ยนไปใช้ helper ที่เป็นเจ้าของโดย user เพื่อให้ test ผ่าน

ให้ operator รันจาก project directory:

```bash
sudo install -D -o root -g root -m 0755 \
  target/release/aivm-container-init /usr/libexec/aivm-container-init
sh scripts/test-container-host.sh
```

สคริปต์สร้าง transient user service, ย้าย test runner เข้า child cgroup แล้ว
เปิด controllers ที่ delegation root ก่อนรัน ignored boundary test แบบเจาะจง
ไม่มีการแก้ global sysctl/AppArmor หรือเปิด writable cgroup root ทั้งระบบ
systemd เก็บกวาด service/cgroup เมื่อจบ

หลังติดตั้ง helper ครั้งแรก test ยังล้มที่ setup: launcher ใส่ทั้ง options และ
COMMAND ในไฟล์ `--args` แต่ bubblewrap ขยายเฉพาะ options และหาคำสั่งจาก argv
จึงแสดง usage แล้ว exit 1 ยืนยันด้วย minimal probe ว่าเมื่อย้าย COMMAND
ออกมาอยู่ใน argv จะรันได้

แก้ launcher ให้เรียก `bwrap --args FD -- /run/aivm-container-init` โดย
mounts และ environment ยังอยู่ใน sealed memfd ไม่มีการลด isolation หรือ
เปิดเผย secret ผ่าน command line ไม่ต้องติดตั้ง helper ซ้ำสำหรับการแก้นี้
เพราะโค้ดที่เปลี่ยนอยู่ฝั่ง launcher

รัน `sh scripts/test-container-host.sh` ซ้ำบน host แล้ว **1 ผ่าน, 0 failed,
0 ignored** ครอบคลุม read/write policy, host/secret/symlink denial,
execution/network restrictions, CPU/RAM/PIDs quotas, timeout และ cgroup cleanup

หลังแก้ launcher รัน `make ci` และ strict Clippy แบบ all-features ผ่านครบ

## หลักฐานในเครื่อง

เก็บสำเนา log ใน `target/host-validation/logs/`:

- `aivm-real-llama.log`
- `aivm-real-local-agent.log`, `aivm-real-local-agent-retry.log`
- `aivm-real-microvm.log`
- `aivm-real-hardware-debug.log` (ความล้มเหลวจาก ELF kernel เดิม)
- `aivm-real-hardware-generic.log`, `aivm-real-hardware-suite.log`
- `aivm-real-container-readiness.log`, `aivm-real-container-build.log`
- `aivm-container-investigation.log` (ก่อนแก้), `aivm-container-fixed.log` (หลังแก้)
- `aivm-container-fix-ci.log`, `aivm-container-fix-clippy.log`

ไฟล์ใน `target` เป็น artifact เฉพาะเครื่อง ไม่อยู่ใน Git และจะถูกลบเมื่อ `cargo clean`
