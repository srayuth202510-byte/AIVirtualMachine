# ทดสอบบน host จริง — 16 ตุลาคม 2026

ตรวจ commit `4ac447d503dc84b1dc85cce63611e685e44752db` โดยรันนอก sandbox ของแชตเพื่อใช้ KVM,
user namespaces และ user systemd delegation ของ host จริง ผลเป็น snapshot
ของเครื่องและ artifacts ที่ระบุ ไม่ใช่การรับรอง host เครื่องอื่น

## สภาพแวดล้อม

- Ubuntu 26.04.1 LTS, kernel `7.0.0-38-generic`, x86_64
- `rustc 1.96.0 (ac68faa20 2026-05-25)`; `cargo 1.96.0 (30a34c682 2026-05-25)`
- bubblewrap 0.11.1; Firecracker v1.17.0; QEMU emulator version 10.2.1 (Debian 1:10.2.1+ds-1ubuntu3.2)
- Container helper `/usr/libexec/aivm-container-init`: UID 0, mode 0o755
- โมเดล `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf` ที่มีอยู่เดิมใน `~/Downloads`
- ใช้ pins/artifacts เดิม ไม่ติดตั้งแพ็กเกจใหม่หรือแก้ global sysctl/AppArmor

Probe ยืนยัน `userns`, `pid_namespace`, `seccomp_install`, `kvm`, `firecracker`
และ `qemu` เป็น true; `sev_snp` และ `tdx` เป็น false
cgroup ของ shell ปกติเขียนไม่ได้ (`cgroup_v2_quotas=false`) แต่ Container
ทั้งสองชุดทดสอบรันผ่าน transient user service ที่ขอ `Delegate=cpu memory pids`
และใช้ delegated subtree ที่เขียนได้

## ผลจริง

| ส่วน | ผล | วินาทีรวม build/setup |
|---|---|---|
| Host probe | ตรวจสำเร็จ | 0.16 |
| Process gateway demo | 14/14 เคสผ่าน | 0.21 |
| Process coding workflow | 6 test ผ่าน | 3.42 |
| Container boundary/quotas | 1 test ผ่าน | 1.92 |
| Firecracker sandbox boot | 1 test ผ่าน | 7.49 |
| Firecracker runtime/gateway | 1 test ผ่าน | 10.64 |
| QEMU Generic boot | 1 test ผ่าน | 9.48 |
| Model worker: process namespace | 1 test ผ่าน | 67.71 |
| Model worker: Container | 1 test ผ่าน | 67.26 |
| Model worker: MicroVM | 1 test ผ่าน | 103.05 |

รวม **13 selected tests ผ่าน** และ **demo 14/14 เคสผ่าน**
ไม่มี selected test ที่ข้ามเพราะ prerequisites ขาด; test อื่นที่ถูก filter
ออกไม่ได้รวมในจำนวนนี้ เวลาข้างต้นเป็นเวลารันรอบนี้ ไม่ใช่ benchmark

- Coding workflow ใช้ scripted model และ GCC/linker/test binary จริง
- Container boundary ครอบคลุม filesystem/network/exec restrictions,
  CPU/RAM/PIDs quotas, timeout และ cleanup ตาม assertions ของชุดทดสอบ
- Firecracker sandbox และ gateway บูต guest จริง โดยตรวจ `/bin/true` → 0 และ
  `/bin/false` → 1; gateway ตรวจ audit/DNA เพิ่มด้วย
- QEMU ใช้ `tee_type=generic`, `attestation_mode=none` และบูตคำสั่ง exit 0/1 จริง
- Worker ทั้งสามแบบโหลด pinned GGUF และตรวจ streaming output เทียบ final response,
  verification status, network isolation evidence และ cancellation จาก callback
  หลังรับ delta แรก การทดสอบนี้ไม่ได้ตรวจความถูกต้องเชิงความหมายของข้อความจากโมเดล
- หลังจบไม่พบ transient units `aivm-container-test-*.service` หรือ
  `aivm-worker-host-*.service` ค้างอยู่

## Artifact integrity

ตรวจ kernel, rootfs และ binary ของ Firecracker/QEMU ตรงกับ pins ก่อนและหลังรัน
hash ของ artifacts เหล่านี้และ GGUF ไม่เปลี่ยน Worker build จาก source ของ commit
ที่ระบุและ pin hash ใหม่สำหรับการทดสอบแต่ละครั้ง; helper ใช้ไฟล์ที่ติดตั้งอยู่แล้ว

| Artifact | SHA-256 |
|---|---|
| Firecracker kernel | `ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6` |
| Rootfs (ใช้ร่วมกัน) | `786f0612582cadcee4c8ad46e30e4cc93dff9a3c0b4ede3f3c597b4c241dd547` |
| Firecracker binary | `99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5` |
| QEMU kernel | `9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e` |
| QEMU binary | `0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc` |
| Qwen GGUF | `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046` |
| Model worker ที่ build ในรอบนี้ | `8e73d7153c21543b9758180105c1bdc15557c6a7d5968dd8eb7ddb2d886da57e` |
| Container helper ที่ติดตั้งไว้ | `12742cf8c51b630b74b2cc4b3842cc8b312d51cb322951500850524878390d96` |

ตำแหน่ง pins เดิม:

- Firecracker: `~/.local/share/aivm/microvm/pins.json`
- QEMU Generic: `target/host-validation/hardware-generic-pins.json`
  (การเตรียม kernel อธิบายใน [รายงานก่อนหน้า](host-validation-2026-10-15.md))

## ตรวจซ้ำ

Process และ Container:

```bash
cargo run -q -p aivm-cli -- probe
cargo run -q -p aivm-cli -- demo
make test-coding
sh scripts/test-container-host.sh
```

Firecracker และ QEMU ใช้ exact test ที่บูตจริง:

```bash
export AIVM_MICROVM_PINS="$HOME/.local/share/aivm/microvm/pins.json"
export AIVM_HARDWARE_PINS="$PWD/target/host-validation/hardware-generic-pins.json"
cargo test -p aivm-sandbox --features microvm microvm::tests::real_boot_runs_true_and_false -- --exact --nocapture
cargo test -p aivm-runtime --features microvm tests::microvm_real_boot_allow_through_gateway -- --exact --nocapture
cargo test -p aivm-sandbox --features hardware hardware::tests::real_boot_runs_true_and_false -- --exact --nocapture
```

Model worker (streaming + cancellation):

```bash
sh scripts/test-worker-host.sh process_namespace "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
sh scripts/test-worker-host.sh container "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
sh scripts/test-worker-host.sh microvm "$HOME/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
```

## หลักฐานและขอบเขต

Raw logs และ JSON อยู่ที่ `target/host-validation/2026-10-16-4ac447d/`:
`host.json`, `versions.json`, `probe.log`, `results.json`, `artifacts-before.json`,
`artifacts-after.json`, `integrity.json`, `cleanup.json` และ log แยกตามชื่อขั้นตอน
ใน `results.json` ซึ่งบันทึก argv, exit code, elapsed time, skip lines และ test summaries
สคริปต์ที่ใช้รวมขั้นตอนอยู่ที่ `run_validation.py` ใน directory เดียวกัน

ไฟล์ใต้ `target` ไม่อยู่ใน Git และอาจหายเมื่อ `cargo clean`; รายงานนี้เก็บ commit,
สภาพแวดล้อม, hashes, ผลสรุป และคำสั่งตรวจซ้ำไว้ใน repository

ยังไม่ได้ทดสอบ TEE/attestation จริง, cloud API หรือความถูกต้องของงาน agent
ที่ใช้โมเดลสรุปข้อมูลอิสระ ผล Generic QEMU ไม่ได้ยืนยัน confidential computing
