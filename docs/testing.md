# Testing — เมทริกซ์คำสั่งทดสอบ

## Verifier และ state/audit crash recovery

`cargo test -p aivm-runtime transaction::tests` ทดสอบ SIGKILL ระหว่าง mutation
และ recovery; `make test-coding` ตรวจ verifier receipt ของ compiler/test binary จริง
รายละเอียดอยู่ใน [Verifier contracts และ transactions](verification-and-transactions.md)

## คำสั่งหลัก

| คำสั่ง | วิ่งอะไร | เมื่อไหร่ที่ใช้ |
|---|---|---|
| `make demo` | self-test 14 เคส ALLOW/DENY ใน temp dir (~1 วินาที) | ดีบักเส้น enforcement — เร็วสุด พิมพ์ decision/reason ต่อเคส |
| `make verify` | `fmt-check` + `clippy(-D warnings)` + `cargo test --workspace` + `demo` | gate ก่อน commit ทุกครั้ง |
| `make ci` | `verify` + `e2e` + `check/test-llama` + `check/test-microvm` + `check/test-hardware` | เท่า CI บน GitHub ทุกอย่าง |
| `make e2e` | `scripts/smoke.sh` (create/inspect/run/agent/transition/logs/audit/kill + demo + adversarial) | ตรวจวงจร CLI ครบ |
| `make test-coding` | agent loop + GCC/ld + test binary จริง และ quota/adversarial checks | แก้ build/output/agent observations |
| `make test-adv` | `cargo test -p aivm-adversarial` (must-deny สเปก §38) | แตะ surface ด้าน security |
| `make test-microvm` | sandbox/tools/runtime แบบเปิดฟีเจอร์ `microvm` | แตะโค้ดหลังฟีเจอร์ microvm |
| `make test-hardware` | sandbox/tools/runtime แบบเปิดฟีเจอร์ `hardware` | แตะโค้ดหลังฟีเจอร์ hardware |
| `make test-llama` | model/model-worker แบบเปิดฟีเจอร์ `llama` | compile และทดสอบ local GGUF backend |
| `make debug-test F=<ชื่อ> [P=<crate>]` | เทสต์เดียว + backtrace + `--nocapture` | ไล่บั๊ก (repro ก่อนแก้เสมอ) |

กฎ: แก้บั๊กโดยไม่มี regression test / demo case = ยังไม่เสร็จ

## Feature flags

| ฟีเจอร์ | chain | ผล |
|---|---|---|
| (default) | — | `make verify` เบา ไม่พึ่ง KVM/โมเดล |
| `llama` | `aivm-cli/llama` → `supervisor` → `runtime` → `model` | โมเดล local GGUF (`make llama-smoke MODEL=…`) |
| `microvm` | `aivm-cli/microvm` → `runtime` → `tools` → `sandbox` | backend MicroVM + config (ปิดโดยปริยาย CI ไม่มี KVM) |
| `hardware` | `aivm-cli/hardware` → `runtime` → `tools` → `sandbox` | backend Hardware Isolation + config (ปิดโดยปริยาย CI ไม่มี KVM) |

`make test-microvm` / `make test-hardware` เปิดฟีเจอร์ให้ทั้งสาม crate
ท้ายสาย (`check-microvm` / `check-hardware` ตรวจ clippy รวม `aivm-cli` ด้วย)

## ตัวแปรสภาพแวดล้อม

| ตัวแปร | ผล |
|---|---|
| `AIVM_MICROVM_PINS=/path/pins.json` | เปิดเทสต์บูตจริง (sandbox `real_boot…` + runtime e2e) ไม่ตั้ง = skip |
| `AIVM_MICROVM_KEEP_SCRATCH=1` | เก็บ scratch dir (รวม `serial.log`) ไว้ดีบัก ไม่ตั้ง = ลบทิ้ง |
| `AIVM_HARDWARE_PINS=/path/pins.json` | เปิดเทสต์บูตจริงฝั่ง hardware (sandbox `real_boot…`) ไม่ตั้ง = skip |
| `AIVM_HARDWARE_KEEP_SCRATCH=1` | เก็บ scratch dir ฝั่ง hardware ไว้ดีบัก ไม่ตั้ง = ลบทิ้ง |

## เพิ่ม surface ใหม่ต้องมีอะไรคุม

- tool ใหม่: ใส่ `ToolGateway::dispatch` แบบ deny-by-default + demo case ใน
  `crates/aivm-runtime/src/demo.rs` + เคสใน adversarial suite
- exec/policy branch ใหม่: adversarial case + unit test ระดับ crate
- decision ใหม่ทุกอันต้องมี audit record (I-7)
- `cargo fmt` ก่อนจบ `make verify` ต้องเขียว

## CI (`.github/workflows/ci.yml` = `make ci`)

fmt → clippy strict → `cargo test --workspace` → Python tests → clippy/test หลังฟีเจอร์ llama → clippy หลังฟีเจอร์ microvm →
`make test-microvm` → clippy/test หลังฟีเจอร์ hardware → demo → smoke.sh
runner ระบุรุ่นเป็น `ubuntu-24.04` (เทสต์บูตจริงข้ามเมื่อไม่มี KVM/pins — unit/plumbing
ที่เหลือยังจับของพังได้)

## Pinned GGUF บน host จริง

รันนอก restricted sandbox บน Linux host ที่มี user/network namespaces, KVM,
Firecracker, bubblewrap, root-owned container helper และ systemd user delegation
สำหรับ `cpu memory pids` เตรียม GGUF และ MicroVM pins ที่ operator อนุมัติไว้ก่อน
สคริปต์ไม่ download โมเดลหรือเปลี่ยน pins เอง:

```bash
python3 scripts/validate-model-host.py \
  --model /path/model.gguf --model-sha256 '<approved-64-hex-sha256>' \
  --pins /path/microvm-pins.json --out target/model-host-validation/manual
```

ตรวจ model/kernel/rootfs/Firecracker กับ pins ก่อนรัน จากนั้นทดสอบ loader จริงหลัง
เขียนทับ inode และแทน source pathname ด้วย symlink ในสำเนาส่วนตัว ไม่แตะ GGUF ต้นฉบับ
ทั้ง `process_namespace`, `container` และ `microvm` ต้องปฏิเสธ hash ผิดโดยไม่ปล่อย token,
โหลด hash ถูก, ตรวจ streaming เทียบ final output และยกเลิกได้หลัง delta แรก
exit 0 ที่ไม่พบเทสต์หรือข้าม prerequisite ไม่นับว่าผ่าน เก็บ command, elapsed time,
raw logs, commit/source identifiers และ hashes ก่อน/หลังใน output directory
ต้องมี temporary storage สำหรับสำเนา GGUF ตาม [model runtime](model-runtime.md)

Workflow [real-model-validation](../.github/workflows/model-host-validation.yml) เตรียมไว้
สำหรับ manual dispatch และรันทุกวัน 20:19 UTC (03:19 Asia/Bangkok วันถัดไป)
ใช้ self-hosted runner labels `self-hosted, linux, aivm-model-kvm` และไม่รับ pull-request trigger
เปิดด้วย repository variable `AIVM_ENABLE_MODEL_VALIDATION=1` พร้อมตั้ง absolute paths
`AIVM_GGUF`, `AIVM_MICROVM_PINS` และ trusted digest `AIVM_GGUF_SHA256`
เก็บ evidence เป็น workflow artifact 30 วัน แม้ test ล้มเหลวเมื่อมีไฟล์ให้เก็บ
การเพิ่ม workflow ใน source ยังไม่เปิดใช้งาน runner หรือตั้ง repository variables ให้เอง
ผลบน host หนึ่งไม่ใช่การรับรอง production hosts อื่นหรือ TEE/attestation

ขั้นตอนเตรียม runner, register, เปิด service และตั้ง variables อัตโนมัติอยู่ใน
[Recurring real-model validation](model-validation-runner.md)
