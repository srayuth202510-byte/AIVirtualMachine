# Testing — เมทริกซ์คำสั่งทดสอบ

## คำสั่งหลัก

| คำสั่ง | วิ่งอะไร | เมื่อไหร่ที่ใช้ |
|---|---|---|
| `make demo` | self-test 14 เคส ALLOW/DENY ใน temp dir (~1 วินาที) | ดีบักเส้น enforcement — เร็วสุด พิมพ์ decision/reason ต่อเคส |
| `make verify` | `fmt-check` + `clippy(-D warnings)` + `cargo test --workspace` + `demo` | gate ก่อน commit ทุกครั้ง |
| `make ci` | `verify` + `e2e` + `check-microvm` + `test-microvm` + `check-hardware` + `test-hardware` | เท่า CI บน GitHub ทุกอย่าง |
| `make e2e` | `scripts/smoke.sh` (create/inspect/run/agent/transition/logs/audit/kill + demo + adversarial) | ตรวจวงจร CLI ครบ |
| `make test-coding` | agent loop + GCC/ld + test binary จริง และ quota/adversarial checks | แก้ build/output/agent observations |
| `make test-adv` | `cargo test -p aivm-adversarial` (must-deny สเปก §38) | แตะ surface ด้าน security |
| `make test-microvm` | sandbox/tools/runtime แบบเปิดฟีเจอร์ `microvm` | แตะโค้ดหลังฟีเจอร์ microvm |
| `make test-hardware` | sandbox/tools/runtime แบบเปิดฟีเจอร์ `hardware` | แตะโค้ดหลังฟีเจอร์ hardware |
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

fmt → clippy strict → `cargo test --workspace` → clippy หลังฟีเจอร์ microvm →
`make test-microvm` → clippy/test หลังฟีเจอร์ hardware → demo → smoke.sh
runner คือ `ubuntu-latest` (ไม่มี KVM เทสต์บูตจริงจึง skip — unit/plumbing
ที่เหลือยังจับของพังได้)
