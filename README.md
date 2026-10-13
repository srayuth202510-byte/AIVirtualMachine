# AI Virtual Machine (AIVM)

«An isolated execution environment for autonomous AI agents, where the AI can reason freely but can only act within capabilities granted by the runtime.»

AIVM คือ runtime สำหรับรัน AI Agent โดยเฉพาะ — AI คิดได้อย่างอิสระ แต่การกระทำทุกอย่างต้องผ่าน Runtime (capability → policy → tool → sandbox) หลักการสำคัญ:

«The AI may think, but the AI does not own the machine.»

สเปกฉบับเต็ม (ภาษาไทย): [`AI Virtual Machine.md`](./AI%20Virtual%20Machine.md)

## สถานะ

| Phase | ขอบเขต | สถานะ |
|---|---|---|
| 1 — Mediated Workspace (MVP-A) | `filesystem.read/write` + `code.search` ผ่าน gateway | ✅ |
| 2 — Policy and Capabilities | capability model, dynamic grant/revoke (§14) | ✅ |
| 3 — Minimal State Machine | INIT→…→DEPLOY แบบ validate + guard | ✅ |
| 4 — Sandboxed Process Tools (MVP-B) | `process.exec` ใน namespace/seccomp/microvm | ✅ |
| 5 — Agent Runtime | observe → reason → intent → execute | ✅ |
| 6 — CubeRAG | workspace retrieval (`index`/`search`) | ✅ |
| 7 — MicroVM (Level 2) | บูต guest จริงผ่าน Firecracker/KVM (หลังฟีเจอร์ `microvm`) | ✅ |
| MVP-C | `network.fetch`/`network.connect` แบบมี policy | ✅ |
| Level 3 — Hardware isolation | อนาคต (สเปก §Level 3) | ❌ |

กฎเหล็ก: **fail-closed** — parse/eval/context error ใด ๆ → `DENY` เสมอ ไม่มี default-allow

## เริ่มใช้ใน 5 นาที

```bash
# 1. ติดตั้งของที่ต้องใช้ (ดูรายละเอียดใน docs/setup.md)
#    Rust stable + clippy + rustfmt

# 2. build + พิสูจน์เส้น enforcement (12 เคส ALLOW/DENY, ~1 วินาที)
cargo build -p aivm-cli
cargo run -q -p aivm-cli -- demo

# 3. สร้าง VM ตัวแรกแล้วรัน
cargo run -q -p aivm-cli -- create coder --config ./examples/aivm.yaml
cargo run -q -p aivm-cli -- inspect coder
cargo run -q -p aivm-cli -- run coder
cargo run -q -p aivm-cli -- agent coder "read the seed file" --max-steps 3

# 4. เลื่อน state แบบมี guard (operator เป็นคนให้หลักฐาน ไม่ใช่ agent อ้างเอง)
cargo run -q -p aivm-cli -- transition coder ANALYZE
cargo run -q -p aivm-cli -- transition coder MODIFY --confidence 0.95
cargo run -q -p aivm-cli -- transition coder VALIDATE --tests-passed
cargo run -q -p aivm-cli -- transition coder DEPLOY --policy-approved

# 5. ตรวจ audit (ทุก decision มี record ตาม I-7)
cargo run -q -p aivm-cli -- logs coder
cargo run -q -p aivm-cli -- audit coder
```

`--root` (default `./vms`) คือบ้านของทุก VM แยกกันด้วย `--root` ได้ตามต้องการ

## คำสั่ง CLI

| คำสั่ง | ใช้ทำอะไร |
|---|---|
| `create <name> --config <yaml>` | สร้าง VM จาก `aivm.yaml` (validate ก่อนบูต) |
| `run <name> [--prompt …]` | รันหนึ่งก้าวแบบผ่านตัวกลาง |
| `agent <name> <task> [--max-steps N]` | agent loop เต็มรอบ (Phase 5) |
| `transition <name> <STATE> [--confidence F] [--tests-passed] [--policy-approved]` | เปลี่ยน state + ให้/เพิกถอนสิทธิ์ |
| `inspect` / `state` / `capabilities` | ดู VM / state / สิทธิ์ |
| `logs` / `audit` | ท้าย audit log / ตรวจ hash chain |
| `index` / `search` | สร้าง/ค้น RAG index (Phase 6) |
| `probe` | ตรวจความพร้อม isolation ของเครื่อง (KVM/firecracker รายงานซื่อสัตย์) |
| `demo` | self-test 12 เคส ไม่ต้องมี VM |
| `pause` / `stop` / `kill` | จัดการ lifecycle |

config เขียนยังไงดู [`docs/configuration.md`](./docs/configuration.md) (มีตัวอย่าง `microvm:` สำหรับ isolation ระดับ MicroVM)

## ทดสอบ

```bash
make verify      # gate หลัก: fmt + clippy(-D warnings) + tests + demo
make ci          # เท่า CI บน GitHub (= verify + e2e + microvm)
make test-adv    # adversarial must-deny อย่างเดียว (สเปก §38)
make test-microvm# MicroVM ทั้งสาย (บูตจริงถ้าตั้ง AIVM_MICROVM_PINS)
make demo        # self-test เร็วสุดสำหรับดีบัก enforcement
```

รายละเอียดดู [`docs/testing.md`](./docs/testing.md)

## โครงสร้าง

```
crates/
  aivm-capability    สิทธิ์ + authorize            \
  aivm-policy        ประเมิน policy (deny-by-default) \
  aivm-cube          state machine + guards (§14)      \
  aivm-audit         append-only log + hash chain       }  boundary
  aivm-tools         gateway (filesystem/network/exec)  /
  aivm-memory  aivm-network  aivm-sandbox  aivm-model    /
  aivm-runtime       agent loop + demo (incl. runtime::demo)
  aivm-supervisor    lifecycle + multi-VM root
  aivm-cli           คำสั่ง aivm
  aivm-adversarial   ชุด must-deny (สเปก §38)
```

ลำดับ dependency: `capability` → `policy` → `cube`, `audit` → `tools` → `memory/network/sandbox/model` → `runtime` → `supervisor` → `cli` (ห้ามวน)

## เอกสาร

- [`docs/setup.md`](./docs/setup.md) — ติดตั้ง Rust, Firecracker, เครื่องมือ host
- [`docs/configuration.md`](./docs/configuration.md) — `aivm.yaml` ทุกบล็อก + defaults + ตัวอย่าง microvm
- [`docs/microvm.md`](./docs/microvm.md) — เตรียม pins, บูตจริง, ข้อจำกัดที่รู้ตัว
- [`docs/testing.md`](./docs/testing.md) — matrix คำสั่งทดสอบ, feature flags, CI
- [`docs/architecture.md`](./docs/architecture.md) — เส้นทาง request, isolation levels, audit, invariants
- [`CLAUDE.md`](./CLAUDE.md) — workflow สำหรับ agent (ไม่ใช่คู่มือผู้ใช้)
