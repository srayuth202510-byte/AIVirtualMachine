# AI Virtual Machine (AIVM)

«A secure model runtime for open-weight models, with optional agent capabilities layered above it.»

AIVM คือ runtime สำหรับรัน open-weight models โดยให้ model worker แยกจาก control plane,
ตรวจสอบ artifact ก่อนโหลด, จำกัดทรัพยากรและ network และบันทึกผลการรันแบบตรวจสอบย้อนหลังได้
ความสามารถด้าน agent และ tools เป็นชั้นเสริมที่ทำงานผ่าน capability, policy และ sandbox:

«The AI may think, but the AI does not own the machine.»

> English summary: AIVM is a fail-closed runtime for open-weight model inference. A verified
> model package runs in a restricted worker with bounded resources and no network by default.
> Agent capabilities are optional and remain mediated by the runtime. The model proposes
> intents (strict JSON); a state machine (`INIT→DEPLOY` with operator guards), capability
> checks, and a deny-by-default policy engine decide ALLOW/DENY before any tool runs.
> Tools (`filesystem/network/process.exec`) go through a gateway into a sandbox.
> Tier1 process is the default; container requires host setup. Tier2 Firecracker
> MicroVM requires KVM and pinned guest artifacts. Hardware/TEE is experimental and
> does not yet provide verified TEE attestation. Audit hash chains detect changes
> against a trusted checkpoint; they do not authenticate logs against a host administrator.
> Full spec is in Thai:
> [`AI Virtual Machine.md`](./AI%20Virtual%20Machine.md). Start with `cargo run -p aivm-cli -- demo`.

สเปกฉบับเต็ม (ภาษาไทย): [`AI Virtual Machine.md`](./AI%20Virtual%20Machine.md)

## สถานะ

| Phase | ขอบเขต | Tier | สถานะ |
|---|---|---|---|
| 1 — Mediated Workspace (MVP-A) | `filesystem.read/write` + `code.search` ผ่าน gateway | Tier1 | ✅ |
| 2 — Policy and Capabilities | capability model, dynamic grant/revoke (§14) | Tier1 | ✅ |
| 3 — Minimal State Machine | INIT→…→DEPLOY แบบ validate + guard | Tier1 | ✅ |
| 4 — Sandboxed Process Tools (MVP-B) | `process.exec` ใน namespace/seccomp/microvm | Tier1 | ✅ |
| 5 — Agent Runtime | observe → reason → intent → execute | Tier1 | ✅ |
| 6 — CubeRAG | workspace retrieval (`index`/`search`) | Tier1 | ✅ |
| 7 — MicroVM (Level 2) | บูต guest จริงผ่าน Firecracker/KVM (หลังฟีเจอร์ `microvm`) | Tier2 | ✅ |
| MVP-C | `network.fetch`/`network.connect` แบบมี policy | Tier1 | ✅ |
| Level 1 — Container | bubblewrap + Landlock/seccomp + cgroups v2 CPU/RAM/PIDs (ต้องเตรียม host) | Tier1 | ✅ |
| Level 3 — Hardware isolation | Generic QEMU บูตจริงได้; TEE/attestation ยังไม่ยืนยัน (ดู `docs/hardware.md`) | Tier3 experimental | 🚧 |
| Model Runtime — Worker boundary | model manifest + worker protocol + bounded inference | Tier1 | 🚧 |

กฎเหล็ก: **fail-closed** — parse/eval/context error ใด ๆ → `DENY` เสมอ ไม่มี default-allow

สถานะ Tier หมายถึงระดับการรองรับในโค้ด ไม่ใช่การรับรองความปลอดภัยของ host ทุกเครื่อง:
Tier1 process เป็นค่าเริ่มต้น; Container และ MicroVM ต้องเตรียม host ตามคู่มือและ
ตรวจผล probe/host validation สำหรับเครื่องเป้าหมาย; Hardware ยังเป็น experimental
และ Generic QEMU ไม่ได้ยืนยัน TEE หรือ attestation. ดู [ผล host validation](./docs/host-validation-2026-10-16.md)
ซึ่งเป็น snapshot ณ 16 ตุลาคม 2026 ของ commit `4ac447d` ไม่ใช่ผลตรวจ host ปัจจุบันโดยอัตโนมัติ.

รายละเอียดการบังคับใช้และพฤติกรรมที่เปลี่ยนหลัง security review: [`docs/security-hardening.md`](./docs/security-hardening.md)

เป้าหมายและลำดับพัฒนาเพื่อรัน open-weight models อย่างปลอดภัย: [`docs/open-weight-security-roadmap.md`](./docs/open-weight-security-roadmap.md)

สถาปัตยกรรม model runner และ worker boundary: [`docs/model-runtime.md`](./docs/model-runtime.md)

## เริ่มใช้ใน 5 นาที

```bash
# 1. ติดตั้งของที่ต้องใช้ (ดูรายละเอียดใน docs/setup.md)
#    Rust stable + clippy + rustfmt

# 2. build + พิสูจน์เส้น enforcement (14 เคส ALLOW/DENY, ~1 วินาที)
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
| `snapshot <name> --store <dir>` / `snapshots --store <dir>` | operator เก็บ/ดูหลายจุดกู้คืนของ workspace นอก VM root |
| `verify-snapshot <id> --store <dir> [--manifest-sha256 <hash>]` | ตรวจ manifest และ hash ของ payload ครบทุกไฟล์ |
| `restore <id> <new-name> --store <dir> --manifest-sha256 <hash> --config <yaml>` | กู้ workspace ลง VM ใหม่ด้วย config ปัจจุบัน ไม่คัดลอก security state เดิม |
| `run <name> [--prompt …]` | รันหนึ่งก้าวแบบผ่านตัวกลาง |
| `agent <name> <task> [--max-steps N]` | agent loop เต็มรอบ; งานโค้ดแบ่ง inspect/implement/verify/repair |
| `transition <name> <STATE> [--confidence F] [--tests-passed] [--policy-approved]` | เปลี่ยน state + ให้/เพิกถอนสิทธิ์ |
| `approve-secret <name> <lease> [--by NAME]` | อนุมัติ PENDING secret lease (operator เท่านั้น) |
| `inspect` / `state` / `capabilities` | ดู VM / state / สิทธิ์ |
| `logs` / `audit` | ท้าย audit log / ตรวจ hash chain |
| `index` / `search` | สร้าง/ค้น RAG index (Phase 6) |
| `probe` | ตรวจความพร้อม isolation ของเครื่อง (KVM/firecracker รายงานซื่อสัตย์) |
| `demo` | self-test 14 เคส ไม่ต้องมี VM |
| `pause` / `stop` / `kill` | จัดการ lifecycle |

config เขียนยังไงดู [`docs/configuration.md`](./docs/configuration.md) (มีตัวอย่าง `microvm:` สำหรับ isolation ระดับ MicroVM)

## ทดสอบ

```bash
make verify      # gate หลัก: fmt + clippy(-D warnings) + tests + demo
make ci          # เท่า CI บน GitHub (= verify + e2e + microvm)
make test-coding # agent อ่าน/แก้ source + compiler/linker/test binary จริง
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
  aivm-runtime       model runtime + optional agent loop + demo
  aivm-supervisor    lifecycle + multi-VM root
  aivm-cli           คำสั่ง aivm
  aivm-adversarial   ชุด must-deny (สเปก §38)
```

ลำดับ dependency: `capability` → `policy` → `cube`, `audit` → `tools` → `memory/network/sandbox/model` → `runtime` → `supervisor` → `cli` (ห้ามวน)

## เอกสาร

- [`docs/workspace-recovery.md`](./docs/workspace-recovery.md) — snapshot workspace, integrity verification และ operator restore ลง VM ใหม่
- [`docs/audit-rotation.md`](./docs/audit-rotation.md) — ลำดับ rotate, recovery หลัง process หยุด และพฤติกรรมเมื่อเกิด error
- [`docs/audit-watcher.md`](./docs/audit-watcher.md) — เฝ้าดู audit ต่อเนื่อง พร้อมตรวจ partial writes/rotation และให้ Qwen ทบทวนเบื้องหลัง
- [`docs/recovery-supervisor.md`](./docs/recovery-supervisor.md) — controller ภายนอกสำหรับงานบนเครื่องเดียว: dry-run, กักกัน, สร้างทดแทน, จำกัดการเกิดใหม่ และ drain
- [`docs/detection-evaluation.md`](./docs/detection-evaluation.md) — พิสูจน์ขอบเขตการตรวจจับด้วย 30 สถานการณ์ วัด false positives/misses แยกจากการทำตาม policy
- [`docs/immunity-lab.md`](./docs/immunity-lab.md) — ห้องทดลองกฎตรวจจับ: สร้างรูปแบบดัดแปลง ให้ Qwen เสนอ ทดสอบ holdout ออกรุ่น shadow และ rollback
- [`docs/security-court-roadmap.md`](./docs/security-court-roadmap.md) — แผนงานศาลจำลองที่ยึดกฎเป็นหลัก มีฝ่ายทักท้วง ลูกขุน และผู้พิพากษาแบบ deterministic (ยังไม่ได้พัฒนา)

- [`docs/audit-reviewer.md`](./docs/audit-reviewer.md) — วิเคราะห์ audit แบบอ่านอย่างเดียว ด้วยกฎและคำแนะนำจาก Qwen

- [`docs/qwen-assistant.md`](./docs/qwen-assistant.md) — สคริปต์ช่วย Qwen อ่านไฟล์ ตรวจคำตอบ และ retry เมื่อไม่ตรงหลักฐาน

- [`docs/container.md`](./docs/container.md) — bubblewrap backend + delegated cgroups v2
- [`docs/setup.md`](./docs/setup.md) — ติดตั้ง Rust, Firecracker, เครื่องมือ host
- [`docs/configuration.md`](./docs/configuration.md) — `aivm.yaml` ทุกบล็อก + defaults + ตัวอย่าง microvm
- [`docs/microvm.md`](./docs/microvm.md) — เตรียม pins, บูตจริง, ข้อจำกัดที่รู้ตัว
- [`docs/build-workflow.md`](./docs/build-workflow.md) — bounded build outputs และ coding end-to-end
- [`docs/testing.md`](./docs/testing.md) — matrix คำสั่งทดสอบ, feature flags, CI
- [`docs/architecture.md`](./docs/architecture.md) — เส้นทาง request, isolation levels, audit, invariants
- [`docs/threat-model.md`](./docs/threat-model.md) — attacker positions, signals, DNA, non-goals, ช่องว่าง G1–G5
- [`CLAUDE.md`](./CLAUDE.md) — workflow สำหรับ agent (ไม่ใช่คู่มือผู้ใช้)

## License

Dual-licensed `MIT OR Apache-2.0` — ดู `LICENSE-MIT` และ `LICENSE-APACHE`
ทุก crate ระบุ `license = "MIT OR Apache-2.0"` ใน `Cargo.toml` แล้ว
