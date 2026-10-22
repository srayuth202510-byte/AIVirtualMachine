# Setup — ติดตั้งของที่ต้องใช้

> แบ่ง 2 ทาง: **quickstart (0-deps)** ลอง Tier1 ได้ทันที กับ **full-isolation**
> สำหรับ Tier2/3 ที่ต้องเตรียม host — สคริปต์ช่วยตรวจอยู่ใน
> `scripts/setup-host.sh` (idempotent อ่านอย่างเดียว ไม่แก้ host ให้เอง)

## 0. Quickstart — Tier1 อย่างเดียว (ไม่ต้องมี KVM/bwrap)

```bash
cargo build --workspace        # หรือ: make build
cargo run -q -p aivm-cli -- demo   # พิสูจน์เส้น enforcement (~1 วินาที)
sh scripts/bench.sh            # วัด demo/audit/adversarial คร่าวๆ (ไม่ต้องมี KVM)
```

## 0b. Local model (GGUF) — ทางหลักของงานนี้ ไม่ต้องมี TEE

```bash
cargo build -p aivm-cli --features llama   # ครั้งแรกคอมไพล์ llama.cpp หลายนาที
sh scripts/llama-smoke.sh ~/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf
python3 -m unittest discover -s scripts -p 'test_llama_replay.py'  # seed เดิมต้องตอบตรงกัน
```

config สำเร็จรูป: `examples/aivm-local.yaml` (provider local + Tier1 sandbox +
ตัดเน็ตทั้งหมด + secret HITL) แก้ `model_path` เป็น path เครื่องนี้แล้วสร้างด้วย
บิลด์ llama (`create` ด้วยบิลด์ปกติจะ fail-closed ว่า provider นี้ต้องใช้ฟีเจอร์ llama)
ตั้ง `AIVM_GGUF=/path/model.gguf` ได้ถ้าไม่อยากใช้ path ดีฟอลต์ ไม่มีไฟล์/ไม่มี
cmake = เทสต์ replay **skip อย่างซื่อสัตย์** (เหมือนบูตจริงที่ไม่มี KVM)

## 1. Rust (บังคับ)

Rust stable + `clippy` + `rustfmt` (CI ใช้สามอย่างนี้ล็อกเกต):

```bash
rustup toolchain install stable --component clippy rustfmt
cargo --version   # 1.8x+
```

build ครั้งแรก:

```bash
cargo build --workspace        # หรือ: make build
cargo run -q -p aivm-cli -- demo   # พิสูจน์เส้น enforcement (~1 วินาที)
```

## 2. เครื่องมือ host สำหรับ MicroVM (ใช้เฉพาะ isolation ระดับ microvm)

`process.exec` ระดับปกติไม่ต้องมีของพวกนี้ ของสี่อย่างนี้ใช้เฉพาะตอนบูต guest จริง
(ดู [`microvm.md`](./microvm.md)):

| ของ | ใช้ทำอะไร | ติดตั้ง (Ubuntu) |
|---|---|---|
| `/dev/kvm` | KVM acceleration | ผู้ใช้ต้องอยู่ในกลุ่ม `kvm` (`sudo usermod -aG kvm $USER` แล้ว login ใหม่) |
| `firecracker` | VMM (ดูเวอร์ชันที่ pin ไว้ใน `docs/microvm.md`) | ดาวน์โหลด release + ตรวจ sha256 + วางใน `PATH` |
| `mkfs.ext4`, `debugfs` | สร้าง data drive / ฉีด init เข้า rootfs สำเนา | `sudo apt install e2fsprogs` |
| `ldd` | หา library closure ของ exe | มากับ glibc อยู่แล้ว |

ตรวจว่าเครื่องพร้อมไหม (รายงานซื่อสัตย์ ไม่ error ถ้าไม่มี):

```bash
cargo run -q -p aivm-cli -- probe
sh scripts/setup-host.sh   # สรุป Tier1/Tier2/Tier3 จาก probe + ของใน PATH (อ่านอย่างเดียว)
```

Container backend ต้องมี bubblewrap, helper ที่ติดตั้งโดย root และ delegated cgroup v2
ดูขั้นตอนและข้อกำหนดใน [`container.md`](./container.md)

## 3. ของเสริมตามฟีเจอร์ (optional ทั้งหมด)

| ฟีเจอร์ | เปิดด้วย | ต้องมีเพิ่ม |
|---|---|---|
| `llama` (โมเดล local GGUF) | `--features llama` (ดู chain ใน `docs/testing.md`) | cmake + toolchain C++ (build `llama-cpp-2`), ไฟล์ `.gguf` |
| `microvm` (บูต guest จริง) | `--features microvm` (หรือ `aivm-cli/microvm` ทั้งสาย) | ของในข้อ 2 + pins (ดู `docs/microvm.md`) |
| `hardware` (Generic VM; TEE experimental) | `--features hardware` (หรือ `aivm-cli/hardware` ทั้งสาย) | `/dev/kvm` + `qemu-system-x86_64` + `mkfs.ext4`/`debugfs`/`ldd` (เหมือนข้อ 2 แต่ใช้ QEMU แทน firecracker) + pins (ดู `docs/hardware.md`); TEE จริงต้อง `/dev/sev` (SEV-SNP) หรือ `/dev/tdx_guest` (TDX) + `swtpm` ถ้าเปิด vTPM |
| `graphify` (`make query/path/explain`) | ไบนารี `graphify` ใน `PATH` | ใช้ค้นโค้ดผ่าน knowledge graph; ไม่มีก็ใช้ `grep` แทนได้ |

## 4. โครงที่ได้หลัง `create`

```bash
cargo run -q -p aivm-cli -- --root ./vms create coder --config ./examples/aivm.yaml
```

```
./vms/coder/
  aivm.yaml        config ที่ใช้บูต (ต้นฉบับความจริงของ policy)
  workspace/       ที่ทำงานของ agent (ขอบเขต filesystem)
  state.json       state + lease ที่ persist (กู้แบบ fail-closed ถ้าไฟล์เสีย)
  audit.jsonl      audit log (append-only + hash chain)
```

`--root` ไหนก็ได้ แยกกันคนละบ้าน VM (smoke test ใช้ temp dir แล้วลบทิ้ง)
