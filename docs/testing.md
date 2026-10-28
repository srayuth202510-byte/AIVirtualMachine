# Testing — เมทริกซ์คำสั่งทดสอบ

## Verifier และ state/audit crash recovery

`cargo test -p aivm-runtime transaction::tests` ทดสอบ SIGKILL ระหว่าง mutation
และ recovery; `make test-coding` ตรวจ verifier receipt ของ compiler/test binary จริง
รายละเอียดอยู่ใน [Verifier contracts และ transactions](verification-and-transactions.md)

## คำสั่งหลัก

ทดสอบการจำกัด registry writes, IPv6 SSRF และข้อมูล template ที่ไม่ถูกรัน:
`cargo test --locked -p aivm-adversarial --test registry_containment`
ดูขอบเขตใน [Registry containment](registry-containment.md)

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

fmt → clippy strict → `cargo test --workspace` → Python tests → `make test-dashboard-http` → clippy/test หลังฟีเจอร์ llama → clippy หลังฟีเจอร์ microvm →
`make test-microvm` → clippy/test หลังฟีเจอร์ hardware → demo → smoke.sh
runner ระบุรุ่นเป็น `ubuntu-24.04` (เทสต์บูตจริงข้ามเมื่อไม่มี KVM/pins — unit/plumbing
ที่เหลือยังจับของพังได้)

`make test-dashboard-http` ต้องเปิด localhost socket ได้ ทดสอบ background importer,
SQLite lock ขณะตอบ HTTP, slow clients, เพดาน handler และ graph cache
unit tests ปกติข้ามเฉพาะเคส HTTP จริงจนกว่าจะตั้ง `AIVM_DASHBOARD_HTTP_TESTS=1`

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
จากนั้นรัน `failure-recovery` แยกแต่ละ tier: request deadline 100 ms และ
memory budget 128 MiB ต้องล้มโดยไม่ส่ง token พร้อมหลักฐานสาเหตุที่ตรงกัน
ตรวจ PID/starttime ของ descendants, process ที่อ้าง private test directory,
staging และ private container cgroups แล้วต้องรัน inference ที่ verified ได้
ด้วย client/pins เดิมหลัง failure แต่ละครั้ง การตรวจ cleanup รอได้สูงสุด 5 วินาที
deadline ของ worker ไม่รวม staging/boot preparation; test จำกัดเวลารวมของ
แต่ละ failure พร้อม setup/cleanup ไว้ 180 วินาที ไม่อ้างว่า latency รวมคือ 100 ms
OOM diagnostic ใน serial ของ pinned guest ใช้เป็นหลักฐานประกอบ host test เท่านั้น
ไม่เปลี่ยน trust ของ guest output ให้เป็น security verdict ของ production
แยก `allocation-failure`, `guest-oom-diagnostic` และ `ram-backed-staging-capacity`
ใน evidence: MicroVM ที่มี RAM น้อยอาจเต็มที่ tmpfs snapshot ก่อนถึง inference
กรณีหลังต้องยืนยันชนิด filesystem ผ่าน descriptor ก่อนระบุว่า RAM-backed staging เต็ม
disk-full ทั่วไปหรือ exit code อย่างเดียวไม่นับเป็น memory-pressure evidence
exit 0 ที่ไม่พบเทสต์หรือข้าม prerequisite ไม่นับว่าผ่าน เก็บ command, elapsed time,
raw logs, commit/source identifiers และ hashes ก่อน/หลังใน output directory
ต้องมี temporary storage สำหรับสำเนา GGUF ตาม [model runtime](model-runtime.md)

รัน failure suite เฉพาะ tier โดยระบุ evidence path แบบ absolute:

```bash
AIVM_GGUF_SHA256='<approved-64-hex-sha256>' \
AIVM_WORKER_HOST_EVIDENCE=/absolute/path/failure-recovery.json \
  sh scripts/test-worker-host.sh container /path/model.gguf /path/pins.json failure-recovery
```

รายงาน `failure-recovery-<tier>.json` ต้องมี timeout, memory failure และ
verified recovery หลังแต่ละกรณีครบทั้ง 4 records พร้อม cleanup evidence
สคริปต์สร้าง private TMPDIR; เก็บ MicroVM scratch ชั่วคราวเพื่ออ่าน diagnostics
แล้วล้างก่อนจบ test ไม่ส่ง rootfs/model copies เข้า workflow artifacts

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

## Worker control hardening และคุณภาพโมเดล

ดู [worker control hardening](model-control-hardening.md) สำหรับการทดสอบ sealed executable,
checked cleanup, blocked controller, slow event consumer, cross-process quotas และ cache
ตั้ง `AIVM_SUPERVISED_CONTROL=1` เมื่อรัน model-host validator เพื่อทดสอบ controller ใหม่
เพิ่ม `--quality` เพื่อวัด model-only task oracles 6 งานทั้ง cache ปิด/เปิดด้วย client เดิม
คะแนน task quality แยกจาก protocol/infrastructure gate และไม่ dispatch intents ที่สร้างขึ้น
Detector holdout อยู่ใน `examples/detection/holdout.json`; ใช้ `eval-detection.py --corpus ...`
เพื่อรายงาน FP/FN แยกจาก baseline โดยไม่เปลี่ยน labels ตามผลที่อยากได้

รัน integration tests ของ controller รวม namespace cases บน Linux host ที่เตรียมไว้:

```bash
cargo test --locked -p aivm-model-worker --features llama,microvm \
  --test hardening -- --include-ignored
```

MicroVM socket regression ใช้ Unix socket จริงใน staging path ที่ยาวเกิน `sun_path`
และไม่ต้องมี KVM; อยู่ใน `cargo test -p aivm-sandbox --features microvm`
