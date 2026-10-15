# Configuration — `aivm.yaml` อ้างอิง

`create` จะ validate config ก่อนบูตเสมอ config ผิด = บูตไม่ขึ้น (fail-closed)
ฟิลด์ที่ไม่ระบุใช้ค่า default ตามตาราง ทุกบล็อก `#[serde(default)]` หมด

```yaml
name: coder

runtime:
  isolation: sandbox   # sandbox | microvm | container | hardware (ดู docs/architecture.md)
  # container:         # ใช้เมื่อ isolation: container; ดู docs/container.md
  #   bubblewrap: /usr/bin/bwrap
  #   init: /usr/libexec/aivm-container-init
  #   cgroup_root: /sys/fs/cgroup/aivm
  # ค่าแปลก (เช่น docker) = บูตไม่ขึ้น ไม่เงียบไปใช้ sandbox

model:
  provider: echo       # echo | local | openai | anthropic (local ต้อง build ด้วย --features llama)
  name: echo
  # local:             # ใช้เมื่อ provider: local
  #   model_path: /models/model.gguf
  #   ctx_size: 8192
  #   gpu_layers: 0    # -1 = ยกทุกชั้นไป GPU
  #   threads: 0       # 0 = อัตโนมัติ
  #   seed: 42         # deterministic seed (default: 42)
  #   temperature: 0.0 # deterministic (default: 0.0)
  #   top_p: 0.1       # low = more focused (default: 0.1)
  #   top_k: 1         # greedy sampling (default: 1)
  #   max_tokens: 2048

resources:
  cpu: 2
  memory: 1GB
  storage: 5GB

filesystem:
  read: [./workspace]
  write: [./workspace/src]

network:
  allow: [github.com, crates.io]   # นอกนี้ + deny list บังคับ = DENY

tools:
  allow:                           # ชื่อ tool ที่ agent เรียกได้
    - filesystem.read
    - filesystem.write
    - code.search
  # ชื่อ exe ล้วน (เช่น cargo) ค้นแค่ /usr/bin กับ /bin ที่ runtime คุม
  # อย่างอื่นต้อง absolute path + canonicalize ผ่าน หาไม่เจอ = ทิ้งเงียบ (fail-closed)

capabilities:
  initial: [read:workspace, search:code]   # สิทธิ์ตั้งต้น state INIT (§14.2)

policy:
  require_test_before_network: true        # false = เตือนตอน create (network ไม่ต้องมีเทสต์ก่อน)

# นโยบาย secrets (G4 §26): มีแค่ patterns — values อยู่ใน secrets.yaml
# ของ operator (ข้างบ้าน VM, 0600 เท่านั้น) ไม่มีไฟล์ = deny หมด
# secrets:
#   allow: ["github_token:read"]
#   deny: ["github_token:admin"]
#   low_risk_allow: ["github_token:read"] # operator เท่านั้นที่กำหนด Low-risk
#   hitl_required_for: ["high"]   # low-risk ออก lease ให้เลย high ต้อง approve
#   max_ttl_seconds: 3600         # 0 = ไม่จำกัด
#   max_uses_allowed: 5           # 0 = ไม่จำกัด
#
# secrets.yaml (`<vm-dir>/secrets.yaml`, 0600 — สิทธิ์หลวมกว่านี้ไม่บูต):
#   github_token: ghp_...
#
# ขอ high-risk → pending (deny + lease id ใน audit) แล้ว operator สั่ง:
#   aivm approve-secret <vm> <lease-id> [--by NAME]
# approve แล้วใช้ได้ตาม max_uses/TTL เดิม (ไม่ต่ออายุ) ข้าม restart ได้
# (persist 0600) หมดอายุ/ใช้ครบ/จบแล้ว = ทิ้ง

# บล็อก microvm: (ใช้เมื่อเปิดฟีเจอร์ microvm เท่านั้น บิลด์ปกติเมินทิ้ง)
# ดูวิธีเตรียม pins ใน docs/microvm.md
# microvm:
#   kernel_path: /path/vmlinux.bin
#   kernel_sha256: "<64 hex>"
#   rootfs_path: /path/rootfs.ext4
#   rootfs_sha256: "<64 hex>"
#   fc_sha256: "<64 hex>"   # ไม่ตั้ง = ไม่ pin ไบนารี VMM (รายงานใน degraded)
#   vcpu_count: 1           # 1..=32 (default 1)
#   mem_mb: 256             # 64..=32768 (default 256)
#   max_artifact_bytes: 536870912   # เพดานไฟล์ artifact (default 512MiB, ต้อง > 0)
#   boot_timeout_secs: 60   # 5..=600 (default 60)
#   alt_kernel: { path: /path/vmlinux2.bin, sha256: "<64 hex>" }   # G5: verify ทุกชุด สุ่มใช้ต่อบูต
#   alt_rootfs: { path: /path/rootfs2.ext4, sha256: "<64 hex>" }
#   dna_jitter: false       # true = สุ่มลด vcpu/mem ≤25% ต่อบูต (ไม่เกิน quota)
#   jailer: ...             # ดู examples/aivm.yaml (ต้อง root)

# บล็อก hardware: (ใช้เมื่อเปิดฟีเจอร์ hardware เท่านั้น บิลด์ปกติเมินทิ้ง)
# Level 3 — Hardware Isolation (TEE/Confidential Computing)
# ต้องการ host ที่รองรับ AMD SEV-SNP (Zen 3+/Genoa) หรือ Intel TDX (Sapphire Rapids+)
# hardware:
#   tee_type: sevsnp              # sevsnp | tdx | generic (default: generic)
#   attestation_mode: strict      # strict | best_effort | none (default: strict)
#   kernel_path: /path/vmlinux.bin
#   kernel_sha256: "<64 hex>"
#   initrd_path: /path/initrd.img  # optional, สำหรับ measured boot
#   initrd_sha256: "<64 hex>"
#   rootfs_path: /path/rootfs.ext4
#   rootfs_sha256: "<64 hex>"
#   qemu_sha256: "<64 hex>"       # ไม่ตั้ง = ไม่ pin QEMU (รายงานใน degraded)
#   vcpu_count: 2                 # 1..=256 (default 2)
#   mem_mb: 2048                  # 1024..=1048576 (default 2048)
#   max_artifact_bytes: 1073741824  # เพดานไฟล์ artifact (default 1GiB, ต้อง > 0)
#   launch_timeout_secs: 120      # 10..=1800 (default 120)
#   gpu:                          # ทั้งบล็อกต้องปิดไว้ทั้งหมด (true ตัวใดตัวหนึ่ง = บูตไม่ขึ้น)
#     mig_enabled: false          # MIG — ยังไม่ implement (เปิด = Invalid)
#     mig_profile: ""
#     sriov_enabled: false        # SR-IOV — ยังไม่ implement (เปิด = Invalid)
#     sriov_num_vfs: 0
#     vgpu_enabled: false         # vGPU — ยังไม่ implement (เปิด = Invalid)
#     vgpu_type: ""
#   disk_encryption:              # host ไม่ฉีดคีย์ให้ guest — initrd ของ guest ต้อง unlock เอง
#     enabled: false              # ขอ disk encryption (รายงานใน degraded — host ไม่ unlock ให้)
#     key_source: vtpm            # vtpm (ต้อง vtpm.enabled) | tpm2 | passphrase (dev only)
#     pcr_policy: "0,1,2,3,4,7"   # PCR indices สำหรับ unseal
#     cipher: aes-xts-plain64
#     key_size: 512
#   measured_boot:                # เปิดได้เฉพาะเมื่อ vtpm.enabled = true
#     enabled: false              # ขอ measured boot (PCR compare ยังไม่ implement — รายงานใน degraded)
#     expected_pcrs: {}           # map PCR index -> expected sha256 hex (ยังไม่ถูกเทียบ)
#     firmware: ovmf              # ovmf | sev-firmware
#     secure_boot: false          # verify kernel/initrd signature (ยังไม่ implement)
#     cert_paths: []
#   vtpm:
#     enabled: false              # swtpm + QEMU vTPM device
#     swtpm_path: ""              # path to swtpm binary (default: PATH)
#     tpm_state_dir: ""           # TPM state directory
#     tpm2: true                  # TPM 2.0 spec
#   alt_kernel: { path: /path/vmlinux2.bin, sha256: "<64 hex>" }  # G5 DNA
#   alt_initrd: { path: /path/initrd2.img, sha256: "<64 hex>" }
#   alt_rootfs: { path: /path/rootfs2.ext4, sha256: "<64 hex>" }
#   dna_jitter: false             # true = สุ่มลด vcpu/mem ≤25% ต่อบูต (ไม่เกิน quota)
#   tee_device_path: /dev/sev     # /dev/sev (SEV-SNP) หรือ /dev/tdx_guest (TDX)
#   kds_cache_dir: ""             # AMD KDS certificate cache (SEV-SNP attestation)
#   qemu_path: ""                 # path to qemu-system-x86_64 (default: PATH)
```

## โปรไฟล์เสถียรภาพโมเดล (Model Stability)

ตั้งค่า `model.local` ต่อไปนี้สำหรับ production ที่ต้องการ deterministic output:

```yaml
model:
  provider: local
  name: my-model
  local:
    model_path: /models/model.gguf
    seed: 42                    # เมล็ดสุ่มตายตัว = ผลลัพธ์ซ้ำได้
    temperature: 0.0            # greedy decoding = deterministic
    top_p: 0.1                  # จำกัด token ใน nucleus sampling
    top_k: 1                    # เลือก token ที่น่าจะเป็นมากสุด (greedy)
    max_tokens: 2048
    ctx_size: 8192
    gpu_layers: -1              # -1 = ใช้ GPU ทั้งหมด
    threads: 0                  # 0 = auto
    use_mmap: true
    use_mlock: true             # lock model ใน RAM (กัน swap)
```

| พารามิเตอร์ | ค่าเริ่มต้น | แนะนำสำหรับเสถียร | ผลกระทบ |
|------------|------------|-------------------|----------|
| `seed` | 42 | 42 (หรือค่าตายตัว) | ทำให้ sampling ซ้ำได้ |
| `temperature` | 0.0 | 0.0 | 0 = deterministic, >0 = creative |
| `top_p` | 0.1 | 0.0–0.1 | ต่ำ = focus, สูง = diverse |
| `top_k` | 1 | 1 | 1 = greedy, >1 = sampling |
| `use_mlock` | false | true | กัน model ถูก swap out |

> **หมายเหตุ**: `temperature: 0.0` + `top_k: 1` = **fully deterministic** (greedy decoding)
> เหมาะสำหรับ coding tasks, structured output, regression testing

## หมายเหตุการบังคับใช้

- runtime สร้าง enforcement policy จาก config + **deny list บังคับ** (เช่น
  `**/.env*`, `**/secrets/**`, `/bin/sh`, `/bin/bash`, เน็ตวงใน `10/8`,
  `127.0.0.1`, `169.254.169.254`) — allow ใน yaml ไม่มีทางลบล้าง deny บังคับได้
  (`deny_overrides: true`)
- `tools.allow` ว่าง = ไม่มี `process.exec` เลย + `create` เตือน
  (`capabilities.initial` ว่าง / `require_test_before_network: false` ก็เตือนเหมือนกัน)
- `runtime.isolation: microvm` แต่ไม่มีบล็อก `microvm:` = gateway ใช้ค่า default
  ที่ deny ตั้งแต่ artifact หาย — ไม่มีทางรันโดยไม่ตั้งใจ

## Guards ของ transition (operator ให้ ไม่ใช่ agent อ้าง)

```bash
aivm transition <name> ANALYZE
aivm transition <name> MODIFY  --confidence 0.95        # ต้อง ≥ threshold
aivm transition <name> VALIDATE --tests-passed          # MODIFY → VALIDATE
aivm transition <name> DEPLOY   --policy-approved       # VALIDATE → DEPLOY (HITL)
```

กระโดดข้าม (เช่น INIT→DEPLOY) ถูกปฏิเสธเสมอ state ไม่ขยับถ้า guard ไม่ผ่าน

## Build output profile (opt-in)

`build.enabled` ค่าเริ่มต้น false, `max_files` ค่าเริ่มต้น 16 (1..64), `max_bytes` ค่าเริ่มต้น 16 MiB (1 KiB..512 MiB) งบแบ่งเท่ากันราย slot Artifact ที่ต้องรันต้องอยู่ใน `tools.allow` เช่น `build:tests` ด้วย ดู [build-workflow.md](build-workflow.md) และ `examples/build-c.yaml`
