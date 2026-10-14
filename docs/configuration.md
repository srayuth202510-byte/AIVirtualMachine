# Configuration — `aivm.yaml` อ้างอิง

`create` จะ validate config ก่อนบูตเสมอ config ผิด = บูตไม่ขึ้น (fail-closed)
ฟิลด์ที่ไม่ระบุใช้ค่า default ตามตาราง ทุกบล็อก `#[serde(default)]` หมด

```yaml
name: coder

runtime:
  isolation: sandbox   # sandbox | microvm | container | hardware (ดู docs/architecture.md)
  # ค่าแปลก (เช่น docker) = บูตไม่ขึ้น ไม่เงียบไปใช้ sandbox

model:
  provider: echo       # echo | local | openai | anthropic (local ต้อง build ด้วย --features llama)
  name: echo
  # local:             # ใช้เมื่อ provider: local
  #   model_path: /models/model.gguf
  #   ctx_size: 8192
  #   gpu_layers: 0    # -1 = ยกทุกชั้นไป GPU
  #   threads: 0       # 0 = อัตโนมัติ
  #   seed: 0
  #   temperature: 0.7
  #   top_p: 0.95
  #   top_k: 40
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
#   hitl_required_for: ["high"]   # low-risk ออก lease ให้เลย high ต้อง approve
#   max_ttl_seconds: 3600         # 0 = ไม่จำกัด
#   max_uses_allowed: 5           # 0 = ไม่จำกัด

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
```

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
