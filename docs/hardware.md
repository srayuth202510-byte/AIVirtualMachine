# Hardware Isolation — Level 3 (skeleton, fail-closed)

สถานะ: 🚧 **skeleton** — ประตู fail-closed ครบทุกลำดับ (spec/shape/supply-chain/host)
โค้ดรัน workload พร้อมแล้ว (drive-stuffing แบบเดียวกับ MicroVM) แต่**ยังไม่เคย
บูตจริงบนเครื่องที่มี KVM** (รอ `AIVM_HARDWARE_PINS` — ดูข้างล่าง) และ
attestation/measured-boot/disk-encryption/GPU ยังเป็น stub ที่รายงานซื่อสัตย์
ใน `degraded` (ดู "ข้อจำกัดที่รู้ตัว" ท้ายไฟล์)

## ต้องการอะไรบน host

| ของ | จำเป็น | หมายเหตุ |
|---|---|---|
| Linux + `/dev/kvm` | ใช่ | ไม่มี = `Disabled` ตั้งแต่ประตู host |
| `qemu-system-x86_64` ใน PATH | ใช่ | ตั้ง `qemu_sha256` เพื่อ pin ไบนารี (ไม่ตั้ง = รายงานใน `degraded`) |
| `debugfs`, `mkfs.ext4`, `ldd` | ใช่ (ตอน launch) | ใช้ฉีด init + สร้าง data drive — ไม่มี = `Spawn` ดัง |
| `/dev/sev` (SEV-SNP) / `/dev/tdx_guest` (TDX) | เฉพาะ `tee_type` นั้น ๆ | `generic` ไม่ต้องการ device (โหมดจำลอง) |
| `sev-tool` / `tdx-attest` | เฉพาะ attestation จริง | ไม่มี + `strict` = `Spawn` + `Suspect` |
| `swtpm` | เฉพาะ `vtpm.enabled` | spawn แบบ foreground + ถือ guard (ไม่มี daemon กำพร้า) |

## โหมดจำลอง (ตอบคำถาม "เทสโดยไม่มี hardware ได้ไหม")

ได้ — ตั้งค่านี้ (ไม่ต้องการ TEE device จริง):

```yaml
runtime:
  isolation: hardware
hardware:
  tee_type: generic            # จำลอง: QEMU/KVM ธรรมดา ไม่ isolate ระดับ hardware
  attestation_mode: none       # generic + strict เป็นไปไม่ได้ (= Disabled)
  kernel_path: /path/vmlinux
  kernel_sha256: "<64 hex>"
  rootfs_path: /path/rootfs.ext4
  rootfs_sha256: "<64 hex>"
```

`generic` รันได้บนเครื่องที่มีแค่ KVM + QEMU (CI ที่ไม่มี KVM จะ skip
อย่างซื่อสัตย์เหมือน MicroVM) แต่**ไม่มี hardware isolation จริง** —
รายงานใน `degraded` ทุกครั้ง (`tee: none (generic simulation, ...)`)

## เตรียม pins สำหรับบูตจริง

เหมือน MicroVM (`docs/microvm.md`): เตรียม kernel + rootfs ที่ verify ได้
แล้วเก็บ sha256 ลง `pins.json`:

```json
{
  "kernel": { "path": "/path/vmlinux", "sha256": "<64 hex>" },
  "rootfs": { "path": "/path/rootfs.ext4", "sha256": "<64 hex>" }
}
```

แล้วรัน `AIVM_HARDWARE_PINS=/path/pins.json make test-hardware`
(ไม่มีตัวแปรนี้ = เทสต์บูตจริง skip อย่างซื่อสัตย์)

## ลำดับประตู (ห้ามสลับ)

1. validate spec (exe/policy/arg/env/cwd — ประตูเดียวกับ Process/MicroVM)
2. `validate_shape` (ตัวเลข + config เป็นไปไม่ได้ เช่น measured-boot ไม่มี
   vTPM, GPU passthrough, `generic` + `strict`)
3. supply chain: kernel/initrd/rootfs (+alt ทุกชุด) ตรง hash ที่ pin
4. host readiness: KVM + TEE device + QEMU (+ pin ถ้าตั้ง)
5. ก็อป kernel/initrd/rootfs ไป scratch + verify สำเนาซ้ำ (กันสลับกลางทาง)
6. drive-stuffing: exe + ldd closure → data drive, ฉีด `/sbin/aivm-init`
   ด้วย debugfs, บูตด้วย `init=` จับผลทาง serial (`-nic none` — guest
   ไม่มีเน็ตเวิร์กเลยตั้งแต่เกิด)
7. เส้นตายรวม `launch_timeout_secs` เกิน = `Suspect` + kill เก็บงานเสมอ

## ข้อจำกัดที่รู้ตัว (รายงานใน `applied`/`degraded` ทุกครั้ง)

- `attestation-tool-check` = มี tool ขอ report เฉย ๆ **ยังไม่มีการ verify
  quote กับ KDS/endorsement keys** (`quote-verification: not implemented`)
- `measured-boot` / `disk-encryption` = รับ config + ตรวจ shape แต่**ยังไม่
  เทียบ PCR / ไม่ unlock ให้** (guest initrd ต้องทำเองผ่าน vTPM)
- GPU passthrough (MIG/SR-IOV/vGPU) = เปิดแล้วบูตไม่ขึ้น (`Invalid` ตั้งแต่
  shape — กันรันแบบขาด GPU โดยไม่มีใครรู้)
- `env_extra` ถูกเมิน, cwd ใน guest คือ `/`, `pids_max` ไม่ enforce ใน guest,
  output ต้องเป็น UTF-8 (เหมือน MicroVM)
- initrd ที่ให้มาต้องเคารพ `init=` (initramfs-tools/dracut ทั่วไปเคารพ)
  ไม่เช่นนั้น guest จะไม่รัน workload แล้วหมดเส้นตายแบบ `Suspect` ดัง ๆ
