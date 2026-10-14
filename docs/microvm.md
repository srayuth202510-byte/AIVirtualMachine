# MicroVM — บูต guest จริง (Phase 7 Level 2)

`process.exec` ที่ `runtime.isolation: microvm` ไม่รันบน host แต่บูต MicroVM
(Firecracker + KVM) ต่อครั้งแล้วรัน exe ข้างใน วิธีเรียก **drive-stuffing**:
ก็อป rootfs ที่ verify แล้วไปไฟล์ชั่วคราว (ห้ามแตะไฟล์ pin ต้นฉบับ) ฉีด
`/sbin/aivm-init` สร้าง data drive จาก exe + `ldd` closure แล้วจับผลทาง
serial console ด้วย marker ต่อ nonce **guest ไม่มีเน็ตเวิร์กเลยตั้งแต่เกิด**
(ไม่ได้ config ไว้)

## 1. เตรียม artifacts + pins (ครั้งเดียวต่อเครื่อง)

ไฟล์ที่ปักหมุดแล้ว (ห้ามรันจากไฟล์ pin ตรง ๆ — โค้ดก็อปไป scratch ทุกครั้ง):

| ไฟล์ | upstream (ดาวน์โหลดซ้ำได้) |
|---|---|
| `vmlinux.bin` (~21MB) | `https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin` |
| `hello-rootfs.ext4` (~30MB) | `https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4` |
| `firecracker` v1.17.0 | `https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz` |

สร้าง `pins.json` ใหม่ (ตัวอย่างค่าจริงอยู่ในไฟล์ — **อย่า copy hash ข้ามเครื่อง
ให้คำนวณจากไฟล์ที่โหลดมาเอง**):

```bash
mkdir -p ~/.local/share/aivm/microvm && cd ~/.local/share/aivm/microvm
curl -sSOL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
curl -sSOL https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4
# firecracker: แตก tgz แล้ววางไบนารีใน PATH (เช่น ~/.local/bin) + ตรวจ sha กับ upstream
sha256sum vmlinux.bin hello-rootfs.ext4 ~/.local/bin/firecracker
# ประกอบ pins.json ตาม schema ข้างล่างด้วย hash ที่ได้
```

schema ของ `pins.json` (เครื่องมืออ่านแค่ `kernel.*`, `rootfs.*`, `binary.sha256`):

```json
{
  "kernel":  { "path": "/home/USER/.local/share/aivm/microvm/vmlinux.bin", "sha256": "<64 hex>" },
  "rootfs":  { "path": "/home/USER/.local/share/aivm/microvm/hello-rootfs.ext4", "sha256": "<64 hex>" },
  "binary":  { "path": "/home/USER/.local/bin/firecracker", "sha256": "<64 hex>" },
  "vcpu_count": 1,
  "mem_mb": 256
}
```

**ความปลอดภัยของ trust root**: การสลับไฟล์ artifact ถูกจับด้วย hash
(fail-closed ทุกครั้งที่รัน) แต่การแก้ **hash ใน yaml/pins** จับไม่ได้ —
จึงต้องล็อกสิทธิ์ให้ operator เท่านั้น:

```bash
chmod 700 ~/.local/share/aivm/microvm
chmod 600 ~/.local/share/aivm/microvm/*
```

## 2. ใช้กับ VM

เพิ่มบล็อก `microvm:` ใน `aivm.yaml` (ฟิลด์ครบดู `docs/configuration.md`)
แล้ว build ด้วยฟีเจอร์:

```bash
cargo build -p aivm-cli --features microvm
```

`runtime.isolation: microvm` แต่ไม่มีบล็อก = deny ตั้งแต่ artifact หาย
ไม่มีทางรันโดยไม่ตั้งใจ

## 3. ทดสอบ

```bash
export AIVM_MICROVM_PINS=~/.local/share/aivm/microvm/pins.json
make test-microvm          # unit + plumbing + บูตจริง (/bin/true → 0, /bin/false → 1)
AIVM_MICROVM_KEEP_SCRATCH=1 ...   # เก็บ scratch (รวม serial.log) ไว้ดีบัก
```

ไม่มี `AIVM_MICROVM_PINS` / KVM / firecracker = เทสต์บูตจริง **skip อย่างซื่อสัตย์**
(เขียว ไม่ใช่แกล้งผ่าน) — CI จึงรัน `make test-microvm` ได้ทุกครั้ง

## 4. ประตูตามลำดับ (ห้ามสลับ)

1. `validate` สเปกงาน (exe/policy/arg/env/cwd — ประตูเดียวกับ Process)
2. shape ของ config (`vcpu_count`, `mem_mb`, `boot_timeout_secs` 5..=600)
   + `verify_artifact` kernel/rootfs (supply chain มาก่อนตรวจ host)
3. host readiness: Linux + `/dev/kvm` + ไบนารี firecracker
   (+ pin hash VMM ถ้าตั้ง `fc_sha256` ไว้)
4. boot พร้อมเส้นตาย ฆ่าทิ้งแบบ fail-closed (`KillOnDrop` — ไม่มี VM กำพร้า)
   + verify สำเนา rootfs ซ้ำหลังก็อป (กันไฟล์ถูกสลับ/ก็อปเสีย)
5. ขนาด guest = min(quota ระดับ VM, quota ระดับ task) — task ไม่เกินโควตาตัวเอง

ผลทุกครั้งรายงานผ่าน `applied` (อะไร enforce แล้ว) กับ `degraded`
(อะไรยังหย่อน: `env_extra` ถูกเมิน, cwd ใน guest คือ `/`, `pids_max` ไม่ enforce,
output ไม่ใช่ UTF-8 ถูกแทนด้วย U+FFFD, VMM ไม่ pin ถ้าไม่ตั้ง `fc_sha256`)

## 4b. Run verdict (G3 — `docs/threat-model.md`)

ทุกครั้งที่พยายามรันมีคำตัดสิน `RunVerdict` ติดไปกับผล/audit
(`verdict:<clean|suspect|compromise>:<reason>`):

- `clean` — จบบริบูรณ์ หรือ deny ตั้งแต่ประตู/infra ล้มแบบไม่มีร่องรอยแทรกแซง
- `suspect:deadline-exceeded` — เกินเส้นตาย; `suspect:exit-marker-missing` /
  `suspect:exit-code-unparsable` — serial ถูกป่วน/ไม่สมบูรณ์
- `compromise:vmm-died-before-marker` — VMM ตายก่อน marker;
  `compromise:rootfs-copy-reverify-failed` — สำเนาถูกสลับกลางบูต

verdict ตอบแค่ "มีหลักฐานละเมิด boundary หรือไม่" ไม่ใช่ "รันสำเร็จหรือไม่"
`suspect`/`compromise` ต้องสืบต่อเสมอ แม้ decision จะเป็น deny อยู่แล้ว

## 4c. Instance DNA (G5 — `docs/threat-model.md`)

ทุกบูตสุ่มเอกลักษณ์ของตัวเอง (ไม่ต้องตั้งอะไร — เกิดเอง ยกเว้น `dna_jitter`
กับ alt images ที่ operator เลือกเปิด):

- **marker scheme** (V0/V1) + ชื่อไฟล์ tmp ใน init — payload สำเร็จรูปที่
  hardcode รูป marker ใช้ไม่ได้ทุกบูต
- **image set** — ตั้ง `alt_kernel`/`alt_rootfs` แล้ว verify ทุกชุดตั้งแต่ประตู
  สุ่มเลือกหนึ่งชุดต่อบูต (exploit ผูก image เดียวใช้ซ้ำไม่ได้)
- **resource jitter** (`dna_jitter: true`) — vcpu/mem ลดไม่เกิน 25% จาก quota
  (ไม่มีทางเกิน ไม่มีทางต่ำกว่า 1 vcpu / 64 MiB) แลก headroom กับ diversity
- **secret lease ไม่ซ้ำข้าม run** (`max_uses=1` ต่อ boot — ดู secrets crate)

dna id รูป `s{scheme}-k{0|1}-r{0|1}-{vcpu}x{mem}-{tmp}` ลง audit ทุกครั้ง
(`applied` มีแค่ชื่อกลไก `instance-dna`)

**ซื่อสัตย์**: DNA คือ diversity ไม่ใช่ความลับ — init อยู่ใน guest อ่าน scheme
ได้เสมอ กัน payload สำเร็จรูปได้ แต่กันการปลอมแบบเห็นข้อความ (live forgery)
ไม่ได้ (marker มี nonce + parse เข้มคุมอยู่แล้วอีกชั้น)

## 5. แก้ปัญหา

| อาการ | สาเหตุที่เป็นไปได้ |
|---|---|
| `microvm needs /dev/kvm` | ไม่อยู่กลุ่ม `kvm` / VM ซ้อน VM ที่ไม่ส่ง KVM ต่อ → DENY แบบมี audit |
| `microvm needs the firecracker binary in PATH` | ไบนารีไม่อยู่ใน `PATH` ของคนรัน |
| `artifact hash mismatch` | ไฟล์ถูกสลับ/โหลดมาเสีย — โหลดใหม่แล้วคำนวณ hash ใหม่ ห้ามแก้ hash ให้ตรงไฟล์ปลอม |
| `microvm run timed out` | guest บูตช้า/ค้าง — เพิ่ม `boot_timeout_secs` (ไม่เกิน 600) หรือดู serial ผ่าน `KEEP_SCRATCH` |
| `debugfs`/`mkfs.ext4` ล้ม | ลง `e2fsprogs` ไม่ครบ (ดู `docs/setup.md`) |
| `jailer binary not found in PATH` | jailer ไม่ได้ติดตั้ง หรือ PATH ไม่ครบ — ติดตั้ง jailer หรือตั้ง `jailer_path` ใน config |
| `jailer spawn failed` | ไม่มีสิทธิ์ root (jailer ต้องการ root) หรือ cgroup/namespace ไม่รองรับ |

## 6. Jailer (Optional, requires root)

Jailer เป็น wrapper ของ Firecracker ที่เพิ่ม isolation layers:
- **chroot**: จำกัด filesystem visibility
- **cgroup v2**: resource limits (CPU, memory, pids, I/O)
- **namespaces**: pid, net, mnt, ipc, uts isolation
- **capability dropping**: drop all capabilities
- **no-new-privs**: prevent privilege escalation

การใช้งาน: เพิ่มบล็อก `jailer:` ใน `aivm.yaml` (ดู `examples/aivm.yaml`) และรันด้วยสิทธิ์ root:

```bash
sudo cargo run -q -p aivm-cli -- --root /opt/aivm create coder --config ./examples/aivm.yaml
```

**ข้อจำกัด**: 
- ต้องการ root (sudo) — นอกขอบเขต unprivileged ของ MVP
- จำเป็นต้องติดตั้ง jailer (build จาก firecracker source หรือ download จาก release)
- ความเร็ว boot ช้าลงเล็กน้อยจากการ setup chroot และ copy images

## 7. ข้อจำกัดที่รู้ตัว

VMM ถูกรันตรง ๆ (หรือผ่าน jailer) — data drive อ่านอย่างเดียว, rootfs สำเนาเขียนได้แต่ทิ้งทุกครั้ง
