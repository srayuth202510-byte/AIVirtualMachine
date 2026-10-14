# Container backend — bubblewrap

`runtime.isolation: container` ใช้ bubblewrap กับ helper `aivm-container-init`
จาก crate `aivm-sandbox` ไม่ต้องเปิด Cargo feature เพิ่ม หาก setup ไม่สำเร็จ
จะ DENY พร้อม audit โดยไม่มี fallback ไป Process

```yaml
runtime:
  isolation: container
  container:
    bubblewrap: /usr/bin/bwrap
    init: /usr/libexec/aivm-container-init
    cgroup_root: /sys/fs/cgroup/aivm
resources:
  cpu: 2
  memory: 1GB
  storage: 5GB
```

`container` อยู่ภายใต้ `runtime` และเป็น config ของ operator เท่านั้น
agent เลือก launcher/helper/cgroup root ผ่าน tool request ไม่ได้
ค่าเริ่มต้นตรงกับตัวอย่างด้านบน

## ข้อกำหนด host

- Linux x86_64, Landlock ABI >= 3 และ openat2
- bubblewrap ที่รองรับ `--bind-fd`, `--ro-bind-fd`, `--json-status-fd`,
  `--disable-userns`, `--assert-userns-disabled` และ cgroup namespace
  (พัฒนาบน 0.11.1; รุ่นที่ไม่รองรับจะ DENY)
- user/mount/PID/network/IPC/UTS/cgroup namespaces ต้องสร้างได้จริง
  ไม่มีการใช้ `--unshare-*-try`
- bubblewrap และ helper ต้องเป็น executable ที่ root เป็นเจ้าของ
  ไม่เป็น setuid/setgid และ group/other เขียนไม่ได้
- `cgroup_root` เป็น directory ที่ operator เตรียมและ delegate ให้ runtime
  บน cgroup v2 จริง ต้องเปิด `cpu memory pids` ใน `cgroup.subtree_control`
  ต้องเขียน quota, `memory.swap.max`, `memory.oom.group`, `cgroup.procs`
  และ `cgroup.kill` ของ child cgroup ได้

ติดตั้ง helper หลัง build โดย operator บน host ที่จะรัน:

```bash
cargo build --release -p aivm-sandbox --bin aivm-container-init
sudo install -D -o root -g root -m 0755 \
  target/release/aivm-container-init /usr/libexec/aivm-container-init
```

runtime ไม่แก้ delegation ของ host ให้อัตโนมัติ ไม่ย้ายตัวเองออกจาก cgroup
และไม่เปิด controllers ของ parent ให้ ควรให้ service manager (เช่น systemd
ที่ตั้ง `Delegate=cpu memory pids`) จัดพื้นที่นี้ แล้วกำหนด `cgroup_root`
เป็น subtree ว่างสำหรับ workloads แยกจาก cgroup ที่มี runtime process
ก่อน enable controllers ต้องไม่มี processes ใน parent ตามกฎ cgroup v2
`pids_max` ใช้ค่า runtime ปัจจุบัน 64 และรวม launcher/reaper/helper/target

`aivm probe` แสดง `container.bubblewrap`, `container.init`,
`container.cgroup_v2_quotas` สำหรับ **paths เริ่มต้น** พร้อมผล probe namespaces
แยกกัน สำหรับ custom paths ใช้ `ContainerConfig::probe()`; probe quota
สร้าง/ลบ child cgroup ชั่วคราว ไม่ทดแทนการทดสอบรันจริง

## สิ่งที่บังคับ

filesystem policy ใช้การเตรียมสิทธิ์ชุดเดียวกับ Process backend:

- เริ่มจาก root tree ว่าง ไม่ bind host `/` หรือ workspace ทั้ง subtree
- grants แบบ READ_DIR สร้าง directory เปล่า; grants รายไฟล์ใช้ bind mounts
  จาก file descriptor ที่ pin ไว้ แทนการเปิด source path ใหม่ตอน mount
- เปิด workspace grants ผ่าน openat2 แบบ BENEATH/NO_SYMLINKS/NO_XDEV
  ข้าม symlink/hardlink และไฟล์ที่ policy deny ตามกฎเดิม
- root เป็น read-only; เขียนได้เฉพาะไฟล์เดิม/output slots ที่อนุญาต
  การสร้างไฟล์ยังผ่าน gateway ไม่ได้เปิด writable directory กว้าง
- helper บังคับ Landlock **หลัง** bubblewrap สร้าง mounts แล้วจึง exec target
  สิทธิ์อ่านไฟล์จึงไม่กลายเป็นสิทธิ์ execute และ write-only ยังถูกจำกัด
- private `/dev` ไม่ expose GPU devices; `/proc` มาจาก PID namespace ใหม่
  Landlock ไม่ให้ target อ่าน proc โดยปริยาย
- system libraries/toolchain ใช้ข้อยกเว้นเดียวกับ Process backend
  workspace ต้องไม่ทับ system mounts หรือ path ของ helper/plan
- จำกัด 1,024 grants ต่อ run; เกินเพดานเป็น DENY

bubblewrap บังคับ namespace isolation, drop capabilities, no-new-privileges,
ปิดการสร้าง user namespaces เพิ่ม และติด seccomp denylist เดิมก่อน exec helper
ตัวกรองนี้ยังเป็น **denylist** ไม่ใช่ syscall allowlist

ทุก run สร้าง private cgroup แล้วตั้งและตรวจ readback ของ:

| ค่า | enforcement |
|---|---|
| CPU | `cpu.max = cpu × 100000 / 100000` (quota รวม process tree) |
| RAM | `memory.max = memory_mb × 1048576` |
| Swap | `memory.swap.max = 0` |
| OOM | `memory.oom.group = 1` |
| PIDs | `pids.max` รวมทุก process/thread ใน cgroup |

child เข้า cgroup ใน pre_exec **ก่อน** launcher fork หรือรัน target
มี rlimit-AS/CPU/core เพิ่ม และ helper ตั้ง rlimit-FSIZE ตาม storage/output
budget เดิม ค่า storage ยังเป็นการจำกัดแบบ conservative ต่อไฟล์ ไม่ใช่
filesystem quota แบบ block accounting

เมื่อ target จบ, timeout หรือ monitor ล้ม ใช้ `cgroup.kill` ฆ่าทั้ง tree
รอ `populated 0` แล้วลบ cgroup ถ้า cleanup ไม่สำเร็จ run เป็น error
stdout/stderr drain พร้อมกันและเก็บสูงสุด 1 MiB ต่อ stream
bubblewrap status ต้องยืนยัน setup/exec สำเร็จ และ helper ต้องส่ง readiness
prefix หลังบังคับ Landlock/rlimit สำเร็จก่อนคืน applied mechanisms
prefix นี้ถูกตัดออกจาก stdout ก่อนส่งผลกลับ agent
helper สงวน exit code **125** สำหรับ setup failure; target ที่คืน 125
จะถูกจัดเป็น error เช่นกัน และ signal exit codes ใช้รูปแบบ 128 + signal
ตาม bubblewrap

CPU/RAM enforcement ชุดนี้ครอบคลุม container tool process tree เท่านั้น
inference ที่รันใน process ของ runtime ยังไม่อยู่ใน cgroup นี้ และยังไม่มี
GPU resource quotas หรือ MIG allocation

## การทดสอบ

`make verify` ครอบคลุม fail-closed routing/audit, config propagation,
helper Landlock read/execute restrictions และ Process regression tests
ไม่ต้องมี namespace delegation เพื่อทดสอบ helper

ชุดรัน container จริงต้องเปิดเองบน host ที่พร้อม:

```json
{
  "bubblewrap": "/usr/bin/bwrap",
  "init": "/usr/libexec/aivm-container-init",
  "cgroup_root": "/sys/fs/cgroup/aivm"
}
```

บันทึก JSON เป็น `/tmp/aivm-container-test.json` แล้วรัน:

```bash
AIVM_CONTAINER_TEST_CONFIG=/tmp/aivm-container-test.json make test-container
```

ชุดนี้ตรวจการอ่าน/เขียนตาม policy, denied files, symlink, host files,
GPU device absence, execute denial, network syscall denial, PIDs/RAM limits,
timeout และ cleanup โดยไม่ fallback หรือ skip เมื่อ host ไม่พร้อม
ต้องมี C compiler (`cc`) สำหรับสร้าง adversarial payload
