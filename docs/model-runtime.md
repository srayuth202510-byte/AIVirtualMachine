# Model Runtime — Worker Boundary

## เป้าหมาย

AIVM ให้ความสำคัญกับการรัน open-weight models เป็นแกนหลัก ส่วน agent loop และ tools
เป็นชั้นเสริม โมเดลต้องทำงานใน worker ที่มีอายุและสิทธิ์แยกจาก control plane

## ขอบเขตของ worker

```text
client → control plane → verifier/policy/quota → inference worker → response/audit
```

Control plane รับผิดชอบ model registry, manifest verification, policy, lifecycle และ audit
Worker รับผิดชอบการโหลด backend, tokenize, generate และรายงาน usage

Process worker ยังใช้ filesystem และ UID ของ operator จึงควรใช้กับ development บน host ที่เชื่อถือได้
Container worker mount เฉพาะไฟล์ที่อนุญาต ส่วน MicroVM รับไฟล์ผ่าน read-only data drive
Network ถูกปิดด้วย worker seccomp รวม x32 และ io_uring; environment ถูกล้างก่อน spawn
GPU/device passthrough ยังไม่รองรับใน launcher สองระดับนี้

## Worker protocol

ทุกคำขอต้องมี:

- `request_id`
- `model_id` หรือ artifact identity
- prompt/messages ที่มีขนาดจำกัด
- generation options ที่ผ่าน allowlist
- deadline และ output limit จาก control plane

ทุกคำตอบต้องมี:

- `request_id`
- output หรือ typed error
- input/output token usage
- elapsed time และ termination reason
- applied limits และ sandbox level
- artifact verification status
- `audit_id`

ข้อความจากโมเดลเป็นข้อมูลผลลัพธ์ ไม่ใช่คำสั่งให้เปลี่ยน policy หรือเพิ่ม capability

## ลำดับ implementation

1. กำหนด request/response schema และ typed errors
2. ทำ worker process สำหรับ backend llama.cpp
3. ใช้ IPC ที่มีการปิดท้ายข้อความและจำกัดขนาด buffer
4. บังคับ resource, timeout และ network boundary ที่ worker
5. เพิ่ม container และ MicroVM launcher ตาม deployment tier
6. เพิ่ม streaming, batching และ backend adapters หลัง boundary ผ่านการทดสอบ

ปัจจุบัน `model.local.worker_path` เปิดใช้ worker-backed model ให้กับ runtime
และคำสั่ง `aivm reason` แล้ว โดยยังต้องเลือก executable ที่ผ่านการติดตั้งและตรวจสอบ
โดย operator เอง

สำหรับการทดสอบ GGUF จริง ใช้ `AIVM_MODEL_WORKER=/absolute/path/aivm-model-worker`
ร่วมกับ `scripts/llama-smoke.sh`; หากไม่ตั้งค่าจะทดสอบ inline backend ตามเดิม

## Launcher contract

ทุก isolation tier ต้องเปิด worker ด้วย executable เดียวกันและส่ง config ผ่าน
ไฟล์ชั่วคราวที่มี permission `0600`:

| tier | กลไกที่ต้องบังคับ | prerequisite | พฤติกรรมเมื่อไม่พร้อม |
|---|---|---|---|
| `process` | no-new-privs, parent-death kill, rlimit, worker seccomp | Linux seccomp | ใช้งานได้ตาม process limits |
| `process_namespace` | user/network namespace + process hardening | unprivileged user namespace | ปฏิเสธก่อน exec |
| `container` | bubblewrap, Landlock/seccomp, cgroup v2 CPU/RAM/PIDs, no network | bubblewrap + delegated cgroup | ปฏิเสธก่อน spawn |
| `microvm` | pinned kernel/rootfs/firecracker, guest channel, no network | `/dev/kvm` + Firecracker + image pins | ปฏิเสธก่อน boot |

การเลือก tier ต้องมาจาก operator configuration เท่านั้น worker หรือ model output
เปลี่ยน tier เองไม่ได้ Launcher ต้องรายงาน tier ที่ใช้จริงและ prerequisite ที่ขาด
ลง audit ทุกครั้ง

## ขอบเขตความเชื่อถือ

การออกแบบ baseline เชื่อถือ host, kernel และ operator ตาม threat model ปัจจุบัน
TEE เป็น optional deployment tier สำหรับกรณีที่ต้องการลดความเชื่อถือใน host เพิ่มเติม

## เลือก launcher ที่ใช้งานจริง

กำหนด `model.local.worker_launcher` แยกจาก `runtime.isolation` ของ agent tools:

```yaml
model:
  provider: local
  name: qwen
  local:
    model_path: /models/model.gguf
    worker_path: /opt/aivm/aivm-model-worker
    worker_launcher:
      tier: container
      config:
        bubblewrap: /usr/bin/bwrap
        init: /usr/libexec/aivm-container-init
        cgroup_root: /sys/fs/cgroup/aivm
```

`{tier: process}` เป็นค่า default; `{tier: process_namespace}` บังคับ empty network namespace
หากต้องการ `tier: microvm` ให้ build CLI ด้วย `--features microvm` และกำหนด `config`
ตาม `MicroVmConfig` ใน [microvm.md](microvm.md) โดยต้องมี `fc_sha256` ด้วย
เมื่อไม่เปิด feature การ parse tier นี้จะล้มเหลว ไม่มี fallback

Container copy model/dependencies เข้า private staging directory ก่อน mount แบบอ่านอย่างเดียว
MicroVM stage เฉพาะ file grants ไม่ copy directory จาก host ทั้งก้อน และตรวจ storage quota
ข้อมูล config/request อยู่ใน directory `0700` และไฟล์ `0600`; ล้างเมื่อ request จบ

## ผูก model pin กับไฟล์ที่โหลดจริง

GGUF loader บน Linux เปิด source ด้วย `O_NOFOLLOW | O_NONBLOCK` และรับเฉพาะ regular file
ไม่เกิน 64 GiB สำหรับ source บน writable mount จะสร้างไฟล์ใน private directory `0700`
แล้ว unlink ก่อน copy แบบจำกัดขนาด เพื่อไม่ทิ้งสำเนาขนาดใหญ่เมื่อ process ถูก kill ระหว่าง copy
จากนั้นเปลี่ยนสำเนาเป็น `0400` และเปิด descriptor แบบ read-only ก่อนตรวจ hash
loader เปิด `/proc/self/fd/<fd>` ของสำเนาที่ตรวจแล้วและเก็บ descriptor จน model ถูกทำลาย
การแทน source pathname, สลับ symlink หรือเขียน source inode เดิมหลังตรวจจึงไม่เปลี่ยน bytes
ที่ loader/mmap ใช้ หาก source เปลี่ยนระหว่าง copy จะยอมรับเฉพาะสำเนาที่ hash ตรง pin เท่านั้น

Container/MicroVM ใช้สำเนาที่ launcher stage ไว้บน read-only mount โดยไม่ copy เพิ่ม
เส้นนี้ต้องเป็นไฟล์ link เดียว, owner เป็น root หรือ UID ปัจจุบัน และไม่มี group/world write
ระบบตรวจ mount และ metadata ผ่าน descriptor จริง ไม่ใช้ชื่อ tier ใน config เป็นหลักฐาน
จากนั้น hash และ load ผ่าน descriptor เดียวกัน ตาม threat model ยังเชื่อถือ host/kernel/operator
รวมถึง host ที่เป็นเจ้าของ backing storage ของ read-only mount

Writable source ต้องมี temporary storage เพิ่มเท่าขนาด GGUF และมีค่า copy/hash ก่อนโหลด
ตำแหน่งมาจาก temporary directory ของ process (`TMPDIR` สำหรับ inline); ถ้าเป็น tmpfs
พื้นที่นี้ใช้ RAM/swap และนับตามข้อจำกัดของ host/worker ด้วย ต้องเตรียม quota ให้พอ
หาก copy, cleanup, hash หรือ `/proc/self/fd` ใช้ไม่ได้จะคืน error โดยไม่มี fallback ไป source
Process worker อาจมีทั้งสำเนาจาก launcher และสำเนาของ loader พร้อมกันระหว่างโหลด
เส้นนี้รองรับ single-file GGUF; ไม่อนุญาตให้ค้น split/shard เพิ่มจาก source directory
โดยไม่ผ่าน verification

## Streaming, cancellation และ verification

`aivm reason --config model.yaml --prompt 'Hello' --stream` ส่ง delta จาก worker
Process ใช้ stdout pipe, container ใช้ stdout observer และ MicroVM ใช้ JSONL ภายใน serial markers
Client ตรวจ request ID/version ทุก frame และตรวจ streamed output ให้ตรงกับ final output
Delta ที่แสดงก่อน final response ยังไม่มีผลยืนยันความสำเร็จของ inference

Rust API ใช้ `WorkerClient::infer_stream` พร้อม callback และ
`WorkerClient::cancellation_token()` เพื่อ clone `Arc<AtomicBool>` ไปยัง thread ควบคุม
ตั้ง token เป็น `true` เพื่อยกเลิก client นั้น; เริ่มงานใหม่ด้วย client ใหม่
Callback ที่คืน error จะหยุดงานและ cleanup เช่นกัน
Process ฆ่าทั้ง process group, container ใช้ `cgroup.kill`, MicroVM ยุติ VMM
การยกเลิกระหว่าง staging/hash/setup จะถูกรับเมื่อจบขั้นตอนปัจจุบัน; ไม่มี hard deadline
ครอบ syscall สำหรับ copy/hash/host-tool setup ทั้งหมดในรุ่นนี้

Response ถูกตรวจ identity, termination, output budget, frame bytes และ exit status
Client คำนวณ SHA-256 ของ output และคืน `verification` ที่เขียนทับค่าจาก worker เสมอ
`verified` หมายถึง protocol/execution evidence ผ่านและมี model/worker pins;
หากไม่มี pins จะเป็น `unverified` ส่วน response ผิดเงื่อนไขคืน typed error
สถานะนี้ไม่ใช่การพิสูจน์ความถูกต้องเชิงเนื้อหาของคำตอบโมเดล

## การยืนยันบน host

CI ตรวจ process streaming/cancellation, forged responses, deadline, network syscalls
และ fail-closed ของ container/MicroVM ที่ prerequisite ไม่ครบ
การทดสอบ host จริงเรียกแยกด้วย config JSON (`ModelConfig`) ที่ operator เตรียมและ pin แล้ว:

```bash
AIVM_WORKER_HOST_CONFIG=/path/to/model-config.json \
  cargo test -p aivm-model-worker --features llama,microvm \
  --test worker real_isolated_worker_host_validation -- --exact --ignored --nocapture
```

ทดสอบสองครั้งโดยสลับ `worker_launcher` เป็น container และ microvm
คำสั่งนี้ fail เมื่อ config/prerequisite ขาด; ไม่ skip หรืออ้างว่า host validation ผ่าน

ผลทดสอบ pinned GGUF จริงผ่าน process namespace, Container และ MicroVM
รวม streaming และ cancellation อยู่ใน [รายงาน host validation วันที่ 16 ตุลาคม 2026](host-validation-2026-10-16.md)
