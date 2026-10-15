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

worker ไม่มีสิทธิ์อ่าน secrets, audit writer, supervisor socket หรือ workspace ที่ไม่อยู่ใน
ขอบเขตที่กำหนด Network ถูกปิดด้วย seccomp filter สำหรับ socket/connect/send/receive
syscalls และ environment ถูกล้างก่อน spawn การเข้าถึง GPU/device ต้องระบุใน deployment policy

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
| `container` | bubblewrap, Landlock/seccomp, cgroup v2 CPU/RAM/PIDs, no network | bubblewrap + delegated cgroup | ปฏิเสธก่อน spawn |
| `microvm` | pinned kernel/rootfs/firecracker, guest channel, no network | `/dev/kvm` + Firecracker + image pins | ปฏิเสธก่อน boot |

การเลือก tier ต้องมาจาก operator configuration เท่านั้น worker หรือ model output
เปลี่ยน tier เองไม่ได้ Launcher ต้องรายงาน tier ที่ใช้จริงและ prerequisite ที่ขาด
ลง audit ทุกครั้ง

## ขอบเขตความเชื่อถือ

การออกแบบ baseline เชื่อถือ host, kernel และ operator ตาม threat model ปัจจุบัน
TEE เป็น optional deployment tier สำหรับกรณีที่ต้องการลดความเชื่อถือใน host เพิ่มเติม
