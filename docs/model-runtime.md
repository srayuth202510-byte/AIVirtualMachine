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
ขอบเขตที่กำหนด Network ถูกปิดโดยปริยาย การเข้าถึง GPU/device ต้องระบุใน deployment policy

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

## ขอบเขตความเชื่อถือ

การออกแบบ baseline เชื่อถือ host, kernel และ operator ตาม threat model ปัจจุบัน
TEE เป็น optional deployment tier สำหรับกรณีที่ต้องการลดความเชื่อถือใน host เพิ่มเติม
