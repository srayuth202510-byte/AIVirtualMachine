# สคริปต์ช่วย Qwen อ่านไฟล์พร้อมตรวจคำตอบ

`qwen-read.py` ช่วยกับปัญหาที่พบจากโมเดลจริง: tool อ่านข้อมูลถูกต้อง
แต่โมเดลแต่ง summary ขึ้นเอง สคริปต์แบ่งงานให้เล็ก ตรวจผล และให้ feedback
เพื่อลองใหม่ โดยไม่เพิ่มสิทธิ์ให้ agent

```bash
python3 scripts/qwen-read.py \
  /home/lokis/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  examples/qwen-evidence.txt
```

ใช้ไฟล์ UTF-8 ขนาด 1..2048 ไบต์ สคริปต์ build CLI ด้วย feature `llama`
แล้วสร้าง VM ชั่วคราวที่มีเฉพาะ read capability และสำเนาไฟล์ `src/evidence.txt`
ต้นฉบับไม่ถูกแก้ โมเดลรันในเครื่อง ไม่ส่งไฟล์ไป cloud

ขั้นตอน:

1. ให้โมเดลอ่านไฟล์ด้วย `filesystem.read` แล้วคืนเนื้อหาใน summary
2. อ่านผลแบบ JSON จาก `aivm agent --json`
3. ตรวจว่ามี tool read สำเร็จจริง, agent จบงาน และ summary ตรงกับ snapshot
   ของไฟล์ทั้งหมด โดยไม่นับ CR/LF ท้ายไฟล์
4. ถ้าไม่ผ่าน บอกเหตุผลและแนบข้อความอ้างอิงจาก snapshot ให้โมเดลแก้คำตอบ
   พร้อมกำหนดให้ต้อง read ใหม่ ลองได้สูงสุด 3 ครั้ง (`--attempts 1..5`)

การ retry มีการให้ reference โดยตรง จึงเป็นการช่วยโมเดลคัดลอกหลักฐาน
ไม่ใช่การวัดความสามารถอ่านจับใจความแบบอิสระของโมเดล

ผลออกเป็น JSON พร้อม hash ของไฟล์และประวัติแต่ละครั้ง:

- exit 0: `verified: true`, มี `answer` ที่ตรวจตรงกับไฟล์แล้ว
- exit 1: ลองครบแล้วแต่ยังตรวจไม่ผ่าน ไม่มีการเปลี่ยนคำตอบผิดให้ดูเหมือนผ่าน
- exit 2: input/config/build/runtime error

ตัวตรวจนี้ยืนยัน **การคัดลอกเนื้อหา** เท่านั้น งานสรุปอิสระ เขียนโค้ด หรือ
วิเคราะห์ข้อมูลต้องเพิ่มตัวตรวจที่ตรงกับงาน เช่น compiler/test suite หรือ
ข้อเท็จจริงที่อ้างหลักฐานตรวจกลับได้ การที่โมเดลบอก `done` อย่างเดียวไม่เพียงพอ

## ผลบนโมเดลจริง

ทดสอบ Qwen2.5 Coder 1.5B Q4_K_M ด้วยไฟล์ที่มี
`LOCAL_MODEL_TOOL_PROOF_20261015`:

- ครั้งที่ 1 อ่านไฟล์สำเร็จ แต่ summary มี prefix ของ tool ปนอยู่ ตัวตรวจปฏิเสธ
- ครั้งที่ 2 หลัง feedback มี read สำเร็จและคืนข้อความตรงกับไฟล์ ตัวตรวจยอมรับ
- ผล `verified: true` โดยยังใช้ read capability เท่าเดิม

หลักฐานในเครื่อง: `target/host-validation/logs/aivm-qwen-assisted.json`

ทดสอบตัวตรวจโดยไม่โหลดโมเดล:

```bash
python3 -m unittest discover -s scripts -p 'test_qwen_read.py'
```

## TEE ยังต้องเตรียมแยก

สคริปต์ช่วย Qwen ไม่ได้สร้าง TEE จากซอฟต์แวร์ เครื่องนี้มี KVM แต่ตรวจพบ
`kvm_amd.sev=N`, `kvm_amd.sev_snp=N` และไม่มี `/dev/sev`
จึงยังยืนยัน SEV-SNP จากการทดสอบบน host นี้ไม่ได้

นอกจาก host ที่รองรับแล้ว backend ปัจจุบันยังไม่ได้ตรวจ attestation quote
กับ endorsement keys/KDS การมีเครื่องมือ attestation อยู่ใน PATH หรือบูต QEMU
Generic สำเร็จยังไม่ใช่การตรวจ TEE จริง ดู [hardware.md](hardware.md)
