# เป้าหมาย: รัน Open-weight Models อย่างปลอดภัย

เป้าหมายของ AIVM คือเป็น model runtime สำหรับให้ผู้ดูแลนำ open-weight models มารัน
อย่างปลอดภัย โดยมี worker ที่แยกจาก control plane ขอบเขตสิทธิ์ที่ตรวจสอบได้ และไม่ให้ความน่าเชื่อถือ
ของโมเดลกลายเป็นสิทธิ์เข้าถึง host โดยปริยาย ระบบนี้เชื่อถือ host, kernel และ
operator; การป้องกันหลักคือการแยก model/agent ออกจาก host ด้วย process,
container หรือ MicroVM

TEE และ confidential computing เป็นความสามารถเสริมสำหรับ deployment ที่ต้อง
ป้องกัน host/operator หรือพิสูจน์สถานะการรัน ไม่ใช่เงื่อนไขของ runtime หลัก

## หลักการ

- โมเดลและไฟล์ประกอบเป็น input ที่ไม่เชื่อถือ จนกว่าจะตรวจ artifact ตามค่าที่ operator อนุมัติ
- inference ได้สิทธิ์น้อยที่สุด จำกัดทรัพยากร และปิด network โดยปริยาย
- ทุก action ภายนอก inference ผ่าน capability, policy และ gateway ที่บังคับใช้จริง
- คำตอบของโมเดลเป็นข้อเสนอ ไม่ใช่หลักฐานว่างานสำเร็จ ต้องตรวจผลกับ state หรือ artifact จริง
- ข้อผิดพลาด ความไม่แน่นอน และการตรวจสอบที่ทำไม่ได้ต้องหยุดการทำงานหรือรายงานสถานะที่ไม่ยืนยันผล

## ขอบเขตงาน

### 1. Model artifacts และ provenance

- ตรวจ SHA-256 ของ weights ก่อนโหลด และผูก hash กับ config ที่รัน
- ขยายจาก hash ของไฟล์เดียวไปสู่ manifest ที่ครอบคลุม tokenizer, config,
  adapter/quantization และ runtime ที่เกี่ยวข้อง
- บันทึกแหล่งที่มา, license, format, ขนาด และผลตรวจในสถานะโมเดลที่ operator ตรวจดูได้
- เพิ่มโหมด production ที่ปฏิเสธโมเดล unpinned; โหมดทดลองอาจอนุญาตพร้อมคำเตือนที่มองเห็นชัด

### 1a. Model worker เป็น boundary หลัก

- control plane ไม่โหลด model โดยตรงใน process เดียวกับ supervisor
- request/response ผ่าน worker protocol ที่มี schema, request id และ quota ชัดเจน
- backend แรกคือ llama.cpp; backend อื่นต้องผ่าน adapter contract เดียวกัน
- worker ส่ง usage, applied limits และ verification status กลับมาพร้อมผลลัพธ์

### 2. แยก inference และจำกัดทรัพยากร

- รัน model loader และ inference ด้วยสิทธิ์ขั้นต่ำ แยกจาก supervisor และ secret broker
- กำหนดเพดาน CPU, RAM/VRAM, เวลา, context และ output; เมื่อเกินเพดานให้ยุติอย่างตรวจสอบได้
- ปิด network สำหรับ inference โดยปริยาย และแยกการดาวน์โหลด artifact ออกจากการรันโมเดล
- ตรวจว่าการตั้งค่า GPU/backend ไม่เปิดทางเข้าถึง host หรืออุปกรณ์เกินที่ตั้งใจ

### 3. ขอบเขต agent และข้อมูล

- คงเส้นทาง intent → capability/policy → gateway → sandbox สำหรับทุก tool
- จำกัดไฟล์และข้อมูลที่เข้าสู่ context ตาม workspace/policy และบันทึกแหล่งที่มาของข้อมูล
- ปฏิบัติต่อ prompt injection ในไฟล์, RAG และ tool output เป็นข้อมูลที่ไม่เชื่อถือ
- แยกการอ่านข้อความของโมเดลออกจากการอนุมัติสิทธิ์หรือ transition ซึ่งเป็นอำนาจ operator

### 4. Audit, monitoring และการตรวจผล

- บันทึก model/artifact/config identifiers, resource usage, tool decisions และผลการตรวจ โดยไม่บันทึก secrets
- ตรวจ output ที่อ้างว่าสำเร็จเทียบกับ filesystem, exit status, test result หรือ artifact ที่คาดหวัง
- ให้ agent รายงาน `verified`, `failed` หรือ `unverified` พร้อมหลักฐานอ้างอิง แทนการเชื่อข้อความสรุปอย่างเดียว
- วัด false positives, missed detections, resource exhaustion และความถูกต้องของงานด้วยชุด evaluation ที่ทำซ้ำได้

## ลำดับความสำคัญ

1. **Inference worker:** แยก model loader/inference ออกจาก control plane พร้อม protocol และ lifecycle
2. **Artifact pinning:** production mode ต้องมี `model_sha256`; เพิ่มคำสั่งตรวจและแสดงสถานะโมเดลที่อนุมัติ
3. **Inference isolation:** กำหนด resource/network boundary ที่ทดสอบได้
4. **Evidence-backed completion:** กำหนดรูปแบบผลลัพธ์และ verifier สำหรับงานที่ agent รายงานว่าสำเร็จ
5. **Operational evaluation:** เพิ่ม replay/evaluation สำหรับ prompt injection, artifact tampering,
   resource exhaustion และความไม่ตรงกันระหว่าง summary กับผลจริง
6. **Artifact manifest:** ขยายการตรวจจาก weights เดี่ยวไปยัง dependencies และ provenance ที่เกี่ยวข้อง

## เกณฑ์ความสำเร็จ

- โมเดลที่ hash ไม่ตรงหรือไม่มี pin ใน production mode โหลดไม่ได้
- inference ที่พยายามใช้ network หรือเกิน resource limits ถูกปฏิเสธ/ยุติ พร้อม audit ที่ตรวจสอบได้
- prompt injection หรือข้อความใน output ไม่สามารถข้าม gateway, policy หรือ operator guard
- agent จะรายงานว่างานผ่านได้ต่อเมื่อ verifier ที่กำหนดตรวจพบหลักฐานตรงกัน มิฉะนั้นรายงาน `unverified` หรือ `failed`
- การทดสอบแยกผลของ unit/plumbing ออกจากการทดสอบบน host จริง และไม่อ้างว่า Generic VM คือ TEE/attestation

## ขอบเขตความเชื่อถือและข้อจำกัด

- Host, kernel และ operator เป็น trust root หากถูกยึด ระบบนี้ไม่รับประกันความลับหรือความถูกต้องของงาน
- Process/container/MicroVM ป้องกัน model และ agent จาก host resources ตามระดับที่เลือก
- TEE เป็น optional Tier เพิ่มเติม ไม่ใช่ baseline และ generic QEMU ไม่ใช่หลักฐานของ TEE หรือ attestation

Hardware/TEE ยังเป็น experimental และ generic QEMU ไม่ได้ยืนยัน confidential computing;
host/operator compromise อยู่นอก threat model; และความถูกต้องของคำตอบโมเดลต้องวัดตามงาน
ไม่อนุมานจากการที่ inference หรือ tool call ทำงานสำเร็จ ดูผลตรวจเดิมใน
[system review](system-review-2026-10-15.md) และ [host validation](host-validation-2026-10-15.md)
