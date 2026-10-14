# Security hardening หลัง code review

การแก้ไขนี้ปิดทางข้าม capability/policy ผ่าน RAG, search และ subprocess พร้อมเพิ่ม regression tests และแก้ lifecycle ข้าม CLI

## ข้อมูลและ filesystem

- Runtime สร้าง RAG จาก gateway workspace เท่านั้น ไม่ใช้ root ที่ผู้เรียกส่งมา ทุกไฟล์ผ่าน read policy/capability ก่อนเข้าบริบทโมเดล
- Search ตรวจสิทธิ์รายไฟล์ ไม่อ่านไฟล์ที่ deny list ห้ามไว้
- Read/write เปิดผ่าน directory fd และ `O_NOFOLLOW` ทุกชั้น ปฏิเสธ special files และ hard links หลายชื่อ จำกัดข้อมูลต่อไฟล์ 1 MiB
- Process backend ต้องมี Landlock ABI >= 3 และติดตั้ง seccomp สำเร็จ มิฉะนั้นปฏิเสธการรัน ไม่มี fallback ไปใช้ process ที่ไม่จำกัด filesystem
- Subprocess อ่านได้เฉพาะไฟล์ workspace ที่ผ่าน policy และexecutable ที่ allowlist และไฟล์ libraries/loader ใน `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` รวม loader cache และอุปกรณ์ที่ระบุไว้ โปรแกรมเขียนได้เฉพาะไฟล์ workspace ที่มีอยู่แล้วและผ่าน write policy; สร้างไฟล์ใหม่ผ่าน filesystem gateway
- จำกัด memory, CPU affinity และ file size จาก resource config; gateway ตรวจผลรวมขนาด workspace ก่อนเขียน ส่วน process แบ่งงบเขียนระหว่างไฟล์ที่เขียนได้อย่าง conservative
- อ่าน stdout/stderr พร้อมกัน มี deadline และฆ่า process group เมื่อจบหรือหมดเวลา ปฏิเสธ `setsid`/`setpgid` หลังเริ่มงานเพื่อกันลูกแยกกลุ่มหนี cleanup
- Namespace เป็นชั้นเสริมและรายงานจากผล syscall จริง PID namespace ของ process backend รายงานว่าไม่ได้ใช้; งานที่ต้องการแยก PID/kernel ให้ใช้ MicroVM

ข้อจำกัด: process backend จึงไม่รองรับ build tool ที่ต้องสร้าง output files ใหม่ใน workspace โดยตรง การสร้างไฟล์ผ่าน gateway ยังคงทำงานได้

## Secrets

คำขอ `risk: low` ลดระดับเองไม่ได้ ต้องตรง `secrets.low_risk_allow` ที่ operator กำหนด เช่น:

```yaml
secrets:
  allow: ["credential:read"]
  low_risk_allow: ["credential:read"]
  hitl_required_for: ["high"]
```

หากไม่ตั้ง `low_risk_allow` ค่าเริ่มต้นของ resource เป็น High โปรแกรมที่ได้รับ secret ไม่มีสิทธิ์เขียน workspace และ stdout/stderr ทั้งหมดถูกปิดก่อนคืนให้ agent เพื่อกันการส่งค่าแบบเข้ารหัสกลับมา ต้องตรวจผลการทำงานผ่าน exit status/audit metadata แทน

## Audit และ state

- เขียน audit ไม่ได้ = action ไม่เริ่ม authorization และ outcome มี record แยกกัน
- Hash version 2 ครอบคลุมทุกฟิลด์หลักฐาน รวม result, rule, capability และ transition ใช้ serialization ที่ไม่กำกวม
- Audit รุ่นเก่ายังตรวจ chain และต่อ log ได้ แต่ฟิลด์หลักฐานที่ hash รุ่นเก่าไม่ครอบคลุมไม่ได้รับการป้องกันย้อนหลัง การแก้ไขนี้ไม่เพิ่มหลักประกันให้ข้อมูลประวัติรุ่นเก่า
- เปิด log ที่ chain เสียไม่ได้ และ rotation ปฏิเสธชื่อ archive ที่มีอยู่แล้ว
- State/leases ใช้ไฟล์ 0600 ตั้งแต่สร้าง เขียนไฟล์ชั่วคราวแล้ว atomic rename + fsync; consume โควต้า/lease ลงดิสก์ก่อน side effect เพื่อป้องกันใช้ซ้ำหลัง crash
- Supervisor ใช้ flock ป้องกันการ run/transition/approve พร้อมกัน สถานะเก็บบนดิสก์ และ pause/stop/kill ส่งสัญญาณผ่าน pidfd ไปยัง process จริง ตรวจ PID + start time ก่อนควบคุม

## Policy และเครือข่าย

- Predicate/pattern ที่ parse ไม่ได้ทำให้ policy ทั้งชุดถูกปฏิเสธ ไม่มี fallback glob เป็น substring
- Intent รับ JSON ทั้งข้อความ ตรวจ unknown/duplicate fields และปฏิเสธ prose/code fences
- Confidence ต้องเป็น finite number ในช่วง 0..1
- Network ใช้ action/scope เดียวกันใน grant และ gateway ตรวจ constraints ก่อน consume ครั้งเดียว
- Default network grants ใช้ HTTPS และ port ที่กำหนด ตรวจ IP หลัง DNS resolve และตรึง resolver ไม่เชื่อม private/loopback/mapped IPv6; ไม่ตาม redirect
- network.connect ทำ TLS handshake และตรวจ certificate ก่อนรายงาน tls-connected
- จำกัด timeout, response size และปฏิเสธ headers ที่เปลี่ยน host/framing ของ request

## การตรวจสอบ

`make ci` ครอบคลุม formatting, strict Clippy, default/adversarial tests, demo, CLI smoke และ MicroVM feature tests

Regression tests เพิ่มกรณี RAG อ่าน VM secrets, search ข้าม deny list, audit failure ก่อน write, แก้ฟิลด์หลักฐาน audit, secret risk downgrade, malformed deny rules, wildcard domain escape, private IP พร้อม port, NaN confidence, filesystem confinement, stderr flood, timeout, quota หลัง restart, lock และ pause/kill process จริง

การบูต MicroVM จริงยังต้องใช้ KVM และ `AIVM_MICROVM_PINS` การไม่มี prerequisites ทำให้ test บูตจริงข้าม ไม่ถือว่าได้ยืนยันการบูตแล้ว
