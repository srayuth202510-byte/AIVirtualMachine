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
- Namespace เป็นชั้นเสริมและรายงานจากผล syscall จริง: user/mount/network namespace ใช้งานได้ PID namespace **ไม่ได้ใช้ใน process backend** (by design) เพราะทำให้ compiler/test runner ที่ spawn subprocess ทำงานผิดปกติ — งานที่ต้องการแยก PID/kernel ให้ใช้ MicroVM แทน (ดู `crates/aivm-sandbox/src/lib.rs` ความคิดเห็นใน `run_checked`)

เปิด bounded output slots ได้ด้วย `build.enabled` โดย operator: gateway เตรียมไฟล์ใน `.aivm-build` และให้ compiler เขียนเฉพาะ slots ที่ประกาศ จำกัดจำนวนไฟล์และขนาดรายไฟล์ ไม่ได้ให้ child สร้างไฟล์ทั่วไป ดู [build-workflow.md](build-workflow.md) สำหรับรูปแบบ intent และข้อจำกัดของ build tools ที่ใช้ temporary files แบบสุ่ม

## Secrets

MicroVM และ Hardware backend ยังไม่ส่ง environment เข้า guest คำขอ exec
ที่แนบ secret lease จึงถูกปฏิเสธก่อน consume/checkpoint เพื่อรักษา one-time lease
ไว้ใช้กับ backend ที่รองรับ

คำขอ `risk: low` ลดระดับเองไม่ได้ ต้องตรง `secrets.low_risk_allow` ที่ operator กำหนด เช่น:

```yaml
secrets:
  allow: ["credential:read"]
  low_risk_allow: ["credential:read"]
  hitl_required_for: ["high"]
```

หากไม่ตั้ง `low_risk_allow` ค่าเริ่มต้นของ resource เป็น High โปรแกรมที่ได้รับ secret จะได้รับผ่าน environment variable (inject ผ่าน `env_extra` ใน `ExecSpec`) และค่า secret จะถูก zeroize ทันทีหลัง spawn เสร็จ ผลลัพธ์ที่คืนให้ agent จะเป็น `[REDACTED]` แทน stdout/stderr จริง เพื่อป้องกันการส่งค่า secret กลับมา ต้องตรวจผลการทำงานผ่าน exit status/audit metadata แทน (ดู `crates/aivm-tools/src/lib.rs` ฟังก์ชัน `exec_inner`)

Secret leases ที่คืนหลัง restart ต้องมี capability ที่ยังครอบคลุม resource/scope
และค่า secret เดิมใน `secrets.yaml` ปัจจุบัน การลบหรือหมุนค่า secret ทำให้ lease เดิม
ใช้ไม่ได้ การลด `max_ttl_seconds` หรือ `max_uses_allowed` ปฏิเสธ lease ที่ขัดกับ
เพดานใหม่ และ `secrets.allow: []` ปฏิเสธทั้งหมด ต้องขอ lease ใหม่ตาม policy ปัจจุบัน
การคืน lease ที่ยังผ่านเกณฑ์คงจำนวนครั้งที่ใช้และวันหมดอายุเดิมไว้

Gateway ตรวจ capability ซ้ำก่อน inject โดยไม่หักโควต้าการออก lease อีกรอบ
การเพิกถอน capability จึงหยุดการใช้ lease เดิม ขณะที่การออก lease จนโควต้าหมด
ยังใช้ lease ที่ออกแล้วได้ตามจำนวนครั้งของ lease นั้น Broker ที่ใช้อยู่จะ revoke
lease ของ resource ทันทีเมื่อเรียก `remove_secret` หรือเปลี่ยนค่าผ่าน `register_secret`
การแก้ไฟล์ config/secret มีผลต่อ Runtime ที่โหลดใหม่

Container backend บังคับ namespaces + Landlock/seccomp + cgroups v2 CPU/RAM/PIDs
ไม่มี fallback เมื่อ setup ไม่ครบ ใช้ mounts จาก pinned descriptors และฆ่าทั้ง tree
ผ่าน `cgroup.kill` ดูข้อกำหนดและข้อจำกัดใน [`container.md`](./container.md)

## Audit และ state

- State เดิมที่ parse ไม่ได้หรืออ่านไม่ได้ทำให้ Runtime ไม่บูต ไม่มีการคืน
  initial capabilities เพื่อกลบข้อผิดพลาดและทำให้ quota ที่หมดแล้วกลับมาใช้ได้
- Supervisor จอง directory ด้วย atomic create และเผยแพร่ config หลัง init/persist
  สำเร็จ เมื่อ create ผิดพลาดจะ cleanup เฉพาะ directory ที่ตัวเองจองสำเร็จ

- เขียน audit ไม่ได้ = action ไม่เริ่ม authorization และ outcome มี record แยกกัน
- Hash version 2 ครอบคลุมทุกฟิลด์หลักฐาน รวม result, rule, capability และ transition ใช้ serialization ที่ไม่กำกวม
- Audit รุ่นเก่ายังตรวจ chain และต่อ log ได้ แต่ฟิลด์หลักฐานที่ hash รุ่นเก่าไม่ครอบคลุมไม่ได้รับการป้องกันย้อนหลัง การแก้ไขนี้ไม่เพิ่มหลักประกันให้ข้อมูลประวัติรุ่นเก่า
- เปิด log ที่ chain เสียไม่ได้ และ rotation ปฏิเสธชื่อ archive ที่มีอยู่แล้ว
- State/leases ใช้ไฟล์ 0600 ตั้งแต่สร้าง เขียนไฟล์ชั่วคราวแล้ว atomic rename + fsync; consume โควต้า/lease ลงดิสก์ก่อน side effect เพื่อป้องกันใช้ซ้ำหลัง crash
- Supervisor ใช้ flock ป้องกันการ run/transition/approve พร้อมกัน สถานะเก็บบนดิสก์ และ pause/stop/kill ส่งสัญญาณผ่าน pidfd ไปยัง process จริง ตรวจ PID + start time ก่อนควบคุม

## Policy และเครือข่าย (เพิ่มเติมหลังรอบ review)

- `process.allow` ต้องเป็น absolute path ที่ชัดเจน ห้ามมี wildcard glob เพื่อป้องกัน interpreter ที่ถูกคัดลอก/เปลี่ยนชื่อ หลุด semantic ban (F-4)
- Capability scope ของ filesystem ที่เป็น root/empty/wildcard (`/`, `*`) จะถูกปฏิเสธก่อน grant (F-9) ลดข้ามขอบเขตแฝง
- `network_pattern` ให้ hostname allow ใช้ได้เฉพาะ default port (443) เว้นแต่จะระบุ port ชัดเจน (`github.com:8443`) (F-8)

## Policy และเครือข่าย

- Predicate/pattern ที่ parse ไม่ได้ทำให้ policy ทั้งชุดถูกปฏิเสธ ไม่มี fallback glob เป็น substring
- Intent รับ JSON ทั้งข้อความ ตรวจ unknown/duplicate fields และปฏิเสธ prose/code fences
- Confidence ต้องเป็น finite number ในช่วง 0..1
- Network ใช้ action/scope เดียวกันใน grant และ gateway ตรวจ constraints ก่อน consume ครั้งเดียว
- Default network grants ใช้ HTTPS และ port ที่กำหนด ตรวจ IP หลัง DNS resolve และตรึง resolver ไม่เชื่อม private/loopback/mapped IPv6; ไม่ตาม redirect
- network.connect ทำ TLS handshake และตรวจ certificate ก่อนรายงาน tls-connected
- จำกัด timeout, response size และปฏิเสธ headers ที่เปลี่ยน host/framing ของ request

## By-design items (documented for auditors)

### F-5: Process level ไม่มี PID namespace (by design)
Process sandbox ไม่บังคับ `CLONE_NEWPID` เพื่อให้ compiler/test runner (cargo, gcc, pytest ฯลฯ) ที่ spawn subprocess ทำงานได้ปกติ
- กลไกควบคุมแทน: `pdeathsig=SIGKILL`, `RLIMIT_NPROC`, `setpgid` cleanup, Landlock/seccomp
- สำหรับ untrusted autonomous agents ต้องใช้ `isolation: container` หรือ `microvm` (มี PID namespace จริง)
- `SandboxProbe` รายงาน `pid_namespace: false` อย่างโปร่งใส (`degraded` ใน `ExecOutcome`)

### F-7: Audit row แรกยอมรับ `hash_prev` ใดก็ได้
- ออกแบบเพื่อรองรับ genesis file และ rotation boundary (archive → live file)
- `verify_sequence` ตรวจ boundary ข้ามไฟล์: `hash_prev` ของ record แรกในไฟล์ใหม่ ต้องตรงกับ tip ของไฟล์เก่า
- Single-file tamper ของ row แรกถูกจับด้วย `verify_sequence` เมื่อมีหลายไฟล์; single-file only case ไม่มี threat model rotation

### F-8: Network allow hostname default port 443
- `network_pattern` ให้ scope แบบ hostname (ไม่มี port) match เฉพาะ target ที่ลงท้าย `:443`
- ต้องการ port อื่น ต้องระบุชัดใน allowlist: `github.com:8443`
- นโยบายนี้เป็น defense-in-depth: default HTTPS เท่านั้น ลดโอกาสโจมตีผ่าน HTTP plaintext


## การตรวจสอบ

`make ci` ครอบคลุม formatting, strict Clippy, default/adversarial tests, demo, CLI smoke และ MicroVM feature tests

Regression tests เพิ่มกรณี RAG อ่าน VM secrets, search ข้าม deny list, audit failure ก่อน write, แก้ฟิลด์หลักฐาน audit, secret risk downgrade, malformed deny rules, wildcard domain escape, private IP พร้อม port, NaN confidence, filesystem confinement, stderr flood, timeout, quota หลัง restart, lock และ pause/kill process จริง

การบูต MicroVM จริงยังต้องใช้ KVM และ `AIVM_MICROVM_PINS` การไม่มี prerequisites ทำให้ test บูตจริงข้าม ไม่ถือว่าได้ยืนยันการบูตแล้ว
