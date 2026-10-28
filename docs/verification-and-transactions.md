# Verifier contracts และ state/audit transactions

ผลสุดท้ายของ agent และ semantic ใช้ `outcome` โครงสร้างเดียวกัน แยก execution,
verification, solution origin และ tested/current workspace digest ฟิลด์สถานะเดิมเป็น mirrors
ดู [Repair milestone และ release gate](repair-milestone.md)

`inspect`, `state` และ `capabilities` ถือ exclusive VM lease ก่อนเปิด runtime
เพราะการเปิดอาจกู้ transaction และเขียน state/audit หากมี operation ทำงานอยู่
คำสั่งจะคืน `VM already has an active operation` ให้เรียกใหม่หลัง operation จบ
แทนการกู้ transaction ซ้อนกับ writer ที่ยังทำงานอยู่ รายการ capabilities แสดง
grants, state usability, scopes, expiry, quotas และ policy จริง ส่วน process count
แสดง `not measured` เพราะไม่ได้วัดจาก runtime snapshot นี้

## ยืนยันผลด้วยสัญญาของ operator

Agent ไม่อนุมานว่า tests ผ่านจากชื่อ test runner, `build:tests`, arguments
หรือข้อความ `exit status: 0` ต้องตั้ง `verification` ใน `aivm.yaml` เช่น:

```yaml
build:
  enabled: true
tools:
  allow: [cc, as, ld, "build:tests"]
verification:
  executable: "build:tests"
  argv: []
  # executable_sha256: "<approved SHA-256>"  # pin artifact เพิ่มได้
  # stdout_contains: "2 tests passed"       # สัญญา stdout เพิ่มเติม
```

`executable` และ `argv` ต้องตรงกับคำขอทุกตัว ไม่มี wildcard หรือ shell
external executable ต้องเป็น absolute path และมี `executable_sha256` 64 hex
build artifact ระบุชื่อชัดเจนและบันทึก digest ของ binary ที่สร้างจริง
การตั้ง verifier ไม่ให้ capability ไม่เพิ่ม allowlist และไม่ข้าม sandbox/state/policy
คำขอที่แนบ secret หรือประกาศ build outputs ไม่เป็น verifier invocation

Gateway ออก `VerificationRecord` หลังรันจริง ตรวจ exit code จาก structured
sandbox outcome ว่าเป็น 0 และตรวจ stdout ตาม contract ถ้ากำหนด
ไม่มีฟิลด์ intent ให้โมเดลส่งผล verification เอง
Receipt ผูกกับ SHA-256 ของ contract, executable และ workspace ก่อนรัน
ตรวจ executable/workspace ซ้ำหลังรัน และอ้าง audit entry hash
workspace digest รวมชื่อและเนื้อหาของ regular files ทุกใบยกเว้น `.aivm-build`
ซึ่ง executable ที่รันถูก hash แยก จำกัด 4,096 entries, source 64 MiB และ
executable 256 MiB; symlink, hard link, special file, read error หรือเกินขอบเขตไม่ผ่าน

`aivm agent --json` คืน `verification_status`: `verified`, `failed`, `unverified`
พร้อม `verification` receipt ถ้ามี CLI แบบข้อความแสดงสถานะด้วย
summary ของโมเดลเป็นข้อความที่ไม่เชื่อถือ ไม่ตั้ง contract = `unverified`
แม้คำสั่ง exit 0 Agent ไม่ตั้ง operator guard `tests_passed` หรือ transition เอง

`verified` หมายถึง invocation ผ่านสัญญากับ inputs ที่บันทึกไว้ คุณภาพและ coverage
ของ tests ยังขึ้นกับ operator โดยเฉพาะ dynamic artifact ที่ agent แก้ source ได้
pin ของ external executable ไม่ pin dependencies นอก workspace ทั้งหมด
Host/kernel/operator และเครื่องมือที่ติดตั้งยังเป็น trust root

## ธุรกรรม state และ audit

`transition_to` และ `approve_secret_lease` ใช้ `.state-transaction.json`
นอก workspace เป็น write-ahead journal มี before/after state และ UUID เฉพาะธุรกรรม
journal มี secret leases จึงสร้าง `0600` ตั้งแต่เปิด เช่นเดียวกับ state
ห้ามเผยแพร่ journal หรือ staging files เป็นหลักฐานสาธารณะ

1. เขียน/fsync journal แล้ว rename และ fsync parent directory
2. append/fsync `transition-prepare` หรือ `secret-approve-prepare`
3. เขียน/fsync state ใหม่แบบ atomic แล้ว fsync directory
4. append/fsync `*-commit` ที่มี transaction ID และ state digest ตรงกัน
5. ลบ journal แล้ว fsync directory ก่อนคืน success

Grant/revoke details อยู่ใน commit เดียวกัน prepare ยังไม่ยืนยันการเปลี่ยนสิทธิ์
ทุก record ของธุรกรรมใช้ `request_id` เดียวกัน จับคู่ข้าม restart ได้

Startup ตรวจ journal และ audit chain ก่อนโหลด state, leases และ model:

- matching commit: กู้ after state และ fsync audit ที่อาจยังอยู่ใน page cache
- ไม่มี commit: กู้ before state และ append/fsync rollback
- journal เสีย/สิทธิ์ผิด, audit เสีย/partial write, commit ไม่ตรง digest,
  audit ถูก rotate ขณะมีธุรกรรมค้าง หรือ recovery I/O ล้ม: ปฏิเสธ startup

Recovery ทำซ้ำได้ I/O error ระหว่าง mutation ทำให้ runtime เดิมปฏิเสธ tool,
persist และ transition ต่อ ต้องเปิด runtime ใหม่ ห้าม retry ผ่าน object เดิม
กรณี chain เสีย/rotation ต้องให้ operator ตรวจและกู้จากหลักฐานที่เชื่อถือได้
โดยเก็บไฟล์เดิมไว้ก่อน ห้ามลบ journal เพื่อข้าม recovery
Caller ต้องถือ exclusive VM writer lease ซึ่ง supervisor ทำให้อยู่แล้ว
การเปิด Runtime/AuditWriter โดยตรงหลายตัวพร้อมกันไม่ได้อยู่ใน contract นี้

## การทดสอบและขอบเขตหลักฐาน

`cargo test -p aivm-runtime transaction::tests` ส่ง `SIGKILL` ให้ child process
ที่ขอบเขต create/write/fsync/rename/directory sync ของ journal, state,
audit prepare/commit และ recovery ทั้ง transition กับ secret approval
ตรวจว่าหลัง restart สิทธิ์ตรงกับ commit, quota ไม่ reset, pending secret
ไม่กลายเป็น approved และ recovery ซ้ำได้ รวม I/O error หลัง commit write/
หลังลบ journal, journal เสีย และ audit เขียนไม่ครบ

เป็น process-crash/fault-injection coverage ยังไม่ได้ทดลองตัดไฟ storage จริง
หรือพิสูจน์ทุก filesystem, storage controller และ production host
