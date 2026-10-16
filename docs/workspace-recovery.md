# Workspace snapshots และการกู้ข้อมูลโดย operator

รุ่นแรกเก็บหลายจุดกู้คืนของ **workspace เท่านั้น** และกู้ลง VM ใหม่ที่ยังไม่รัน
รองรับไฟล์ binary, ไฟล์ว่าง, directory ว่าง และ owner executable bit
Operator เป็นผู้เลือกจุดกู้คืนและ config ปัจจุบัน ไม่เลือก snapshot ล่าสุดให้อัตโนมัติ

## สร้างและตรวจจุดกู้คืน

```bash
# ทำก่อนเริ่มงานที่จะเปลี่ยนข้อมูล โดย VM ต้องไม่มี operation ทำงานอยู่
aivm --root ./vms snapshot coder --store ./backups

# ดูรายการ: payload_verified=false เพราะยังไม่อ่าน payload ทุกไฟล์
aivm --root ./vms snapshots --store ./backups

# ใช้ id และ manifest_sha256 จากผล snapshot ที่บันทึกไว้อย่างเชื่อถือได้
aivm --root ./vms verify-snapshot 'snap-<id>' --store ./backups \
  --manifest-sha256 '<64-hex-digest>'
```

คำสั่งคืน JSON มี `id`, `source_vm`, `created_at`, จำนวน files/directories,
จำนวน bytes, `manifest_sha256` และ `payload_verified`
เก็บ id/digest ไว้ภายนอก host ที่ต้องการป้องกันด้วย หากไม่ส่ง digest ให้
`verify-snapshot` จะตรวจเทียบ checksum ใน store ซึ่งตรวจการเสียหายได้ แต่ไม่ยืนยัน
ว่าผู้ควบคุม store ไม่ได้เขียน manifest และ checksum ใหม่พร้อมกัน

Store ต้องเป็น directory ของ operator ที่มี permission แบบ private (สร้างด้วย
0700; data/metadata สร้างด้วย 0600) อยู่นอกต้นไม้ VM root และไม่ครอบ VM root
ปฏิเสธที่เก็บใต้ system library/toolchain trees ที่ sandbox อาจอ่านได้
เช่น `/usr/lib` ห้าม bind-mount หรือให้ policy เปิด store เข้าไปใน agent

แต่ละจุดมีโครงสร้าง:

```text
backups/
  snapshot.lock
  snap-<uuid>/
    manifest.json        version, origin, UTC time, source audit tip, paths/sizes/hashes
    manifest.sha256      SHA-256 ของ raw manifest bytes
    data/                สำเนา workspace ที่แยก inode จากต้นฉบับ
```

Manifest ผูก path, SHA-256, ขนาดไฟล์และ executable bit ของแต่ละไฟล์
การ verify ตรวจไฟล์ครบ รวมไฟล์ที่หายหรือเพิ่มจาก manifest ด้วย
ไฟล์ใน store ไม่ถูก execute และไม่มีคำสั่งแก้/ลบ snapshot ใน CLI รุ่นนี้

## กู้หลังข้อมูลเสียหายหรือสงสัยการโจมตี

1. หยุด/กักกัน workload และเก็บ VM เดิมกับ audit ไว้เป็นหลักฐาน
2. เลือกจุดก่อนความเสียหายจากหลายเวอร์ชัน โดยใช้ digest ที่เก็บไว้เชื่อถือได้
3. ตรวจ integrity แล้วกู้ลงชื่อใหม่ด้วย **config ปัจจุบันจาก operator**:

   ```bash
   aivm --root ./vms restore 'snap-<id>' recovered-coder --store ./backups \
     --manifest-sha256 '<64-hex-digest>' --config ./trusted-current.yaml
   ```

4. ตรวจข้อมูลและสแกนตามความเสี่ยงก่อนสั่ง `run`/`agent` ตัวใหม่ แก้ช่องโหว่และ
   หมุนเวียน credentials ที่อาจรั่วก่อนกลับมาใช้งาน

Restore ต้องระบุ digest เสมอ และปฏิเสธชื่อเดิมหรือชื่อ VM ที่มีอยู่แล้ว
ตรวจ payload ก่อนสร้าง VM และตรวจ hash ซ้ำขณะ copy เพื่อจับการเปลี่ยนระหว่างกู้
ย้ายข้อมูลเสร็จและบันทึก audit จึง publish `aivm.yaml` ให้ supervisor discover ได้
หาก copy/boot/config/audit ล้มเหลว จะเก็บต้นฉบับและ snapshot เดิมไว้ และลบเฉพาะ
directory ใหม่ที่ operation นี้จองเอง

VM ใหม่เริ่ม INIT ตาม config/policy ปัจจุบัน ไม่คัดลอก VM-root `state.json`,
capability counters, secret leases, secrets store, memory หรือ audit เดิม
การให้สิทธิ์ตัวใหม่เป็นการสร้าง instance ใหม่โดย operator ไม่ใช่การคืนสิทธิ์
จาก checkpoint เก่า หากต้องคง revocation ระดับ deployment ต้องระบุใน policy
ปัจจุบันด้วย ข้อมูลที่มีชื่อ `state.json` ภายใน workspace ยังเป็นข้อมูล workspace
ตามปกติและไม่ถูกนำมาใช้เป็น runtime state

Source audit ต่อด้วย `snapshot.create`; audit ใหม่มี `snapshot.restore` ที่อ้าง id
และ digest ส่วน audit เก่าไม่ถูกย้อนหรือคัดลอกมาทับ log ใหม่ Event ใช้สถานะ
`prepared` เพราะถูกเขียนก่อน publish: หาก crash หลัง event อาจยังไม่มีผลลัพธ์
ที่ publish แล้ว ให้ตรวจรายการ snapshot/VM ประกอบ ไม่ตีความ event เป็น commit receipt

## ความสอดคล้องและข้อจำกัด

- Snapshot ถือ VM operation lease; หาก run/agent/transition ยังทำงานอยู่จะปฏิเสธ
  รวมถึง VM ที่ pause แต่ operation ยังถือ lease ไม่ใช่ hot/application snapshot
  ต้องหยุด writers ภายนอกที่ไม่ใช้ lease ด้วย ตรวจ metadata ก่อน/หลังอ่านเพื่อจับ
  การเปลี่ยนไฟล์ระหว่าง copy แต่ไม่รับประกัน transaction consistency ของ writers เหล่านั้น
- ใช้ descriptor-relative traversal และ pinned inode; ปฏิเสธ symlink, hard link,
  FIFO/device/socket และ path ที่ไม่ใช่ UTF-8 โดยไม่ข้ามไฟล์เงียบ ๆ
- เพดานต่อ snapshot: 1 GiB, 10,000 entries รวม files/directories, ลึกไม่เกิน 64,
  path ไม่เกิน 4096 bytes และ manifest ไม่เกิน 8 MiB เกินเพดานจะล้มโดยไม่ publish
  Store รองรับรวมไม่เกิน 10,000 directory entries รวม lock/staging ด้วย
- Directory เป็น 0700; restore ไฟล์เป็น 0600 หรือ 0700 ตาม owner executable bit
  ไม่คืน setuid/setgid, group/other permissions, ACL, extended attributes หรือ timestamps
- เขียนลง `.pending-<uuid>` แล้ว sync files/directories และ publish แบบ atomic
  ไม่เขียนทับ id เดิม Crash ก่อน publish อาจทิ้ง `.pending-*` ที่ไม่ปรากฏในรายการ
  เก็บไว้ตรวจหรือให้ operator ล้างภายหลังเมื่อไม่มี operation ทำงานอยู่
- Crash ระหว่าง restore อาจทิ้ง VM directory ที่ยังไม่มี `aivm.yaml` จึงไม่ถูก discover
  ให้ตรวจหลักฐานก่อนล้าง directory นั้นหรือใช้ชื่อใหม่ ไม่ลบ VM เดิมอัตโนมัติ
- Store ใช้ exclusive lock เมื่อสร้าง และ shared lock เมื่ออ่าน/restore
  เปิด backup ที่ mount read-only ได้หากคง `snapshot.lock` และ ownership/permissions ไว้
- Snapshot เป็นข้อมูลที่ตรวจ integrity ได้ **ไม่ได้รับรองว่าไม่มี malware** และ
  อาจมีข้อมูลลับที่อยู่ใน workspace ต้องจัดการ access/encryption ของที่เก็บให้เหมาะสม

Snapshot บน host เดียวกันป้องกันความเสียหายจากการกระทำผ่าน agent gateway/sandbox
ตาม boundary ที่ตั้งไว้ ไม่ป้องกันผู้ยึด host หรือ native worker ที่อ่านเขียนไฟล์
ด้วยสิทธิ์ operator ได้ ควรมีสำเนา offline/ภายนอกที่แยกสิทธิ์และเก็บ digest ภายนอก
รุ่นนี้ยังไม่ทำ encryption, external replication, retention pruning, scheduling
หรือเชื่อม automatic recovery supervisor ให้เลือก restore เอง

## การทดสอบ

```bash
cargo test -p aivm-supervisor
cargo test -p aivm-cli --test snapshots
```

ครอบคลุมลบ/เขียนทับไฟล์, หลายจุดกู้คืน, binary/empty directory/executable,
current config และ INIT แทน security state เดิม, corrupt/missing/extra payload,
manifest ถูกแก้แม้คำนวณ checksum ใหม่, traversal/duplicates, unsafe filesystem
nodes, limits, operation/store locks, abandoned staging และ failure cleanup
มีการรัน cat/rm ผ่าน gateway/sandbox จริงเพื่อยืนยันว่าอ่านหรือลบ backup ไม่ได้
และ CLI integration tests ที่สร้าง/ตรวจ/กู้ข้อมูลผ่าน executable จริง
