# Recurring real-model validation บน KVM host

Workflow `.github/workflows/model-host-validation.yml` รันทุกวัน 03:19 น.
Asia/Bangkok และสั่งรันเองได้ ต้องมี repository-specific runner ที่มี labels
`self-hosted`, `linux`, `aivm-model-kvm` และเปิด repository variable
`AIVM_ENABLE_MODEL_VALIDATION=1` ไม่มี pull-request trigger
ใช้ label เฉพาะนี้แทน generic `kvm` เพื่อไม่รับงาน KVM อื่นโดยไม่ตั้งใจ

## เตรียม host

ใช้ account operator เดียวกับที่เข้าถึง pinned GGUF/kernel/rootfs/Firecracker ได้
เครื่องต้องมี user/network namespaces, KVM, trusted root-owned container helper,
Rust/C++ build tools และ systemd user manager ที่ delegate `cpu memory pids` ได้
ไม่เปลี่ยน model/boot pins ตามไฟล์ที่พบเอง

```bash
python3 scripts/setup-model-validation.py \
  --repo OWNER/REPO \
  --model /absolute/path/model.gguf \
  --model-sha256 '<approved-64-hex-sha256>' \
  --pins /absolute/path/pins.json \
  --prepare-runner
```

ไม่ใส่ `--prepare-runner` = ตรวจ prerequisites/pins เท่านั้น
รายงานเก็บใน `target/model-validation-setup/host.json` เป็น `0600`

`--prepare-runner` ดาวน์โหลด GitHub Actions runner ตาม version/URL/SHA-256
ใน `infra/github/model-validation-runner.json` ตรวจ hash ก่อน extract ด้วย
archive traversal filter และติดตั้งใน `~/.local/share/aivm/model-validation-runner`
ไม่ register, ไม่เปิด service และไม่เปิด workflow ในขั้นนี้
ทำซ้ำได้เมื่อ package marker ตรงกัน ไม่เขียนทับ runner directory ที่ไม่รู้จัก
การเปลี่ยน runner pin ต้องตรวจข้อมูลจาก [official releases](https://github.com/actions/runner/releases)

## เปิดใช้งานจริง

ต้องมี GitHub CLI ที่ authenticate ด้วยสิทธิ์บริหาร repository แล้ว
และ workflow/setup script รุ่นนี้ต้องอยู่บน default branch ของ repository
ใช้ arguments ชุดเดิมเพิ่ม `--enable` (ใส่ `--prepare-runner` ร่วมกันได้)

สคริปต์จะ:

1. ตรวจ host และ artifact pins ซ้ำ และตรวจสิทธิ์ repository/workflow
2. ลงทะเบียน runner เฉพาะ repository ด้วย registration token ชั่วคราว
3. สร้าง user unit `aivm-model-validation-runner.service` ด้วย `UMask=0077`,
   `Delegate=cpu memory pids` และ PATH ของ Rust/Firecracker รวมถึง sbin
   สำหรับ `mkfs.ext4`/`debugfs`; เปิด signal forwarding ของ runner เพื่อหยุด listener ได้
4. เปิด linger ของ account นี้ให้รับ job หลัง logout แล้วเปิด service
5. ตรวจว่า GitHub รายงาน runner online พร้อม labels ครบ
6. ปิด gate ชั่วคราว ตั้ง `AIVM_GGUF`, `AIVM_GGUF_SHA256`, `AIVM_MICROVM_PINS`,
   enable workflow แล้วเปิด gate เป็นขั้นสุดท้าย
7. dispatch validation ครั้งแรกบน default branch

ถ้าข้อ 6 ล้ม สคริปต์พยายามคืน gate เป็น 0; ถ้าการคืนค่าล้มด้วยจะรายงานว่า
ยืนยันสถานะไม่ได้ ต้องตรวจ repository settings ก่อนรันใหม่
Registration token ไม่ถูกเก็บในรายงานหรือพิมพ์ผ่าน command errors
Runner เก็บ credentials ใน directory ของตนเอง ไม่ใส่ token ใน Git
การ dispatch สำเร็จยังไม่ใช่ผล validation ผ่าน ต้องตรวจผล job และ artifacts

Workflow ตรวจ prerequisites ก่อนทดสอบ loader และ workers ทั้งสาม tier
รวม timeout/memory-pressure failure และ verified recovery หลังแต่ละ failure
โดยต้องมี structured evidence ครบและไม่เหลือ descendants/staging/cgroups ของเทสต์
เก็บ evidence 30 วันแม้ test ล้มเมื่อมีไฟล์ให้เก็บ ไม่มีการ download/re-pin GGUF
ห้าม build/test อื่นที่เปลี่ยน worker binary ระหว่าง host validation

## ตรวจและหยุด

```bash
systemctl --user status aivm-model-validation-runner.service
journalctl --user -u aivm-model-validation-runner.service
# หยุดรับงานใหม่แบบถาวรเมื่อจำเป็น
gh variable set AIVM_ENABLE_MODEL_VALIDATION --repo OWNER/REPO --body 0
systemctl --user disable --now aivm-model-validation-runner.service
```

การปิด gate ไม่ยกเลิก job ที่เริ่มแล้ว ตรวจและยกเลิก job ผ่าน GitHub ก่อนหยุด
service ถ้าต้องการเก็บผลให้ครบ Linger เป็นค่าระดับ account; การปิด service
ไม่เปลี่ยน linger เพื่อไม่กระทบ user services อื่น

รายละเอียด registration และ permissions:
[GitHub self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners),
[repository variables API](https://docs.github.com/en/rest/actions/variables)
