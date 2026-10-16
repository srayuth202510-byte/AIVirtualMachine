# สำรอง workspace ออกไป S3 และทดลองกู้คืน

ชุดนี้เป็น CloudFormation template และขั้นตอน operator สำหรับ snapshot ที่มีอยู่แล้ว
ยังไม่ใช่บริการส่ง backup อัตโนมัติ และยังไม่มีหลักฐานว่า deploy/ส่ง/กู้กับ AWS จริง
ดูขอบเขตข้อมูลและข้อจำกัดใน [workspace recovery](workspace-recovery.md) ก่อนใช้งาน

## โครงสร้างและสิทธิ์

- เก็บ local snapshot สำหรับกู้เร็ว และส่งสำเนาไป **บัญชี AWS สำหรับ backup แยกต่างหาก**
- [template](../infra/backup/s3.yaml) สร้าง bucket ชื่ออัตโนมัติ พร้อม Versioning,
  Object Lock แบบ GOVERNANCE เริ่มต้น 30 วัน, ปิด public access/ACL, บังคับ TLS
  และ SSE-S3 (`AES256`) สำหรับ upload ไม่มี lifecycle ลบข้อมูลอัตโนมัติ
- อายุ lock เป็นช่วงที่ห้ามลบ **แต่ละ version** ไม่ใช่กำหนดเวลาลบข้อมูล:
  พ้น 30 วันข้อมูลยังอยู่และมีค่าเก็บต่อ ต้องกำหนด pruning ภายหลัง
- ลบ stack หรือ replace bucket จะ retain bucket และ bucket policy ไว้
- Template สร้าง managed policies สองชุด แต่ไม่สร้าง role, trust policy, access key
  หรือผูก policy ให้ principal ใด ผู้ดูแลบัญชี backup เป็นผู้ผูกให้ dedicated roles
  ที่ไม่มีสิทธิ์อื่น: uploader เขียน `snapshots/*` ได้; recovery operator อ่านได้
  credentials ฝั่งกู้และ administrator ต้องอยู่นอกเครื่อง runtime
- Uploader policy มี explicit deny สำหรับการลบ/เปลี่ยน lock และการตั้งค่า bucket
  ห้ามให้ role นี้แก้ IAM, assume role ผู้ดูแล หรือถอด policy ของตัวเอง
  Managed policy นี้ไม่ใช่ permissions boundary และไม่ควบคุมผู้ดูแลบัญชี
  สิทธิ์จาก workload account ต้องผ่าน trust ของ dedicated role ในบัญชี backup
  จำกัด source principal ให้เฉพาะงาน backup ห้าม trust ทั้งบัญชีโดยไม่มีเงื่อนไข

Governance ยังถูก bypass โดยผู้ดูแลที่มีสิทธิ์เฉพาะได้ ให้เริ่มทดสอบด้วยโหมดนี้
ก่อนพิจารณา COMPLIANCE ซึ่งลดระยะ lock ของ version ที่ถูกล็อกแล้วไม่ได้
Object Lock ไม่ป้องกันการสร้าง version ใหม่ทับชื่อเดิม จึงเก็บ version ID ใน receipt
และใช้ version นั้นในการกู้เสมอ
อ้างอิง [AWS Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
และ [CloudFormation bucket](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html)

SSE-S3 เข้ารหัสที่ AWS ไม่ใช่การเข้ารหัสก่อนส่งโดย operator และไม่ซ่อนข้อมูลจาก
principal ที่อ่าน object ได้ หากต้องการ client-side encryption ต้องเพิ่มการจัดการ
กุญแจนอก host และทดลองกู้ด้วยกุญแจนั้นก่อนนำมาใช้จริง

## เตรียมปลายทาง

เลือกบัญชี/region, ช่วงเก็บ และผู้ดูแลก่อน deploy ใช้ AWS CLI v2 และ profile
แยกเป็น `backup-admin`, `backup-upload`, `backup-restore` ตามบทบาท ไม่ส่ง secret
เข้า repository หรือใส่ในคำสั่ง ตัวอย่างต่อไปนี้สำหรับ operator รันเองจาก repo root
ไม่ใช่คำสั่งที่ agent/workload ควรเรียกได้

```bash
# ตรวจ identity ว่าเป็นบัญชี backup และ region ที่ตั้งใจใช้ก่อน
aws --profile backup-admin sts get-caller-identity
# การรัน deploy สร้างทรัพยากรจริงและมีค่าใช้จ่าย
aws --profile backup-admin cloudformation deploy \
  --template-file infra/backup/s3.yaml --stack-name aivm-backups \
  --capabilities CAPABILITY_IAM --parameter-overrides RetentionDays=30
aws --profile backup-admin cloudformation describe-stacks \
  --stack-name aivm-backups --query 'Stacks[0].Outputs'
```

ผูก policy ARNs จาก outputs ให้ dedicated roles ตามด้านบน แล้วตรวจจากฝั่งผู้ดูแลว่า
versioning เป็น Enabled, lock เป็น GOVERNANCE/ช่วงเก็บที่เลือก และ public access ถูกปิด
การตั้ง default retention ไม่รับรองว่า object เก่าหรือ object ที่ override retention
จะถูกล็อกตามค่านี้ ให้ตรวจ retention ของ **version ที่ส่งจริง** ด้วย

## ส่งหนึ่ง snapshot

ใช้ Bash, GNU tar, `flock`, `sha256sum`, Python 3 และ AWS CLI v2 ที่รองรับ
`put-object --if-none-match` เครื่องต้นทางต้องมีพื้นที่สำหรับ tar เพิ่มอีกหนึ่งสำเนา
snapshot เดิมต้องสร้างสำเร็จแล้ว ให้หยุด writers ภายนอกที่แก้ store ได้ด้วย
`flock` คุมเฉพาะโปรแกรมที่ร่วมใช้ lock เดียวกัน ไม่ป้องกันผู้ยึด host

ตัวอย่างตั้งค่าต่อไปนี้ต้องแทนที่ด้วย path/bucket/id/digest จริงจาก snapshot receipt:

```bash
set -euo pipefail
umask 077
VM_ROOT=/absolute/path/vms
STORE=/absolute/path/backups
SNAPSHOT_ID='snap-REPLACE-WITH-UUID'
MANIFEST_SHA256='REPLACE-WITH-TRUSTED-64-HEX-DIGEST'
BUCKET='REPLACE-WITH-STACK-OUTPUT'
[[ "$SNAPSHOT_ID" =~ ^snap-[0-9a-f-]{36}$ ]]
[[ "$MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]]
# พื้นที่ operator นอก VM/store และไม่ให้ sandbox อ่านได้
EXPORT_DIR=$(mktemp -d /tmp/aivm-export.XXXXXXXX)
ARCHIVE="$EXPORT_DIR/$SNAPSHOT_ID.tar"
KEY="snapshots/$SNAPSHOT_ID.tar"
(
  flock --shared 9
  aivm --root "$VM_ROOT" verify-snapshot "$SNAPSHOT_ID" --store "$STORE" \
    --manifest-sha256 "$MANIFEST_SHA256"
  # ไม่รวม .pending-* หรือ snapshot อื่น และคง snapshot.lock สำหรับ restore
  tar --create --file "$ARCHIVE" --directory "$STORE" -- snapshot.lock "$SNAPSHOT_ID"
) 9<"$STORE/snapshot.lock"
ARCHIVE_SHA256=$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)
aws --profile backup-upload s3api put-object \
  --bucket "$BUCKET" --key "$KEY" --body "$ARCHIVE" \
  --server-side-encryption AES256 --checksum-algorithm SHA256 \
  --if-none-match '*' > "$EXPORT_DIR/upload.json"
VERSION_ID=$(python3 -c \
  'import json,sys; v=json.load(open(sys.argv[1]))["VersionId"]; assert v and v != "null"; print(v)' \
  "$EXPORT_DIR/upload.json")
python3 - "$BUCKET" "$KEY" "$VERSION_ID" "$SNAPSHOT_ID" \
  "$MANIFEST_SHA256" "$ARCHIVE_SHA256" > "$EXPORT_DIR/receipt.json" <<'PY'
import json, sys
fields = ("bucket", "key", "version_id", "snapshot_id", "manifest_sha256", "archive_sha256")
json.dump(dict(zip(fields, sys.argv[1:])), sys.stdout, indent=2)
print()
PY
```

`412` หมายถึง key มีอยู่แล้ว; `409` หรือ network timeout อาจต้องตรวจผลที่ปลายทาง
อย่าลบ object เดิมหรือเอาเงื่อนไข `--if-none-match` ออกเพื่อ retry ให้ผู้ดูแลตรวจ
version/ดาวน์โหลดตรวจเทียบ archive digest ก่อนออก receipt หรือส่งด้วย key ใหม่
ที่ไม่ซ้ำแล้วบันทึก key/version ที่ได้จริง ไม่ถือว่า HTTP error แปลว่าไม่มี upload

เก็บ `receipt.json` ในช่องทาง operator ที่เชื่อถือได้ **นอก host ต้นทาง**
receipt ใน bucket เดียวกันอย่างเดียวไม่พอสำหรับยืนยันความแท้ หากผู้โจมตีแก้ได้ทั้งคู่
ไม่ใช้ ETag เป็น SHA-256 และไม่ใช้ snapshot ใหม่ล่าสุดอัตโนมัติหลังเกิดเหตุ
Operator ฝั่ง backup ตรวจ retention ของ version ที่ระบุ:

```bash
aws --profile backup-restore s3api get-object-retention \
  --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION_ID"
```

ยืนยัน Mode/RetainUntilDate ตามที่ต้องการก่อนถือว่ามี offsite backup ที่ถูกล็อกแล้ว
หลังตรวจสำเร็จจึงลบ **เฉพาะ export directory ของรอบนี้** ตามนโยบาย operator
tar เป็น plaintext บนเครื่องต้นทางแม้ object ที่ปลายทางเข้ารหัสอยู่

## กู้บนเครื่องสะอาดและบันทึกการซ้อม

ใช้ recovery role บนเครื่องสะอาด เตรียม `aivm` และ config/policy ปัจจุบันจากแหล่ง
ที่เชื่อถือได้เอง สำเนานี้ไม่มี secrets, VM state, audit history หรือ OS image
ตรวจ receipt จากช่องทางภายนอก แล้วตั้ง `BUCKET`, `KEY`, `VERSION_ID`,
`SNAPSHOT_ID`, `MANIFEST_SHA256`, `ARCHIVE_SHA256` ตาม receipt นั้น

```bash
set -euo pipefail
umask 077
RECOVERY_DIR=$(mktemp -d /tmp/aivm-recovery.XXXXXXXX)
aws --profile backup-restore s3api get-object \
  --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION_ID" \
  --checksum-mode ENABLED "$RECOVERY_DIR/snapshot.tar" > "$RECOVERY_DIR/download.json"
[[ "$ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$ARCHIVE_SHA256" "$RECOVERY_DIR/snapshot.tar" | sha256sum --check -
# ต้องผ่าน trusted archive digest ก่อน extract; ใช้ directory ใหม่ที่ private เท่านั้น
mkdir -m 700 "$RECOVERY_DIR/store"
tar --extract --file "$RECOVERY_DIR/snapshot.tar" \
  --directory "$RECOVERY_DIR/store" --no-same-owner --no-same-permissions
# mkdir root แยกจาก store; ชื่อ VM และ config มาจาก operator
mkdir -m 700 "$RECOVERY_DIR/vms"
aivm --root "$RECOVERY_DIR/vms" verify-snapshot "$SNAPSHOT_ID" \
  --store "$RECOVERY_DIR/store" --manifest-sha256 "$MANIFEST_SHA256"
aivm --root "$RECOVERY_DIR/vms" restore "$SNAPSHOT_ID" recovered-coder \
  --store "$RECOVERY_DIR/store" --manifest-sha256 "$MANIFEST_SHA256" \
  --config /absolute/path/trusted-current.yaml
aivm --root "$RECOVERY_DIR/vms" state recovered-coder
aivm --root "$RECOVERY_DIR/vms" audit recovered-coder
```

ตรวจว่า VM เริ่ม INIT, audit ใหม่ตรวจผ่าน และไฟล์สำคัญ/แอปพลิเคชันอ่านข้อมูลได้
ตรวจ malware ตามความเสี่ยงก่อนเริ่ม workload สำเนาที่ hash ถูกอาจมีข้อมูลที่ถูก
โจมตีอยู่แล้ว หมุน credentials และแก้ช่องโหว่ก่อนกลับมารัน

เริ่มซ้อมเดือนละครั้ง โดยไม่อาศัย VM root/store/config จาก host ต้นทาง
บันทึกวันที่, tool version, bucket/key/version, digest, ผลตรวจ lock/integrity,
ผลเปิดข้อมูล, เวลากู้ (RTO จริง) และอายุข้อมูลที่หายไป (RPO จริง)
ทดสอบด้วยข้อมูลสังเคราะห์ว่าตัว uploader อ่าน/ลบ/เปลี่ยน retention ไม่ได้ด้วย
หากยังไม่เคยกู้จาก AWS จริงให้รายงานว่า **ยังไม่ผ่าน offsite restore drill**

ขั้นตอนนี้ยังไม่มี scheduling, retry queue, alert เมื่อส่งไม่สำเร็จ, pruning หรือ
client-side encryption ต้องติดตามอายุ **backup ที่ส่งและตรวจปลายทางสำเร็จ**
ก่อนนำไปใช้เป็นระบบสำรองประจำวัน ไม่ถือว่า CI ผ่านเท่ากับกู้จาก AWS ได้

อ้างอิงคำสั่ง [PutObject](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html)
และ [GetObject](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object.html)
