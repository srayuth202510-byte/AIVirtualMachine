# External recovery supervisor (single host)

ดู [detection-evaluation.md](detection-evaluation.md) สำหรับผลการทดสอบ
false positives/misses รวมกรณี config ผิดที่ทำให้ containment ทำงานเกินเหตุ

`scripts/aivm-supervisor.py` เพิ่ม reconciliation loop นอก runtime ของ agent
ใช้ desired replicas, durable state และ systemd user services เพื่อควบคุมงาน
เริ่มด้วยแผนเท่านั้น ต้องระบุ `--apply` จึงจะสร้างหรือหยุด workload จริง

รุ่นแรกเป็น **finite jobs**: แต่ละ slot ทำงานหนึ่งรอบ เมื่อ process จบปกติ
จะเป็น `completed` และไม่รันงานเดิมซ้ำ รักษาจำนวน slot ที่ยังไม่จบด้วยการ
สร้างทดแทนเมื่อ runtime ล้มเหลว หมดเวลา หรือเข้าเกณฑ์ containment
จึงยังไม่ใช่ Kubernetes เต็มรูปแบบ ไม่มี scheduler ข้ามเครื่อง, load balancer,
service readiness probe, rolling update หรือ external credential broker
`running` หมายถึง systemd service ทำงานอยู่ ไม่ได้รับรองว่างานสำเร็จ
และ `completed` หมายถึง CLI exit 0 ซึ่งอาจเป็นการจบเพราะถึง max steps

## โครงสร้างและขอบเขตการควบคุม

```text
Trusted deployment JSON + private state (host)
                    |
             External controller
              |              |
       verified audit     systemd user manager
       watcher/rules          |
                        per-instance service cgroup
                              |
                       AIVM agent process
                              |
                      gateway process.exec
                        /             \
                    Container       MicroVM
```

Supervisor อ่าน audit จริงผ่าน `Watcher` เดิม และตรวจ snapshot ด้วย Rust CLI
`verify-audit` โดยไม่รับคำสั่งหรือ event inbox จากโมเดล Qwen watcher เดิม
รันขนานกันเพื่อให้คำแนะนำได้ แต่ผล Qwen ไม่มีสิทธิ์สร้าง/หยุด instance

ตามโครงสร้าง runtime ปัจจุบัน Container/MicroVM ใช้กับการเรียก process tool
ผ่าน gateway ไม่ได้ย้าย model inference และ agent loop ทั้งหมดเข้า guest
systemd จึงครอบ agent process และ process ลูก รวมถึง bubblewrap/Firecracker
อีกชั้นหนึ่ง Worker ตั้ง container `cgroup_root` ให้เป็น delegation ของ service
ตัวเอง เพื่อให้ sandbox process ที่ย้าย cgroup ยังคงอยู่ใต้ service ที่หยุดได้

ต้องใช้ Linux, cgroup v2 และ systemd user manager ที่รองรับ
`DelegateSubgroup=` (systemd 254+) ส่วน Container ต้องมี bubblewrap และ
helper ตาม [container.md](container.md); MicroVM ต้อง build ด้วยฟีเจอร์
`microvm` พร้อม kernel/rootfs pins และ KVM ตาม [microvm.md](microvm.md)
PATH ของ worker มีเพียง `/usr/local/bin:/usr/bin:/bin` จึงต้องติดตั้ง
Firecracker ใน PATH นี้หากเลือก MicroVM

Controller, spec, binary และ state directory ต้องอยู่นอกพื้นที่ที่ agent เขียนได้
ใช้ state directory ใหม่ที่เป็นเจ้าของโดยผู้ใช้เดียวกันและ mode 0700
single-writer lock ป้องกัน controller สองตัวใน directory เดียวกัน
atomic writes ใช้ไฟล์ 0600, fsync ไฟล์และ directory
การแยกนี้ไม่ป้องกันผู้โจมตีที่ควบคุม host หรือ UID ของ controller ได้แล้ว

## นโยบาย containment และ recovery

รุ่นนี้มีนโยบายคงที่: ใน audit ที่ตรวจ chain ผ่าน พบอย่างน้อย 20 denials
ของ agent/session เดียวกันภายใน 60 วินาที และอย่างน้อยหนึ่งรายการในกลุ่ม
เป็น `boundary_violation` หรือ `sensitive_access` ตามกฎ reviewer เดิม
นี่คือ **เกณฑ์ตอบสนองความเสี่ยง** ไม่ใช่หลักฐานยืนยันว่าถูกยึดเครื่อง
การ deny ครั้งเดียว, burst ที่ไม่มีสัญญาณดังกล่าว หรือคำตัดสิน Qwen เพียงอย่างเดียว
ไม่ทำให้สร้างทดแทน

```text
starting -> running -> completed
               |
        severe rule / failure / timeout
               |
         quarantining   (persist intent and evidence first)
               |
         systemctl stop (KillMode=control-group; immediate SIGKILL)
               |
            retired -> fresh instance, subject to budget
```

- ต้องหยุด unit เดิมสำเร็จก่อนสร้างตัวแทน ถ้าหยุดหรือสังเกต unit ไม่ได้
  หรือ cgroup ยังมี process อยู่ controller รายงาน `blocked` และไม่เริ่ม
  workload เพิ่มในรอบนั้น
- เก็บ reason พร้อม source sequence, timestamp และ hash ของหลักฐานใน state
  ใช้หลักฐาน 20 รายการที่พอพิสูจน์เกณฑ์ เก็บ workspace/audit ตัวเก่าไว้
  ไม่มีการลบทิ้งโดยอัตโนมัติ จำกัดประวัติ 256 instances ต่อ deployment
  เมื่อเต็มต้อง drain และตรวจหลักฐานก่อนเริ่ม deployment ใหม่
- ตัวใหม่มีชื่อและ directory ใหม่ ไม่คัดลอก workspace, memory, capability
  state หรือ secret lease ตัวเก่า ใช้เฉพาะ trusted template เดิม
- ไม่มี external credential revocation ในรุ่นนี้ จึงรองรับเฉพาะ local/echo
  model และปฏิเสธ secret policy ที่ไม่ว่าง Worker ล้าง environment ที่สืบทอดมา
  และใช้ HOME/TMPDIR ใหม่ ไม่ใช่ระบบหมุนเวียน API key ภายนอก
- การล้มเหลวและ security replacement ใช้งบเดียวกันต่อ deployment:
  `max_replacements` ครั้งใน `window_seconds` รวมข้าม restart
  initial replicas ไม่ใช่ replacement; เมื่อเกินงบจะกักกันแล้วรอจนพ้น window
- ถ้า audit ถูกแก้ เสีย หายหลังเคยเห็น หรือเกินขีดจำกัด watcher จะกักกันและ
  `hold` slot ไว้ให้ผู้ดูแลตรวจ **ไม่** สร้างตัวแทนอัตโนมัติจากข้อมูลที่ตรวจไม่ได้
- ต่อ audit ได้ข้าม rotation ขณะ controller ทำงาน ถ้า restart แล้ว hash tip
  ล่าสุดที่ persist ไว้ไม่อยู่ในไฟล์ปัจจุบัน จะ hold แม้เป็น rotation ที่ถูกต้อง
  ระหว่าง controller หยุดอยู่ ข้อจำกัดนี้ตั้งใจ fail closed
- Audit hash chain ยืนยันความต่อเนื่องภายในเท่านั้น ไม่ใช่ external authentication
  และยังใช้ขอบเขต 1 MiB/4096 records ต่อไฟล์, 4096 records ต่อหน้าต่าง 60 วินาที
- ถ้า crash ระหว่างเริ่ม unit จะรับช่วง unit ที่ยังทำงานอยู่ได้ แต่จะไม่ใช้
  directory ของการเริ่มที่ไม่แน่นอนซ้ำเมื่อ unit หายไป

## ทดลองใช้

สร้าง binary แล้วทำสำเนาที่ pin ไว้สำหรับ deployment ไม่ใช้ binary ที่ cargo
จะเขียนทับทุกครั้งที่ build คำสั่งนี้เตรียม spec จากตัวอย่าง echo model:

```sh
cargo build -p aivm-cli
python3 - <<'PY'
import hashlib, json, pathlib, shutil
directory = pathlib.Path('target/supervisor-demo').resolve()
directory.mkdir(parents=True, exist_ok=True)
binary = directory / 'aivm'
shutil.copy2('target/debug/aivm', binary)
spec = json.loads(pathlib.Path('examples/supervisor.json').read_text())
spec['binary'] = str(binary)
spec['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
(directory / 'deployment.json').write_text(json.dumps(spec, indent=2) + '\n')
PY

# แผนเท่านั้น ไม่สร้าง/หยุด unit (อาจสร้าง directory/lock สำหรับ controller)
python3 scripts/aivm-supervisor.py target/supervisor-demo/deployment.json \
  --state-dir "$HOME/.local/state/aivm/demo"

# เปิดวงจรจริงกับ deployment นี้
python3 scripts/aivm-supervisor.py target/supervisor-demo/deployment.json \
  --state-dir "$HOME/.local/state/aivm/demo" --apply --watch
```

Echo ไม่ได้ทำงาน coding จริง ใช้ยืนยันการเริ่ม/จบ process เท่านั้น
สำหรับ Qwen ให้ build `--features llama` ก่อน copy binary แล้วเปลี่ยน
`vm_config.model` เป็น local config ตาม `examples/aivm.yaml` ใช้ model path
แบบ absolute และเลือกงาน/จำนวน steps/timeout ให้เหมาะสม ก่อนเริ่ม deployment ใหม่
ตัวอย่างนี้ไม่ส่ง seed workspace เข้าไป ตัวใหม่จึงเริ่มด้วย workspace ว่าง
ถ้าต้องกู้ข้อมูล operator ใช้ [workspace snapshots/restore](workspace-recovery.md)
ลง VM ใหม่แยกต่างหากได้ Controller รุ่นนี้ยังไม่เลือก snapshot หรือเรียก restore
ให้ instance ทดแทนอัตโนมัติ

Spec รวม binary SHA256 ต้องตรงกับที่ persist ไว้ ถ้าเปลี่ยน template หรือ
binary ให้ drain deployment เดิมและใช้ state directory ใหม่ ไม่แก้ config
ของ instance เดิมเพื่อให้ทำงานต่อ

Ctrl+C หยุด controller แต่ unit ที่ยังทำงานอยู่ยังอยู่ภายใต้ systemd และ
`RuntimeMaxSec` เริ่มคำสั่งเดิมอีกครั้งเพื่อรับช่วงต่อ ถ้าต้องการหยุด deployment
และไม่ให้ controller ที่เริ่มใหม่สร้าง instance เพิ่ม ให้ drain:

```sh
python3 scripts/aivm-supervisor.py target/supervisor-demo/deployment.json \
  --state-dir "$HOME/.local/state/aivm/demo" --apply --drain

python3 -m json.tool "$HOME/.local/state/aivm/demo/controller.json"
# ดู output ของ instance ตามชื่อ unit ที่รายงาน
journalctl --user -u aivm-INSTANCE.service
```

`--drain` โดยไม่มี `--apply` แสดงแผนอย่างเดียว
Drain ยังทำงานได้เมื่อ binary เดิมหายหรือ SHA256 ไม่ตรง โดยต้องใช้ spec เดิม
ที่ตรงกับ fingerprint ใน state และจะควบคุมเฉพาะ unit ที่ persist ไว้
รายงานเป็น JSONL: `start`, `running`, `quarantine`, `retired`, `completed`,
`rate_limited`, `blocked`, `drained` พร้อม `dry_run`
One-shot คืน exit 2 เมื่อ `blocked`; watch mode รายงานแล้วเฝ้าต่อ
เมื่อ hold ต้องตรวจหลักฐานและแก้สาเหตุก่อน drain/เริ่ม deployment ใหม่
ไม่แก้ state ด้วยมือเพื่อล้างข้อผิดพลาด

## การทดสอบ

```sh
python3 -m unittest discover -s scripts -p 'test_supervisor.py' -v

# ต้องเข้าถึง systemd user bus และ delegation จริง
AIVM_SUPERVISOR_HOST_TEST=1 \
  python3 -m unittest discover -s scripts -p 'test_supervisor.py' -v
```

เทสต์ปกติครอบคลุม state machine, dry-run, restart, lock, replacement budget,
timeout, drain, การหยุดล้มเหลว และการตรวจ hash chain ด้วย Rust CLI จริง
Host tests เริ่ม CLI จริงจนจบงาน และใช้ workload จำลองที่ส่ง audit สังเคราะห์
เพื่อทดสอบ containment/replacement จริงผ่าน systemd รวมถึง process ลูกที่
แยก session และย้ายเข้า cgroup ลูกอีกกลุ่ม มี cleanup เฉพาะ test units หลังทดสอบ
นี่ไม่ได้อ้างว่าได้จำลอง exploit จริง หรือยืนยัน TEE/attestation
