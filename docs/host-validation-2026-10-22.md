# Dashboard และ recurring model CI preparation — 22 ตุลาคม 2026

ตรวจ baseline `4a21a8c` พร้อม working-tree changes ของรอบนี้ ไม่ใช่การรับรอง
baseline ที่ไม่มี changes เหล่านี้ ผล model validation เก็บใต้
`target/model-host-validation/2026-10-22-steps34/` มี commit/diff digest,
source hashes, commands, raw logs และ artifact hashes ก่อน/หลัง
หลักฐาน Dashboard/setup อยู่ใน `target/model-validation-setup/`
และ source digests ของรอบนี้อยู่ใน `target/steps34-validation/validation.json`

## ผลตรวจ

| รายการ | ผล |
|---|---|
| `make verify` | ผ่าน: Rust 339 ผ่าน, 2 ignored; Python suites และ demo 14/14 |
| Dashboard regression suite | 5 ผ่าน |
| Runner setup regression suite | 6 ผ่าน |
| HTTP smoke บน localhost จริง | ผ่าน: HTML escaping, Prometheus text, JSON, 404, private DB |
| CI parity / diff whitespace | ผ่าน |
| Prepared user-service definition | ผ่าน `systemd-analyze verify --user` |
| Protected GGUF loader หลัง source tampering | ผ่าน exact host test, 55.30 วินาที |
| Worker `process_namespace` | ผ่าน exact host test, 99.08 วินาที |
| Worker `container` | ผ่าน exact host test, 98.67 วินาที |
| Worker `microvm` | ผ่าน exact host test, 152.03 วินาที |
| Model/kernel/rootfs/Firecracker/pins/worker integrity หลังทดสอบ | ไม่เปลี่ยน |

Host tests ทั้ง 4 รายการรันจริงโดยไม่มี skip/ignored ใน exact test summaries
เวลาเป็น command/setup elapsed ไม่ใช่ benchmark
ใช้ GGUF และ boot pins เดิมจากรายงาน 21 ตุลาคม ไม่ download หรือ re-pin โมเดล
เลือก host จริงนอก chat sandbox ซึ่งเข้าถึง KVM, namespaces และ systemd delegation ได้

## สถานะ recurring CI

- Host เดิม: `MondayBtype`; KVM/user-network namespaces และ delegated CPU/memory/PIDs พร้อม
- ติดตั้งและตรวจ version ของ pinned official runner `2.338.0` แล้ว
  อยู่ที่ `~/.local/share/aivm/model-validation-runner` มี directory mode `0700`
- GitHub CLI `2.103.0` ติดตั้งแบบ user-local จาก official archive ที่ตรวจ SHA-256 แล้ว
- เตรียมและตรวจ user-service definition แล้ว; ใช้ label เฉพาะ `aivm-model-kvm`
- **ยังไม่ register runner, ไม่ติดตั้ง/เปิด user service, ไม่เปิด linger และไม่ตั้ง repository variables**
- `gh auth status` ยืนยันว่าไม่มี GitHub account ที่ authenticate; GitHub plugin ยังไม่เชื่อมต่อ
- **ยังไม่ได้เปิด recurring workflow หรือ dispatch GitHub Actions job**

ผล manual host validation ที่ผ่านข้างต้นไม่ใช่หลักฐานว่า scheduled CI เปิดแล้ว
ขั้นตอนเปิดจริงอยู่ใน [runner setup](model-validation-runner.md)
และการแก้ Dashboard อยู่ใน [dashboard guide](dashboard.md)
