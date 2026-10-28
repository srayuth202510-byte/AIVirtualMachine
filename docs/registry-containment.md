# Registry และ dataset containment

ขอบเขตการแก้วันที่ 28 ตุลาคม 2026: source ของ AIVM ใน repository นี้
ไม่พบการติดตั้ง JFrog Artifactory หรือ dependency/runtime ของ Jinja2 และ fsspec
จึงไม่ได้อัปเกรด Artifactory หรือทดสอบ exploit กับบริการภายนอก
ไม่ถือเป็นการรับรองว่าป้องกัน zero-day ทุกชนิดได้

## สิทธิ์เครือข่าย

`network.read_only` มีค่าเริ่มต้น `true` ทั้งกรณีไม่มี network block,
ไม่มีฟิลด์ใน YAML และการสร้าง config/policy ด้วย Rust `Default`
gateway อนุญาตเฉพาะ GET/HEAD ที่ไม่มี body หรือ method-override header
ปฏิเสธ POST/PUT/PATCH/DELETE และ raw `network.connect` ก่อน resolve DNS
หรือหัก capability quota โดยคำขอที่ถูกปฏิเสธยังมี audit record
runtime ไม่ออก capability `network:connect` เมื่อเปิด read-only
และการ restart จะใช้สิทธิ์จาก config ปัจจุบันแทนสิทธิ์ที่เคยบันทึกไว้

```yaml
network:
  read_only: true
  allow: []              # ไม่ต้องใช้เครือข่าย ให้ปิดทั้งหมด
  max_calls: 20
  max_total_bytes: 10485760
```

งานที่ต้องส่ง POST หรือ publish artifact ต้องให้ operator ตั้ง
`network.read_only: false` อย่างชัดเจน พร้อม hostname allowlist และ capability
ที่เหมาะสม ยังต้องผ่าน TLS, policy/state gate และ quota เดิมทั้งหมด
เป็นการเปลี่ยน default: config เดิมที่เคยส่ง POST หรือใช้ raw connect ต้องแก้
เมื่ออัปเดตไบนารี และต้อง restart runtime ที่กำลังทำงานจึงจะใช้ policy ใหม่

HTTP method ไม่ใช่หลักประกันว่าปลายทางไม่มี side effect: GET อาจเขียนข้อมูล
หรือส่งข้อมูลออกผ่าน URL/header ได้ และ server-side proxy อาจส่ง request ต่อ
ต้องใช้ credential แบบ read-only แยกตามงาน จำกัด repository/path และ
upstream/egress ที่ฝั่ง Artifactory ด้วย ห้ามใช้ token ร่วมที่เขียนข้ามงานได้
ถ้าไม่จำเป็นต้องติดต่อ registry ให้คง `allow: []`

## SSRF และ IPv6

ตัวตรวจ IP ยอมรับเฉพาะ IPv6 global unicast ปกติใน `2000::/3` โดยตัด
IETF protocol assignments `2001::/23`, documentation `2001:db8::/32` และ
`3fff::/20`, และ 6to4 `2002::/16` ออกด้วย บล็อก special-purpose บางช่วง
อย่างจงใจแม้บางที่อยู่จะ route ได้ เพื่อให้ขอบเขตเป็นแบบ conservative
IPv4-mapped IPv6 ใช้เกณฑ์ IPv4 เดิม
จึงปฏิเสธ well-known NAT64, IPv4-compatible, site-local, discard-only,
Teredo และ 6to4 ที่ฝังปลายทางภายใน/metadata
อ้างอิง [IANA IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry/)

DNS results ทุก address ยังต้องผ่านตัวตรวจเดียวกันและถูกตรึงก่อนเชื่อมต่อ
ไม่ตาม redirect และปิดการรับ proxy จาก environment อย่างชัดเจน
ไม่รองรับการพิสูจน์ว่า operator-defined NAT64 prefix หรือ network routing
ภายนอกโปรเซสจะไม่ส่งต่อไปยัง private network ต้องมี egress firewall เสริม

## Dataset และ template

gateway ของ AIVM อ่าน JSON/template เป็นข้อความ ไม่ได้เรียก Jinja2 หรือ
รับ tool `template.render` การทดสอบตรวจว่า `{{ 7 * 7 }}` คงเดิมหลังอ่าน
และไม่สามารถใช้ filesystem gateway เขียน workspace ของอีกงาน
นี่เป็นการตรวจ boundary ของ AIVM ไม่ใช่การทดสอบ Jinja sandbox escape

หากเพิ่ม Python dataset service ภายหลัง ต้องแยก worker ด้วย container/microvm,
ไม่ให้ production secrets/host mounts และบังคับ fsspec `simple_templates=True`
จากฝั่งบริการ ไม่ยอมให้ metadata เปลี่ยนเป็น Jinja mode
ตรวจ protocol/URL/file paths ก่อนประมวลผล และไม่ใช้ข้อมูลผู้ใช้เป็น template source
หากจำเป็นต้อง render template ของผู้ใช้ ต้องมี Jinja sandbox และ resource limits
พร้อมเทสต์ในบริการนั้นเอง ดู [fsspec](https://filesystem-spec.readthedocs.io/en/latest/api.html#fsspec.implementations.reference.ReferenceFileSystem)
และ [Jinja sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/)

## การตรวจสอบ

```sh
cargo test --locked -p aivm-adversarial --test registry_containment
make verify
```

ชุด adversarial ไม่เปิด socket: ใช้ `.invalid` และยืนยันเหตุผลปฏิเสธก่อน DNS
ตรวจ write methods, GET/HEAD body, method-override headers, stale write capability,
raw connect, IP ที่อยู่ใน allowlist แต่เป็น special IPv6, audit chain,
ข้อมูล template ที่ไม่ถูกรัน และการเขียนข้าม workspace
unit tests มี GET/HEAD ที่ถูกต้องเป็น positive controls และ public-IP controls
runtime tests ตรวจ default, opt-in write และการถอด connect capability หลัง restart
ผล `make verify` ครอบคลุม fmt, strict Clippy, Rust/Python tests และ demo
ไม่รวมการบูต KVM จริงหรือการรับรองการตั้งค่าบริการ Artifactory ภายนอก

ผลวันที่ 28 ตุลาคม 2026: ชุด adversarial ใหม่ 3 tests ผ่าน และ `make verify`
ผ่านครบ (`verify: all green`, demo 14/14) เมื่อรันนอก chat sandbox
ใน chat sandbox เทสต์ worker เดิม
`pinned_worker_snapshot_survives_source_replacement_and_in_place_writes`
ติด `Permission denied` ขณะรัน executable ชั่วคราว; เทสต์เดียวกันผ่านบน host
เก็บ raw logs ใน `target/registry-hardening-verify-host.log` และ
`target/registry-hardening-adversarial.log` (ไม่ commit build/test artifacts)
