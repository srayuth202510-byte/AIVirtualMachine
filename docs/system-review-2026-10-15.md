# ผลตรวจระบบ AIVM — 15 ตุลาคม 2026

ตรวจโครงสร้าง Rust workspace ทั้ง 14 crates, การตั้งค่า/CI/เอกสาร และอ่านเส้นทางหลักของ capability, gateway, filesystem, state, secrets, sandbox, model และ supervisor ประกอบกับการรันทดสอบ รายงานนี้เป็นการตรวจโค้ดและพฤติกรรมในเครื่อง ไม่ใช่หลักประกันว่าปราศจากช่องโหว่ทั้งหมด

## สถานะหลังแก้ไข

แก้ครบทั้ง 7 ข้อแล้ว รายละเอียดปัญหาด้านล่างเป็นหลักฐานก่อนแก้

| ข้อ | พฤติกรรมหลังแก้ | Regression test |
|---|---|---|
| 1 | Cache ตรวจขนาดตาม capability ของคำขอปัจจุบันและ audit เมื่อ deny | `cached_reads_enforce_current_size_constraints` |
| 2 | Parser/gateway ปฏิเสธ write ที่ขาด content หรือเป็น null; empty string ยังใช้ได้ | `write_intents_require_explicit_content`, `missing_write_content_never_truncates_a_file` |
| 3 | State เสีย/อ่านไม่ได้/เป็น dangling symlink ทำให้ boot ล้ม และไม่เขียนทับ state | `corrupt_state_file_prevents_boot_without_resetting_quotas`, `inaccessible_state_is_not_treated_as_a_new_runtime` |
| 4 | ส่ง provider config จาก YAML ถึง factory และส่งชื่อที่เลือกใน request payload; shared name ที่ระบุเองมาก่อน nested model | `cloud_provider_blocks_reach_the_runtime_model_factory`, `cloud_model_selection_respects_names_and_provider_overrides`, `selected_*_model_reaches_request_payload` |
| 5 | จองชื่อแบบ atomic, publish config เป็นขั้นสุดท้าย, cleanup เมื่อ create ผิดพลาด | `failed_create_removes_partial_vm_and_allows_retry`, `concurrent_creators_cannot_overwrite_each_other` |
| 6 | Hardware/MicroVM ปฏิเสธ secret ก่อน consume; lease ยังใช้ได้ | `unsupported_guest_secret_injection_preserves_the_lease` |
| 7 | ตรวจ QEMU pin ก่อน KVM readiness และใช้ fake artifact ที่เทสต์ควบคุม ไม่ต้องติดตั้ง QEMU/KVM | `wrong_qemu_pin_fails_closed_as_invalid` |

การเลือก cloud model และการกู้ state อธิบายเพิ่มเติมใน [configuration.md](configuration.md)

ทดสอบนอก sandbox บน host จริงเพิ่มเติมแล้ว: Local inference และ MicroVM ผ่าน
รวมถึง QEMU Generic boot; Container boundary test ผ่านหลังติดตั้ง helper
และแก้การส่งคำสั่งจาก launcher ไปยัง bubblewrap
รายละเอียดและข้อจำกัดความถูกต้องของ summary จากโมเดลอยู่ใน
[host-validation-2026-10-15.md](host-validation-2026-10-15.md)

## ผลตรวจที่ต้องแก้ เรียงตามความสำคัญ

### 1. P1 — Cache ข้ามข้อจำกัด `max_bytes` ของ read capability

- จุด: `crates/aivm-tools/src/lib.rs:544` และการเติม cache จาก `write` ที่บรรทัด 612/657
- `read` ตรวจ capability/policy แล้วคืน cache ทันที โดยไม่เรียก `check_file_size` ของ capability ที่ใช้ครั้งนี้
- ยืนยันด้วยโปรแกรมจำลอง: cache มีข้อมูล 10 ไบต์ เมื่อใช้ read capability ที่จำกัด 1 ไบต์ ยังอ่านได้ 10 ไบต์ แต่เมื่อล้าง cache คำขอเดียวกันถูกปฏิเสธ
- ไม่จำเป็นต้องเปลี่ยนสิทธิ์ระหว่าง run: การ write ข้อมูล 10 ไบต์จะเติม read cache และ subsequent read ที่มี `max_bytes=1` ก็ผ่าน
- แก้: ตรวจขนาด cached content ด้วย capability ของคำขอปัจจุบันก่อนคืนผล และ audit การปฏิเสธ เพิ่ม regression สำหรับ write → limited read และเปลี่ยน capability หลัง cache ถูกเติม

### 2. P1 — คำสั่งเขียนไฟล์ที่ไม่มี `content` ล้างข้อมูลเดิม

- จุด: `crates/aivm-tools/src/lib.rs:1339` และ `crates/aivm-runtime/src/agent.rs:118`
- Parser ยอมรับ `{"tool":"filesystem.write","path":"src/data.txt"}` แล้ว dispatch แปลง `None` เป็นสตริงว่าง
- ยืนยันผ่าน parser และ gateway จริง: คำสั่งสำเร็จและไฟล์เดิมเหลือ 0 ไบต์ เช่นเดียวกับ `content: null` ที่ deserialize เป็น `None`
- แก้: บังคับให้ write มี content; ปฏิเสธ missing/null ก่อน side effect แต่ยังให้ผู้ใช้ระบุ `content: ""` เพื่อล้างไฟล์โดยตั้งใจได้

### 3. P1 — State ที่อ่านหรือ parse ไม่ได้ทำให้ข้อจำกัดเดิมหายเงียบ ๆ

- จุด: `crates/aivm-runtime/src/lib.rs:355`
- เมื่อไฟล์ state มีอยู่แต่เสียหรืออ่านไม่ได้ Runtime เริ่ม INIT พร้อม initial capabilities ใหม่ แทนที่จะหยุดด้วย error
- ยืนยัน: persist read capability `max_uses=1` หลังใช้ครบแล้ว; restart ปกติอ่านไม่ได้ แต่หลังทำ `state.json` ให้เป็น JSON เสีย restart สำเร็จและอ่านได้ด้วย initial capability ที่ไม่จำกัดจำนวนครั้ง
- ผล: quota/revocation ที่แคบกว่าสิทธิ์เริ่มต้นไม่คงอยู่เมื่อ state เสีย และการเขียน checkpoint ถัดไปอาจทับหลักฐาน state ที่เสีย
- แก้: แยกกรณีเริ่ม VM ใหม่ที่ยังไม่มี state จากกรณี state เดิมเสีย/อ่านไม่ได้ ให้กรณีหลัง fail closed และมีการ reset/recovery โดย operator อย่างชัดเจน

### 4. P2 — ชื่อโมเดล cloud ใน VM config ไม่ถูกใช้จริง

- จุด: `crates/aivm-runtime/src/lib.rs:395`, `crates/aivm-runtime/src/lib.rs:114`, `crates/aivm-model/src/lib.rs:354`
- Runtime ส่ง `model.name` เข้า `ModelConfig.name` แต่ cloud factory อ่านเฉพาะ `config.openai` / `config.anthropic` ซึ่ง Runtime ไม่ส่งให้ และ ModelBlock ยังไม่มีสองฟิลด์นี้
- จากเส้นทางโค้ด `provider: openai` จึงใช้ชื่อโมเดลจาก `OpenAIConfig::default()` เสมอ และ Anthropic มีปัญหาเดียวกัน การตั้ง nested provider config ใน YAML ก็ถูกเมินเป็น unknown fields
- ผล: ผู้ใช้เลือกโมเดลผ่าน config แล้วได้โมเดลอื่น และกำหนดชื่อ environment variable ของ API key ผ่าน VM config ไม่ได้
- แก้: เชื่อม config provider จาก YAML ถึง factory และกำหนดแหล่งความจริงของ model name ให้ชัดเจน ทดสอบ request payload ผ่าน mock transport โดยไม่ต้องใช้ API จริง
- ข้อนี้ตรวจยืนยันเส้นทางโค้ด ยังไม่ได้เรียก cloud API

### 5. P2 — สร้าง VM ล้มเหลวแล้วทิ้ง directory/config ทำให้สร้างชื่อเดิมซ้ำไม่ได้

- จุด: `crates/aivm-supervisor/src/lib.rs:104`
- `create` สร้าง directory และเขียน `aivm.yaml` ก่อน `Runtime::init` validate ครบ แต่เมื่อ init ล้มเหลวไม่มี rollback
- ยืนยัน: create ด้วย isolation ผิดคืน error; แก้ config แล้ว create ชื่อเดิมคืน `Exists("broken")` และ supervisor รอบใหม่อาจ discover directory ที่สร้างไม่สำเร็จเป็น VM
- แก้: validate ก่อน commit หรือเตรียมใน staging directory แล้ว publish เมื่อสำเร็จ พร้อม cleanup เมื่อ error และป้องกัน create ชื่อเดียวกันพร้อมกัน

### 6. P2 — Hardware backend รับ secret lease ทั้งที่ไม่ส่ง environment เข้า guest

- จุด: `crates/aivm-tools/src/lib.rs:795`, `crates/aivm-tools/src/lib.rs:882`, `crates/aivm-sandbox/src/hardware/launch.rs:756`
- Gateway ปฏิเสธ secret injection เฉพาะ MicroVm แต่ Hardware ยัง resolve/consume lease และ checkpoint ก่อนเรียก backend
- Hardware ระบุ `env_extra: ignored (not passed to guest)` และไม่มีเส้นทาง inject secret ใน guest invocation
- ผลเมื่อ host พร้อมรัน: one-time lease ถูกใช้ไปแต่งานใน guest ไม่ได้รับ secret ที่ขอ
- แก้: ปฏิเสธ Hardware ตั้งแต่ก่อน consume lease จนกว่าจะ implement ช่องส่ง secret ที่รองรับจริง พร้อม regression test ว่า lease ไม่ถูกเผา
- ข้อนี้ตรวจจากโค้ด ยังไม่ได้บูต Hardware VM จริง

### 7. P2 — Hardware pin test ล้มบนเครื่องที่มี QEMU แต่ไม่มี KVM

- จุด: `crates/aivm-sandbox/src/hardware.rs:563` และ readiness gate ที่บรรทัด 410
- เทสต์ `wrong_qemu_pin_fails_closed_as_invalid` ตรวจ prerequisite แค่ QEMU แล้วคาดหวัง `Invalid` แต่ backend ตรวจ KVM ก่อน pin และคืน `Disabled` เมื่อไม่มี KVM
- ยืนยันด้วย `cargo test --workspace --all-features`: เทสต์นี้ล้มจริง เครื่องนี้ probe ได้ `qemu=true`, `kvm=false`
- นี่เป็นปัญหา test portability ไม่ใช่หลักฐานว่า hash pin ปล่อย binary ที่ผิดผ่าน
- แก้: แยก pin verification เป็น unit test ที่ไม่ต้องใช้ KVM หรือจัดลำดับ validation ให้ตรวจ pin ก่อน readiness ตาม contract ที่ต้องการ หลีกเลี่ยงการเพิ่ม skip จนไม่มีการทดสอบ hash

## การตรวจก่อนแก้

| การตรวจ | ผล |
|---|---|
| `cargo fmt --all -- --check` | ผ่าน |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | ผ่าน |
| `cargo test --workspace` | 207 ผ่าน, 1 ignored |
| `cargo test --workspace --all-features` | ไม่ผ่านที่ hardware pin test; Cargo หยุดก่อนจบทุก test binary |
| All-features โดยกรอง hardware pin test ข้างต้นออก | 257 ผ่าน, 1 ignored, 1 filtered out |
| `sh scripts/smoke.sh` | ผ่าน |
| `cargo run -q -p aivm-cli -- demo` | 14/14 ผ่าน |
| โปรแกรมจำลองแยกใน `/tmp/aivm-review` | ยืนยันข้อ 1, 2, 3 และ 5 |
| `aivm probe` | seccomp ใช้ได้; ไม่มี KVM, user namespaces, delegated cgroups, bubblewrap/helper |

จำนวนผ่านเป็นจำนวนที่ test runner รายงาน บางเทสต์บูตจริงใช้ early return เมื่อ prerequisites ไม่ครบ จึงไม่เท่ากับยืนยันการบูตจริง

## ขอบเขตที่ยังพิสูจน์ไม่ได้ในเครื่องนี้

- Container boundary test จริงยัง ignored และไม่มี host prerequisites
- MicroVM/Hardware boot จริงยังไม่มี KVM และไม่ได้เตรียม pins สำหรับ e2e
- ไม่ได้เรียก cloud LLM หรือโหลด GGUF จริง; all-features ยืนยัน compile และเทสต์ที่มีเท่านั้น
- ไม่ได้ตรวจฐานข้อมูล CVE/dependency advisory ออนไลน์หรือทำ penetration/fuzz testing

หลักฐานการรันใน session นี้อยู่ที่ `/tmp/aivm-audit-tests.log`, `/tmp/aivm-audit-all-features.log`, `/tmp/aivm-audit-smoke.log`, `/tmp/aivm-audit-demo.log`, `/tmp/aivm-audit-probe.log` และ `/tmp/aivm-review-results.log` ไฟล์ใน `/tmp` ไม่ใช่ artifact ถาวรของ repository

## การตรวจหลังแก้

- `cargo test --workspace`: 218 ผ่าน, 1 ignored
- `cargo test --workspace --all-features`: 269 ผ่าน, 1 ignored, ไม่มี filtered test
- Formatting, strict Clippy, CLI smoke และ demo ผ่าน
- `make ci` ผ่านครบ รวม default checks และชุด microvm/hardware แยก feature; strict Clippy แบบ all-features ผ่านด้วย
- Cloud request payload ทดสอบผ่าน builder เดียวกับที่ HTTP client ใช้ โดยไม่เรียก API จริงหรือเปิด socket
- ข้อจำกัดเรื่อง host prerequisites สำหรับ Container/MicroVM/Hardware boot จริงยังคงเดิม

หลักฐานหลังแก้อยู่ใน `/tmp/aivm-fixes-default.log`, `/tmp/aivm-fixes-all-features.log`, `/tmp/aivm-fixes-clippy.log`, `/tmp/aivm-fixes-smoke.log` และ `/tmp/aivm-fixes-ci.log`
