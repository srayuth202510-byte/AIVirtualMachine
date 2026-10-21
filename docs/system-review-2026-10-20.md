# รายงานวิเคราะห์และทบทวนระบบ AIVM — 20 ตุลาคม 2026

## สถานะติดตาม — 22 ตุลาคม 2026

รายงานด้านล่างเป็นผลประวัติศาสตร์ที่ commit `f6aa57a` ไม่ใช่รายการช่องโหว่ปัจจุบันทั้งหมด
ตรวจติดตาม source ถึง `44aba9e` และชุด validation ที่เพิ่มภายหลัง:

| Finding | สถานะติดตาม |
|---|---|
| H-1 | `696a15e` เพิ่ม strict config parsing และ regression สำหรับ security/isolation typo |
| M-1 | `696a15e` รักษา deadline เดิมเมื่อ restore พร้อม regression test |
| M-2 | แทน runner-name/argv heuristic ด้วย operator verifier contract และ gateway receipt ที่ผูก contract/executable/workspace digest แล้ว ดู [รายละเอียดและข้อจำกัด](verification-and-transactions.md) |
| M-3 | เพิ่ม durable transaction journal, startup recovery, runtime fencing และ SIGKILL/fault-injection coverage แล้ว; ยังไม่ได้ทดลองตัดไฟ storage จริง ดู [ขอบเขตหลักฐาน](verification-and-transactions.md) |
| M-4 | `44aba9e` เพิ่ม protected snapshot/fd loading; ผล loader และ worker บน host จริงอยู่ใน [รายงานติดตาม](host-validation-2026-10-21.md) |
| M-5 | เพิ่ม `llama` clippy/tests ใน CI หลักแล้ว; recurring real-model workflow เพิ่มใน source แต่ต้องเปิด runner/variables ก่อน |
| L-1 / L-2 | ยังไม่ได้แก้ครบในการติดตามรอบนี้ |

จึงต้องอ่านข้อสรุป production readiness เดิมประกอบสถานะข้างบนและขอบเขตหลักฐานใหม่
ไม่ถือว่าประเด็นที่ลดความเสี่ยงแล้วได้รับการพิสูจน์ครบทุก failure mode

## บทสรุปผู้บริหาร

ตรวจ commit `f6aa57a9299ec532890e91526eed7fe578b1e3ea` ครอบคลุม Rust workspace 15 crates,
Python operational scripts, CI, configuration, isolation backends, model worker, secrets,
audit/recovery และเอกสารสถาปัตยกรรม

สถาปัตยกรรมหลักมีทิศทางที่แข็งแรง: model/agent ไม่ได้รับสิทธิ์โดยตรง, ทุก tool request
ผ่าน capability และ policy, filesystem ใช้ descriptor-relative access, process sandbox บังคับ
Landlock กับ seccomp, audit ใช้ hash chain และ state/snapshot เขียนแบบ durable หลายจุด
ชุด adversarial และ recovery tests ครอบคลุมกรณีสำคัญมากกว่าระบบต้นแบบทั่วไป

อย่างไรก็ตาม ยังไม่ควรจัดระบบเป็น production-ready ในสภาพปัจจุบัน พบ 1 ประเด็นระดับสูง,
5 ประเด็นระดับกลาง และ 2 ประเด็นระดับต่ำ ประเด็นเร่งด่วนที่สุดคือ YAML ยอมรับ field
ที่สะกดผิดแล้วใช้ค่า default ทำให้ operator ตั้งใจเลือก `container` และ `production`
แต่ระบบกลับใช้ `sandbox` (process) และ `development` โดยไม่แจ้งข้อผิดพลาด

สถานะรวม: **ผ่าน quality gate ปัจจุบัน แต่ยังต้องแก้ configuration fail-open ก่อนใช้งานจริง**

## ขอบเขตและวิธีตรวจ

- อ่าน dependency flow และเส้นบังคับใช้ตั้งแต่ CLI → supervisor → runtime →
  capability/policy → gateway → sandbox/model worker
- ตรวจ source ในส่วนความเสี่ยงสูง: configuration, filesystem, network, process execution,
  seccomp/Landlock, artifact verification, secret lease, audit rotation, snapshot/restore
- เปรียบเทียบ README, architecture, threat model, model-runtime และ CI กับพฤติกรรมจริง
- รัน `make ci`, CI parity, host probe, dependency advisory scan แบบ offline และ compile
  feature `llama` เพิ่มเติม
- ทำ reproduction แยกใน `/tmp` สำหรับ configuration typo และ network lease renewal

การตรวจนี้เป็น source review และ dynamic checks บน host ปัจจุบัน ไม่ใช่ penetration test,
formal verification หรือการรับรอง isolation บน production host

## Findings เรียงตามความรุนแรง

### H-1 — Configuration typo ลดระดับ security profile และ isolation โดยเงียบ

**ระดับ: สูง**

`VmConfig`, `RuntimeBlock` และ `SecurityBlock` ไม่ใช้ `deny_unknown_fields`
([runtime config](../crates/aivm-runtime/src/lib.rs#L48)) ขณะที่ฟิลด์ `runtime` และ
`security` มีค่า default เมื่อฟิลด์ที่คาดไว้หายไป การสะกดชื่อ field ผิดจึงไม่ล้มเหลว

Reproduction ที่ยืนยันแล้ว:

```yaml
runtime:
  isolaton: container
security:
  profle: production
```

คำสั่ง `aivm create` สำเร็จ และไฟล์ config ที่ระบบ publish กลายเป็น:

```yaml
runtime:
  isolation: sandbox
security:
  profile: development
```

ผลกระทบคือ operator อาจเชื่อว่ากำลังใช้ container isolation และ production artifact
requirements แต่ระบบใช้ process sandbox และ development profile การตรวจค่าหลัง parse
ไม่ช่วยกรณีนี้ เพราะค่าที่ผิดถูกทิ้งก่อนและ default ที่เหลือเป็นค่าถูกต้องตาม validator

แนวทางแก้:

1. เพิ่ม `#[serde(deny_unknown_fields)]` ให้ทุก operator-facing configuration struct
   รวม nested blocks
2. เมื่อ build ไม่มี feature `microvm`/`hardware` ให้ตรวจพบ block ดังกล่าวแล้วคืน error
   แทนการเมิน block
3. เพิ่ม regression tests สำหรับ typo ใน `runtime.isolation`, `security.profile`, model,
   resource, capability และ policy fields

### M-1 — Network lease อายุ 300 วินาทีถูกต่อใหม่ทุกครั้งที่เปิด runtime

**ระดับ: กลาง**

เมื่อ restore state ระบบสร้าง state grants ใหม่จาก config ก่อน แล้วคืนเฉพาะ usage counters
จาก state เดิม ([restore path](../crates/aivm-runtime/src/lib.rs#L451)) แต่ network grant
กำหนด expiry เป็น `now + 300` ทุกครั้ง ([state_grants](../crates/aivm-runtime/src/lib.rs#L793))
จึงไม่รักษาเวลาหมดอายุเดิม

Reproduction ใน VM สถานะ `VALIDATE`:

```text
ก่อนเรียก agent: expiration=1792499141
หลังเรียก agent:  expiration=1792499146
delta=5 seconds
```

เพียงเปิด runtime ผ่าน CLI และ persist อีกครั้งก็เลื่อน expiry ไปข้างหน้า แม้ usage count
และ byte count ยังถูกเก็บอยู่ ผลคือ time-bounded JIT permission กลายเป็นสิทธิ์ที่ต่ออายุได้
ตราบใดที่ VM ยังอยู่ใน `VALIDATE`

แนวทางแก้: restore expiry เดิมสำหรับ grant identity เดิมและใช้ค่าที่เข้มกว่าระหว่าง state เดิม
กับ config ปัจจุบัน; grant ใหม่ควรเกิดเฉพาะ transition ที่ operator อนุมัติจริง เพิ่ม test ที่
restart หลายครั้งแล้ว expiry ไม่เปลี่ยนและหมดอายุตามเวลาต้นฉบับ

### M-2 — Agent อาจรายงานว่า tests ผ่านจาก executable ใดก็ได้ที่ exit 0

**ระดับ: กลาง**

ตัวตรวจความสำเร็จพิจารณาเพียง `process.exec`, output มี `exit status: 0`, task มีคำว่า
`test` และ argv มีค่า `test`, `tests` หรือ suffix `_test`
([is_successful_test](../crates/aivm-runtime/src/agent.rs#L330)) จากนั้นสรุปทันทีว่า
`Requested tests passed` ([completion path](../crates/aivm-runtime/src/agent.rs#L600))

ตัวอย่าง `/usr/bin/true test` ผ่าน heuristic นี้ได้หาก executable ถูก allowlist แม้ไม่ได้รัน
test suite ใดเลย ประเด็นนี้ไม่ข้าม capability/policy แต่ทำลาย evidence-backed completion
และอาจทำให้ operator เชื่อผลผิด

แนวทางแก้: ให้ operator config ระบุ verifier command/artifact แบบ typed, ผูก command digest,
argv schema, working tree revision และ expected output/exit contract แล้วออก verification record
จาก trusted runtime แทนการอนุมานจากคำใน argv

### M-3 — Audit บันทึก transition/secret approval ว่าสำเร็จก่อน state durable

**ระดับ: กลาง**

`transition_to` append audit สำหรับ revoke, grant และ transition ก่อนสลับ state และเรียก
`persist`; หาก persist ล้ม state ใน memory ถูก rollback แต่ audit ที่เขียนแล้วไม่ถูกชดเชย
([transition](../crates/aivm-runtime/src/lib.rs#L547)) เส้น secret approval มีลำดับเดียวกัน:
audit `secret-approve` ก่อน persist และ revoke เมื่อ persist ล้ม
([approval](../crates/aivm-runtime/src/lib.rs#L596))

ผลคือ audit chain ยังตรวจ hash ผ่าน แต่บอกว่า action สำเร็จทั้งที่ durable state ไม่เคยรับ action
นั้น ซึ่งลดความน่าเชื่อถือของ audit ในเหตุการณ์ disk-full, permission failure หรือ I/O failure

แนวทางแก้: ใช้ prepare/commit record หรือ append outcome `committed`/`rolled-back` หลัง persist;
consumer ต้องถือ action ว่าสำเร็จเมื่อเห็น commit record เท่านั้น เพิ่ม fault-injection tests ที่ทำให้
state fsync/rename ล้มหลัง audit append

### M-4 — Inline local model verification มี path TOCTOU ระหว่าง hash และ load

**ระดับ: กลาง**

local model ถูก hash ผ่าน path แล้วคืนจาก verifier
([verify_model_file](../crates/aivm-model/src/lib.rs#L219)) จากนั้น backend เปิด path เดิมอีกครั้ง
เพื่อ load ([LocalLlamaModel::new](../crates/aivm-model/src/lib.rs#L423)) ผู้ที่เปลี่ยนไฟล์หรือ
สลับ symlink ใน directory ของ model ได้ระหว่างสองขั้นอาจทำให้ไฟล์ที่โหลดไม่ใช่ไฟล์ที่ hash ผ่าน

Container/MicroVM staging ลดความเสี่ยงบางส่วนเพราะ worker ตรวจ artifact ใน boundary อีกครั้ง
แต่ inline backend และ process worker ยังพึ่ง pathname trust

แนวทางแก้: เปิดไฟล์ด้วย `O_NOFOLLOW`, ตรวจ regular file/link count/owner ตาม policy, hash ผ่าน
file descriptor เดียวกับที่ส่งให้ loader หรือ copy ไป owner-only immutable staging file แล้ว hash
สำเนาและ load สำเนานั้น; production profile ควรบังคับ isolated worker

### M-5 — CI หลักไม่ compile/test feature `llama`

**ระดับ: กลาง**

CI default รัน workspace โดยไม่เปิด features และเพิ่มเฉพาะ `microvm` กับ `hardware`
([workflow](../.github/workflows/ci.yml#L26), [Makefile](../Makefile#L37)) ขณะที่ local GGUF
backend อยู่หลัง feature `llama` และเป็นแกนหลักตาม product positioning

การตรวจครั้งนี้รันเพิ่ม:

```text
cargo check -p aivm-model -p aivm-model-worker --features llama --locked --offline
PASS
```

จึงไม่มี build break ณ commit ที่ตรวจ แต่ regression ใน feature นี้สามารถเข้า main ได้โดย CI ปัจจุบัน

แนวทางแก้: เพิ่ม job compile + clippy + tests สำหรับ `llama`; เพิ่ม scheduled/self-hosted smoke
ด้วย model fixture ที่ pin แล้ว แยก compile gate ออกจาก expensive real-model evaluation

### L-1 — Dashboard มี path เฉพาะเครื่องและ contract metrics ไม่ตรงชื่อ

**ระดับ: ต่ำ**

`scripts/aivm-dashboard.py` hard-code SQLite path เป็น `/home/lokis/Documents/...`, มี HTML/CSS
ที่พิมพ์ผิดหลายตำแหน่ง (`<divclass>`, `1pxsolid`) และ endpoint ที่ระบุว่า Prometheus-compatible
คืน JSON แทน Prometheus exposition format ทำให้ deploy ต่างเครื่องและ integration monitoring เปราะ

แนวทางแก้: รับ DB/port/log path ผ่าน CLI หรือ environment, ใช้ relative state directory ที่ private,
เพิ่ม `/metrics` แบบ text exposition และ smoke test HTTP/HTML

### L-2 — เอกสาร/comment บางส่วนล้าหลังกว่า implementation

**ระดับ: ต่ำ**

comment ใน sandbox ยังระบุ MicroVM ว่าเป็น skeleton แม้ backend ปัจจุบันมี boot path จริง
([sandbox module](../crates/aivm-sandbox/src/lib.rs#L25)) และข้อความบางส่วนยังเรียก network crate
ว่า MVP-A no-egress ทั้งที่ network tools ถูก implement ใน `aivm-tools` แล้ว ความคลาดเคลื่อนนี้
เพิ่มโอกาสประเมิน assurance หรือ maintenance ผิด

## จุดแข็งที่ยืนยันจาก source และ tests

- Capability และ policy ใช้ default-deny; unknown tool/intent และ parse error ไม่ execute
- Filesystem gateway เปิด path แบบ descriptor-relative, ปฏิเสธ symlink, hard link และ special file
- Process sandbox บังคับ Landlock และ hybrid seccomp แบบ default-kill พร้อม rlimit, no-new-privs,
  environment clearing, process-group cleanup และ timeout
- Network path บังคับ HTTPS, resolve/check public IP, pin resolver, ปิด redirect และนับ byte quota
  ทั้ง request/response
- Secret broker แยก value จาก config, ใช้ owner-only state, approval exact lease ID, TTL/max uses,
  capability recheck, zeroization และ output redaction
- Audit hash v2 ครอบคลุม fields สำคัญ, append แล้ว sync, verify chain และ rotation recovery
- Snapshot/restore ใช้ descriptor-relative traversal, hash manifest/payload, จำกัด entries/bytes และไม่
  restore security state เดิม
- Supervisor มี per-VM lease และ create publication marker หลัง validation/persist
- Threat model ระบุ trust root และข้อจำกัดของ host/TEE อย่างตรงไปตรงมา

## ผลการตรวจอัตโนมัติ

| การตรวจ | ผล |
|---|---|
| `make ci` | ผ่าน (exit 0) |
| Rust default workspace | 319 ผ่าน, 0 ล้มเหลว, 2 ignored |
| Python unit tests | 94 ผ่าน, 2 skipped |
| strict Clippy / rustfmt | ผ่าน |
| enforcement demo | 14/14 ผ่าน |
| CLI end-to-end smoke | ผ่าน |
| MicroVM/hardware feature suites | ผ่านในส่วน unit/plumbing; ไม่มี real boot บน host นี้ |
| CI parity | ผ่าน |
| `llama` offline compile check | ผ่าน |
| Cargo advisory scan | ไม่พบ known vulnerability ใน 244 dependencies จาก cached DB |
| `git diff --check` | ผ่าน |

Advisory database ล่าสุดในเครื่องเป็น commit วันที่ 3 ตุลาคม 2026 ขณะที่ตรวจวันที่ 20 ตุลาคม
จึงเป็น offline snapshot อายุประมาณ 17 วัน ไม่ใช่ supply-chain clearance ปัจจุบัน

## สภาพ host และสิ่งที่ยังไม่ได้พิสูจน์

Host probe ปัจจุบันรายงาน seccomp ใช้ได้ แต่ user namespace, delegated cgroup quotas,
container helper และ `/dev/kvm` ไม่พร้อม แม้พบ Firecracker, QEMU และ swtpm ก็ตาม ดังนั้น:

- ไม่ได้รัน container boundary จริง
- ไม่ได้ boot MicroVM หรือ hardware VM จริง
- ไม่ได้ยืนยัน SEV-SNP/TDX หรือ remote attestation
- ไม่ได้รัน GGUF inference จริง เพราะไม่มี pinned model fixture ใน scope
- ไม่ได้ทำ power-loss/kill-at-every-fsync fault injection
- ไม่ได้ทดสอบ cloud provider กับ external API

ผล unit/feature tests จึงยืนยัน logic และ fail-closed plumbing แต่ไม่รับรอง isolation ของ production host

## ลำดับแก้ไขที่แนะนำ

1. แก้ H-1 และเพิ่ม strict config regression suite ก่อน deploy รุ่นถัดไป
2. แก้ M-1 เพื่อให้ lease expiry monotonic และไม่ต่ออายุจาก restart
3. เปลี่ยน test completion เป็น trusted verifier contract (M-2)
4. ทำ audit/state transaction semantics และ fault injection (M-3)
5. ปิด artifact TOCTOU พร้อมบังคับ production worker isolation (M-4)
6. เพิ่ม `llama` CI gate และ real-model scheduled validation (M-5)
7. จัดหา host ที่มี container prerequisites/KVM แล้วรัน ignored host validations พร้อมเก็บ pins,
   commit, probe และผล boot เป็นหลักฐานต่อ release

หลังแก้ข้อ 1–5 และผ่าน real host validation จึงควรประเมิน production readiness ใหม่
