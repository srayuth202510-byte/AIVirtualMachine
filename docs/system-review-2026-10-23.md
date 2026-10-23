# ตรวจบั๊กและ technical debt — 23 ตุลาคม 2026

## สถานะหลังแก้ใน working tree

ติดตามด้วย [host validation และ dashboard soak](host-validation-2026-10-23.md):
worker ทั้งสาม tier ผ่านบน host จริง ส่วน soak พบ restart/retention bug เพิ่ม
จึงเพิ่ม persistent cursor, การรองรับ DB รุ่นเดิม และ regression อีก 4 tests
ใน working tree รายงานด้านล่างบันทึกการแก้ชุดแรกที่ commit `50b5d0e`

แก้ B1–B4 และ D1–D3 แล้ว รายละเอียดด้านล่างเป็นหลักฐานก่อนแก้ที่ commit
`48bf35c` ไม่ใช่รายการปัญหาที่ยังค้างใน working tree ปัจจุบัน

| รายการ | การแก้และ regression ที่เพิ่ม |
|---|---|
| B1 | inspect ถือ VM lease ก่อน init/recovery; test ป้องกันการแตะ journal ของ operation ที่ยังทำงาน |
| B2 | ตรวจ whole-history ต้องเริ่ม genesis; test ต้น archive หาย แต่ single-file verify ยังตรวจ continuation ได้ |
| B3 | search ใช้ capability ของตัวเองพร้อม file policy/byte quota; unit, adversarial และ demo ครอบคลุม search-only/secret/symlink |
| B4 | inspect แสดง grants/constraints/policy จริง และ process count เป็น not measured; test state VALIDATE และ expiry |
| D1 | dashboard เดิน cursor ต่อ, drain inode เก่าระหว่าง rotation, แจ้ง backlog/coverage gaps และ rollback cursor เมื่อ DB ล้ม; เพิ่ม 6 tests |
| D2 | ล้าง lease value เมื่อ exhausted/revoked/expired; Drop ล้าง lease/broker/env และ cleanup pending ที่หมดอายุ; test terminal values และ cleanup |
| D3 | runtime/config API ใช้ policy builder เดียวกัน พร้อม VM home ชัดเจนและ reject policy เก่าที่ต่างกัน; test เทียบ policy จริง |

Reproduction B1 หลังแก้: inspect คืน busy โดย journal ยังอยู่, transition เดิม
exit 0 และ `aivm audit` ตรวจผ่าน (ก่อนแก้ transition exit 1 และ chain เสีย)
การเปลี่ยนพฤติกรรมนี้หมายความว่า inspect/state/capabilities ระหว่างมี operation
จะต้องเรียกใหม่หลังงานจบ รายละเอียดอยู่ใน [transactions](verification-and-transactions.md)

ผลหลังแก้: `CARGO_NET_OFFLINE=true make ci` **exit 0** ครบ format, strict clippy,
workspace tests, Python tests/evaluation, demo/e2e และ lint/tests ของฟีเจอร์
`llama`, `microvm`, `hardware` ชุด Rust default มี 349 passed, 0 failed, 3 ignored
Python ใน gate รวม 115 tests และ dashboard ผ่าน 11 tests (เพิ่มใหม่ 6)
เก็บ logs หลังแก้ใน `target/review-2026-10-23/after/`

ไม่ได้รัน pinned GGUF inference หรือบูต KVM/container บน host จริงในรอบนี้
ขอบเขต dashboard เป็น coverage ของ source ที่ process สังเกตได้ ไม่ใช่ authentication
หรือการ import archives ย้อนหลัง

## หลักฐานก่อนแก้

ตรวจ source ที่ commit `48bf35c` โดยอ่านเส้นทาง runtime, capability/policy,
gateway, audit/transaction, supervisor/lifecycle และ Python monitoring เป็นหลัก
เทียบรายงานเดิมกับโค้ดปัจจุบัน และทำ reproduction แยกจาก production code
ผลนี้เป็นการตรวจเฉพาะส่วนสำคัญ ไม่ใช่การรับรองว่าโค้ดทั้ง repository ไม่มีบั๊กอื่น

พบ **4 บั๊กที่จำลองซ้ำได้**: P1 หนึ่งข้อ และ P2 สามข้อ พร้อม technical debt
อีก 3 ข้อ ลำดับความสำคัญประเมินจากผลกระทบที่ยืนยันได้ ไม่ได้พบหลักฐาน guest escape
หรือ secret รั่วออกจาก sandbox ในการตรวจครั้งนี้

## การตรวจสอบที่รันจริง

| การตรวจ | ผล |
|---|---|
| `cargo test --workspace --offline` | 342 passed, 0 failed, 3 ignored |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 109 tests, ผ่าน 107, skipped 2 |
| `cargo clippy --workspace --all-targets --offline -- -D warnings` | ผ่าน |
| `cargo fmt --all -- --check` | ผ่าน |
| `python3 scripts/check-ci-parity.py` | ผ่าน |
| `target/debug/aivm demo` | 14/14 ผ่าน |

ไม่ได้รัน `make ci` ทั้งชุดหรือทดสอบ GGUF/KVM/container บน host จริงในรอบนี้
จำนวน tests ที่ผ่านจึงไม่ใช่หลักฐานยืนยัน isolation tiers เหล่านั้น
ข้อค้นพบด้านล่างเกิดได้แม้ชุดทดสอบข้างต้นผ่านทั้งหมด

เก็บ logs และโปรแกรมจำลองไว้ใน `target/review-2026-10-23/` ซึ่งถูก Git ignore
รายละเอียดคำสั่งอยู่ใน `target/review-2026-10-23/README.md`

## บั๊ก

### B1 — P1: inspect กู้ transaction ซ้อนกับงานที่ยังถือ lock จน audit chain เสีย

ตำแหน่ง: [Supervisor::inspect](../crates/aivm-supervisor/src/lib.rs#L306),
[Runtime::init](../crates/aivm-runtime/src/lib.rs#L458),
[transaction recovery](../crates/aivm-runtime/src/transaction.rs#L152)

`inspect` เรียก `Runtime::init` โดยไม่ acquire VM lease แต่ `init` สามารถกู้
state transaction และแก้ audit/state ได้ ขณะที่ `transition` กับ `approve-secret`
ใช้ exclusive lease อยู่ คำสั่ง CLI `state` และ `capabilities` เรียกเส้นทาง inspect
เดียวกัน จึงมีปัญหานี้ด้วย

Reproduction ใช้ CLI จริงและ shim ชะลอหลัง rename journal สำเร็จ เพื่อกำหนด
จังหวะ thread/process ให้ทำซ้ำได้ shim ไม่เปลี่ยน state, audit, lock หรือ return value:

1. สร้าง VM ใหม่ แล้วเริ่ม `transition ... ANALYZE`
2. หยุดรอหลัง publish `.state-transaction.json` ก่อน append prepare
3. ยืนยันด้วย `flock(LOCK_EX | LOCK_NB)` ว่า transition ถือ `runtime.lock` จริง
4. เรียก `inspect`: exit 0, append `transition-rollback` และลบ journal
5. ปล่อย transition เดิมให้ทำต่อ

ผลจริง:

```text
inspect returncode: 0
journal exists after inspect: False
original transition returncode: 1
audit verification: CHAIN BROKEN: sequence gap: expected 1, got 0
```

state บนดิสก์จบที่ `ANALYZE` ทั้งที่ transition คืน error และไม่มี journal เหลือ
audit มี rollback seq 0 ตามด้วย prepare seq 0 และ commit seq 1
การเปิด runtime ครั้งถัดไปจะติดการตรวจ chain ที่เสีย
เป็นปัญหา integrity/availability จากคำสั่ง operator สองคำสั่งที่ทำงานพร้อมกัน
ไม่ต้องอาศัย guest escape

แนวทางแก้: ให้ทุกเส้นทางที่เรียก recovery ถือ lease เดียวกัน หรือแยก inspect
ให้อ่าน snapshot โดยไม่มี recovery/side effect พร้อมทดสอบ concurrent inspect
กับ transition และ secret approval ในจังหวะ publish/commit/recovery

### B2 — P2: audit รายงาน chain verified ทั้งที่ archive ต้นสายหายไป

ตำแหน่ง: [verify_sequence](../crates/aivm-audit/src/lib.rs#L421),
[CLI audit](../crates/aivm-cli/src/main.rs#L418)

`verify_sequence` ตรวจรอยต่อเฉพาะไฟล์ที่สองเป็นต้นไป แต่ไม่ตรวจว่า record แรก
ของไฟล์แรกมี `hash_prev` ว่างหรือมี trusted anchor ที่ยืนยันต้นทาง
การยอมรับ continuation มีประโยชน์กับ API ตรวจบางช่วง แต่ CLI ไม่รายงานว่าตรวจได้เพียง suffix

จำลองโดยสร้าง log, rotate หนึ่งครั้ง, append ใน active log แล้วเอา archive
ออกจากชุดหลักฐาน เหลือ active log ที่เริ่มด้วย resume:

```text
verify_sequence=Ok(2)
audit audit-prefix: 1 file(s), 2 entries, chain verified
```

คำสั่ง exit 0 แม้ history ก่อน rotation ไม่อยู่แล้ว จึงใช้ผลนี้ยืนยันความครบถ้วน
ของประวัติไม่ได้ ข้อนี้ไม่ใช่หลักฐานว่า agent ลบไฟล์ audit ของ host ได้

แนวทางแก้: ให้ CLI ที่ตรวจทั้งประวัติต้องเริ่มจาก genesis หรือรับ trusted anchor
แบบ explicit และแสดงขอบเขต partial-chain ให้ชัดเจน รักษา API ตรวจ suffix
แยกไว้ได้ พร้อม regression สำหรับ archive แรกหายและ genesis หาย

### B3 — P2: search:code เพียงสิทธิ์เดียวค้นไม่เจอไฟล์ แต่คืน success

ตำแหน่ง: [context_files](../crates/aivm-tools/src/lib.rs#L750),
[search](../crates/aivm-tools/src/lib.rs#L781)

Config ยอมรับ `capabilities.initial: [search:code]` และ `search()` authorize
capability นี้สำเร็จ แต่ `context_files()` คัดเฉพาะไฟล์ที่มี capability `read`
แล้วเรียก `read()` อีกครั้ง ทำให้ไฟล์ทุกใบถูกข้ามเมื่อมี search อย่างเดียว

จำลองด้วยไฟล์ `sample.txt` ที่มี `unique-review-marker`:

```text
SEARCH_ONLY decision=allow ok=true output=""
```

ผลคือสิทธิ์ search ที่ออกให้ใช้งานไม่ได้โดยลำพัง และผู้เรียกแยกไม่ออกระหว่าง
ไม่มีผลค้นหากับไม่มีสิทธิ์อ่านข้อมูลที่ search จำเป็นต้องใช้

แนวทางแก้: กำหนดสัญญา search ให้ชัด ถ้า search อนุญาตค้นเนื้อหาได้ด้วยตัวเอง
ให้เส้นทางอ่านภายในผูกกับ search capability และ quota ของใบเดียวกัน
ถ้าต้องใช้ read ร่วมด้วย ให้ตรวจและคืน denial ชัดเจนแทน empty success

### B4 — P2: inspect/capabilities แสดงสิทธิ์แบบ hardcoded ไม่ตรงกับ state จริง

ตำแหน่ง: [Runtime::inspect](../crates/aivm-runtime/src/lib.rs#L838),
[CLI aliases](../crates/aivm-cli/src/main.rs#L404)

ข้อความแสดง `READ <workspace>`, `Denied: NETWORK`, `DEPLOY` และ `Processes: 0`
เป็น literal ไม่ได้สร้างจาก capability set, policy หรือสถานะ process

จำลอง config ที่อนุญาต `example.com` แล้ว transition ถึง `VALIDATE`
ด้วย guard ที่ผ่าน พบ capability `network:fetch` และ `network:connect`
สำหรับ `example.com:443` ซึ่งยังไม่หมดอายุ แต่ inspect ยังคงแสดง `NETWORK`
ใต้ Denied ส่วน VM ที่มี search อย่างเดียวก็ยังถูกแสดงว่ามี READ

เป็นความผิดพลาดของข้อมูลที่ใช้ตรวจสิทธิ์ ไม่ได้แปลว่าตัว enforcement อนุญาต
เกิน policy แนวทางแก้คือแสดง grants, scopes, expiry/usage และข้อจำกัดจากข้อมูลจริง
แยกสถานะที่วัดไม่ได้ออกจากค่าศูนย์ และทดสอบแต่ละ state กับ config ที่จำกัดสิทธิ์ต่างกัน

## Technical debt และข้อจำกัด

### D1 — Dashboard มีช่องว่างการเก็บเหตุการณ์ระหว่างการอ่าน

ตำแหน่ง: [deque ก่อน filter](../scripts/aivm-dashboard.py#L79),
[เอกสารขอบเขต](dashboard.md#L41)

อ่านเฉพาะ `max_entries` บรรทัดท้าย ก่อนคัด DENY/budget/quarantine
จำลอง `max_entries=3` แล้วเพิ่ม DENY 1 บรรทัดตามด้วย ALLOW 3 บรรทัดระหว่าง sync
สองครั้ง พบ DB เก็บ DENY 0 รายการ แต่ `audit_read_success=True`
ค่า default ก็เกิดรูปแบบเดียวกันเมื่อมีบรรทัดใหม่เกิน 500 บรรทัดระหว่างการอ่าน

จัดเป็นข้อจำกัดที่มีเอกสารระบุแล้ว ไม่ใช่บั๊กผิดสัญญาที่เพิ่งค้นพบ
ถ้าจะใช้ dashboard ติดตามเหตุการณ์อย่างต่อเนื่อง ควรมี cursor ตาม inode/offset,
การตาม rotation และตัวบอก coverage/gap แยกจากการเปิดไฟล์อ่านสำเร็จ
ปัจจุบันยังใช้แทน event collector ที่เก็บครบไม่ได้

### D2 — อายุ plaintext ในสำเนา secret lease ยังยาวกว่าการใช้งาน

ตำแหน่ง: [use_lease/revoke_lease](../crates/aivm-secrets/src/lib.rs#L374),
[cleanup](../crates/aivm-secrets/src/lib.rs#L506)

หลังใช้ one-time lease จน Exhausted และหลัง revoke ยังพบ `lease.value`
ของข้อมูลสังเคราะห์ยาว 20 bytes อยู่ใน broker ส่วน `cleanup` ลบ String
ตามปกติโดยไม่ zeroize และไม่พบผู้เรียก cleanup ใน production path ที่ตรวจ
การ zeroize ใน gateway ล้างเพียงสำเนาบางส่วน ไม่ได้ครอบคลุม lifetime ทุกสำเนา

เป็น security hardening/memory lifecycle debt ไม่ใช่หลักฐานว่า secret หลุด
หรือ exhausted lease กลับมาใช้งานได้ Canonical value ใน broker ต้องเก็บเพื่อ
ออก lease ใหม่อยู่แล้ว แต่สำเนาที่หมดหน้าที่ควรล้างและถอดออก พร้อมใช้ RAII
ที่ล้างข้อมูลเมื่อออกจาก scope รวม error paths

### D3 — มีตัวสร้าง policy สองชุดที่ให้ความหมายต่างกัน

ตำแหน่ง: [Runtime::init](../crates/aivm-runtime/src/lib.rs#L351),
[config::build_default_policy](../crates/aivm-runtime/src/lib.rs#L1169)

Runtime ใช้ workspace จริงและ `filesystem.read/write` จาก config แต่ config API
สร้าง scope `/workspace/<name>` และค่าคงที่ read/write อีกชุดหนึ่ง
ค่า `require_test_before_network` ก็ถูกกำหนดต่างกันระหว่างสองเส้นทาง
ไม่พบ production caller ของ `config::load_and_validate` ใน repository ปัจจุบัน
จึงไม่จัดความต่างนี้เป็นบั๊กที่กำลังกระทบ CLI แต่เป็น public API/maintenance debt
ที่ทำให้ผู้ใช้ API หรือการเปลี่ยนเส้นทางในอนาคตได้รับ policy คนละความหมาย

ควรรวมการสร้าง policy ไว้จุดเดียวโดยรับ workspace/context ที่จำเป็นชัดเจน
หรือเลิกเปิดเผย adapter ที่ไม่ได้ใช้ และทดสอบความหมายของ policy จาก config จริง

## ลำดับแก้ที่แนะนำ

แก้ B1 ก่อน เพราะคำสั่งดูสถานะสามารถทำให้ audit/state ใช้งานต่อไม่ได้
ตามด้วย B2 และ B4 เพื่อให้ผลตรวจ integrity/สิทธิ์เชื่อถือได้ แล้วแก้ B3
ส่วน D1 ให้จัดลำดับตามว่าจะใช้ dashboard เป็นเพียงหน้าต่างดูข้อมูลหรือเป็น monitoring หลัก
รายการและผลทดลองข้างต้นเป็น baseline ก่อนแก้ สถานะหลังแก้และ regression อยู่ต้นรายงาน
