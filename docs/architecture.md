# Architecture — ภาพรวมระบบ

## เส้นทางของหนึ่ง action

```text
AI (คิดอิสระ)
 │  intent (JSON เข้มเท่านั้น ไม่ใช่คือ DENY)
 ▼
Cube (state + confidence + guards — §14: guard คือหลักฐาน operator)
 │  capability check (execute/read/… + scope)
 ▼
Policy Engine (allowlist, deny-by-default, deny-overrides)
 │  ├── DENY → audit (I-7) → จบ
 │  └── ALLOW
 ▼
Tool (filesystem / network / process.exec — ผ่าน gateway เท่านั้น)
 ▼
Sandbox (ดูตาราง isolation)
```

AI ไม่มี direct access ไปยัง host OS (I-1) ทุกขั้นตรวจก่อนรัน (I-9)
สงสัย = DENY (I-6) AI แก้ boundary ตัวเองไม่ได้ (I-5)
deny burst (20 ครั้ง/60 วิ) = quarantine ทั้ง gateway 60 วิ (circuit breaker
กัน runaway loop — เรียก method ตรงโดยไม่ผ่าน dispatch ก็หนีไม่พ้น,
operator transition ล้างได้, ไม่ยืดเวลาเอง)

## Secrets (G4 §26)

`secret.request` (structured schema เข้ม) → broker ตรวจ capability + policy →
Low-risk ที่ operator ตั้ง `low_risk_allow` ออก one-time lease (คืนแต่ lease_id) / High-risk ไม่มี approval =
DENY + audit `hitl-required` → `process.exec` แนบ `{"argv":[…],"secret":id}`
ฉีดค่าเข้า child env (`env_extra` ช่องเดียว) แล้ว zeroize + ปิด process output/สิทธิ์เขียนไฟล์ — value ไม่มีทาง
อยู่ AI context/memory/audit (redaction โดย construction) ระดับ microvm
inject ไม่ได้ = DENY ตรง ๆ ไม่เงียบทิ้ง

High-risk flow (G4b): request → pending (deny + lease id ใน audit) →
operator `approve-secret` ด้วย id ตรงตัว (audit ระบุคน) → ใช้ได้ตาม
max_uses/TTL เดิม ข้าม restart ได้ (persist 0600, หมดอายุทิ้ง) ใช้ก่อน
approve = DENY (`lease-not-approved`)

## Isolation levels (`runtime.isolation`)

| ค่า | backend | สถานะ |
|---|---|---|
| `sandbox` / `process` | Landlock ABI >= 3 + seccomp (บังคับ), user/mount/net namespace แบบ best-effort พร้อมรายงานจริง, rlimit, CPU affinity, deadline, process group cleanup | default (MVP-B) |
| `microvm` | บูต guest จริงต่อครั้ง (Firecracker/KVM, drive-stuffing, ไม่มีเน็ต) | ต้องเปิดฟีเจอร์ `microvm` + บล็อก pins (ดู `docs/microvm.md`) |
| `container` | ยังไม่มี backend → DENY พร้อม audit | fail-closed |
| `hardware` | อนาคต (สเปก §Level 3) → DENY พร้อม audit | fail-closed |
| ค่าอื่น | config ผิด → บูตไม่ขึ้น | fail-closed ไม่เงียบไปใช้ sandbox |

## State machine + dynamic capability (§14)

`INIT → ANALYZE → MODIFY → VALIDATE → DEPLOY` (กระโดด = ปฏิเสธ)
guard ต่อขอบ: `confidence` (→MODIFY), `tests_passed` (→VALIDATE),
`policy_approved` (→DEPLOY — HITL ฝั่ง operator) สิทธิ์ให้แบบ JIT ตาม state
และ revoke เมื่อหมดความหมาย lease ที่ยังใช้ได้รอดข้าม restart ผ่าน `state.json`
(ไฟล์เสีย = เริ่มใหม่ด้วยสิทธิ์ INIT ขั้นต่ำ)

## Audit (I-7, I-10)

- Hash version 2 ครอบคลุมหลักฐานทุกฟิลด์; audit failure หยุดก่อน action (รุ่นเก่าไม่มีหลักประกันเพิ่มย้อนหลัง)
- ทุก request + decision + outcome ลง `audit.jsonl` **นอก** boundary ที่ agent แตะถึง
- append-only + hash chain (`verify_sequence`, `aivm audit`) + `rotate()`
  (archive ถูกผนึก ห้ามเขียนทับ)
- decision ที่ deny (รวมระดับ level) มี record ครบ — เงียบหายไม่ได้

## Invariants (สเปก §35, non-negotiable)

I-1 ไม่มี direct host access · I-2 ทุก action ต้องมี capability ·
I-3 ทุก capability ต้องมี policy · I-4 transition ต้อง validate ·
I-5 แก้ boundary ตัวเองไม่ได้ · I-6 fail-closed · I-7 audit ครบ ·
I-8 least privilege (scoped/time-bounded/JIT) · I-9 ตรวจก่อนรัน (+TOCTOU hardening) ·
I-10 boundary ระดับโครงสร้าง (namespace/seccomp/mount/capability-drop)

มี invariant suite (`I-1`–`I-10`) + adversarial suite (สเปก §38) คุมใน
`crates/aivm-adversarial`

## Crate map

`capability` → `policy` → `cube`, `audit` → `tools` →
`memory` / `network` / `sandbox` / `model` → `runtime` (รวม `runtime::demo`) →
`supervisor` → `cli` (ห้ามวน) ดู `crates/<ชื่อ>/src/` ตามแผนที่นี้ได้เลย
