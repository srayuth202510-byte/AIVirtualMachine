# Threat Model — นิยาม threat ของ AIVM

> กฎ: threat ทุกตัวต้องผูกกับ **signal ฝั่ง host ที่มีอยู่จริง** + **test ที่คุม**
> threat ไหนไม่มี test = สมมติฐาน ไม่ใช่หลักประกัน ดูช่องว่างท้ายไฟล์

สเปกอ้างอิง: invariants I-1–I-10 (§35), adversarial categories (§38)

## 1. Trust boundaries

```text
host / operator  ................. trust root (แตก = game over, §4 non-goals)
 │  runtime / gateway ............ trusted (capability → policy → tool)
 │   │  sandbox / VMM ............ boundary (namespace/seccomp/KVM)
 │   │   │  guest ................ untrusted
 │   │   │   │  agent / model ..... untrusted (คิดอิสระ, สั่งได้แค่ intent)
```

หลักการบังคับใช้: output ใน guest **ปลอมได้** signal ฝั่ง host **ปลอมไม่ได้**
การตรวจจับจึงอ่านเฉพาะ signal ฝั่ง host (`audit.jsonl`, exit path, parser verdict,
deadline) — serial log ของ guest ใช้สืบย้อนเท่านั้น ห้ามใช้ตัดสิน

## 2. Attacker positions

### A1 — agent โดน jailbreak / prompt-inject (นั่งใน guest)

- **ทำได้**: ส่ง intent อะไรก็ได้, ขอ tool ซ้ำ ๆ (probing), หลอกด้วย justification
- **อยากได้**: action นอกสิทธิ์ / ข้อมูลนอก workspace / หนีออก guest
- **ประตูที่กัน**: capability + policy allowlist + deny-overrides (I-2, I-3),
  structured intent (JSON เข้ม ไม่ใช่คือ DENY), justification เป็น metadata
  ไม่ใช่ trust signal, guest ไม่มีเน็ต
- **signal**: `DENY` ซ้ำใน audit + `invalid intent` + `no-capability`
- **test ที่มี**: `fs_escape_must_deny`, `dotenv_and_secrets_must_deny`,
  `symlink_escape_must_deny`, `shell_and_unknown_tools_must_deny`,
  `network_must_deny`, `exec_without_capability_denied`,
  `exec_policy_deny_wins`, `agent_intent_must_be_strict_json_to_execute`,
  `agent_loop_denies_non_json_model_output`, `i2`, `i3`, `i6`
- **หมายเหตุ**: diversity (DNA) **ไม่ช่วย** A1 — attacker อยู่ใน guest อยู่แล้ว

### A2 — input ปนเปื้อน (ไฟล์/repo ที่ agent อ่านมีคำสั่งฝัง)

- **ทำได้**: ฝังข้อความสั่งการในข้อมูล (prompt injection ผ่าน content)
- **อยากได้**: หลอก agent ให้ขอ action ที่ operator ไม่ตั้งใจ
- **ประตูที่กัน**: intent ต้องผ่าน capability/policy เหมือนเดิม + guard มาจาก
  operator (CLI flags) ไม่ใช่คำอ้างของ agent
- **signal**: intent ผิดปกติเทียบกับ task (ยังไม่มี baseline — ดูช่องว่าง G2)
- **test ที่มี**: บางส่วนผ่าน `agent_intent_must_be_strict_json_to_execute`
  (โครง intent เข้ม แต่ยังไม่ป้อน payload ปนเปื้อนจริง)

### A3 — guest-escape exploit (kernel / VMM bug)

- **ทำได้**: โค้ดใน guest → โจมตี host ผ่านช่องโหว่ KVM/firecracker/kernel
- **อยากได้**: หลุดออกมานอก VM
- **ประตูที่กัน**: KVM isolation + guest ไม่มีเน็ต + image ที่ pin + seccomp
  ฝั่ง host + `KillOnDrop`
- **signal**: VMM ตายก่อน marker, marker/exit parse ไม่ได้, timeout,
  seccomp kill — ทั้งหมดคือ "มีคนแตะกำแพง" ไม่ต้องตีความเจตนา
- **test ที่มี**: `exec_microvm_level_must_deny`, `garbage_kernel_fails_closed`,
  `tampered_artifact_fails_closed_as_invalid`, `wrong_fc_pin_fails_closed_as_invalid`,
  `missing_artifact_fails_closed_as_invalid`, `i10_structural_enforcement`
- **DNA ช่วยตรงนี้เต็ม ๆ**: layout/image/profile ไม่ซ้ำต่อบูต → exploit ที่ผูก
  กับค่าตายตัวใช้ไม่ได้ทุกครั้ง (ดู §3)

### A4 — ขโมย secret ข้าม instance

- **ทำได้**: อ่าน secret ที่ตัวเองได้ใน run นี้
- **อยากได้**: เอาไปใช้นอก run / ใน instance อื่น
- **ประตูที่กัน**: one-time lease (`max_uses`, expiry) + zeroize หลังใช้ +
  broker ไม่ log value + audit เฉพาะ metadata (§26)
- **signal**: `LeaseExhausted` / `LeaseExpired` / ใช้ lease ซ้ำ
- **test ที่มี**: `aivm-secrets` unit tests (exhaustion, HITL, deny pattern)
- **ช่องว่าง**: secrets crate ยังไม่ต่อเข้า gateway (standalone) — ดู G4

### A5 — supply chain (image / VMM ปลอม)

- **ทำได้**: สลับไฟล์ kernel/rootfs/firecracker
- **อยากได้**: ฝัง backdoor ใน guest หรือ VMM
- **ประตูที่กัน**: `verify_artifact` ทุกไฟล์ทุกครั้งที่รัน (hash mismatch =
  fail-closed) + verify สำเนาซ้ำหลังก็อป + pin VMM ถ้าตั้ง `fc_sha256`
- **signal**: `artifact hash mismatch` (Invalid ตั้งแต่ประตูก่อน boot)
- **test ที่มี**: `tampered_artifact…`, `wrong_fc_pin…`, `missing_artifact…`,
  `exec_with_tampered_artifact_denied_with_audit`,
  `exec_with_tampered_fc_pin_denied_with_audit`
- **หมายเหตุ**: monitoring ไม่ช่วย A5 — ต้องกันที่ verify (กันได้ 100% ถ้า
  trust root ของ hash ไม่แตก)

### A6 — host / operator โดนยึด

- **out of scope ชัดเจน** (ดู §4)

## 3. Instance DNA — สุ่มอะไรได้บ้าง (กัน A3 + A4)

สุ่มได้โดย contract ไม่พัง: nonce marker/scheme ต่อบูต (มีแล้ว), vcpu/mem
สุ่มในกรอบ quota, `boot_timeout` สุ่มใน 5..=600, init-script layout
(ชื่อ tmp, ลำดับ mount), เลือก image จากชุดที่ pin ไว้หลายชุด, jailer
profile variant, **secret lease ไม่ซ้ำข้าม run** (`max_uses=1` ต่อ boot)

ห้ามสุ่ม: exe/libs (ต้องตรง allowlist), kernel boot args หลัก, ความหมาย marker
สุ่มแล้วไม่มีผล (อย่าทำ): ชื่อ VM, UUID สวย ๆ — attacker ใน guest ไม่แคร์

DNA ทุกครั้งต้องลง audit (ไม่รวม secret) ไว้สืบย้อน

## 4. Non-goals (ไม่กัน ไม่แกล้งว่ามี)

- A6: host/operator compromise (trust root)
- Hardware side-channel (spec §Level 3 อนาคต)
- โมเดลโกหกเรื่อง confidence/justification (กันด้วย guard ฝั่ง operator แทน)
- Availability ภายใต้ DoS จากภายนอก (fail-closed อาจปฏิเสธงานตัวเอง — ยอมรับ)

## 5. ช่องว่าง (threat มี แต่ test/signal ยังไม่มี)

| id | threat | ของที่ขาด | ความสำคัญ |
|---|---|---|---|
| G1 | A1 probing | ✅ เสร็จ: `DenyTracker` (20 denies / 60s → quarantine 60s ทั้ง gateway ทุก method รวมเรียกตรง + audit `quarantine-started`/`quarantine-probing` + ไม่ยืดเวลาเอง + operator transition ล้าง) — เป็น circuit breaker กัน runaway loop/burst ไม่ใช่ตัวจับ slow probing | เสร็จ |
| G2 | A2 poisoned input | test ป้อน payload ปนเปื้อนผ่าน read → intent ต้องไม่ escalate | กลาง — design กันอยู่ แต่ไม่มี test ผูก |
| G3 | A3 escape signal | ✅ เสร็จ: `RunVerdict` (`Clean`/`Suspect`/`Compromise` + reason ตายตัว) แนบคู่ error ทุกขั้นบูตแบบ explicit + ลง audit ทุก decision — VMM ตายก่อน marker / สำเนาถูกสลับ = `Compromise`, timeout / marker หาย / exit parse ไม่ได้ = `Suspect`, deny ตั้งแต่ประตู / infra ล้ม = `Clean` | เสร็จ |
| G4 | A4 gateway wiring | ✅ เสร็จ: `secret.request` tool (strict schema) + broker ตรวจ capability/policy + Low ออก lease (คืนแต่ id) / High deny `hitl-required` + `process.exec` ฉีดเข้า child env ช่องเดียว + zeroize + audit ไม่มี value + microvm deny ตรง | เสร็จ (เหลือ G4b: approve flow สำหรับ High-risk — ดูข้างล่าง) |
| G5 | A3/A4 DNA | ✅ เสร็จ: DNA ต่อบูต (marker scheme V0/V1 + init tmp layout + เลือก image จากชุดที่ verify แล้ว + jitter resource opt-in + secret lease ไม่ซ้ำ) + dna id ลง audit (`dna:s…`) | เสร็จ |

ลำดับแนะนำ: ~~G3 → G5 → G1 → G4 →~~ G2

## 6. งานค้างหลัง G4 (G4b — approve flow สำหรับ High-risk)

G4 ที่เสร็จครอบคลุม: request → lease (low) / deny (high) → inject → audit
ส่วนที่ยังไม่มี: pending lease + operator approve (`aivm approve-secret`
หรือเทียบเท่า) + lease persistence ข้าม restart (ตอนนี้ approve หายเมื่อ restart
= fail-closed ปลอดภัย) — ออกแบบก่อนลงมือ (threat: approval phishing /
confused deputy ผ่าน lease id เดา)
