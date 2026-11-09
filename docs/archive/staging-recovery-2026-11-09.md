# Staging lease/recovery: deterministic tests, strace และ nextest — 2026-11-09

สถานะ: **ปิดส่วน 3 ของ [structured output test plan](../structured-output-quality-test-plan.md)**
บน base `cc6960f` (ทำงานใน working tree; ไม่รวม model host evaluation ซึ่งต้องใช้ KVM/pins)

## ปัญหาเดิม

`recovery_skips_active_leases_and_removes_abandoned_requests` ใช้ `/tmp` ร่วมกัน
ทุก test แล้ววน `recover()` + `sleep(10ms)` สูงสุด 2 วินาทีเพื่อรอให้ directory
หายไป การรอซ้ำนี้กลบสาเหตุจริงและทำให้ผลขึ้นกับจังหวะ fork ของ test อื่น:

- staging directory ทุกตัวอยู่ใต้ `std::env::temp_dir()` เดียวกัน
- `recover(root)` สแกนทุก entry ใต้ root; test หนึ่งจึงเห็น lease ของอีก test
- `flock` ผูกกับ open file description ซึ่งถูกคัดลอกข้าม `fork`
  แม้ fd จะเป็น `O_CLOEXEC` (หายตอน `exec`) แต่ช่วง `fork → exec` ลูกยังถือ lock
  อยู่ ทำให้ recovery เห็น `EAGAIN` ชั่วคราวและ skip อย่างถูกต้องตาม fail-safe

สรุป: สัญญา recovery ไม่ผิด; ที่ผิดคือ test isolation (shared root) และการใช้
retry/sleep แทนการพิสูจน์ ownership

## สิ่งที่เปลี่ยน

- `StagedConfig::new_in(root)` เป็น test seam; production `new()` ยังใช้
  `std::env::temp_dir()` ตามเดิม — recovery/flock logic ไม่เปลี่ยน
- `TestRoot` สร้าง root 0700 ไม่ซ้ำต่อ test และลบทิ้งเมื่อจบ
- `recovery_keeps_owned_leases_and_removes_abandoned_requests` ตรวจสองด้าน
  แบบ deterministic: lease ที่ยังถืออยู่ต้องรอด, หลังปิด descriptor แล้วต้องกู้ได้
- `recovery_respects_a_live_lease_holder_process` ใช้ subprocess จริง +
  pipe barrier: child ประกาศ directory, ถือ lease, รอ byte, แล้วจบ process;
  recovery ต้อง `EAGAIN`/skip ขณะ child มีชีวิต และกู้ได้หลัง `wait()`
- `concurrent_recovery_stress` (ignored) รัน 1,000 รอบ ขนาน 8 threads
- `.config/nextest.toml`: `retries = 0`, process-per-test, profile `ci`
- `cargo-nextest` pin `0.9.151`; `make test-nextest` + CI step + parity check
- `scripts/staging-strace.sh` / `make strace-staging` สำหรับเก็บหลักฐาน syscall
- ไม่มี `sleep` หรือ retry ใน test ที่ใช้ตัดสินผล

## ผลที่วัดได้

```text
make test-staging
  cargo test -p aivm-model --lib worker::staging::tests -- --test-threads=8
  5 passed, 1 ignored

make test-nextest
  cargo nextest run --workspace --profile ci (nextest 0.9.151)
  518 tests run: 518 passed, 14 skipped (ignored), 27.8s

make test-staging-stress
  AIVM_STAGING_STRESS_ROUNDS=1000 AIVM_STAGING_STRESS_THREADS=8
  1 passed, 0 failed, 0.11s
  residual /tmp/aivm-staging-test-* = 0, /tmp/aivm-model-* = 0
```

`make verify`, `make check-llama` และ `make test-llama` ผ่านหลังการเปลี่ยน
(report ten ล่าสุด: `verify: all green`, demo 14/14)

## หลักฐาน strace

`make strace-staging` เขียน `target/staging-strace-2026-11-09/strace.log`
(1.4 MB, `-f -yy -e trace=%process,%file,flock`). ลำดับสำคัญของ holder
คนเดียว (pid 117873 recovery, 117874/117875 holder):

```text
117875 openat(..., ".lease-pending", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3
117875 flock(3<.../.lease-pending>, LOCK_EX|LOCK_NB) = 0
117875 rename(".../.lease-pending", ".../.lease") = 0
117873 openat(..., ".lease", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = 7
117873 flock(7<.../.lease>, LOCK_EX|LOCK_NB) = -1 EAGAIN (Resource temporarily unavailable)
117874 execve(".../aivm_model-...", ["--exact", "worker::staging::tests::lease_holder_child", ...]) = 0
117874 exit_group(0) = ?
117873 flock(6<.../.lease>, LOCK_EX|LOCK_NB) = 0
117873 unlinkat(7<.../, ".lease", 0) = 0
117873 unlinkat(AT_FDCWD, ".../aivm-model-...", AT_REMOVEDIR) = 0
```

สิ่งที่พิสูจน์ได้: `.lease-pending` เป็น `O_CLOEXEC`; recovery ถูกปฏิเสธด้วย
`EAGAIN` ขณะ holder มีชีวิต; หลัง `exit_group` ของ holder (kernel ปิด fd)
recovery lock ได้และลบ `.lease` + directory สำเร็จ — ไม่มี retry/sleep
และไม่มี PID-reuse assumption

## ข้อจำกัด

- Stress 1,000 รอบใช้เวลาสั้น (~0.11s) เพราะ operation เป็น filesystem ใน
  `/tmp`; จำนวนรอบไม่ใช่ข้อพิสูจน์ว่าไม่มี race ใน production เสมอ
  แต่ test ที่ตัดสินผลเป็น deterministic และ nextest แยก process ต่อ test
- `14 skipped` เป็น test ที่ `#[ignore]` (รวม stress); ไม่ถูกนับว่าผ่าน
- recovery lock `/tmp/.aivm-staging-recovery-<uid>.lock` ยังคงอยู่โดยเจตนา
  (ทุก writer ต้อง lock inode เดียวกัน) — ไม่ใช่ residual ของ request
- Model host evaluation (KVM/pins) และ MicroVM/Container จริงไม่ได้อยู่ใน
  รอบนี้; ไม่มีการอ้างผล host validation จาก unit/CI
