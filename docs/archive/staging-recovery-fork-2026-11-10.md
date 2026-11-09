# Staging recovery: fork-inherited lease regression — 10 November 2026

แก้ต่อจากรายงาน [9 พฤศจิกายน](staging-recovery-2026-11-09.md) บน baseline
`cb64ef9` พร้อม working-tree changes เฉพาะ test และเอกสาร
หลักฐานอยู่ใน `target/staging-recovery-fork-2026-11-10/` และไม่ commit raw logs

## สาเหตุและ reproduction

CI ล้มที่ `recovery_keeps_owned_leases_and_removes_abandoned_requests`
หลัง parent ปิด lease แต่ staging ยังอยู่ รัน test เดี่ยวผ่าน
เมื่อรัน native model suite แบบขนาน 32 threads บน host เดิม ทำซ้ำ failure
เดียวกันได้ที่รอบ 24: `59 passed; 1 failed; 1 ignored`
เก็บทั้ง 23 รอบที่ผ่านและ failure แรกไว้ใน `host-baseline-*.log`
พร้อมผลรายรอบใน `host-baseline-runs.json`

Private root ต่อ test ป้องกันการสแกน directory ข้าม test แต่ยังไม่ป้องกัน
descriptor inheritance: test thread อื่นอาจ fork ขณะที่ lease เปิดอยู่
child จะถือ open file description เดียวกันจน exec แม้ parent ปิด fd แล้ว
ดังนั้นข้อสรุปก่อนหน้าว่าแยก root แล้ว assertion นี้ deterministic ยังไม่ครบ
การที่ recovery เห็น lock และยังไม่ลบ directory เป็นพฤติกรรมที่ถูกต้อง

## สิ่งที่แก้

- Ownership test และ concurrent stress สร้าง lease ใน subprocess ที่เลือก
  test เดียวด้วย `--exact --test-threads=1` จึงไม่มี test อื่น fork ไปถือ lease
  parent suite และ stress ภายใน subprocess ยังรันขนานตามเดิม
- เพิ่ม `recovery_keeps_a_fork_inherited_lease_until_exec` ใช้ Unix socket barrier
  หยุด child ใน `pre_exec` ตรวจว่า lease เป็น CLOEXEC แล้วปิด lease ฝั่ง parent
  recovery ต้องเก็บ directory ไว้ขณะ child ยังถือ fd หลังปล่อย barrier และรอ
  child exec/exit แล้ว recovery ต้องลบได้ทันที ไม่มี sleep/retry
- Barrier มี read timeout และปิดปลาย parent เมื่อ unwind เพื่อให้ child
  ออกจาก pre-exec barrier ได้เมื่อ assertion ล้ม
- การแก้โค้ดทั้งหมดอยู่ใต้ `#[cfg(all(test, unix))]`; production recovery,
  lease locking และ fail-closed behavior ไม่เปลี่ยน

## หลักฐาน syscall

`fork-strace.log` ของ regression ที่บังคับจังหวะเองแสดงลำดับนี้
(ย่อ pathname ของ staging):

```text
20970 clone(..., flags=...|SIGCHLD, ...) = 20971
20969 close(3<.../.lease>) = 0
20969 flock(8<.../.lease>, LOCK_EX|LOCK_NB) = -1 EAGAIN
20971 execve("/bin/true", ["/bin/true"], ...) = 0
20969 flock(6<.../.lease>, LOCK_EX|LOCK_NB) = 0
20969 unlinkat(..., ".lease", 0) = 0
```

Regression จึงตรวจทั้งการรักษา lease ที่ child สืบทอดและการกู้หลัง kernel
ปิด CLOEXEC fd โดยไม่อาศัยจังหวะ scheduler เพื่อให้เกิด race เอง

## ผลตรวจ

| การตรวจ | ผล |
|---|---|
| Staging tests, native runner / 32 threads | 6 passed, 0 failed, 1 ignored (stress แยกรัน) |
| Forced fork/exec regression พร้อม strace | Passed |
| Concurrent recovery stress | 1,000 รอบ / 8 threads ผ่าน |
| Native model suite / 32 threads | 100/100 รอบผ่าน แต่ละรอบ 61 passed, 0 failed, 1 ignored |
| `make verify` บน host | ผ่าน: fmt, strict Clippy, Python/workspace tests และ demo 14/14; 86.173 s |

ทุก diagnostic attempt ถูกเก็บไว้ ไม่มีการเปลี่ยน failure เป็นผลผ่านด้วย retry
จำนวน stress/parallel runs เป็นหลักฐานเสริม; barrier regression เป็นตัวพิสูจน์
ลำดับ ownership ไม่ใช้เพียงจำนวนรอบที่ผ่านแทน proof

`cargo-nextest` ไม่มีติดตั้งบน host ของรอบนี้ จึงไม่ได้รัน nextest ซ้ำ
CI ยัง pin nextest 0.9.151 และตั้ง `retries = 0` ตามเดิม
รอบนี้ไม่รวม real-model/KVM host evaluation ใหม่ ผล host validation ก่อนหน้า
ยังอ้างอิง commit ที่ระบุในรายงานของรอบนั้น

ไฟล์หลักสำหรับตรวจย้อนหลัง: `regression-results.json`, `fixed-parallel-*.log`,
`fork-trace.log`, `fork-strace.log`, `stress.log`, `verify.log`,
`verify-result.json` และ `summary.json`
