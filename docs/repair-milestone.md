# Milestone: bug report → protected verification → reviewable patch

ขอบเขตรอบนี้คือเส้นทางแก้โค้ดที่ทำซ้ำได้ ยังไม่เพิ่ม Planner, Reviewer หรือ parallel roles
runtime/isolation/RAG เป็นกลไกรองรับเส้นทางนี้ ไม่ใช่คะแนนความสามารถของโมเดล

## ผลสุดท้ายจากแหล่งเดียว

`AgentRun.outcome` และ `SemanticRun.outcome` ใช้โครงสร้างเดียวกัน:

```json
{
  "schema": 1,
  "task_id": "host-issued-uuid",
  "task_revision": 1,
  "execution": "completed",
  "verification": "passed",
  "solution_origin": "model_repair",
  "tested_workspace_digest": "sha256:...",
  "current_workspace_digest": "sha256:...",
  "receipt_ids": ["gateway-audit-entry-hash"],
  "reason": "current-task gateway receipt matches final workspace",
  "audit_id": "task-outcome-audit-entry-hash"
}
```

execution แยก `completed`, `budget_exhausted`, `stalled`, `failed`
verification แยก `passed`, `failed`, `unverified`, `stale`
solution_origin แยก `model`, `model_repair`, `tool_solver`, `operator_patch`, `unknown`
การรันจบหรือสรุปว่า "done" ไม่ใช่ verification และ helper ที่คำนวณถูกยังเป็น `tool_solver`
`verification_status` / semantic `status` เดิมเป็น compatibility mirrors ที่แปลงจาก outcome ตอนจบ
ตัววัด semantic evidence ตรวจ canonical outcome กับ audit เพิ่มแล้ว

gateway เปิด TaskContract ของ operator ก่อนเริ่มงาน ระบุ task ID, revision, digest ของ task
และ source ตั้งต้น ก่อนยอมรับผลตรวจต้องเป็น receipt ที่ gateway ออกใน task รอบนั้นจริง
พร้อม digest ของ workspace ปัจจุบันตรงกับที่ตรวจ ไม่รับ receipt จาก JSON/คำอ้างของโมเดล
receipt ของ task ก่อนหน้า หรือ source ก่อนแก้ไฟล์ ต่อให้ exit 0 หรือ hash ของ source บางไฟล์ตรงกัน
metadata ของ task, receipt และ outcome อยู่ใน audit chain ตามลำดับ
เมื่อ restart จะไม่ฟื้น in-memory authority ของ receipt เก่า ต้องตรวจใหม่

## Artifact handoff

ArtifactContract ระบุ task ID/revision/digest, artifact revision/kind, byte length,
content digest, workspace digest, evidence IDs และ audit ID ของการออก artifact
`publish_artifact` เป็น API ของ host หลัง finalization ไม่ใช่ tool ที่โมเดลเรียกได้
gateway ปฏิเสธ outcome ที่ไม่ได้ออกเองและ source ที่เปลี่ยนก่อน publish
consumer ต้องตรวจ body ของ artifact กับ audit entry รวมถึง task/revision/hash ของ bytes ที่รับจริง
การมี hash string หรือ receipt ID อยู่เฉย ๆ ไม่ใช่หลักฐาน
`ArtifactContract::validate_for` ตรวจ identity/bytes เทียบ trusted contract/evidence ที่ caller ตรวจ audit แล้ว
ตัว release gate ทำการตรวจ body กับ audit ด้วย

## Benchmark 24 งาน

corpus อยู่ใน `examples/repair-benchmark.json` เป็นงาน synthetic C ขนาดเล็ก 24 งาน:
arithmetic, branching, boundary cases, loops, arrays, strings, bits และ searches
แต่ละงานมี bug report, source ที่มีบั๊ก, reference patch และ protected oracle ของ operator
reference patch อยู่ใน corpus ของ host ไม่ส่งเข้าพื้นที่ที่ agent อ่านได้

เส้นทางต่อหนึ่งงาน:

1. สร้างไฟล์ reproduction/verification ของ operator แยกจาก source ที่ agent เขียนได้
2. compile/run ผ่าน gateway ให้ baseline ล้มด้วย exit 1 ก่อนเริ่มแก้
3. ให้โมเดลอ่านและแก้ `src/main.c`; ไม่ให้เปลี่ยน verifier หรือสร้างไฟล์ source อื่น
4. operator plan compile/link/run protected verifier ผ่าน gateway หลัง edit
5. ออก canonical outcome และตรวจซ้ำโดย operator
6. เก็บ `source.c`, `patch.diff`, audited ArtifactContract และ audit log สำหรับ review

reproduction test รอบนี้มาจาก operator corpus; **ยังไม่อ้างว่าโมเดลสร้าง regression test เอง**
reference controls ยืนยันเพียงว่า benchmark แยก buggy/fixed source ได้ ไม่ใช่ model capability
mode `reference_control` ใช้ `operator_patch`; release gate รับเฉพาะ `fresh_model`
ไม่มี semantic solver/reference fallback ใน model repair benchmark
นี่ไม่ใช่ benchmark แก้ production repositories หรือการรับรอง general coding success rate

```sh
# ไม่ใช้โมเดล; output directory ต้องเป็น directory ใหม่
python3 scripts/run-repair-benchmark.py --mode reference_control \
  --out target/repair-control-new

# ใช้ ModelConfig JSON ที่ pin model/worker และเตรียม host launcher ไว้แล้ว
python3 scripts/run-repair-benchmark.py --mode fresh_model \
  --profile release --model-config /path/approved-candidate.json --out target/repair-model-new
```

runner ไม่เปลี่ยน pins ให้เข้ากับ binary ที่พบ เมื่อ pin ไม่ตรงจะเก็บ preflight failure
candidate ใหม่ที่ build จาก source ต้องมี identity/hash ของ build output แยกจาก config ที่อนุมัติเดิม
runner ใช้ release build โดยค่าเริ่มต้นและบันทึก profile; release gate ไม่รับ fresh-model debug benchmark
worker candidate ที่ใช้วัดต้นทุนควร build ด้วย `cargo build --release --locked -p aivm-model-worker --features llama,microvm`
timeout/interrupt ของ runner ส่งสัญญาณหยุด cargo/test process group ไม่ทิ้ง test รันต่ออย่างเงียบ ๆ
ผลของ development candidate บน dirty tree ยังไม่ใช่ release approval แม้ benchmark รันครบ
output เป็น report พร้อม patches; correctness ต้องตรงกับ canonical outcome และ receipts
partial runs, skipped tests, artifact/audit ที่เปลี่ยน และคะแนนที่ไม่ตรงหลักฐานไม่ผ่าน validator
กรณีโมเดลแก้ไม่ได้เป็น task failure; infrastructure failures แยกจากคะแนนและไม่เป็น release evidence

## Cost ต่อ successful model repair

รายงานต่อ task และรวมทุก task รวมงานที่ล้มเหลว: total wall time, client initialization,
inference wall time, model calls, patch retries และ sampled process-tree RSS peak
reported input/output tokens มาจาก pinned worker ผ่าน `Model::last_usage()` เมื่อมี
ประมาณการจาก `token_count` เก็บแยก ไม่อ้างเป็น tokens ที่ worker รายงาน
request ที่ไม่มี usage มีตัวนับ unreported calls; token total จึงอาจเป็นเพียง lower bound
ตัว reducer แสดง total และ per-success โดยหารด้วยจำนวนงานสำเร็จจริง; เมื่อไม่มี success ใช้ null

model loading รวมอยู่ใน wall time ของ client initialization/inference โดยไม่ตัดออกจาก cost
ไม่ได้แยกเวลาการโหลด weights ออกจาก inference อย่างแม่นยำ จึงรายงาน `model_loading_ms: null`
RAM เป็นผลรวม RSS ของ process/descendants ที่ sample ทุก 25 ms ไม่ใช่ cgroup memory.peak
อาจนับ shared pages ซ้ำหรือพลาด spike สั้น ๆ ไม่ใช้แทน OS resource enforcement

## Failure injection และ recovery

มี SIGKILL จริง 20 boundaries: quota temporary write/fsync/rename, ก่อนเขียน source,
source temporary create/partial write/fsync/rename/directory sync,
audit append และ verifier receipt append/delivery
source write ใช้ pinned parent descriptor + temporary file + fsync + atomic rename
quota checkpoint เสร็จก่อน side effect ไฟล์จึงเป็นเก่าหรือใหม่ทั้งใบ ไม่ใช่ partial source
temporary namespace `.aivm-write-<uuid>.tmp` สงวนให้ runtime; โมเดลเขียนไม่ได้
Runtime.init กู้ temporary files ที่เป็น regular/one-link/owned/private ขณะ caller ถือ VM lease
ยอด quota ที่บันทึกแล้วไม่ถูกคืนเพราะ process ตาย และ receipt เดิมไม่ยกระดับ task ใหม่
ทดสอบ SIGKILL/process recovery ไม่ใช่การตัดไฟจริงหรือ disk-controller durability certification

```sh
cargo test --locked -p aivm-tools failure_tests:: --lib
make verify
```

## Release gate: exact commit เท่านั้น

host validator เก็บ source manifest ก่อน/หลัง ครอบ tracked และ untracked source,
candidate config digest, model/worker/kernel/rootfs/VMM pins, scenario logs และ recovery evidence
candidate config ต้องผ่าน `candidate-worker` โดยใช้ config นั้นจริง เพิ่มจาก validation ทั้ง 3 tiers
ทั้งสาม tiers ใช้สำเนา validated worker ที่ pin ไว้ชุดเดียวกัน ไม่รับ binary ที่ถูก rebuild เปลี่ยนระหว่าง scenarios
ตัว gate ต้องได้ clean tree ของ commit เดียวกันทุก evidence ไม่มีการนับผลของ ancestor หรือ dirty build แทน

```sh
python3 scripts/validate-model-host.py \
  --model /path/model.gguf --model-sha256 '<approved-model-pin>' \
  --pins /path/pins.json --candidate-config /path/approved-candidate.json \
  --worker-profile release --out target/release-host-new

python3 scripts/release-gate.py --commit '<full-40-hex-commit>' \
  --config /path/approved-candidate.json --pins /path/pins.json \
  --host-evidence target/release-host-new/release-evidence.json \
  --benchmark target/repair-model-new/report.json \
  --minimum-successes 20 --out target/release-gate.json
```

20 เป็นตัวอย่าง policy ของ operator ไม่ใช่ default หรือคะแนนที่วัดได้ ต้องกำหนด threshold เอง
gate ตรวจ logs ว่ารัน test จริง/ไม่ skip, recovery data, complete corpus, source/config/pins,
audit-backed outcomes/artifacts, model origin และ protected verifier ของ source ที่ส่ง review
ผ่าน gate เป็น manifest สำหรับ operator review ไม่ deploy/publish โดยอัตโนมัติ
evidence ภายใน host อาศัย host/operator เป็น trust root ไม่ใช่ signed remote attestation

workflow `real-model-validation` รองรับ optional candidate/benchmark/gate ด้วย variables:
`AIVM_CANDIDATE_CONFIG`, `AIVM_ENABLE_REPAIR_BENCHMARK=1`, `AIVM_RELEASE_MIN_SUCCESSES`
ยังต้องเปิด host workflow/runner ตามเดิม การแก้ workflow source ไม่ได้เปิด variables ให้เอง
