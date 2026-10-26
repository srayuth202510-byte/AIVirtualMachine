# Worker control plane: execution identity, cleanup และขีดจำกัดรวม

การปรับปรุงนี้ครอบคลุม executable identity, checked cleanup, supervised deadline,
structured errors, admission/cache และการประเมินคุณภาพแยกจาก protocol success
ผล real-model validation รอบล่าสุดเก็บใน `target/control-hardening-2026-10-25/` เมื่อรันบน host
สรุปผลและข้อจำกัดของรอบนี้: [host validation 25 ตุลาคม 2026](host-validation-2026-10-25.md)

## ไฟล์ที่ตรวจต้องเป็นไฟล์ที่รัน

Pinned process worker และ controller ใช้ Linux memfd โดย seal WRITE/GROW/SHRINK/SEAL
ก่อนตรวจ SHA-256 แล้ว inherit descriptor เข้า child เพื่อ exec ผ่าน `/proc/self/fd`
จึงใช้ได้หลังเข้า user namespace โดยไม่ต้องอ่าน `/proc` ของ parent แม้ pathname หรือ inode
ต้นทางเปลี่ยน สำเนาที่รันก็เปลี่ยนไม่ได้ ไม่เปิด fallback ไปยังไฟล์ต้นทางเมื่อ seal/exec ล้ม
container/MicroVM ใช้สำเนา worker ใน staging ของ request ที่ตรวจ hash แล้วส่งสำเนานั้น
ผ่าน launcher แทน executable ต้นทาง การเปลี่ยนไฟล์หลังตรวจมี regression test จริง
Runtime dependencies ของ executable ยังอยู่ใน trust ของ host/rootfs ตาม tier ที่เลือก
Process worker ยังมีขอบเขต filesystem ตามเดิม; memfd ไม่เพิ่ม filesystem isolation

## Cleanup และ crash recovery

Completion ถูกปล่อยหลัง checked cleanup สำเร็จเท่านั้น หาก cleanup ล้ม จะคืน
`cleanup_failed` พร้อม residual path และเก็บ error เดิมไว้ใน `CleanupAfterFailure`
`Drop` เป็น fallback ระหว่าง unwind; ไม่ใช้การเรียก Drop เป็นหลักฐานว่า cleanup สำเร็จ

Staging มี private directory และ file-lock lease; ก่อนเริ่มงานใหม่ scanner ล้างเฉพาะ
staging ของ UID นี้ที่มี marker และไม่มีเจ้าของถือ lock แล้ว ไม่ใช้ PID อย่างเดียว
จึงไม่สับสนกับ PID reuse และไม่แตะ request ที่ยังรันอยู่ Scanner ไม่ตาม symlink
หรือ directory ที่ owner/mode ไม่ตรง contract; residual ที่เข้าถึงไม่ได้ต้องให้ operator
แก้ตาม path ที่รายงาน ไม่ลบ directory ที่ไม่รู้จักโดยเดาเอง

## Controller process และ event API

เปิดด้วย operator config:

```yaml
model:
  provider: local
  total_timeout_ms: 180000
  host_resources:
    root: /tmp/aivm-host-quota-v1-1000 # ใช้ root เดียวกันทุก VM ของ UID นี้
    max_requests: 2
    memory_mb: 12288
    storage_mb: 16384
    queue_timeout_ms: 30000
    cache_mb: 0
  local:
    model_path: /models/model.gguf
    model_sha256: '<approved-model-sha256>'
    worker_path: /usr/local/bin/aivm-model-worker
    worker_sha256: '<approved-worker-sha256>'
    controller_path: /usr/local/bin/aivm-model-worker
    controller_sha256: '<approved-worker-sha256>'
    worker_launcher:
      tier: process_namespace
```

ตัวอย่างเป็นส่วน model; production profile ยังต้องมี manifest และ pins ตาม configuration
ใช้ `WorkerClient::from_config` เพื่อเตรียม controller/cache ตอน boot ก่อนเริ่ม request
controller binary ต้องรองรับ `--control` และมี pin; ตัว `aivm-model-worker` รองรับ mode นี้
controller รับเฉพาะ PATH ของ operator และ private TMPDIR เพื่อใช้ host helpers;
model worker ยังคงล้าง environment ก่อน exec ตามเดิม

`WorkerClient::start` คืน `WorkerJob` ที่ผู้ใช้เรียก `next_event`, `cancel` และ
`wait_for_cleanup(timeout)` ได้ งบ request รวม queue, child preparation และ execution
caller ไม่ต้องรอ helper/syscall ของ controller คืนการควบคุมจึงจะหมดเวลารอ event
watchdog แยกจากผู้รับ event และหยุด controller/ลูก รวมถึง cgroups ที่ติดตามได้
bounded delta queue มี 8 slots; ผู้รับที่ช้าจนเต็มจะถูกยุติด้วย `resources_unavailable`
terminal outcome แยก channel จึงไม่หายไปเพราะ delta queue เต็ม

เมื่อหมดเวลา event API คืน `deadline` และอาจยัง cleanup อยู่:
`wait_for_cleanup` คืน true เมื่อ watchdog ตรวจเสร็จ, false เมื่อยัง pending,
หรือ error เมื่อ cleanup ล้ม การคืน deadline ไม่ใช่หลักฐานว่า cleanup เสร็จแล้ว
API แบบ `infer`/`infer_stream` รอ cleanup grace ได้อีกสูงสุด 3 วินาที

MicroVM รองรับ TMPDIR ที่ซ้อนใต้ controller/request โดยให้ Firecracker bind ชื่อ
`api.sock` จาก cwd ของ child และให้ host connect ผ่าน directory descriptor ใน
`/proc/self/fd` จึงไม่ติดเพดาน `sun_path` แม้ staging path ยาวกว่า 108 bytes
socket ยังคงอยู่ใต้ request directory ที่ checked cleanup เป็นเจ้าของ

Callback เดิมยังเป็นโค้ดใน caller; หาก callback ไม่คืนการควบคุม caller thread ยังค้างได้
watchdog ยุติทรัพยากรของ worker ได้โดยไม่รอ callback ผู้ใช้ที่ต้องการ bounded wait
ควรใช้ event API Kernel task ที่อยู่ใน uninterruptible I/O อาจยังไม่ยุติทันทีหลัง SIGKILL
จึงไม่อ้างเป็น hard realtime guarantee หรืออ้าง cleanup สำเร็จทั้งที่ยัง pending
การเตรียม controller image/cache ตอน boot อยู่นอกงบต่อ request

## Error contract และ diagnostics

`WorkerError::code()` เป็นรหัสคงที่: protocol, invalid_request, limit_exceeded,
worker_failed, deadline, cancelled, cleanup_failed และ resources_unavailable
`Context` เก็บ source enum, phase และ `ControlPlaneUsage`; `cause()` เข้าถึง error เดิม
protocol/limit failures ไม่ถูกบีบให้เป็น generic Failed ในเส้นทาง process อีก
ข้อความ stderr และ error string จาก worker ไม่ถูกส่งต่อดิบ ใช้เฉพาะคำอธิบายคงที่
สำหรับ diagnostic ที่รู้จัก และไม่ถือข้อความจาก worker เป็น host attestation

### Exit status ของ process worker

`WorkerError::worker_exit()` คืน `Option<&WorkerExit>` สำหรับ process/process_namespace
worker ที่เริ่มทำงานแล้วและ host เก็บ wait status ได้ โดยมี `exit_code`, `signal`,
`core_dumped` และ `observed_before_cleanup` ข้อมูลถูกเก็บใน `WorkerError::Exit`
และส่งผ่าน pinned controller ได้; `code()` และ `cause()` ยังให้สาเหตุหลักเดิม
หาก checked staging cleanup ล้มตามหลัง ยังเข้าถึง exit evidence ผ่าน
`CleanupAfterFailure` ได้ Raw worker frames ไม่มีสิทธิ์อ้าง host exit evidence

Client อ่านสถานะก่อนเริ่ม cleanup และเมื่อเจอ stdout EOF จะรอ process ออกจริง
ภายใน execution/total deadline เดิม ถ้า worker ปิด stdout แต่ยังรันต่อ จะคืน deadline
และ cleanup ตามปกติ Exit 0 ที่ไม่มี completion หรือ completion ที่ตามด้วย exit ไม่สำเร็จ
ยังเป็น failure เสมอ ไม่ปล่อย partial stream เป็น completion

`observed_before_cleanup=false` หมายถึงเห็นสถานะหลังเริ่ม cleanup ซึ่งอาจรวม SIGKILL
ที่ client ส่งเอง ค่า true บอกจังหวะที่อ่านสถานะเท่านั้น ไม่ได้พิสูจน์ว่า worker ถูก
ฆ่าด้วยสาเหตุใด SIGKILL ไม่ถูกเปลี่ยนเป็น OOM หรือ CPU-limit diagnosis โดยไม่มี
หลักฐานเพิ่มเติม และ `core_dumped` เป็น wait-status flag ไม่ใช่หลักฐานว่าเก็บ core file
Error ที่เกิดก่อน spawn หรือ event deadline ที่กลับก่อน controller ส่งผล cleanup
อาจยังไม่มี exit evidence จึงไม่เติมค่าขึ้นมาเอง

ตัวอย่าง diagnostic ใหม่เมื่อ worker ออกด้วย code 73 ก่อนส่ง completion:

```text
worker failed: worker returned no completion; worker_exit: exit_code=73; signal=none; core_dumped=false; observed_before_cleanup=true
```

การเปลี่ยนนี้ช่วยวิเคราะห์ failure ครั้งถัดไป ไม่ได้ระบุย้อนหลังว่าสาเหตุของ
`worker returned no response` ใน [ผลรอบก่อน](host-validation-2026-10-25.md) คืออะไร
หลักฐาน CI, process-failure และ namespace regressions ของ exit diagnostics อยู่ใน
`target/worker-exit-diagnostics-2026-10-25/`; ผล GGUF/coding quality ยังคงอ้าง snapshot รอบก่อน

## Admission และ cache

ค่าเริ่มต้นของ pool คือ max_requests=2, memory_mb=75% ของ MemTotal (fallback 4096),
storage_mb=16384, queue_timeout_ms=30000 และ cache_mb=0 ต้องปรับตาม host ที่ใช้งานจริง
File-lock reservations คุมจำนวนงาน, RAM budget และ staging budget รวมข้าม process
ที่ใช้ quota root เดียวกัน งานที่ยังไม่มี capacity รอแบบตรวจ deadline/cancellation ได้
policy ใน root ต้องตรงกันทุก client; การเปลี่ยน cap ฝั่ง client เดียวจะ fail-closed
ก่อนเปลี่ยน policy ให้หยุด participating clients ทั้งหมดและจัดการ root ตาม operator workflow
lease ถูกคืนโดย kernel เมื่อ process ตาย และมี test SIGKILL ข้าม process จริง
นี่เป็น cooperative admission ของ AIVM ไม่ใช่ OS-wide RAM/disk quota สำหรับโปรแกรมอื่น
หาก staging เป็น tmpfs จะบวก storage reservation เข้ากับ RAM reservation ด้วย
และตรวจยอดจอง staging เทียบกับพื้นที่ว่างจริงก่อนรับงาน เป็นการจองแบบ conservative
ที่อาจรอแม้ request ยังใช้พื้นที่ไม่เต็ม quota; ไม่อ้างเป็น filesystem quota ที่ kernel บังคับ
per-worker rlimit/cgroups และ storage checks ยังทำงานแยกตาม launcher
controller pending queue จำกัดอีกชั้นที่ 64 งานต่อ process

`cache_mb > 0` เปิด model cache สำหรับ pinned process/process_namespace เท่านั้น
เป็น sealed memfd ที่ถือด้วยอายุ client และมี RAM reservation แยกจาก request slots
RAM cache รวมทุก client ต้องไม่เกิน cache_mb และนับรวมใน memory_mb ของ pool
loader ตรวจ hash ของ sealed bytes ก่อน mmap ทุก request แต่ไม่ต้องทำ private copy ซ้ำ
source ถูกแก้หลังสร้าง cache จะไม่เปลี่ยน bytes ที่ใช้ cache ปิดโดย default
container/MicroVM หรือ unpinned model ที่ขอ cache จะถูกปฏิเสธ ไม่มี silent fallback
cache ยังไม่แชร์ model state หรือ KV cache ระหว่าง inference และคืน RAM เมื่อ client หยุด
การวัด warm latency ต้องใช้ client เดิมและรายงาน client boot แยกด้วย

## Evaluation ที่ทำซ้ำได้

```bash
# เต็มทั้งสาม tier พร้อม quality และ benchmark cache; รันบน Linux host ที่เตรียมไว้
AIVM_SUPERVISED_CONTROL=1 python3 scripts/validate-model-host.py \
  --model /path/model.gguf --model-sha256 '<approved-sha256>' \
  --pins /path/pins.json --quality --out target/control-hardening-2026-10-25/model

python3 scripts/eval-detection.py --output target/control-hardening-2026-10-25/detection-baseline.json
python3 scripts/eval-detection.py --corpus examples/detection/holdout.json \
  --output target/control-hardening-2026-10-25/detection-holdout.json
```

Detector holdout แยกจาก baseline และไม่ปรับกฎ/label ตามคำตอบโมเดล รายงาน FP/FN
และ indistinguishable inputs ตามจริง ไม่ใช้ policy-test success แทน detection accuracy
เป็น synthetic regression holdout ขนาดเล็ก ผู้เขียนชุดนี้เห็น baseline มาก่อน
จึงยังไม่ใช่ independent production benchmark

`examples/model-quality.json` ใช้ oracle คงที่ 6 งาน แยก infrastructure_passed
จาก task_correct เก็บ output, phase timing, config/corpus hashes และ client boot
intent ที่โมเดลเสนอถูกตรวจเป็นข้อมูล ไม่มีการ execute ผล benchmark อาจรันครบ
แต่ได้คะแนนต่ำ จึงเก็บคะแนนแยกจากผล gate; ไม่รับ partial evidence เป็นผลผ่าน
validator ปฏิเสธ JSON ที่ชนิดผิด, records ที่ขาด และ boolean ที่ถูกใช้แทนจำนวนเต็ม
agent/compiler/gateway integration ยังตรวจแยกด้วย `make test-coding`
มี ignored host benchmark `real_model_repairs_source_checked_by_an_independent_verifier`
ใน `crates/aivm-runtime/tests/coding_workflow.rs` ให้โมเดลจริงแก้ฟังก์ชัน C ผ่าน gateway
ภายใน 8 ก้าวรวม model intents และ build ตาม operator verifier contract แล้ว operator verifier ที่ agent เขียนไม่ได้ตรวจ 289 input pairs
compiler/linker/test binary ทั้งหมดผ่าน gateway/sandbox; baseline ที่ผิดต้องถูกปฏิเสธก่อน
รายงาน `task_correct` แยกจาก summary/verification status ของ agent ไม่อนุมานอัตรา
แก้ repository จริงจาก task เดียวหรือ model-only probes เหล่านี้

Coding benchmark ใช้ 8k context, 2 model threads, RAM 4 GiB และ CPU allowance
240 วินาทีต่อ worker; execution timeout ยังเป็น 120 วินาที และ total timeout
180 วินาทีต่อ request รายงาน `effective_model_config`, hash ของ benchmark source
และ `infrastructure_passed` เพิ่มจาก input config hash จึงเห็นค่า override ของ fixture
หาก inference/runtime ล้ม test จะเขียน evidence แล้ว fail; patch ที่ผิดแต่รันครบ
ยังรายงาน `task_correct=false` แยกจาก infrastructure status ตามเดิม
การผ่าน operator verifier ไม่เปลี่ยนสถานะ completion ของ agent เป็น `verified`
โดยอัตโนมัติ; ผลทั้งสองอยู่คนละ field และอาจไม่ตรงกัน

### เปรียบเทียบคุณภาพ prompt โดยไม่เปลี่ยน oracle

`scripts/eval-model-quality.py` เปรียบเทียบ prompt เดิมกับ suffix ใน
`examples/model-quality-format.json` โดยใช้ pinned ModelConfig เดิมตลอดทั้งสี่รัน
รัน corpus เดิม 6 งานและ synthetic transfer corpus ใหม่ 8 งานแยกกัน:

```bash
python3 scripts/eval-model-quality.py \
  --config /absolute/path/pinned-quality-config.json \
  --out target/quality-comparison-new-run
```

ต้องใช้ output directory ใหม่เพื่อไม่เขียนทับหลักฐานเก่า ต้องเตรียม worker
ด้วย `cargo build --locked -p aivm-model-worker --features llama,microvm`
และตรวจ worker pin ของ build ที่อนุมัติก่อนรัน ห้าม build worker คนละ features
หรือเปลี่ยน model/config/profile/corpora ระหว่างรัน
ถ้าใช้ host quota ให้แยก root จาก workload ที่มี quota policy ต่างกัน

Suffix เป็นคำกำกับรูปแบบทั่วไป ไม่มีคำตอบ oracle และไม่ได้แก้ prompt เดิม
ใน corpus หลัก เกณฑ์เดิมยังปฏิเสธ Markdown, extra fields และคำตอบผิด
`failure_kind=markdown_fence` ใช้อธิบายข้อผิดพลาดเท่านั้น ไม่ตัด fence เพื่อเพิ่มคะแนน
รายงานเก็บ prompt/output จริง, config/corpus/profile hashes, latency, คะแนน
และรายชื่อ cases ที่ดีขึ้นหรือถดถอย พร้อมตรวจคะแนนซ้ำจาก output ก่อนรับรายงาน
Infrastructure ผ่านไม่ได้แปลว่าคุณภาพผ่าน threshold; ไม่มีการปรับ weights
หรืออ้าง production accuracy จาก corpus เล็กนี้

Corpus ใหม่เขียนหลังเห็น baseline จึงไม่ใช่ independent holdout
การกำกับรูปแบบใช้เฉพาะรัน `strict` ของการเปรียบเทียบ ไม่ได้เปลี่ยนคำตอบ
ของ model clients ทุกตัวโดยอัตโนมัติ ผู้เรียกที่ต้องการ JSON/plain output
นำ suffix ที่ประเมินแล้วไปต่อท้าย prompt ก่อนส่ง request ได้ โดยเก็บ prompt
เต็มเพื่อให้ context/output limits และหลักฐานตรงกับงานที่รันจริง

ผล [เปรียบเทียบวันที่ 26 ตุลาคม](model-quality-2026-10-26.md): baseline ดีขึ้น
4/6 → 5/6 แต่ synthetic transfer คงที่ 3/8 และยังมี semantic errors
suffix นี้จึงยังเป็น candidate สำหรับการประเมิน ไม่ใช่ production default

ผล [coding validation วันที่ 26 ตุลาคม](coding-validation-2026-10-26.md):
ใช้ `verification.prepare` จาก operator ให้ runtime build/test ผ่าน gateway
หลัง model edit ได้ทั้ง `agent_verified=true` และผลตรวจอิสระ 289 input pairs ผ่าน

ตัวอย่างรัน coding benchmark บน host หลังเตรียม pinned ModelConfig JSON แล้ว:

```bash
AIVM_WORKER_HOST_CONFIG=/absolute/path/model-config.json \
AIVM_AGENT_QUALITY_EVIDENCE=/absolute/path/agent-quality.json \
  cargo test -p aivm-runtime --features llama,microvm --test coding_workflow \
    real_model_repairs_source_checked_by_an_independent_verifier -- --exact --ignored --nocapture
```
