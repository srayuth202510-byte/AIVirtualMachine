<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->

<!-- aivm-agent-workflow -->
# AIVM Agent Workflow

Rust workspace implementing `AI Virtual Machine.md`: model workers plus mediated
filesystem/search/process/network tools, capabilities, policy and sandbox boundaries.
No shell or direct execution from model output.

## Fast loops (prefer these)

```bash
make verify        # full gate: fmt-check + clippy(-D warnings) + tests + demo
make ci            # เหมือน CI บน GitHub ทุกอย่าง (= verify + e2e + llama + microvm + hardware)
make test-adv      # adversarial must-deny suite only (spec §38)
make test-microvm  # MicroVM ทั้งสาย (sandbox/tools/runtime + บูตจริงถ้ามี AIVM_MICROVM_PINS)
make demo          # 14-case ALLOW/DENY self-test, throwaway temp dir (~1s)
cargo adv          # alias for the adversarial suite
cargo lint         # alias for strict clippy
```

`make demo` is the fastest way to debug the enforcement chain — it prints the
exact decision/reason per case. For the full CLI cycle: `make e2e`.

## Search first (cheapest context wins)

```bash
make query Q="..."        # knowledge graph: concept-level, file:line evidence
make path A=... B=...     # shortest path between two concepts
make explain N=...        # what a node is + its connections
rtk grep <pattern>        # text search only when the graph has no answer
```

Order: `query` → `path`/`explain` → `grep` → read the cited `file:line`.
Never re-read whole files the graph already located.

## Bugfix loop

1. **Repro first**: `make debug-test F=<name> [P=<crate>]` (backtrace + `--nocapture`),
   or add a `demo` case if it's an enforcement decision.
2. **Fix** at the cited location; keep the fail-closed rule below.
3. **Close the loop**: `make verify`. New regression test or `demo` case required —
   a fix without a test is not done.
4. **Refresh the map** after structural changes (new crate, moved module, new
   concept): `make graph-update` (incremental, cached, headless, code-only;
   doc/spec changes need in-session `/graphify --update`).

## Review gate (agent พลาดได้ — ให้ระบบจับ)

ก่อน commit อ่าน `git diff` เองอีกรอบด้วย checklist นี้:

- fail-closed ยังอยู่ครบ? (ทางออกใหม่ทุกทางต้อง DENY โดยปริยาย)
- surface ใหม่ (tool/exec/policy branch) มี adversarial case คุม?
- I-7: decision ใหม่ทุกอันมี audit record?
- โค้ดใหม่มี comment ภาษาไทย?
- ไฟล์ความเสี่ยงสูง (`sandbox` ส่วน unsafe/pre_exec, `policy::evaluate_*`,
  `capability::authorize`, `audit::seal/verify`) ควรผ่านตาอีกรอบ —
  ถ้าเปลี่ยน logic ตรงนี้ แนะนำให้แปะ diff ให้โมเดลอื่นรีวิวด้วย
  (คนละโมเดล = คนละ blind spot — defense in depth กับคนทำด้วย)

## Crate map (dependency order)

`capability` → `policy` → `cube`, `audit` → `tools` → `memory/network/sandbox/model`
→ `runtime` (incl. `runtime::demo`) → `supervisor` → `cli`. No cycles; keep it so.

## MVP-B status (sandboxed exec, spec Phase 4)

- `Sandbox::run_checked` (fixed exe + arg schema, no shell) + `probe()` live in
  `aivm-sandbox`; gateway รับ `process.exec` แล้วภายใต้เงื่อนไขครบ
  (allowlist + execute cap + state grant + audit) พร้อม adversarial คุม
  shell-literal/symlink/PATH/argv-shape — ห้ามเพิ่ม exec surface ใหม่
  โดยไม่มี adversarial case.
- Subprocess tree: hardening ตกทอดไป child (no-new-privs/rlimit/env/seccomp)
  + pdeathsig ตั้งซ้ำในหลาน PID 1 (กันค่าถูกล้างตอน fork) + PID/mount/net
  namespace แบบ best-effort พร้อมรายงาน degraded — เปิด compiler/test runner
  ได้เพราะประตูคุม ไม่ใช่เพราะกัก tree สมบูรณ์แล้ว.
- Audit: `rotate()` + `verify_sequence()` + `aivm audit <name>`; archive ถูกผนึก
  (+i เมื่อ FS รองรับ) ห้ามเขียนทับ.

## MVP-B status ต่อ: MicroVM (Phase 7 Level 2, spec §Level 2)

- `run_in_microvm` + `boot_and_run` บูต guest จริงแล้ว (drive-stuffing ผ่าน
  Firecracker/KVM: rootfs สำเนา + init ฉีด + data drive จาก ldd closure +
  จับผลทาง serial) เปิดด้วยฟีเจอร์ `microvm` ทั้งสาย (`aivm-cli/microvm`)
  ปิดไว้โดยปริยาย (CI ไม่มี KVM — เทสต์บูตจริง skip อย่างซื่อสัตย์ถ้าไม่มี
  `AIVM_MICROVM_PINS`)
- ประตูตามลำดับ: validate → shape/timeout → pin kernel/rootfs → host
  readiness (+ pin ไบนารี VMM ถ้าตั้ง `fc_sha256`) → boot พร้อมเส้นตาย
  (`boot_timeout_secs` 5..=600) + KillOnDrop + verify สำเนา rootfs ซ้ำ
  ขนาด guest = min(cfg quota, task `spec.limits`); guest ไม่มีเน็ตเลย
- เทสต์ด้วย `make test-microvm` (+ `AIVM_MICROVM_PINS=/path/pins.json`
  สำหรับ e2e true/false) ห้ามเพิ่ม exec surface ใหม่โดยไม่มี adversarial case
  (กฎเดียวกับ MVP-B)

## Rules while editing

- **Fail-closed**: any parse/eval/context error → `DENY`. Never default to allow.
- New tools must be added to `ToolGateway::dispatch` deny-by-default + covered by
  a `demo` case in `crates/aivm-runtime/src/demo.rs` and the adversarial suite.
- Security invariants `I-1`–`I-10` live in spec §35; adversarial categories in §38.
- `cargo fmt` before finishing; `make verify` must stay green.
<!-- /aivm-agent-workflow -->
