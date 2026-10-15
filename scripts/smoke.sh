#!/bin/sh
# สโมกเทสต์ CLI แบบ end-to-end: ใช้ไบนารี `aivm` ตัวจริงวิ่งตลอด
# วงจรชีวิต VM ใน root ชั่วคราวที่แยกจากกัน เจอข้อผิดพลาดแรกล้มทันที
# วิธีใช้: sh scripts/smoke.sh (หรือ: make e2e)
set -eu

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aivm-smoke-XXXXXX")"
BIN="cargo run -q -p aivm-cli -- --root $ROOT"
trap 'rm -rf "$ROOT"' EXIT INT TERM

echo "== build =="
cargo build -q -p aivm-cli

echo "== create =="
$BIN create coder --config ./examples/aivm.yaml
test -f "$ROOT/coder/aivm.yaml" || { echo "FAIL: aivm.yaml missing"; exit 1; }

echo "== seed a file via example workspace =="
mkdir -p "$ROOT/coder/workspace/src"
echo 'fn hello() {}' > "$ROOT/coder/workspace/src/hello.rs"

echo "== inspect =="
$BIN inspect coder | grep -q "AI VM: coder" || { echo "FAIL: inspect"; exit 1; }

echo "== run =="
$BIN run coder | grep -q "intent from context" || { echo "FAIL: run"; exit 1; }

echo "== agent loop (Phase 5): non-conforming output is denied, nothing runs =="
$BIN agent coder "read the seed file" | grep -q "invalid intent" || { echo "FAIL: agent loop"; exit 1; }

echo "== structured agent output for scripts =="
$BIN agent coder "read the seed file" --max-steps 1 --json > "$ROOT/agent.json"
python3 - "$ROOT/agent.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as file:
    run = json.load(file)
assert run["stopped"] == "max-steps"
assert run["summary"] is None
assert len(run["steps"]) == 1
assert run["steps"][0]["action"] == "invalid-intent"
PY

echo "== transition (dynamic grants) =="
$BIN transition coder ANALYZE | grep -q "granted 0" || { echo "FAIL: ANALYZE grant"; exit 1; }
$BIN transition coder MODIFY --confidence 0.95 | grep -q "granted 1" || { echo "FAIL: MODIFY grant"; exit 1; }
$BIN inspect coder | grep -q "MODIFY" || { echo "FAIL: persisted state"; exit 1; }
$BIN transition coder DEPLOY 2>/dev/null && { echo "FAIL: jump allowed"; exit 1; } || true
test -f "$ROOT/coder/state.json" || { echo "FAIL: state.json missing"; exit 1; }

echo "== pause/stop/kill =="
$BIN pause coder
$BIN stop coder
$BIN kill coder

echo "== logs =="
$BIN logs coder | grep -q '"decision"' || { echo "FAIL: logs (no audit entries)"; exit 1; }

echo "== audit verify =="
$BIN audit coder | grep -q "chain verified" || { echo "FAIL: audit chain"; exit 1; }

echo "== demo =="
cargo run -q -p aivm-cli -- demo

echo "== adversarial suite =="
cargo test -q -p aivm-adversarial

echo "smoke: all green ($ROOT cleaned up)"
