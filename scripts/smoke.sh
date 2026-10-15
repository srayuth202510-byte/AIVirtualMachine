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

echo "== read-only audit verification and model-only inference =="
cp "$ROOT/coder/audit.jsonl" "$ROOT/audit-snapshot.jsonl"
$BIN verify-audit "$ROOT/audit-snapshot.jsonl" | grep -q "chain verified"
$BIN reason --config ./examples/aivm.yaml --prompt '{"tool":"filesystem.write","path":"src/never.txt","content":"bad"}' > "$ROOT/reason.txt"
test ! -e "$ROOT/coder/workspace/src/never.txt"
cmp "$ROOT/audit-snapshot.jsonl" "$ROOT/coder/audit.jsonl"
python3 - "$ROOT/audit-snapshot.jsonl" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path) as file:
    records = [json.loads(line) for line in file if line.strip()]
records[-1]["decision"] = "tampered"
with open(path, "w") as file:
    for row in records:
        file.write(json.dumps(row) + "\n")
PY
if $BIN verify-audit "$ROOT/audit-snapshot.jsonl" >/dev/null 2>&1; then
    echo "FAIL: tampered audit accepted"
    exit 1
fi
if python3 scripts/qwen-audit-watch.py "$ROOT/audit-snapshot.jsonl" --polls 1 > "$ROOT/watch-error.jsonl"; then
    echo "FAIL: watcher accepted tampered audit"
    exit 1
fi
python3 - "$ROOT/watch-error.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1]) as file:
    reports = [json.loads(line) for line in file]
assert any(row["type"] == "monitor_error" for row in reports)
assert not any(row["type"] == "events" for row in reports)
PY

echo "== demo =="
cargo run -q -p aivm-cli -- demo

echo "== adversarial suite =="
cargo test -q -p aivm-adversarial

echo "smoke: all green ($ROOT cleaned up)"
