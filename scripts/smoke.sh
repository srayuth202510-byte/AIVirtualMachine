#!/bin/sh
# End-to-end CLI smoke test: exercises the real `aivm` binary through a
# full VM lifecycle in an isolated temp root. Fails on first error.
# Usage: sh scripts/smoke.sh  (or: make e2e)
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

echo "== pause/stop/kill =="
$BIN pause coder
$BIN stop coder
$BIN kill coder

echo "== logs =="
$BIN logs coder | grep -q '"decision"' || { echo "FAIL: logs (no audit entries)"; exit 1; }

echo "== demo =="
cargo run -q -p aivm-cli -- demo

echo "== adversarial suite =="
cargo test -q -p aivm-adversarial

echo "smoke: all green ($ROOT cleaned up)"
