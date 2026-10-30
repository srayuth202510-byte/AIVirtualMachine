#!/bin/sh
# สโมกเทสต์แบ็กเอนด์ local (GGUF ผ่าน llama.cpp) — รัน inference จริง
# ต้องมี cmake + toolchain C++ (build llama.cpp ครั้งแรกใช้เวลาหลายนาที)
# วิธีใช้: sh scripts/llama-smoke.sh /path/to/model.gguf ["prompt"]
#          หรือ: make llama-smoke MODEL=/path/to/model.gguf
# หาโมเดลจิ๋วไว้ลองได้จาก: https://huggingface.co/ggml-org/models
set -eu

MODEL="${1:-${AIVM_GGUF:-}}"
if [ -z "$MODEL" ]; then
    echo "usage: sh scripts/llama-smoke.sh /path/to/model.gguf [prompt]"
    echo "   or: make llama-smoke MODEL=/path/to/model.gguf [PROMPT='...']"
    exit 2
fi
[ -f "$MODEL" ] || { echo "FAIL: model not found: $MODEL"; exit 2; }
PROMPT="${2:-Once upon a time}"

WORKER="${AIVM_MODEL_WORKER:-}"
WORKER_TIER="${AIVM_WORKER_TIER:-process_namespace}"
WORKER_YAML=""
if [ -n "$WORKER" ]; then
    [ -x "$WORKER" ] || { echo "FAIL: worker not executable: $WORKER"; exit 2; }
    WORKER_YAML="    worker_path: $WORKER
    worker_launcher:
      tier: $WORKER_TIER"
fi

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aivm-llama-XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT INT TERM
CFG="$ROOT/localtest.yaml"

cat > "$CFG" <<EOF
name: localtest
model:
  provider: local
  name: $(basename "$MODEL")
  local:
    model_path: $MODEL
${WORKER_YAML}
    ctx_size: 512
    threads: 4
    temperature: 0.9
    top_k: 40
    top_p: 0.95
    max_tokens: 48
    gpu_layers: 0
resources:
  cpu: 4
  memory: 4GB
  storage: 5GB
filesystem:
  read: [./workspace]
  write: [./workspace/src]
network:
  allow: [github.com]
capabilities:
  initial: [read:workspace, search:code]
EOF

echo "== build (--features llama) =="
cargo build -q -p aivm-cli --features llama
if [ -n "$WORKER" ]; then
    cargo build -q -p aivm-model-worker --features llama
fi

BIN="cargo run -q -p aivm-cli --features llama -- --root $ROOT"

echo "== create (loads GGUF) =="
$BIN create localtest --config "$CFG" >/dev/null

echo "== run (real inference) =="
OUT="$($BIN run localtest --prompt "$PROMPT")"
printf '%s\n' "$OUT"
[ -n "$OUT" ] || { echo "FAIL: empty model output"; exit 1; }

if [ -n "$WORKER" ]; then
    echo "llama-smoke: worker-backed inference green"
else
    echo "llama-smoke: inline inference green"
fi
