#!/bin/sh
# Real pinned GGUF inference through container/MicroVM, including live streaming.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
TIER=${1:-}
MODEL=${2:-}
PINS=${3:-"$HOME/.local/share/aivm/microvm/pins.json"}
SCENARIO=${4:-baseline}
case "$SCENARIO" in baseline|failure-recovery) ;; *) echo 'scenario must be baseline or failure-recovery' >&2; exit 2 ;; esac
case "$TIER" in container|microvm|process_namespace) ;; *) echo 'usage: sh scripts/test-worker-host.sh container|microvm|process_namespace /path/model.gguf [pins.json] [baseline|failure-recovery]' >&2; exit 2 ;; esac
[ -f "$MODEL" ] || { echo "model missing: $MODEL" >&2; exit 2; }
cd "$PROJECT_DIR"
if [ "${5:-}" != --inside ]; then
    cargo build --locked -q -p aivm-model-worker --features llama,microvm
    if [ "$TIER" = container ]; then
        exec systemd-run --user --wait --pipe --collect \
            --property='Delegate=cpu memory pids' --setenv="PATH=$PATH" --setenv="AIVM_WORKER_STRACE=${AIVM_WORKER_STRACE:-}" \
            --setenv="AIVM_GGUF_SHA256=${AIVM_GGUF_SHA256:-}" \
            --setenv="CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-1}" \
            --setenv="AIVM_WORKER_HOST_EVIDENCE=${AIVM_WORKER_HOST_EVIDENCE:-}" \
            --unit="aivm-worker-host-$(id -u)-$$" \
            /bin/sh "$SCRIPT_DIR/test-worker-host.sh" "$TIER" "$MODEL" "$PINS" "$SCENARIO" --inside
    fi
fi
CGROUP_ROOT=''
if [ "$TIER" = container ]; then
    CGROUP_ROOT="/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
    case "$CGROUP_ROOT" in */aivm-worker-host-*.service) ;; *) echo 'delegated service required' >&2; exit 2 ;; esac
    mkdir "$CGROUP_ROOT/runner"
    printf '%s\n' "$$" > "$CGROUP_ROOT/runner/cgroup.procs"
    printf '+cpu +memory +pids\n' > "$CGROUP_ROOT/cgroup.subtree_control"
fi
RUN_DIR=$(mktemp -d /tmp/aivm-worker-host-XXXXXX)
CONFIG="$RUN_DIR/config.json"
trap 'rm -rf "$RUN_DIR"' EXIT HUP INT TERM
python3 - "$CONFIG" "$TIER" "$MODEL" "$PROJECT_DIR/target/debug/aivm-model-worker" "$PINS" "$CGROUP_ROOT" <<'PY'
import hashlib,json,os,pathlib,re,sys
output,tier,model,worker,pins,cgroup=sys.argv[1:]
def digest(path):
    with open(path,'rb') as file:
        return hashlib.file_digest(file,'sha256').hexdigest()
expected=os.environ.get('AIVM_GGUF_SHA256') or digest(model)
if not re.fullmatch(r'[0-9a-fA-F]{64}',expected) or digest(model)!=expected.lower():
    raise SystemExit('model sha256 mismatch or invalid operator pin')
launcher={'tier':tier}
if tier=='container':
    launcher['config']={'bubblewrap':'/usr/bin/bwrap','init':'/usr/libexec/aivm-container-init','cgroup_root':cgroup}
if tier=='microvm':
    pins=json.loads(pathlib.Path(pins).read_text())
    launcher['config']={'kernel_path':pins['kernel']['path'],'kernel_sha256':pins['kernel']['sha256'],
      'rootfs_path':pins['rootfs']['path'],'rootfs_sha256':pins['rootfs']['sha256'],
      'fc_sha256':pins['binary']['sha256'],'mem_mb':4096,'vcpu_count':2,'boot_timeout_secs':120}
config={'provider':'local','name':'host-model','local':{'model_path':str(pathlib.Path(model).resolve()),'model_sha256':expected,
    'worker_path':worker,'worker_sha256':digest(worker),'worker_launcher':launcher,
    'ctx_size':512,'max_tokens':32,'threads':2,'gpu_layers':0},
    'worker_limits':{'max_context_tokens':512,'max_output_tokens':32,'timeout_ms':120000,'memory_mb':4096,'cpu_seconds':120,'pids_max':64,'storage_mb':5120}}
pathlib.Path(output).write_text(json.dumps(config))
PY
set --
if [ -n "${AIVM_WORKER_STRACE:-}" ]; then set -- strace -f -o "$AIVM_WORKER_STRACE"; fi
if [ "$SCENARIO" = failure-recovery ]; then
    [ -n "${AIVM_WORKER_HOST_EVIDENCE:-}" ] || { echo 'failure-recovery requires AIVM_WORKER_HOST_EVIDENCE' >&2; exit 2; }
    # scratch อยู่ใต้ directory เฉพาะเทสต์; เก็บ serial ชั่วคราวเพื่อแยก OOM จาก error อื่น
    FAIL_TMP=$(mktemp -d "$RUN_DIR/aivm-worker-failures-XXXXXX")
    TMPDIR="$FAIL_TMP" AIVM_WORKER_HOST_TMPDIR="$FAIL_TMP" AIVM_MICROVM_KEEP_SCRATCH=1 \
        AIVM_WORKER_HOST_CONFIG="$CONFIG" "$@" cargo test --locked -p aivm-model-worker --features llama,microvm \
        --test failure_recovery real_isolated_worker_failure_recovery -- --exact --ignored --nocapture
    exit $?
fi
AIVM_WORKER_HOST_CONFIG="$CONFIG" "$@" cargo test --locked -p aivm-model-worker --features llama,microvm \
    --test worker real_isolated_worker_host_validation -- --exact --ignored --nocapture
