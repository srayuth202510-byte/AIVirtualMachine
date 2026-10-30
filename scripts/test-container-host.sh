#!/bin/sh
# Run the real container boundary test in a transient delegated user service.
# Install the root-owned helper first (see docs/container.md).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
HELPER=/usr/libexec/aivm-container-init

if [ ! -x "$HELPER" ]; then
    echo "Container helper is missing. Run from the project directory:" >&2
    echo "  cargo build --release -p aivm-sandbox --bin aivm-container-init" >&2
    echo "  sudo install -D -o root -g root -m 0755 target/release/aivm-container-init $HELPER" >&2
    exit 2
fi

case "${1:-}" in
    '')
        exec systemd-run --user --wait --pipe --collect \
            --property='Delegate=cpu memory pids' \
            --unit="aivm-container-test-$(id -u)-$$" \
            /bin/sh "$SCRIPT_DIR/test-container-host.sh" --inside
        ;;
    --inside) ;;
    *) echo "usage: sh scripts/test-container-host.sh" >&2; exit 2 ;;
esac

cd "$PROJECT_DIR"
CGROUP_ROOT="/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
case "$CGROUP_ROOT" in
    */aivm-container-test-*.service) ;;
    *) echo "Run this script through its transient user service." >&2; exit 2 ;;
esac

# Keep the delegation root empty before enabling child controllers. Test
# processes stay in runner; each workload gets a sibling cgroup of its own.
mkdir "$CGROUP_ROOT/runner"
printf '%s\n' "$$" > "$CGROUP_ROOT/runner/cgroup.procs"
printf '+cpu +memory +pids\n' > "$CGROUP_ROOT/cgroup.subtree_control"

CONFIG=$(mktemp /tmp/aivm-container-config-XXXXXX.json)
LOG=$(mktemp /tmp/aivm-container-test-XXXXXX.log)
trap 'rm -f "$CONFIG" "$LOG"' EXIT HUP INT TERM
python3 - "$CONFIG" "$CGROUP_ROOT" "$HELPER" <<'PY'
import json
import sys
with open(sys.argv[1], "w") as file:
    json.dump({"bubblewrap": "/usr/bin/bwrap", "init": sys.argv[3],
               "cgroup_root": sys.argv[2]}, file)
PY

if AIVM_CONTAINER_TEST_CONFIG="$CONFIG" cargo test -p aivm-sandbox \
    --test container real_container_enforces_boundary_and_quotas \
    -- --exact --nocapture >"$LOG" 2>&1; then
    cat "$LOG"
else
    CODE=$?
    cat "$LOG"
    exit "$CODE"
fi
# exit 0 ที่เลือก 0 test หรือ skip ไม่ใช่หลักฐานว่า boundary ผ่าน
python3 - "$SCRIPT_DIR/validate-model-host.py" "$LOG" <<'PY'
import pathlib,runpy,sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent))
validator=runpy.run_path(sys.argv[1])
if not validator['exact_test_passed'](pathlib.Path(sys.argv[2]).read_text()):
    raise SystemExit('container boundary test did not execute exactly once without skips')
PY
