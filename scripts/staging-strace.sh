#!/bin/sh
# เก็บหลักฐาน syscall ของ staging lease/recovery: fork/exec, open/close, flock, remove
# ใช้เฉพาะตอนสืบสาเหตุ ไม่ใช่ gate ปกติ และไม่มีการ retry/sleep เพื่อกลบ failure
set -eu

out="${1:-target/staging-strace-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out"

if ! command -v strace >/dev/null 2>&1; then
	echo "strace ไม่ถูกติดตั้ง: ติดตั้งเพื่อเก็บหลักฐาน staging" >&2
	exit 2
fi

strace -f -qq -s 256 -yy -e trace=%process,%file,flock \
	-o "$out/strace.log" \
	cargo test -p aivm-model --lib worker::staging::tests -- --test-threads=1 --nocapture \
	>"$out/test.log" 2>&1

echo "strace: $out/strace.log"
echo "test:   $out/test.log"
