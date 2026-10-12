#!/bin/sh
# จำลองบั๊กแบบโฟกัส: รันเทสต์เดียว (หรือ crate เดียว) พร้อม backtrace
# และ output เต็ม เหมาะกว่าตอนไล่ความล้มเหลว `cargo test`
# เพราะไม่ซ่อน output panic/assert จะพิมพ์ตามลำดับจริง
# วิธีใช้: sh scripts/debug-test.sh <name-filter> [package]
#    ตัวอย่าง: sh scripts/debug-test.sh traversal_denied
#    ตัวอย่าง: sh scripts/debug-test.sh tools aivm-tools
set -eu

F="${1:?usage: debug-test.sh <name-filter> [package]}"
P="${2:-}"
export RUST_BACKTRACE=1

if [ -n "$P" ]; then
    cargo test -p "$P" "$F" -- --nocapture
else
    cargo test --workspace "$F" -- --nocapture
fi
