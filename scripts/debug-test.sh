#!/bin/sh
# Focused bug repro: run one test (or one package) with backtrace and
# full output. Prefer this over `cargo test` when chasing a failure —
# it skips capture so panics/asserts print in order.
# Usage: sh scripts/debug-test.sh <name-filter> [package]
#    ex: sh scripts/debug-test.sh traversal_denied
#    ex: sh scripts/debug-test.sh tools aivm-tools
set -eu

F="${1:?usage: debug-test.sh <name-filter> [package]}"
P="${2:-}"
export RUST_BACKTRACE=1

if [ -n "$P" ]; then
    cargo test -p "$P" "$F" -- --nocapture
else
    cargo test --workspace "$F" -- --nocapture
fi
