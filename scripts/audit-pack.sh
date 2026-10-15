#!/bin/sh
# รวมหลักฐานเตรียม external audit (อ่านอย่างเดียว ไม่แตะโค้ด ไม่รวม secret values)
# วิธีใช้: sh scripts/audit-pack.sh [OUTDIR]  (default: ./target/audit-pack-<date>)
# ข้างในมี: git log/status, probe, demo, check-ci, test summary, bench,
# pins hashes (แค่ sha ไม่ใช่ค่า secret), รายชื่อ docs/spec
set -eu

OUT="${1:-./target/audit-pack-$(date -u +%F)}"
mkdir -p "$OUT"

# 1. ที่มาของโค้ด (กันถามว่า "ตรวจของรุ่นไหน")
git log --oneline -20 > "$OUT/git-log.txt" 2>&1 || echo "no git log" > "$OUT/git-log.txt"
git status --short > "$OUT/git-status.txt" 2>&1 || true
git diff --stat > "$OUT/git-diff-stat.txt" 2>&1 || true

# 2. ความพร้อม host + เส้น enforcement (รันใหม่สดทุกครั้ง ไม่ใช้ log เก่า)
cargo run -q -p aivm-cli -- probe > "$OUT/probe.json" 2>&1 || echo "probe failed" > "$OUT/probe.json"
cargo run -q -p aivm-cli -- demo > "$OUT/demo.txt" 2>&1 || echo "demo FAILED" > "$OUT/demo.txt"
python3 scripts/check-ci-parity.py > "$OUT/parity.txt" 2>&1 || echo "parity FAILED" > "$OUT/parity.txt"

# 3. สรุปผลเทสต์ทั้ง workspace (ไม่เอา output เต็ม แค่บรรทัด test result)
cargo test --workspace > "$OUT/cargo-test.log" 2>&1 || echo "cargo test FAILED" >> "$OUT/cargo-test.log"
grep -h "test result" "$OUT/cargo-test.log" > "$OUT/test-summary.txt" || true

# 4. bench 3 รอบ (ตัวเลขประกอบ ไม่ใช่หลักประกันความปลอดภัย)
ROUNDS=3 sh scripts/bench.sh "$OUT/bench.md" > /dev/null 2>&1 || echo "bench FAILED" > "$OUT/bench.md"

# 5. supply chain: hash ของ pins ที่เครื่องนี้ใช้ (ไม่มี secret values ใน pins)
{
  echo "# pins in use (paths + sha256, no secret values)"
  for pins in "$HOME/.local/share/aivm/microvm/pins.json" \
              "$HOME/.local/share/aivm/hw-generic-pins.json" \
              "$PWD/target/host-validation/hardware-generic-pins.json"; do
    if [ -r "$pins" ]; then
      echo "== $pins"
      sha256sum "$pins"
    else
      echo "== $pins (missing)"
    fi
  done
} > "$OUT/pins.txt" 2>&1

# 6. สารบัญเอกสาร (auditor เริ่มอ่านจากไหน)
ls docs/ > "$OUT/docs-index.txt" 2>&1
wc -l "AI Virtual Machine.md" README.md docs/*.md > "$OUT/docs-lines.txt" 2>&1 || true

# 7. manifest (ตรวจซ้ำได้ว่า pack นี้เกิดเมื่อไหร่จากอะไร)
{
  echo "date: $(date -u +%FT%TZ)"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"
  sha256sum "$OUT"/* | sed 's|.*/||'
} > "$OUT/MANIFEST.txt" 2>&1

echo "wrote $OUT"
