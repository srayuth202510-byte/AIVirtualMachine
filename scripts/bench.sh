#!/bin/sh
# bench เริ่มต้นแบบไม่พึ่ง dependency เพิ่ม (วัด wall-time ของของที่มีอยู่แล้ว)
# ครอบคลุม: demo (enforcement ALLOW/DENY + audit verify) + adversarial must-deny + audit crate
# วิธีใช้: sh scripts/bench.sh [output.md]  (หรือ: make bench)
# หมายเหตุ: ตัวเลขนี้คือ smoke-bench ไว้จับ regression คร่าวๆ ไม่ใช่ criterion ที่กัน noise เต็มรูป
set -eu

OUT="${1:-}"
# เวลานาโนวินาทีแบบ portable บน GNU date (Ubuntu runner ใช้ได้)
now_ns() { date +%s%N; }

# รันคำสั่งแล้วคืนวินาทีทศนิยม 3 ตำแหน่ง เก็บ exit code ไว้กันบังเอิญเขียวปลอม
run_timed() {
  # $1 = ชื่อ, $2... = คำสั่ง
  name="$1"
  shift
  start="$(now_ns)"
  # shellcheck disable=SC2068
  if $@ >/dev/null 2>&1; then
    status="pass"
  else
    status="FAIL"
  fi
  end="$(now_ns)"
  ms="$(( (end - start) / 1000000 ))"
  # แปลงเป็นวินาทีทศนิยมด้วย awk (มีทุกเครื่อง ไม่ต้องพึ่ง python)
  secs="$(awk "BEGIN {printf \"%.3f\", $ms/1000}")"
  printf '%s|%s|%s\n' "$name" "$secs" "$status"
}

echo "== AIVM smoke-bench ==" >&2

DEMO="$(run_timed demo cargo run -q -p aivm-cli -- demo)"
ADV="$(run_timed adversarial cargo test -q -p aivm-adversarial)"
AUDIT="$(run_timed audit cargo test -q -p aivm-audit)"

TABLE="| case | secs | result |
|---|---|---|
| demo (14-case enforcement + audit verify) | $(printf '%s' "$DEMO" | cut -d'|' -f2) | $(printf '%s' "$DEMO" | cut -d'|' -f3) |
| adversarial must-deny (§38) | $(printf '%s' "$ADV" | cut -d'|' -f2) | $(printf '%s' "$ADV" | cut -d'|' -f3) |
| audit (hash chain + rotate) | $(printf '%s' "$AUDIT" | cut -d'|' -f2) | $(printf '%s' "$AUDIT" | cut -d'|' -f3) |"

printf '%s\n' "$TABLE"

# ถ้าส่ง path มาให้เขียนไฟล์ด้วย (ไว้แปะ PR กัน regression แบบง่าย)
if [ -n "$OUT" ]; then
  {
    printf '# AIVM smoke-bench\n\n'
    printf 'date: %s\n\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$TABLE"
  } > "$OUT"
  echo "wrote $OUT" >&2
fi

# fail-closed: ตัวไหน FAIL ให้ bench ตกด้วย (กันอ้างตัวเลขจากรันที่พัง)
case "$TABLE" in
  *FAIL*) exit 1 ;;
esac
