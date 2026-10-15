#!/bin/sh
# bench เริ่มต้นแบบไม่พึ่ง dependency เพิ่ม (วัด wall-time ของของที่มีอยู่แล้ว)
# ครอบคลุม: demo (enforcement ALLOW/DENY + audit verify) + adversarial must-deny + audit crate
# วิธีใช้: sh scripts/bench.sh [output.md]  (หรือ: make bench)
# ROUNDS=N รันซ้ำหลายรอบแล้วรายงาน mean/min/max (default 1 เร็วสุด)
# หมายเหตุ: ตัวเลขนี้คือ smoke-bench ไว้จับ regression คร่าวๆ ไม่ใช่ criterion ที่กัน noise เต็มรูป
set -eu

OUT="${1:-}"
ROUNDS="${ROUNDS:-1}"
case "$ROUNDS" in
  ''|*[!0-9]*|0) echo "ROUNDS must be a positive integer" >&2; exit 2 ;;
esac
# เวลานาโนวินาทีแบบ portable บน GNU date (Ubuntu runner ใช้ได้)
now_ns() { date +%s%N; }

# เก็บ ms ทุกรอบแล้วสรุป mean/min/max (ตัด noise แบบง่าย ไม่ใช่สถิติเต็มรูป)
bench_case() {
  # $1 = ชื่อ, $2... = คำสั่ง
  name="$1"
  shift
  samples=""
  status="pass"
  i=0
  while [ "$i" -lt "$ROUNDS" ]; do
    start="$(now_ns)"
    # shellcheck disable=SC2068
    if $@ >/dev/null 2>&1; then
      :
    else
      status="FAIL"
    fi
    end="$(now_ns)"
    samples="$samples $(( (end - start) / 1000000 ))"
    i=$(( i + 1 ))
  done
  stats="$(awk -v s="$samples" 'BEGIN{n=split(s,a); sum=0; min=a[1]; max=a[1];
    for(i=1;i<=n;i++){sum+=a[i]; if(a[i]<min)min=a[i]; if(a[i]>max)max=a[i]}
    printf "%.3f|%.3f|%.3f", sum/n/1000, min/1000, max/1000}')"
  printf '%s|%s|%s\n' "$name" "$stats" "$status"
}

DEMO="$(bench_case demo cargo run -q -p aivm-cli -- demo)"
ADV="$(bench_case adversarial cargo test -q -p aivm-adversarial)"
AUDIT="$(bench_case audit cargo test -q -p aivm-audit)"

TABLE="| case | mean | min | max | result |
|---|---|---|---|---|
| demo (14-case enforcement + audit verify) | $(printf '%s' "$DEMO" | cut -d'|' -f2) | $(printf '%s' "$DEMO" | cut -d'|' -f3) | $(printf '%s' "$DEMO" | cut -d'|' -f4) | $(printf '%s' "$DEMO" | cut -d'|' -f5) |
| adversarial must-deny (§38) | $(printf '%s' "$ADV" | cut -d'|' -f2) | $(printf '%s' "$ADV" | cut -d'|' -f3) | $(printf '%s' "$ADV" | cut -d'|' -f4) | $(printf '%s' "$ADV" | cut -d'|' -f5) |
| audit (hash chain + rotate) | $(printf '%s' "$AUDIT" | cut -d'|' -f2) | $(printf '%s' "$AUDIT" | cut -d'|' -f3) | $(printf '%s' "$AUDIT" | cut -d'|' -f4) | $(printf '%s' "$AUDIT" | cut -d'|' -f5) |"

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
