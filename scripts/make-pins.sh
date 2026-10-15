#!/bin/sh
# สร้าง pins.json จากไฟล์จริงบนเครื่องนี้ (ไม่ copy hash ข้ามเครื่อง)
# วิธีใช้ microvm: sh scripts/make-pins.sh KERNEL ROOTFS FIRECRACKER OUT.json [--vcpu N] [--mem MB]
# วิธีใช้ hardware/generic (ไม่มีไบนารี VMM): sh scripts/make-pins.sh KERNEL ROOTFS - OUT.json
# สคริปต์นี้อ่านอย่างเดียว + เขียนไฟล์ OUT เดียว ไม่มีผลอื่น (idempotent)
set -eu

# ค่า default ตรงกับ docs/microvm.md schema
VCPU=1
MEM=256

# แกะออปชันท้าย (sh ล้วน ไม่พึ่ง getopt ยาว)
ARGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vcpu) VCPU="$2"; shift 2 ;;
    --mem) MEM="$2"; shift 2 ;;
    -h|--help) sed -n '1,12p' "$0"; exit 0 ;;
    *) ARGS="$ARGS $1"; shift ;;
  esac
done
# shellcheck disable=SC2086
set -- $ARGS
if [ $# -ne 4 ]; then
  echo "usage: sh scripts/make-pins.sh KERNEL ROOTFS FIRECRACKER|'-' OUT.json [--vcpu N] [--mem MB]" >&2
  exit 2
fi
KERNEL="$1"; ROOTFS="$2"; FC="$3"; OUT="$4"

# ไฟล์ต้นทางต้องมีจริงและอ่านได้ (fail-closed ตั้งแต่ก่อนคำนวณ hash)
for f in "$KERNEL" "$ROOTFS"; do
  [ -r "$f" ] || { echo "miss: อ่าน $f ไม่ได้" >&2; exit 1; }
done
if [ "$FC" != "-" ]; then
  [ -x "$FC" ] || [ -r "$FC" ] || { echo "miss: อ่าน $FC ไม่ได้" >&2; exit 1; }
fi

# คำนวณ sha256 จากไฟล์ที่โหลดมาเอง (ห้าม copy hash ข้ามเครื่อง)
kh="$(sha256sum "$KERNEL" | cut -d' ' -f1)"
rh="$(sha256sum "$ROOTFS" | cut -d' ' -f1)"
# ตรวจว่าเป็น hex 64 ตัวจริงก่อนเขียน (กัน sha256sum เพี้ยน/ไฟล์ถูกสลับกลางทาง)
case "$kh $rh" in
  *[^0-9a-f]*|*" "*[^0-9a-f]*|????*) : ;;
esac
for h in "$kh" "$rh"; do
  case "$h" in
    ????????????????????????????????????????????????????????????????) : ;;
    *) echo "miss: hash ไม่ใช่ 64 hex ($h)" >&2; exit 1 ;;
  esac
done

if [ "$FC" = "-" ]; then
  # โหมด hardware/generic: ไม่มี binary pin (schema มีแค่ kernel/rootfs)
  python3 - "$KERNEL" "$kh" "$ROOTFS" "$rh" "$OUT" <<'PY'
import json,sys
k,ks,r,rs,out = sys.argv[1:6]
doc = {"kernel":{"path":k,"sha256":ks},"rootfs":{"path":r,"sha256":rs}}
open(out,"w").write(json.dumps(doc,indent=2)+"\n")
PY
else
  fh="$(sha256sum "$FC" | cut -d' ' -f1)"
  case "$fh" in
    ????????????????????????????????????????????????????????????????) : ;;
    *) echo "miss: hash ไม่ใช่ 64 hex ($fh)" >&2; exit 1 ;;
  esac
  python3 - "$KERNEL" "$kh" "$ROOTFS" "$rh" "$FC" "$fh" "$VCPU" "$MEM" "$OUT" <<'PY'
import json,sys
k,ks,r,rs,f,fs,vcpu,mem,out = sys.argv[1:10]
doc = {"kernel":{"path":k,"sha256":ks},"rootfs":{"path":r,"sha256":rs},
       "binary":{"path":f,"sha256":fs},"vcpu_count":int(vcpu),"mem_mb":int(mem)}
open(out,"w").write(json.dumps(doc,indent=2)+"\n")
PY
fi

# ล็อกสิทธิ์ตาม docs/microvm.md (pins คือ trust root ต้อง operator-only)
chmod 600 "$OUT"
echo "wrote $OUT (0600)"
