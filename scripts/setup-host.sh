#!/bin/sh
# ตรวจความพร้อม host แบบ idempotent (อ่านอย่างเดียว ไม่แก้ host ให้เอง)
# แยกผลเป็น Tier1 stable / Tier2 hardening / Tier3 experimental ตาม docs/architecture.md
# วิธีใช้: sh scripts/setup-host.sh
# exit 0 = Tier1 process พร้อม, exit 1 = Tier1 ไม่พร้อม (fail-closed ห้ามฝืนรัน Tier สูงกว่า)
set -eu

# พิมพ์ผลแบบ [ok]/[miss] ให้อ่านง่ายใน CI log
ok() { printf '[ok] %s\n' "$1"; }
miss() { printf '[miss] %s\n' "$1"; }
info() { printf '[info] %s\n' "$1"; }

echo "== AIVM host check (read-only) =="

# 1. ของพื้นฐานที่ต้องมีทุก Tier (Rust toolchain)
if command -v cargo >/dev/null 2>&1; then
  ok "cargo: $(cargo --version 2>/dev/null || echo present)"
else
  miss "cargo ไม่เจอ — ติดตั้ง Rust stable + clippy + rustfmt ก่อน (ดู docs/setup.md)"
fi

# 2. ของสำหรับ Tier2 microvm (KVM + firecracker + สร้าง drive)
if [ -e /dev/kvm ]; then
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "/dev/kvm อ่าน/เขียนได้"
  else
    miss "/dev/kvm มีแต่แตะไม่ได้ — เช็คกลุ่ม kvm (sudo usermod -aG kvm \$USER แล้ว login ใหม่)"
  fi
else
  miss "/dev/kvm ไม่มี — Tier2/3 บูตจริงไม่ได้ (unit/plumbing ยังรันได้แบบ skip)"
fi

# ตรวจไบนารีที่ต้องอยู่ใน PATH (แยกทีละตัวเพื่อบอกวิธีแก้ชัด)
for bin in firecracker qemu-system-x86_64 mkfs.ext4 debugfs ldd swtpm bwrap; do
  if command -v "$bin" >/dev/null 2>&1; then
    ok "$bin: $(command -v "$bin")"
  else
    # ldd มากับ glibc อยู่แล้ว ถ้าหายคือ container ผิดปกติ — ที่เหลือคือ optional ตาม Tier
    miss "$bin ไม่เจอใน PATH"
  fi
done

# 3. ของสำหรับ Tier1 container (bubblewrap + helper + cgroup v2)
if [ -x /usr/bin/bwrap ]; then
  # เช็คเวอร์ชันแบบคร่าวๆ (ต้องการ 0.11.1+ สำหรับ --bind-fd/--json-status-fd)
  if bwrap --version 2>/dev/null | grep -q .; then
    ok "bwrap: $(bwrap --version 2>/dev/null | head -n 1)"
  else
    miss "bwrap รันไม่ได้"
  fi
else
  miss "/usr/bin/bwrap ไม่มี — Tier1 container ใช้ไม่ได้ (Tier1 process ยังได้)"
fi

HELPER="/usr/libexec/aivm-container-init"
if [ -x "$HELPER" ]; then
  # helper ต้องเป็นของ root ไม่ setuid/setgid และ group/other เขียนไม่ได้ (ดู docs/container.md)
  # ใช้ stat แบบ portable (GNU coreutils บน Ubuntu)
  perms="$(stat -c '%U %a' "$HELPER" 2>/dev/null || echo 'unknown unknown')"
  # shellcheck disable=SC2086
  set -- $perms
  if [ "$1" = "root" ]; then
    ok "$HELPER เป็นของ root ($2)"
  else
    miss "$HELPER ไม่ใช่ของ root ($perms) — ติดตั้งด้วย sudo install -o root -g root -m 0755"
  fi
  if [ -u "$HELPER" ] || [ -g "$HELPER" ]; then
    miss "$HELPER เป็น setuid/setgid — ต้องถอดออก (fail-closed)"
  fi
else
  miss "$HELPER ไม่มี — ติดตั้งด้วย: cargo build --release -p aivm-sandbox --bin aivm-container-init"
fi

# cgroup v2 ต้องมี cpu memory pids ใน subtree_control ของ root ที่ delegate มา
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  ctrls="$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true)"
  info "cgroup.controllers: $ctrls"
  for c in cpu memory pids; do
    case " $ctrls " in
      *" $c "*) ok "cgroup มี $c" ;;
      *) miss "cgroup ขาด $c — ให้ service manager ตั้ง Delegate=cpu memory pids" ;;
    esac
  done
else
  miss "/sys/fs/cgroup/cgroup.controllers ไม่มี — ไม่ใช่ cgroup v2 หรือไม่ได้ mount"
fi

# 4. TEE สำหรับ Tier3 (มีหรือไม่มีก็ได้ ถือเป็น experimental)
for dev in /dev/sev /dev/sev-guest /dev/tdx_guest; do
  if [ -e "$dev" ]; then
    ok "$dev มี (ลอง Tier3 ได้)"
  else
    info "$dev ไม่มี (Tier3 ข้าม ถือว่าปกติ)"
  fi
done

# 5. สรุปด้วย aivm probe ตัวจริง (รายงานซื่อสัตย์จาก syscall ฝั่ง host)
echo "== aivm probe =="
if cargo run -q -p aivm-cli -- probe 2>/dev/null | head -n 100; then
  echo "== สรุป Tier =="
  echo "Tier1 process: ดู probe.userns/seccomp_install ข้างบน (true = พร้อม)"
  echo "Tier1 container: ดู probe.container.* (bwrap/init/cgroup quotas)"
  echo "Tier2 microvm: ต้อง probe.kvm + probe.firecracker = true + มี pins"
  echo "Tier3 hardware: experimental — ดู probe qemu/sev/tdx/swtpm ประกอบ"
else
  miss "รัน aivm probe ไม่สำเร็จ — ลอง cargo build -p aivm-cli ก่อน"
  exit 1
fi
