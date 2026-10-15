#!/usr/bin/env python3
"""กัน CI/docs drift: `make ci` ต้องตรงกับ steps ใน .github/workflows/ci.yml."""
import re
import sys
from pathlib import Path

# รากโปรเจค (ไฟล์นี้อยู่ใน scripts/)
PROJECT = Path(__file__).resolve().parent.parent


def fail(msg):
    print(f"paraty FAIL: {msg}")
    return False


def main():
    ok = True
    mk = (PROJECT / "Makefile").read_text()
    ci = (PROJECT / ".github/workflows/ci.yml").read_text()

    # 1. make ci ต้องมี gate ครบ (verify + e2e + microvm + hardware)
    m = re.search(r"^ci:(.*)$", mk, re.M)
    deps = m.group(1) if m else ""
    for need in ["verify", "e2e", "check-microvm", "test-microvm", "check-hardware", "test-hardware"]:
        if need not in deps:
            ok = fail(f"Makefile ci ขาด {need}") and False

    # 2. CI verify job ต้องมีขั้นตอนครบ (กันลืมเพิ่ม step หลังเพิ่ม test ใหม่)
    for need in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-targets",
        "cargo test --workspace",
        "test_qwen_",
        "test_supervisor.py",
        "test_detection.py",
        "test_immunity.py",
        "test_pins.py",
        "test_security_court.py",
        "eval-qwen-audit.py",
        "smoke-qwen-watch.py",
        "make test-microvm",
        "make check-hardware",
        "make test-hardware",
        "cargo run -q -p aivm-cli -- demo",
        "sh scripts/smoke.sh",
    ]:
        if need not in ci:
            ok = fail(f"ci.yml ขาด {need!r}") and False

    # 3. กันคอมเมนต์เก่า (demo ตอนนี้ 14 เคส ไม่ใช่ 12)
    if "12 เคส" in ci:
        ok = fail("ci.yml ยังเขียน 12 เคส (demo ปัจจุบัน 14 เคส)") and False

    # 4. Makefile test ต้องมี pins + court test (เพิ่มใน P2/P7 ห้ามหลุดเงียบ)
    for need in ("test_pins.py", "test_security_court.py"):
        if need not in mk:
            ok = fail(f"Makefile test ขาด {need}") and False

    print("parity: all green" if ok else "parity: FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
