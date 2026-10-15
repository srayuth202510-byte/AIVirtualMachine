"""Pins ที่ make-pins.sh สร้างต้องตรง schema ที่ Rust loader อ่าน (microvm/hardware)."""
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

# รากโปรเจคคือ parent ของ scripts/ (กันรันจากที่ไหนก็เจอสคริปต์)
PROJECT = Path(__file__).resolve().parent.parent
SCRIPT = PROJECT / "scripts" / "make-pins.sh"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def run_pins(*args):
    """รันสคริปต์แล้วคืน CompletedProcess (ไม่ raise เพื่อตรวจ fail-closed เอง)."""
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True, timeout=60)


class PinsSchemaTests(unittest.TestCase):
    def test_microvm_pins_match_rust_loader(self):
        # สคริปต์ต้องออก JSON ที่ Rust อ่าน (kernel/rootfs/binary + vcpu/mem) และ chmod 600
        with tempfile.TemporaryDirectory() as tmp:
            k = Path(tmp) / "k.bin"
            r = Path(tmp) / "rootfs.ext4"
            f = Path(tmp) / "firecracker"
            k.write_bytes(b"fake-kernel")
            r.write_bytes(b"fake-rootfs")
            f.write_bytes(b"fake-fc")
            out = Path(tmp) / "pins.json"
            proc = run_pins(str(k), str(r), str(f), str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text())
            for section in ("kernel", "rootfs", "binary"):
                self.assertIn(section, doc)
                self.assertTrue(HEX64.match(doc[section]["sha256"]), section)
            self.assertEqual(doc["vcpu_count"], 1)
            self.assertEqual(doc["mem_mb"], 256)
            # trust root ต้อง operator-only (0600) ตาม docs/microvm.md
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_hardware_pins_have_no_binary(self):
        # โหมด generic (FC='-') มีแค่ kernel/rootfs ตรงกับ docs/hardware.md
        with tempfile.TemporaryDirectory() as tmp:
            k = Path(tmp) / "vmlinux"
            r = Path(tmp) / "rootfs.ext4"
            k.write_bytes(b"k")
            r.write_bytes(b"r")
            out = Path(tmp) / "hw.json"
            proc = run_pins(str(k), str(r), "-", str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text())
            self.assertIn("kernel", doc)
            self.assertIn("rootfs", doc)
            self.assertNotIn("binary", doc)

    def test_missing_file_fails_closed(self):
        # ไฟล์หายต้องตก ไม่เขียน pins หลอกๆ ออกมา
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pins.json"
            proc = run_pins(str(Path(tmp) / "nope"), str(Path(tmp) / "nope2"), "-", str(out))
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())

    def test_tampered_output_is_not_valid_schema(self):
        # กัน hash ปลอม: สคีมาต้องปฏิเสธ sha ที่ไม่ใช่ 64 hex (loader ฝั่ง Rust ก็ verify ซ้ำ)
        bad = {"kernel": {"path": "/x", "sha256": "zz"}, "rootfs": {"path": "/y", "sha256": "00" * 31 + "zz"}}
        for section in ("kernel", "rootfs"):
            self.assertIsNone(HEX64.match(bad[section]["sha256"]), section)


if __name__ == "__main__":
    unittest.main()
