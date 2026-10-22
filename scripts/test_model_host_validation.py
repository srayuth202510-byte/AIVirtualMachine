"""Regression checks for trusted pins and honest host-test evidence."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "validate_model_host", Path(__file__).with_name("validate-model-host.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class HostEvidenceTests(unittest.TestCase):
    def test_container_service_preserves_incremental_build_setting_before_worker_pinning(self):
        # systemd ต้องไม่เปลี่ยน build identity แล้วทำให้ worker pin เก่าหลัง cargo test
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            script = scripts / "test-worker-host.sh"
            shutil.copyfile(Path(__file__).with_name(script.name), script)
            tools = root / "bin"
            tools.mkdir()
            (tools / "cargo").write_text("#!/bin/sh\nexit 0\n")
            capture = root / "systemd-arguments.json"
            (tools / "systemd-run").write_text(
                "#!/usr/bin/python3\nimport json,os,sys\n"
                "open(os.environ['CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\n")
            for tool in tools.iterdir():
                tool.chmod(0o755)
            model = root / "model.gguf"
            model.write_bytes(b"fixture")
            for setting in (None, "0", "1"):
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], CAPTURE=str(capture))
                env.pop("CARGO_INCREMENTAL", None)
                if setting is not None:
                    env["CARGO_INCREMENTAL"] = setting
                subprocess.run(["sh", str(script), "container", str(model)], env=env,
                               capture_output=True, text=True, check=True)
                self.assertIn("--setenv=CARGO_INCREMENTAL=" + (setting or "1"), json.loads(capture.read_text()))

    def test_zero_exit_without_exact_test_or_with_skip_is_not_success(self):
        passed = "test result: ok. 1 passed; 0 failed; 0 ignored; 9 filtered out; finished in 1s"
        self.assertTrue(HOST.exact_test_passed(passed))
        self.assertFalse(HOST.exact_test_passed("build succeeded"))
        self.assertFalse(HOST.exact_test_passed(passed.replace("1 passed", "0 passed")))
        self.assertFalse(HOST.exact_test_passed(passed.replace("0 ignored", "1 ignored")))
        self.assertFalse(HOST.exact_test_passed("skip: no KVM\n" + passed))

    def test_snapshot_rejects_changed_model_and_changed_boot_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = root / "model.gguf"
            model.write_bytes(b"approved model")
            expected = hashlib.sha256(model.read_bytes()).hexdigest()
            boot = root / "boot"
            boot.write_bytes(b"approved boot artifact")
            entry = {"path": str(boot), "sha256": HOST.digest(boot)}
            pins = root / "pins.json"
            pins.write_text(json.dumps(dict.fromkeys(("kernel", "rootfs", "binary"), entry)))
            before = HOST.snapshot(model, expected, pins)
            self.assertEqual(before["model"]["sha256"], expected)
            model.write_bytes(b"changed model")
            with self.assertRaisesRegex(ValueError, "model: sha256 mismatch"):
                HOST.snapshot(model, expected, pins)
            model.write_bytes(b"approved model")
            boot.write_bytes(b"changed boot artifact")
            with self.assertRaisesRegex(ValueError, "kernel: sha256 mismatch"):
                HOST.snapshot(model, expected, pins)


if __name__ == "__main__":
    unittest.main()
