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
    def test_failure_evidence_requires_both_failures_recovery_and_cleanup(self):
        # ห้ามนับเพียง process exit หรือรายงานบางส่วนว่า failure/recovery ผ่าน
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "failure.json"
            self.assertFalse(HOST.failure_evidence_passed(evidence))
            rows = []
            for case in ("timeout", "recovery-after-timeout", "memory", "recovery-after-memory"):
                rows.append({"case": case, "passed": True, "descendants_reaped": True,
                    "staging_clean": True, "observed_processes": {"123": 456}, "verification": "verified",
                    "stream_deltas": 0, "error": "specific resource failure", "elapsed_ms": 10,
                    "timeout_ms": 100, "memory_mb": 128, "memory_failure_kind": "allocation-failure"})
            evidence.write_text(json.dumps(rows))
            self.assertTrue(HOST.failure_evidence_passed(evidence))
            for invalid in ([], rows[:3], rows[::-1], [{**rows[0], "passed": False}] + rows[1:],
                            [{**rows[0], "observed_processes": {}}] + rows[1:],
                            [{**rows[0], "observed_processes": {"123": True}}] + rows[1:],
                            [{**rows[0], "elapsed_ms": True}] + rows[1:],
                            [{**rows[0], "staging_clean": False}] + rows[1:],
                            rows[:2] + [{**rows[2], "memory_mb": 4096}] + rows[3:],
                            rows[:2] + [{**rows[2], "memory_failure_kind": "unknown"}] + rows[3:],
                            rows[:3] + [{**rows[3], "verification": "unverified"}]):
                evidence.write_text(json.dumps(invalid))
                self.assertFalse(HOST.failure_evidence_passed(evidence), invalid)

    def test_quality_evidence_keeps_wrong_answers_separate_from_execution_failures(self):
        # คะแนน 0/6 ที่รันครบยังเป็น evidence ที่ถูกต้อง แต่ 5/6 records หรือ infra ล้มไม่ผ่าน
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "quality.json"
            cases = json.loads((HOST.PROJECT / "examples/model-quality.json").read_text())["cases"]
            rows = [{"id": case["id"], "infrastructure_passed": True, "task_correct": False} for case in cases]
            report = {"schema": 1, "completed": len(rows), "total": len(rows), "task_correct": 0, "cases": rows}
            path.write_text(json.dumps(report))
            self.assertTrue(HOST.quality_evidence_passed(path))
            for invalid in ({**report, "cases": rows[:-1]}, {**report, "task_correct": len(rows)},
                            {**report, "cases": [{**rows[0], "infrastructure_passed": False}] + rows[1:]},
                            None, [], {**report, "cases": None}, {**report, "cases": [None]},
                            {**report, "cases": [{}]}, {**report, "cases": {}},
                            {**report, "task_correct": False}, {**report, "completed": float(len(rows))}):
                path.write_text(json.dumps(invalid))
                self.assertFalse(HOST.quality_evidence_passed(path))

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
            # evidence path และ scenario ต้องข้าม delegated service โดยไม่แตก argv เมื่อมีช่องว่าง
            evidence = root / "evidence with spaces.json"
            env["AIVM_WORKER_HOST_EVIDENCE"] = str(evidence)
            subprocess.run(["sh", str(script), "container", str(model), "/pins.json", "failure-recovery"],
                           env=env, capture_output=True, text=True, check=True)
            arguments = json.loads(capture.read_text())
            self.assertIn("--setenv=AIVM_WORKER_HOST_EVIDENCE=" + str(evidence), arguments)
            self.assertEqual(arguments[-2:], ["failure-recovery", "--inside"])

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
