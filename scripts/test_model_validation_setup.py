"""Runner setup must preserve pins and enable the workflow only after configuration."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("setup_model_validation", Path(__file__).with_name("setup-model-validation.py"))
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


class RunnerSetupTests(unittest.TestCase):
    def test_enable_gate_is_last_and_failure_leaves_it_disabled(self):
        for fail in [False, True]:
            calls = []

            def set_variable(name, value):
                calls.append((name, value))
                if fail and name == "AIVM_GGUF_SHA256":
                    raise RuntimeError("write failed")

            def api(endpoint, method):
                calls.append((endpoint, method))

            variables = {"AIVM_GGUF": "/model", "AIVM_GGUF_SHA256": "a" * 64, "AIVM_MICROVM_PINS": "/pins"}
            if fail:
                with self.assertRaises(RuntimeError):
                    SETUP.enable_workflow("owner/repo", variables, set_variable, api)
                self.assertNotIn(("AIVM_ENABLE_MODEL_VALIDATION", "1"), calls)
            else:
                SETUP.enable_workflow("owner/repo", variables, set_variable, api)
                self.assertEqual(calls[-1], ("AIVM_ENABLE_MODEL_VALIDATION", "1"))
                self.assertEqual(calls[-2][1], "PUT")
            self.assertEqual(calls[0], ("AIVM_ENABLE_MODEL_VALIDATION", "0"))

    def test_verified_runner_archive_is_installed_idempotently_and_traversal_is_rejected(self):
        for malicious in [False, True]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "actions-runner-1.2.3.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    for name in (["../escape"] if malicious else ["config.sh", "run.sh"]):
                        entry = tarfile.TarInfo(name)
                        data = b"#!/bin/sh\nexit 0\n"
                        entry.size, entry.mode = len(data), 0o755
                        output.addfile(entry, io.BytesIO(data))
                pin = {"version": "1.2.3", "url": "https://github.com/actions/runner/releases/download/v1.2.3/actions-runner-linux-x64-1.2.3.tar.gz", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
                with patch.object(SETUP.urllib.request, "urlopen", side_effect=AssertionError("no download required")):
                    if malicious:
                        with self.assertRaises(tarfile.TarError):
                            SETUP.prepare_runner(root / "runner", pin)
                        self.assertFalse((root / "escape").exists())
                        self.assertFalse((root / "runner").exists())
                    else:
                        SETUP.prepare_runner(root / "runner", pin)
                        SETUP.prepare_runner(root / "runner", pin)
                        self.assertEqual(json.loads((root / "runner/aivm-runner-package.json").read_text()), pin)
                        self.assertEqual((root / "runner").stat().st_mode & 0o777, 0o700)

    def test_mismatched_download_never_installs_and_timeout_never_prints_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin = {"version": "1.2.3", "url": "https://github.com/actions/runner/releases/download/v1.2.3/actions-runner-linux-x64-1.2.3.tar.gz", "sha256": "0" * 64}
            with patch.object(SETUP.urllib.request, "urlopen", return_value=io.BytesIO(b"tampered")):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    SETUP.prepare_runner(Path(temporary) / "runner", pin)
            self.assertFalse((Path(temporary) / "runner").exists())
        command = ["config.sh", "--token", "PRIVATE-REGISTRATION-TOKEN"]
        with patch.object(SETUP.subprocess, "run", side_effect=subprocess.TimeoutExpired(command, 120)):
            with self.assertRaises(RuntimeError) as context:
                SETUP.run(command)
        self.assertNotIn("PRIVATE-REGISTRATION-TOKEN", str(context.exception))

    def test_systemd_paths_are_quoted_and_delegation_is_explicit(self):
        service = SETUP.service_text(Path('/home/operator/runner with "quotes"%'), Path("/home/operator"))
        self.assertIn("Delegate=cpu memory pids", service)
        self.assertIn("UMask=0077", service)
        self.assertIn("Environment=RUNNER_MANUALLY_TRAP_SIG=1", service)
        # runner ต้องค้นพบ mkfs.ext4/debugfs ได้เหมือน operator shell
        environment = next(line for line in service.splitlines() if line.startswith('Environment="PATH='))
        executable_paths = environment.removeprefix('Environment="PATH=').removesuffix('"').split(":")
        for directory in ("/usr/local/sbin", "/usr/sbin", "/sbin"):
            self.assertIn(directory, executable_paths)
        self.assertIn('runner with \\"quotes\\"%%/run.sh"', service)
        with self.assertRaises(ValueError):
            SETUP.systemd_quote("path\nExecStart=bad")

    def test_activation_needs_github_and_online_runner_with_complete_labels(self):
        with patch.object(SETUP.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "authentication"):
                SETUP.activate(None, {})
        for online in [False, True]:
            with tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                directory = home / "runner"
                directory.mkdir()
                (directory / "config.sh").write_text("#!/bin/sh")
                (directory / ".runner").write_text(json.dumps({"gitHubUrl": "https://github.com/owner/repo"}))
                args = SimpleNamespace(repo="owner/repo", runner_dir=directory, runner_name="model-host")
                report = {"repository_variables": {"AIVM_GGUF": "/model"}}

                def api(endpoint, *args):
                    if endpoint.endswith("/actions/runners?per_page=100"):
                        labels = SETUP.LABELS if online else {"self-hosted", "linux", "kvm"}
                        return {"runners": [{"name": "model-host", "status": "online", "labels": [{"name": label} for label in labels]}]}
                    return {"permissions": {"admin": True}, "default_branch": "main"}

                with patch.object(SETUP.shutil, "which", return_value="/usr/bin/gh"), \
                     patch.object(SETUP.Path, "home", return_value=home), \
                     patch.object(SETUP, "gh_api", side_effect=api), \
                     patch.object(SETUP, "run", return_value=""), \
                     patch.object(SETUP.time, "sleep"), \
                     patch.object(SETUP, "enable_workflow") as enable:
                    if online:
                        SETUP.activate(args, report)
                        enable.assert_called_once()
                        self.assertIn("dispatched", report["activation"])
                    else:
                        with self.assertRaisesRegex(RuntimeError, "not online"):
                            SETUP.activate(args, report)
                        enable.assert_not_called()

    def test_uncertain_enable_attempt_is_compensated_by_disabling_the_gate(self):
        calls = []

        def set_variable(name, value):
            calls.append((name, value))
            if value == "1":
                raise RuntimeError("response lost after enabling")

        with self.assertRaises(RuntimeError):
            SETUP.enable_workflow("owner/repo", {}, set_variable, lambda *args: None)
        self.assertEqual(calls[-1], ("AIVM_ENABLE_MODEL_VALIDATION", "0"))


if __name__ == "__main__":
    unittest.main()
