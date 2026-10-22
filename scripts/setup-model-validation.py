#!/usr/bin/env python3
"""Check the KVM host, prepare a pinned runner, and enable recurring model validation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

PROJECT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("model_host_validation", PROJECT / "scripts/validate-model-host.py")
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
WORKFLOW = "model-host-validation.yml"
UNIT = "aivm-model-validation-runner.service"
LABELS = {"self-hosted", "linux", "aivm-model-kvm"}


def run(command, **kwargs):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, **kwargs)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{Path(command[0]).name} timed out") from None
    if result.returncode:
        # ไม่รวม command/output เพราะ registration token อาจอยู่ใน argv หรือ diagnostics
        raise RuntimeError(f"{Path(command[0]).name} failed (exit {result.returncode})")
    return result.stdout


def write_private(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".aivm-setup-")
    try:
        with os.fdopen(fd, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def preflight(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise RuntimeError("runner requires a non-root Linux x86_64 operator account")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("KVM is not accessible; run on the original host outside the chat sandbox")
    for tool in ("git", "cargo", "rustc", "bwrap", "systemd-run", "systemctl", "loginctl", "unshare", "mkfs.ext4", "debugfs", "ldd", "cmake", "g++"):
        if not shutil.which(tool):
            raise RuntimeError(f"host prerequisite missing: {tool}")
    helper = Path("/usr/libexec/aivm-container-init")
    metadata = helper.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022 or not os.access(helper, os.X_OK):
        raise RuntimeError("container init must be an executable, root-owned, non-writable helper")
    model, pins = args.model.resolve(strict=True), args.pins.resolve(strict=True)
    artifacts = HOST.snapshot(model, args.model_sha256, pins)
    run(["unshare", "--user", "--map-root-user", "--net", "/usr/bin/true"])
    probe = ("from pathlib import Path; "
             "relative=[line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::')][0]; "
             "controllers=Path('/sys/fs/cgroup'+relative+'/cgroup.controllers').read_text().split(); "
             "assert {'cpu','memory','pids'}.issubset(controllers), controllers")
    run(["systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect",
         "--property=Delegate=cpu memory pids", "/usr/bin/python3", "-c", probe])
    linger = run(["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"]).strip() == "yes"
    return {"host": socket.gethostname(), "artifacts": artifacts, "user_linger_enabled": linger,
            "repository_variables": {"AIVM_GGUF": str(model), "AIVM_GGUF_SHA256": args.model_sha256.lower(),
                                     "AIVM_MICROVM_PINS": str(pins)}}


def prepare_runner(directory, pin):
    directory = Path(directory)
    marker = directory / "aivm-runner-package.json"
    if directory.exists():
        if marker.is_file() and json.loads(marker.read_text()) == pin and (directory / "config.sh").is_file():
            return
        raise RuntimeError("runner directory already exists without the expected package marker")
    if not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]):
        raise ValueError("runner pin must be SHA-256")
    expected_url = f"https://github.com/actions/runner/releases/download/v{pin['version']}/actions-runner-linux-x64-{pin['version']}.tar.gz"
    if pin["url"] != expected_url:
        raise ValueError("runner must use the pinned official GitHub release URL")
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache = directory.parent / f"actions-runner-{pin['version']}.tar.gz"
    if not cache.exists() or HOST.digest(cache) != pin["sha256"]:
        fd, download = tempfile.mkstemp(dir=directory.parent, prefix=".runner-download-")
        try:
            request = urllib.request.Request(pin["url"], headers={"User-Agent": "AIVM-runner-setup"})
            with os.fdopen(fd, "wb") as output, urllib.request.urlopen(request, timeout=60) as response:
                shutil.copyfileobj(response, output)
            if HOST.digest(download) != pin["sha256"]:
                raise ValueError("runner download SHA-256 mismatch")
            os.replace(download, cache)
        finally:
            if os.path.exists(download):
                os.unlink(download)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".runner-stage-") as temporary:
        staging = Path(temporary) / "runner"
        staging.mkdir(mode=0o700)
        # data filter ปฏิเสธ archive traversal และ links ที่หนี directory
        with tarfile.open(cache, "r:gz") as archive:
            archive.extractall(staging, filter="data")
        for script in ("config.sh", "run.sh"):
            if not (staging / script).is_file():
                raise ValueError(f"runner package missing {script}")
        write_private(staging / marker.name, json.dumps(pin, indent=2) + "\n")
        staging.rename(directory)


def gh_api(endpoint, method="GET"):
    content = run(["gh", "api", "--method", method, endpoint])
    return json.loads(content) if content.strip() else None


def systemd_quote(value):
    if "\n" in value or "\r" in value or "\0" in value:
        raise ValueError("invalid newline in service path")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def service_text(directory, home):
    path = f"{home}/.cargo/bin:{home}/.local/bin:/usr/local/bin:/usr/bin:/bin"
    systemd_quote(str(directory))  # ตรวจ control characters; WorkingDirectory ไม่ใช้ shell quoting
    working_directory = str(directory).replace("%", "%%")
    return ("# AIVM model validation runner\n[Unit]\nDescription=AIVM model validation GitHub runner\n"
            "\n[Service]\n"
            f"WorkingDirectory={working_directory}\n"
            f"ExecStart={systemd_quote(str(directory / 'run.sh'))}\n"
            f"Environment={systemd_quote('PATH=' + path)}\n"
            "UMask=0077\nDelegate=cpu memory pids\nKillSignal=SIGINT\nKillMode=mixed\n"
            "TimeoutStopSec=120\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n")


def enable_workflow(repo, variables, set_variable=None, api=None):
    api = api or gh_api
    if set_variable is None:
        set_variable = lambda name, value: run(["gh", "variable", "set", name, "--repo", repo, "--body", value])
    # สลับ gate เป็น 0 ก่อนแก้ config และเปิดเป็น 1 เป็นขั้นสุดท้ายเท่านั้น
    try:
        set_variable("AIVM_ENABLE_MODEL_VALIDATION", "0")
        for name, value in variables.items():
            set_variable(name, value)
        api(f"repos/{repo}/actions/workflows/{WORKFLOW}/enable", "PUT")
        set_variable("AIVM_ENABLE_MODEL_VALIDATION", "1")
    except Exception:
        try:
            set_variable("AIVM_ENABLE_MODEL_VALIDATION", "0")
        except Exception:
            raise RuntimeError("could not confirm the workflow gate is disabled; inspect GitHub repository settings") from None
        raise


def activate(args, report):
    if not shutil.which("gh"):
        raise RuntimeError("GitHub CLI authentication is required to register the runner and enable the repository workflow")
    run(["gh", "auth", "status"])
    repository = gh_api(f"repos/{args.repo}")
    if not repository.get("permissions", {}).get("admin"):
        raise RuntimeError("GitHub repository administration permission is required")
    gh_api(f"repos/{args.repo}/actions/workflows/{WORKFLOW}")
    directory = args.runner_dir
    if not (directory / "config.sh").is_file():
        raise RuntimeError("prepare the pinned runner with --prepare-runner first")
    registration = directory / ".runner"
    if registration.exists():
        data = json.loads(registration.read_text())
        if data.get("gitHubUrl", "").rstrip("/").lower() != f"https://github.com/{args.repo}".lower():
            raise RuntimeError("existing runner belongs to a different repository")
    else:
        token = gh_api(f"repos/{args.repo}/actions/runners/registration-token", "POST")["token"]
        run([str(directory / "config.sh"), "--unattended", "--url", f"https://github.com/{args.repo}",
             "--token", token, "--name", args.runner_name, "--labels", "aivm-model-kvm", "--work", "_work"], cwd=directory)
        del token
    unit = Path.home() / ".config/systemd/user" / UNIT
    content = service_text(directory, Path.home())
    if unit.exists() and not unit.read_text().startswith("# AIVM model validation runner\n"):
        raise RuntimeError("refusing to replace an unrelated systemd unit")
    write_private(unit, content)
    # user service ต้องอยู่หลัง logout เพื่อรับ scheduled job ได้
    run(["loginctl", "--no-ask-password", "enable-linger"])
    run(["systemctl", "--user", "daemon-reload"])
    run(["systemctl", "--user", "enable", "--now", UNIT])
    for attempt in range(12):
        runners = gh_api(f"repos/{args.repo}/actions/runners?per_page=100")["runners"]
        if any(runner.get("name") == args.runner_name and runner.get("status") == "online"
               and LABELS.issubset({label["name"].lower() for label in runner.get("labels", [])}) for runner in runners):
            break
        time.sleep(5)
    else:
        raise RuntimeError("runner is not online with all required labels; workflow configuration was not changed")
    enable_workflow(args.repo, report["repository_variables"])
    run(["gh", "workflow", "run", WORKFLOW, "--repo", args.repo, "--ref", repository["default_branch"]])
    report["activation"] = "runner online; workflow enabled and initial validation dispatched"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--runner-dir", type=Path, default=Path.home() / ".local/share/aivm/model-validation-runner")
    parser.add_argument("--runner-name", default=socket.gethostname() + "-aivm-model")
    parser.add_argument("--out", type=Path, default=PROJECT / "target/model-validation-setup/host.json")
    parser.add_argument("--prepare-runner", action="store_true")
    parser.add_argument("--enable", action="store_true")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo) or not re.fullmatch(r"[\w.-]{1,64}", args.runner_name):
        parser.error("invalid repository or runner name")
    args.runner_dir = args.runner_dir.expanduser().absolute()
    report = {"repository": args.repo, "runner_directory": str(args.runner_dir), "activation": "not enabled"}
    try:
        report.update(preflight(args))
        if args.prepare_runner:
            print("Preparing pinned GitHub runner...", flush=True)
            prepare_runner(args.runner_dir, json.loads((PROJECT / "infra/github/model-validation-runner.json").read_text()))
            report["runner_package"] = "prepared"
        if args.enable:
            activate(args, report)
        write_private(args.out, json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired, tarfile.TarError) as error:
        report["error"] = str(error)
        write_private(args.out, json.dumps(report, indent=2) + "\n")
        print(f"Setup incomplete: {error}")
        return 1


if __name__ == "__main__":
    previous_mask = os.umask(0o077)
    try:
        raise SystemExit(main())
    finally:
        os.umask(previous_mask)
