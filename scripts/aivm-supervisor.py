#!/usr/bin/env python3
"""Single-host, finite-job reconciler. Plans by default; --apply controls systemd units."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

module = importlib.util.spec_from_file_location("security_watch", Path(__file__).with_name("qwen-audit-watch.py"))
watch = importlib.util.module_from_spec(module)
module.loader.exec_module(watch)
MAX_INSTANCES = 256


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def private_write(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".save-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            file.write(canonical(value) + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_spec(path, verify_binary=True):
    spec = watch.audit.decode(path.read_text())
    allowed = {"name", "replicas", "binary", "binary_sha256", "vm_config", "task", "max_steps",
               "max_replacements", "window_seconds", "job_timeout_seconds"}
    if not isinstance(spec, dict) or set(spec) != allowed:
        raise ValueError("spec must contain exactly: " + ", ".join(sorted(allowed)))
    if not isinstance(spec["name"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", spec["name"]):
        raise ValueError("invalid deployment name")
    for key, low, high in [("replicas", 1, 16), ("max_steps", 1, 1000),
                           ("max_replacements", 0, 10), ("window_seconds", 60, 86400),
                           ("job_timeout_seconds", 10, 86400)]:
        if type(spec[key]) is not int or not low <= spec[key] <= high:
            raise ValueError("invalid " + key)
    if not isinstance(spec["task"], str) or not 1 <= len(spec["task"]) <= 8192:
        raise ValueError("task must contain 1..8192 characters")
    binary = Path(spec["binary"])
    if not binary.is_absolute():
        raise ValueError("binary must be an absolute executable path")
    if verify_binary and (not binary.is_file() or not os.access(binary, os.X_OK)):
        raise ValueError("binary must be an absolute executable path")
    if verify_binary and digest(binary.read_bytes()) != spec["binary_sha256"]:
        raise ValueError("binary SHA256 mismatch")
    config = spec["vm_config"]
    if not isinstance(config, dict) or config.get("runtime", {}).get("isolation") not in {"container", "microvm"}:
        raise ValueError("managed jobs require explicit container or microvm isolation")
    # This first adapter intentionally has no external credential provider.
    if config.get("secrets") or config.get("model", {}).get("provider", "echo") not in {"echo", "local"}:
        raise ValueError("v1 supports local/echo models and no secret policies")
    return spec


class Store:
    """One controller owns this private directory; state is durable before each effect."""
    def __init__(self, root, spec):
        self.root = root
        self.spec = spec
        self.path = root / "controller.json"

    @contextlib.contextmanager
    def locked(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if self.root.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("state directory must be owned by this user, mode 0700, and not a symlink")
        fd = os.open(self.root / "controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def load(self):
        if self.path.exists():
            state = watch.audit.decode(self.path.read_text())
            if state["version"] != 1:
                raise ValueError("unsupported controller state version")
            if state["spec_sha256"] != digest(canonical(self.spec).encode()):
                raise ValueError("spec changed; use a new state directory for a new deployment")
            return state
        return {"version": 1, "deployment": uuid.uuid4().hex, "spec_sha256": digest(canonical(self.spec).encode()),
                "replacements": [], "instances": [], "next_generation": 0}

    def save(self, state):
        private_write(self.path, state)


class SystemdAdapter:
    """Commands come exclusively from the operator spec; never from model/event text."""
    def __init__(self, root, spec):
        self.root, self.spec = root, spec

    def command(self, args, timeout=30):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("command failed: " + result.stderr[-2000:])
        return result.stdout

    def observe(self, instance):
        result = subprocess.run(["systemctl", "--user", "show", instance["unit"],
                                 "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus"],
                                capture_output=True, text=True, timeout=30)
        text = result.stdout
        values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        if values.get("LoadState") == "not-found":
            return "missing"
        if result.returncode:
            raise RuntimeError("cannot observe unit: " + result.stderr[-2000:])
        active, sub = values.get("ActiveState"), values.get("SubState")
        if (active == "active" and sub == "exited" and values.get("ExecMainStatus") == "0"
                and values.get("Result") == "success"):
            return "completed"
        if active in {"active", "activating"}:
            return "running"
        if active == "deactivating":
            return "stopping"
        return "failed"

    def start(self, instance):
        name = instance["id"]
        vms = self.root / "instances"
        directory = vms / name
        # A prepared job is never resumed with state from a prior attempt. On an
        # uncertain start after controller death, the reconciler retires it.
        if directory.exists():
            raise RuntimeError("fresh instance directory already exists")
        launch = self.root / "launch" / name
        launch.mkdir(mode=0o700, parents=True)
        for subdir in ["home", "tmp"]:
            (launch / subdir).mkdir(mode=0o700)
        private_write(launch / "job.json", {"spec": self.spec, "name": name, "root": str(vms)})
        self.command(["systemd-run", "--user", "--quiet", "--unit=" + instance["unit"],
                      "--service-type=exec", "--property=RemainAfterExit=yes",
                      "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
                      "--property=KillSignal=SIGKILL",
                      "--property=TimeoutStopSec=10s", "--property=Delegate=yes",
                      "--property=DelegateSubgroup=payload",
                      "--property=RuntimeMaxSec=" + str(self.spec["job_timeout_seconds"]),
                      "--property=WorkingDirectory=" + str(launch),
                      "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                      "HOME=" + str(launch / "home"), "TMPDIR=" + str(launch / "tmp"),
                      "/usr/bin/python3", str(Path(__file__).resolve()), "--worker", str(launch / "job.json")])

    def stop(self, instance):
        group = ""
        if self.observe(instance) != "missing":
            group = self.command(["systemctl", "--user", "show", instance["unit"],
                                  "--property=ControlGroup", "--value"]).strip()
            self.command(["systemctl", "--user", "stop", instance["unit"]])
        if self.observe(instance) in {"running", "stopping", "completed"}:
            raise RuntimeError("unit has not stopped")
        if group:
            events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
            try:
                if "populated 1" in events.read_text():
                    raise RuntimeError("unit cgroup still contains processes")
            except FileNotFoundError:
                pass  # systemd already removed the empty service cgroup


class Evidence:
    """Read actual logs through the existing verified watcher; no event inbox/LLM authority."""
    def __init__(self, root, spec):
        self.root, self.spec, self.watchers = root, spec, {}

    def verify(self, raw):
        with tempfile.TemporaryDirectory(prefix="aivm-supervisor-verify-") as temp:
            path = Path(temp) / "snapshot.jsonl"
            path.write_bytes(raw)
            subprocess.run([self.spec["binary"], "verify-audit", str(path)],
                           check=True, capture_output=True, timeout=30)

    def inspect(self, instance, final=False):
        name = instance["id"]
        watcher = self.watchers.get(name)
        if watcher is None:
            expected = instance.get("audit_tip")
            def verify(raw):
                self.verify(raw)
                rows = watch.audit.load_records(raw)
                if expected and not any(row["hash_entry"] == expected for row in rows):
                    raise ValueError("audit continuity lost across controller restart")
                if not expected and rows[0]["hash_prev"]:
                    raise ValueError("first observation is missing the audit genesis")
            watcher = watch.Watcher(self.root / "instances" / name / "audit.jsonl", verify)
            self.watchers[name] = watcher
        batches = list(watcher.poll())
        # Stop checking the startup anchor after the first accepted prefix;
        # Watcher checks subsequent append/rotation continuity itself.
        if watcher.accepted:
            watcher.verify = self.verify
        if watcher.last_record:
            instance["audit_tip"] = watcher.last_record["hash_entry"]
        if any(batch["type"] == "waiting_for_log" for batch in batches) and instance.get("audit_tip"):
            raise ValueError("previously observed audit log is missing")
        if final and (not watcher.accepted or any(batch["type"] == "waiting_for_complete_record" for batch in batches)):
            raise ValueError("completed process has no complete audit evidence")
        recent = watcher.history
        if not recent:
            return None
        alerts = watch.audit.inspect_records(recent)
        sensitive = {event for alert in alerts if alert["category"] in {"boundary_violation", "sensitive_access"}
                     for event in alert["event_ids"]}
        actors = {}
        for row in recent:
            if row["decision"] == "deny":
                actors.setdefault((row["agent"], row["session_id"]), []).append(row)
        for rows in actors.values():
            if len(rows) >= 20 and sensitive.intersection(row["seq"] for row in rows):
                proof = rows[-20:]
                if not sensitive.intersection(row["seq"] for row in proof):
                    proof = [next(row for row in rows if row["seq"] in sensitive)] + rows[-19:]
                return {"policy": "deny-burst-with-boundary-or-sensitive-access", "count": len(rows),
                        "evidence": [watcher.evidence(row) for row in proof]}
        return None

    def release(self, instance):
        watcher = self.watchers.pop(instance["id"], None)
        if watcher:
            watcher.close()

    def close(self):
        for watcher in self.watchers.values():
            watcher.close()
        self.watchers.clear()


def worker(path):
    """Runs in the delegated service, so every sandbox cgroup remains inside it."""
    job = watch.audit.decode(path.read_text())
    spec, name, root = job["spec"], job["name"], job["root"]
    config = {**spec["vm_config"], "name": name}
    if config["runtime"]["isolation"] == "container":
        entry = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::"))
        payload = Path("/sys/fs/cgroup") / entry.lstrip("/")
        if payload.name != "payload" or not payload.parent.name.startswith("aivm-"):
            raise ValueError("worker must run inside its own delegated service payload")
        delegated = payload.parent
        (delegated / "cgroup.subtree_control").write_text("+cpu +memory +pids")
        config["runtime"]["container"] = {**config["runtime"].get("container", {}),
                                            "cgroup_root": str(delegated)}
    template = path.parent / "vm.json"
    private_write(template, config)
    subprocess.run([spec["binary"], "--root", root, "create", name, "--config", str(template)],
                   check=True, timeout=120)
    os.execv(spec["binary"], [spec["binary"], "--root", root, "agent", name,
                             "--max-steps", str(spec["max_steps"]), "--json", "--", spec["task"]])


class Controller:
    def __init__(self, store, adapter, evidence, apply=False, now=time.time):
        self.store, self.adapter, self.evidence = store, adapter, evidence
        self.apply, self.now = apply, now
        self.reports = []

    def report(self, action, instance=None, **fields):
        self.reports.append({"action": action, "dry_run": not self.apply,
                             "instance": instance["id"] if instance else None, **fields})

    def save(self, state):
        if self.apply:
            self.store.save(state)

    def retire(self, state, instance):
        self.report("quarantine", instance, reason=instance["reason"])
        if not self.apply:
            return
        # Intent was persisted before stopping. Repeating stop after a crash is safe.
        self.adapter.stop(instance)
        instance["phase"] = "retired"
        instance["retired_at"] = self.now()
        self.save(state)
        self.evidence.release(instance)
        self.report("retired", instance, evidence_retained=True)

    def reconcile(self):
        self.reports = []
        state = self.store.load()
        now = self.now()
        # Never start a replacement while any previous unit is unconfirmed stopped.
        blocked = False
        for instance in state["instances"]:
            if instance["phase"] in {"retired", "completed"}:
                continue
            try:
                if state.get("draining") and instance["phase"] != "quarantining":
                    instance.update(phase="quarantining", reason={"policy": "operator-drain"})
                    self.save(state)
                if instance["phase"] == "quarantining":
                    self.retire(state, instance)
                    continue
                actual = self.adapter.observe(instance)
                if instance["phase"] == "starting" and actual == "missing":
                    # Start may have happened before a crash. Do not reuse its disk.
                    reason = {"policy": "uncertain-start"}
                else:
                    try:
                        reason = self.evidence.inspect(instance, final=actual == "completed")
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                        # Loss of observation causes containment, but never auto-replacement.
                        reason = {"policy": "observation-failure", "error": str(error)[:2000]}
                        instance["hold"] = True
                if not reason and actual == "completed":
                    self.report("completed", instance)
                    if self.apply:
                        self.adapter.stop(instance)  # also removes any lingering children
                    instance["phase"] = "completed"
                    self.save(state)
                    self.evidence.release(instance)
                    continue
                if not reason and (actual in {"missing", "failed", "stopping"}
                                   or now - instance["created_at"] > self.store.spec["job_timeout_seconds"]):
                    reason = {"policy": "runtime-unhealthy-or-timeout"}
                if reason:
                    instance.update(phase="quarantining", reason=reason)
                    self.save(state)
                    self.retire(state, instance)
                else:
                    instance["phase"] = "running"
                    self.report("running", instance)
                    self.save(state)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                blocked = True
                self.report("blocked", instance, error=str(error)[:2000])
        if blocked:
            return self.reports
        if state.get("draining"):
            self.report("drained")
            return self.reports
        for slot in range(self.store.spec["replicas"]):
            previous = [item for item in state["instances"] if item["slot"] == slot]
            last = previous[-1] if previous else None
            if last and last["phase"] != "retired":
                continue
            if last and last.get("hold"):
                self.report("blocked", last, error="observation failed; operator review required")
                continue
            if len(state["instances"]) >= MAX_INSTANCES:
                self.report("blocked", last, error="retained history limit reached; drain and review this deployment")
                continue
            attempts = [stamp for stamp in state["replacements"]
                        if now - stamp < self.store.spec["window_seconds"]]
            if last and len(attempts) >= self.store.spec["max_replacements"]:
                self.report("rate_limited", last)
                continue
            generation = state["next_generation"]
            name = "aivm-" + state["deployment"][:12] + "-" + str(generation)
            instance = {"id": name, "unit": name + ".service", "slot": slot, "phase": "starting",
                        "created_at": now, "audit_tip": None}
            self.report("start", instance, slot=slot, replaces=last["id"] if last else None)
            if not self.apply:
                state["next_generation"] += 1
                continue
            state["next_generation"] += 1
            state["instances"].append(instance)
            state["replacements"] = attempts + ([now] if last else [])
            self.save(state)
            try:
                self.adapter.start(instance)
                instance["phase"] = "running"
                self.save(state)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                # Leave starting durable: next reconciliation contains any partial start.
                self.report("blocked", instance, error=str(error)[:2000])
                break
        return self.reports

    def drain(self):
        state = self.store.load()
        state["draining"] = True
        if self.apply:
            self.save(state)
            return self.reconcile()
        return [{"action": "drain", "dry_run": True, "instance": item["id"]}
                for item in state["instances"] if item["phase"] not in {"retired", "completed"}]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path, help="Trusted deployment JSON")
    parser.add_argument("--state-dir", type=Path, required=True, help="Private host directory outside all agent workspaces")
    parser.add_argument("--apply", action="store_true", help="Allow provisioning and systemd control; default only plans")
    parser.add_argument("--watch", action="store_true", help="Reconcile until Ctrl+C; otherwise one pass")
    parser.add_argument("--drain", action="store_true", help="Stop this deployment and persistently disable new starts")
    parser.add_argument("--interval", type=float, default=2)
    args = parser.parse_args()
    if not 0.1 <= args.interval <= 60:
        raise ValueError("interval must be 0.1..60 seconds")
    # Emergency drain controls only persisted units; it must still work when
    # the original runtime binary has disappeared or failed its integrity pin.
    spec = load_spec(args.spec, verify_binary=not args.drain)
    store = Store(args.state_dir.absolute(), spec)
    evidence = Evidence(store.root, spec)
    try:
        with store.locked():
            controller = Controller(store, SystemdAdapter(store.root, spec), evidence, args.apply)
            while True:
                reports = controller.drain() if args.drain else controller.reconcile()
                for report in reports:
                    print(json.dumps(report), flush=True)
                if not args.watch:
                    if any(report["action"] == "blocked" for report in reports):
                        sys.exit(2)
                    break
                time.sleep(args.interval)
    finally:
        evidence.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--worker":
            worker(Path(sys.argv[2]))
        else:
            main()
    except KeyboardInterrupt:
        pass  # Workloads stay managed by systemd; a restarted controller rediscovers them.
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"action": "controller_error", "error": str(error)}), file=sys.stderr)
        sys.exit(2)
