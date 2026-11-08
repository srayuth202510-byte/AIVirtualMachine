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
import stat
import tempfile
import time
import uuid
from datetime import datetime, timezone

module = importlib.util.spec_from_file_location("security_watch", Path(__file__).with_name("qwen-audit-watch.py"))
watch = importlib.util.module_from_spec(module)
module.loader.exec_module(watch)
court_module = importlib.util.spec_from_file_location("security_court", Path(__file__).with_name("security-court.py"))
court = importlib.util.module_from_spec(court_module)
court_module.loader.exec_module(court)
MAX_INSTANCES = 256


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def court_input(path):
    """อ่าน snapshot จำกัดขนาด: ไม่ตาม symlink และไม่รอ FIFO/device."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise ValueError("court input cannot be read: " + Path(path).name) from error
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError("court input must be a regular file")
        raw = file.read(watch.audit.MAX_BYTES + 1)
    if len(raw) > watch.audit.MAX_BYTES:
        raise ValueError("court input exceeds 1 MiB limit")
    return raw


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

    def court_records(self, instance):
        """ตรวจ audit โดยไม่แก้ watcher/audit_tip หรือเรียก runtime ที่อาจกู้ state."""
        raw = court_input(self.root / "instances" / instance["id"] / "audit.jsonl")
        if not raw.endswith(b"\n"):
            raise ValueError("audit snapshot is incomplete")
        rows = watch.audit.load_records(raw)
        try:
            self.verify(raw)
        except subprocess.SubprocessError as error:
            raise ValueError("audit verification failed") from error
        anchor = instance.get("audit_tip")
        if anchor and not any(row["hash_entry"] == anchor for row in rows):
            raise ValueError("audit continuity lost against controller state")
        if not anchor and rows[0]["hash_prev"]:
            raise ValueError("audit genesis is missing")
        if any(a["timestamp"] > b["timestamp"] for a, b in zip(rows, rows[1:])):
            raise ValueError("audit timestamp regressed")
        return rows

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
        # Restore sealed source sequences; watcher event IDs span rotations.
        # Rust owns the containment rule. No Python fallback if it fails.
        records = [{"event_id": row["seq"], "generation": row["_generation"],
                    "record": {**{key: value for key, value in row.items()
                                  if key not in {"_source_seq", "_generation"}},
                               "seq": row["_source_seq"]}} for row in recent]
        result = subprocess.run([self.spec["binary"], "inspect-containment"],
                                input=canonical({"records": records}), text=True,
                                capture_output=True, check=True, timeout=30)
        reason = watch.audit.decode(result.stdout)
        if reason is not None and (
                not isinstance(reason, dict) or set(reason) != {"policy", "count", "evidence"}
                or reason["policy"] != "deny-burst-with-boundary-or-sensitive-access"
                or type(reason["count"]) is not int or not 20 <= reason["count"] <= 4096
                or not isinstance(reason["evidence"], list) or len(reason["evidence"]) != 20):
            raise ValueError("invalid Rust containment response")
        if reason is not None:
            expected = {row["seq"]: watcher.evidence(row) for row in recent}
            proof = reason["evidence"]
            if (any(not isinstance(item, dict) or type(item.get("event_id")) is not int
                    or item != expected.get(item["event_id"]) for item in proof)
                    or len({item["event_id"] for item in proof}) != 20):
                raise ValueError("Rust containment response references invalid evidence")
        return reason

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


class CourtPreview:
    """Receiver แบบ dry-run เท่านั้น ไม่มี adapter หรือเส้นทางเปลี่ยน runtime."""
    def __init__(self, store, evidence, now=time.time):
        self.store, self.evidence, self.now = store, evidence, now

    def preview(self, corpus_dir, ledger_path, policy_path):
        # ล็อกเดียวกับ controller ป้องกัน reconcile เปลี่ยน instance ระหว่างอ่าน
        with self.store.locked():
            now = self.now()
            report = {"action": "court_preview", "dry_run": True, "enforcement_enabled": False,
                      "status": "blocked", "evaluated_utc": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                      "cases": []}
            try:
                if not self.store.path.is_file():
                    raise ValueError("court preview requires persisted controller state")
                state = self.store.load()
                report["state_sha256"] = digest(canonical(state).encode())
                report["deployment"] = state["deployment"]
                raw = court_input(ledger_path)
                report["ledger_sha256"] = digest(raw)
                policy_raw = court_input(policy_path)
                report["policy_sha256"] = digest(policy_raw)
                policy = court.validate_policy(watch.audit.decode(policy_raw.decode()))
                rows = [watch.audit.decode(line) for line in raw.decode().splitlines() if line.strip()]
                if not rows:
                    raise ValueError("court ledger is empty")
                if len(rows) > min(policy["budget_cases"], MAX_INSTANCES):
                    raise ValueError("court preview budget exceeded")
                bundles = {}
                for path in Path(corpus_dir).glob("*.json"):
                    if path.name == "labels.json":
                        continue
                    if len(bundles) >= MAX_INSTANCES:
                        raise ValueError("court corpus file limit exceeded")
                    bundle = watch.audit.decode(court_input(path).decode())
                    if not isinstance(bundle, dict) or set(bundle) != {
                            "case", "evidences", "allegations", "objections", "votes"}:
                        raise ValueError("court bundle fields mismatch")
                    case_id = bundle["case"]["id"]
                    if case_id in bundles:
                        raise ValueError("duplicate court bundle case_id")
                    bundles[case_id] = bundle
                instances = {item["id"]: item for item in state["instances"]}
                if len(instances) != len(state["instances"]):
                    raise ValueError("duplicate instance in controller state")
                plans, seen, snapshots = [], set(), {}
                for row in rows:
                    if not isinstance(row, dict) or set(row) != court.DIRECTIVE_FIELDS:
                        raise ValueError("court directive fields mismatch")
                    case_id = row["case_id"]
                    if case_id in seen:
                        raise ValueError("duplicate directive case_id")
                    seen.add(case_id)
                    if case_id not in bundles:
                        raise ValueError("court directive has no matching bundle")
                    bundle = bundles[case_id]
                    # ถอดเพดานที่เกิดผลจาก record แล้ว replay ทุกฟิลด์ ไม่เชื่อ applied
                    # หรือตัวเลขที่ Python อาจเทียบ True == 1; policy ปัจจุบันครอบอีกชั้น
                    replay_policy = {**policy, "max_action": row["action"],
                                     "kill_switch": row["outcome"] == "killed"}
                    expected = court.enforcement_directive(
                        court.judge(**bundle), bundle, replay_policy, row["created_utc"])
                    if canonical(expected) != canonical(row):
                        raise ValueError("court directive does not match bundle replay")
                    created = datetime.fromisoformat(row["created_utc"]).timestamp()
                    if created > now:
                        raise ValueError("court directive creation is in the future")
                    if now >= datetime.fromisoformat(row["review_deadline_utc"]).timestamp():
                        raise ValueError("court directive requires policy review; no automatic release")
                    name = row["instance"]
                    if name not in instances or not re.fullmatch(r"aivm-[0-9a-f]{12}-[0-9]+", name):
                        raise ValueError("court directive targets an unknown instance")
                    instance = instances[name]
                    if (state.get("draining") or instance.get("hold")
                            or instance["phase"] != "running"):
                        raise ValueError("controller state does not permit a court plan")
                    if name not in snapshots:
                        snapshots[name] = self.evidence.court_records(instance)
                    records = snapshots[name]
                    latest = records[-1]
                    if (latest["agent"] != name or not latest["session_id"]
                            or latest["session_id"] != row["session"]):
                        raise ValueError("court directive session does not match latest audit")
                    by_hash = {record["hash_entry"]: record for record in records}
                    used = set(row["evidence_used"])
                    refs = {ref for evidence in bundle["evidences"] if evidence["id"] in used
                            for ref in evidence["event_ids"]}
                    for ref in refs:
                        record = by_hash.get(ref)
                        if record is None:
                            raise ValueError("court evidence event is absent from verified audit")
                        if record["agent"] != name or record["session_id"] != row["session"]:
                            raise ValueError("court evidence event has wrong instance/session binding")
                        age = now - record["timestamp"]
                        if age < 0 or age > bundle["case"]["max_evidence_age_secs"]:
                            raise ValueError("court evidence is stale or has a future timestamp")
                    action = min((row["directive"], policy["max_action"]), key=court.SEVERITY.__getitem__)
                    reason = "validated-preview"
                    if policy["kill_switch"]:
                        action, reason = "none", "kill-switch"
                    elif action != row["directive"]:
                        reason = "policy-cap"
                    plans.append({"case_id": case_id, "instance": name, "session": row["session"],
                                  "directive": action, "would_apply": action != "none", "applied": False,
                                  "release_mode": court.RELEASE_MODES[action], "reason": reason,
                                  "bundle_sha256": row["bundle_sha256"], "audit_tip": latest["hash_entry"],
                                  "evidence_events": sorted(refs)})
                report.update(status="ready", cases=plans)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                # แถวท้ายผิดก็ไม่ปล่อยแผนแถวต้น และแทนรายงาน ready เก่าด้วย blocked
                report["error"] = str(error)[:2000]
            private_write(self.store.root / "court-preview.json", report)
            return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path, help="Trusted deployment JSON")
    parser.add_argument("--state-dir", type=Path, required=True, help="Private host directory outside all agent workspaces")
    parser.add_argument("--apply", action="store_true", help="Allow provisioning and systemd control; default only plans")
    parser.add_argument("--watch", action="store_true", help="Reconcile until Ctrl+C; otherwise one pass")
    parser.add_argument("--drain", action="store_true", help="Stop this deployment and persistently disable new starts")
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--court-ledger", type=Path, help="Preview court directives; never reconciles or applies")
    parser.add_argument("--court-corpus", type=Path, help="Trusted original court bundles for replay")
    parser.add_argument("--court-policy", type=Path, help="Current operator court policy")
    args = parser.parse_args()
    court_args = (args.court_ledger, args.court_corpus, args.court_policy)
    if any(court_args) and (not all(court_args) or args.apply or args.watch or args.drain):
        parser.error("court preview requires ledger, corpus and policy; incompatible with --apply/--watch/--drain")
    if not 0.1 <= args.interval <= 60:
        raise ValueError("interval must be 0.1..60 seconds")
    # Emergency drain controls only persisted units; it must still work when
    # the original runtime binary has disappeared or failed its integrity pin.
    spec = load_spec(args.spec, verify_binary=not args.drain)
    store = Store(args.state_dir.absolute(), spec)
    evidence = Evidence(store.root, spec)
    try:
        if args.court_ledger:
            report = CourtPreview(store, evidence).preview(args.court_corpus, args.court_ledger, args.court_policy)
            print(json.dumps(report), flush=True)
            if report["status"] == "blocked":
                sys.exit(2)
            return
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
