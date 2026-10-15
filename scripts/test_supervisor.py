"""Recovery invariants, real audit verification, and opt-in systemd integration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

module = importlib.util.spec_from_file_location("supervisor", Path(__file__).with_name("aivm-supervisor.py"))
sup = importlib.util.module_from_spec(module)
module.loader.exec_module(sup)
PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "examples/audit-review"


class FakeAdapter:
    def __init__(self):
        self.units, self.operations = {}, []
        self.stop_fails = False

    def observe(self, instance):
        return self.units.get(instance["id"], "missing")

    def start(self, instance):
        self.operations.append(("start", instance["id"]))
        self.units[instance["id"]] = "running"

    def stop(self, instance):
        self.operations.append(("stop", instance["id"]))
        if self.stop_fails:
            raise RuntimeError("cannot stop")
        self.units[instance["id"]] = "failed"


class FakeEvidence:
    def __init__(self):
        self.reason, self.error = None, None

    def inspect(self, instance, final=False):
        if self.error:
            raise self.error
        return self.reason

    def release(self, instance):
        pass


class SpecTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "deployment.json"
        self.spec = json.loads((PROJECT / "examples/supervisor.json").read_text())
        self.spec["binary"] = "/usr/bin/true"
        self.spec["binary_sha256"] = sup.digest(Path("/usr/bin/true").read_bytes())

    def load(self):
        self.path.write_text(json.dumps(self.spec))
        return sup.load_spec(self.path)

    def test_pinned_spec_accepts_only_explicit_isolation_and_local_models(self):
        self.assertEqual(self.load()["replicas"], 1)
        self.spec["vm_config"]["runtime"]["isolation"] = "sandbox"
        with self.assertRaisesRegex(ValueError, "isolation"):
            self.load()

    def test_external_credentials_rejected_until_revocation_adapter_exists(self):
        self.spec["vm_config"]["secrets"] = {"allow": ["token:read"]}
        with self.assertRaisesRegex(ValueError, "no secret"):
            self.load()
        self.spec["vm_config"].pop("secrets")
        self.spec["vm_config"]["model"]["provider"] = "openai"
        with self.assertRaisesRegex(ValueError, "local/echo"):
            self.load()

    def test_binary_change_and_unbounded_replica_count_rejected(self):
        self.spec["replicas"] = 100000
        with self.assertRaisesRegex(ValueError, "replicas"):
            self.load()
        self.spec["replicas"] = 1
        self.spec["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.load()

    def test_emergency_drain_can_read_spec_even_when_binary_is_missing(self):
        self.spec["binary"] = "/no-longer-installed/aivm"
        self.path.write_text(json.dumps(self.spec))
        with self.assertRaises(ValueError):
            sup.load_spec(self.path)
        self.assertEqual(sup.load_spec(self.path, verify_binary=False), self.spec)

    def test_cli_dry_run_does_not_launch_workloads(self):
        self.load()
        root = self.path.parent / "state"
        result = subprocess.run(["python3", str(Path(sup.__file__)), str(self.path),
                                 "--state-dir", str(root)], capture_output=True, text=True, check=True)
        self.assertTrue(json.loads(result.stdout)["dry_run"])
        self.assertFalse((root / "controller.json").exists())
        self.assertFalse((root / "instances").exists())


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = {"replicas": 1, "max_replacements": 2, "window_seconds": 60, "job_timeout_seconds": 100}
        self.store = sup.Store(self.root, self.spec)
        self.adapter, self.evidence = FakeAdapter(), FakeEvidence()
        self.now = 1000
        self.controller = sup.Controller(self.store, self.adapter, self.evidence, True, lambda: self.now)

    def instances(self):
        return self.store.load()["instances"]

    def test_default_dry_run_has_no_effects_or_persisted_state(self):
        controller = sup.Controller(self.store, self.adapter, self.evidence)
        self.assertEqual(controller.reconcile()[0]["action"], "start")
        self.assertFalse(self.store.path.exists())
        self.assertEqual(self.adapter.operations, [])

    def test_replica_count_and_restart_do_not_duplicate_live_units(self):
        self.spec["replicas"] = 2
        self.controller.reconcile()
        restarted = sup.Controller(self.store, self.adapter, self.evidence, True, lambda: self.now)
        restarted.reconcile()
        self.assertEqual(len(self.instances()), 2)
        self.assertEqual(len(self.adapter.operations), 2)

    def test_severe_evidence_stops_before_fresh_replacement_and_retains_reason(self):
        self.controller.reconcile()
        self.evidence.reason = {"policy": "test-severe", "evidence": [{"hash_entry": "proof"}]}
        self.controller.reconcile()
        old, new = self.instances()
        self.assertEqual(old["phase"], "retired")
        self.assertNotEqual(old["id"], new["id"])
        self.assertEqual(old["reason"]["evidence"][0]["hash_entry"], "proof")
        self.assertEqual([op[0] for op in self.adapter.operations], ["start", "stop", "start"])
        self.assertIsNone(new["audit_tip"])

    def test_stop_failure_prevents_replacement_and_recovers_after_restart(self):
        self.controller.reconcile()
        self.evidence.reason = {"policy": "severe"}
        self.adapter.stop_fails = True
        reports = self.controller.reconcile()
        self.assertEqual(reports[-1]["action"], "blocked")
        self.assertEqual(len(self.instances()), 1)
        self.assertEqual(self.instances()[0]["phase"], "quarantining")
        self.adapter.stop_fails = False
        self.evidence.reason = None
        sup.Controller(self.store, self.adapter, self.evidence, True, lambda: self.now).reconcile()
        self.assertEqual(len(self.instances()), 2)

    def test_observation_failure_contains_but_holds_recovery(self):
        self.controller.reconcile()
        self.evidence.error = ValueError("forged audit")
        self.controller.reconcile()
        self.assertEqual(len(self.instances()), 1)
        self.assertTrue(self.instances()[0]["hold"])
        self.assertEqual(self.instances()[0]["phase"], "retired")
        self.assertEqual(self.adapter.operations[-1][0], "stop")

    def test_budget_survives_restart_and_resets_after_window(self):
        self.controller.reconcile()
        self.evidence.reason = {"policy": "severe"}
        for _ in range(3):
            sup.Controller(self.store, self.adapter, self.evidence, True, lambda: self.now).reconcile()
        self.assertEqual(len(self.instances()), 3)
        self.assertEqual(self.instances()[-1]["phase"], "retired")
        self.now += 61
        self.controller.reconcile()
        self.assertEqual(len(self.instances()), 4)

    def test_uncertain_start_is_not_reused(self):
        self.controller.reconcile()
        state = self.store.load()
        state["instances"][0]["phase"] = "starting"
        self.store.save(state)
        self.adapter.units.clear()
        self.controller.reconcile()
        self.assertEqual(len(self.instances()), 2)
        self.assertEqual(self.instances()[0]["reason"]["policy"], "uncertain-start")

    def test_successful_process_completes_slot_and_stops_lingering_children(self):
        self.controller.reconcile()
        self.adapter.units[self.instances()[0]["id"]] = "completed"
        self.controller.reconcile()
        self.controller.reconcile()
        self.assertEqual(len(self.instances()), 1)
        self.assertEqual(self.instances()[0]["phase"], "completed")
        self.assertEqual(self.adapter.operations[-1][0], "stop")

    def test_lock_excludes_second_controller_and_spec_changes_rejected(self):
        with self.store.locked():
            with self.assertRaises(BlockingIOError):
                with self.store.locked():
                    pass
        self.controller.reconcile()
        self.spec["replicas"] = 2
        with self.assertRaisesRegex(ValueError, "spec changed"):
            self.store.load()

    def test_drain_is_durable_and_never_recreates_retired_units(self):
        self.controller.reconcile()
        self.controller.drain()
        self.assertEqual(self.instances()[0]["phase"], "retired")
        sup.Controller(self.store, self.adapter, self.evidence, True, lambda: self.now).reconcile()
        self.assertEqual(len(self.instances()), 1)
        self.assertEqual(self.adapter.operations[-1][0], "stop")

    def test_runtime_failure_replaces_but_spends_budget(self):
        self.controller.reconcile()
        self.adapter.units[self.instances()[0]["id"]] = "failed"
        self.controller.reconcile()
        self.assertEqual(len(self.instances()), 2)
        self.assertEqual(len(self.store.load()["replacements"]), 1)

    def test_timeout_stops_a_still_running_unit(self):
        self.controller.reconcile()
        self.now += 101
        self.controller.reconcile()
        self.assertEqual(self.instances()[0]["phase"], "retired")

    def test_crash_during_start_is_contained_before_retry(self):
        def partial_start(instance):
            self.adapter.units[instance["id"]] = "failed"
            raise RuntimeError("start returned an error")
        original = self.adapter.start
        self.adapter.start = partial_start
        self.controller.reconcile()
        self.assertEqual(self.instances()[0]["phase"], "starting")
        self.adapter.start = original
        self.controller.reconcile()
        self.assertEqual(self.instances()[0]["phase"], "retired")
        self.assertEqual(len(self.instances()), 2)

    def test_retained_history_limit_blocks_unbounded_recovery(self):
        self.controller.reconcile()
        state = self.store.load()
        old = state["instances"][0]
        old["phase"] = "retired"
        state["instances"] = [{**old, "id": str(index)} for index in range(sup.MAX_INSTANCES)]
        self.store.save(state)
        self.assertEqual(self.controller.reconcile()[-1]["action"], "blocked")
        self.assertEqual(len(self.instances()), sup.MAX_INSTANCES)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "aivm-cli"], cwd=PROJECT, check=True, timeout=600)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.instance = {"id": "test", "audit_tip": None}
        self.path = self.root / "instances/test/audit.jsonl"
        self.path.parent.mkdir(parents=True)
        self.evidence = sup.Evidence(self.root, {"binary": str(PROJECT / "target/debug/aivm")})
        self.addCleanup(self.evidence.close)

    def test_single_boundary_denial_and_plain_burst_do_not_trigger_replacement(self):
        for fixture in ["boundary", "burst", "benign"]:
            self.evidence.close()
            self.evidence.watchers.clear()
            self.instance["audit_tip"] = None
            self.path.write_bytes((FIXTURES / (fixture + ".jsonl")).read_bytes())
            self.assertIsNone(self.evidence.inspect(self.instance))

    def severe_bytes(self, late_boundary=False):
        rows = sup.watch.audit.load_records((FIXTURES / "burst.jsonl").read_bytes())
        if late_boundary:
            rows.append({**rows[-1], "seq": 20})
        previous = ""
        fields = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id", "state", "action",
                  "resource", "decision", "policy", "capability", "result", "rule_matched", "state_transition", "hash_prev"]
        for row in rows:
            if not late_boundary or row["seq"] == 20:
                row["rule_matched"] = "path-traversal"
            row["hash_prev"] = previous
            row["hash_entry"] = hashlib.sha256(json.dumps([row[key] for key in fields],
                                                        separators=(",", ":")).encode()).hexdigest()
            previous = row["hash_entry"]
        return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()

    def test_verified_burst_with_boundary_evidence_triggers_and_is_read_only(self):
        raw = self.severe_bytes()
        self.path.write_bytes(raw)
        reason = self.evidence.inspect(self.instance)
        self.assertEqual(reason["count"], 20)
        self.assertEqual(len(reason["evidence"]), 20)
        self.assertEqual(self.path.read_bytes(), raw)

    def test_boundary_after_initial_generic_burst_still_triggers(self):
        self.path.write_bytes(self.severe_bytes(late_boundary=True))
        self.assertEqual(self.evidence.inspect(self.instance)["count"], 21)

    def test_corruption_fails_closed_and_restart_checks_previous_tip(self):
        raw = (FIXTURES / "boundary.jsonl").read_bytes()
        self.path.write_bytes(raw)
        self.evidence.inspect(self.instance)
        self.evidence.close()
        self.evidence.watchers.clear()
        self.path.write_bytes((FIXTURES / "benign.jsonl").read_bytes())
        with self.assertRaisesRegex(ValueError, "continuity lost"):
            self.evidence.inspect(self.instance)
        self.evidence.close()
        self.evidence.watchers.clear()
        self.path.write_bytes(raw.replace(b"path-traversal", b"path-traversaL"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.evidence.inspect(self.instance)

    def test_completed_process_with_partial_log_is_not_accepted(self):
        self.path.write_bytes((FIXTURES / "boundary.jsonl").read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, "complete audit"):
            self.evidence.inspect(self.instance, final=True)


@unittest.skipUnless(os.environ.get("AIVM_SUPERVISOR_HOST_TEST") == "1", "opt-in: needs systemd user bus and delegation")
class HostTests(unittest.TestCase):
    def setUp(self):
        subprocess.run(["cargo", "build", "-q", "-p", "aivm-cli"], cwd=PROJECT, check=True, timeout=600)
        self.temp = tempfile.TemporaryDirectory(prefix="aivm-supervisor-host-")
        self.root = Path(self.temp.name)
        self.spec = {"name": "host-test", "replicas": 1, "binary": str(PROJECT / "target/debug/aivm"),
                     "vm_config": {"name": "template", "runtime": {"isolation": "container"}},
                     "task": "finish", "max_steps": 1, "max_replacements": 1,
                     "window_seconds": 60, "job_timeout_seconds": 120}
        self.store = sup.Store(self.root, self.spec)
        self.evidence = sup.Evidence(self.root, self.spec)
        self.adapter = sup.SystemdAdapter(self.root, self.spec)
        self.controller = sup.Controller(self.store, self.adapter, self.evidence, True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.evidence.close()
        if self.store.path.exists():
            for instance in self.store.load()["instances"]:
                subprocess.run(["systemctl", "--user", "stop", instance["unit"]], capture_output=True, timeout=30)
                subprocess.run(["systemctl", "--user", "reset-failed", instance["unit"]], capture_output=True, timeout=30)
        self.temp.cleanup()

    def wait_until(self, predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            reports = self.controller.reconcile()
            self.assertFalse(any(report["action"] == "blocked" for report in reports), reports)
            if predicate(self.store.load()["instances"]):
                return
            time.sleep(0.1)
        self.fail("host reconciliation did not reach expected state")

    def test_real_cli_worker_completes_without_restarting_job(self):
        self.wait_until(lambda instances: instances and instances[0]["phase"] == "completed")
        self.controller.reconcile()
        self.assertEqual(len(self.store.load()["instances"]), 1)
        config = (self.root / "instances" / self.store.load()["instances"][0]["id"] / "aivm.yaml").read_text()
        self.assertIn(".service", config)
        self.assertIn("cgroup_root:", config)

    def test_real_systemd_contains_descendants_and_replaces_on_synthetic_evidence(self):
        # A deliberately simple workload shim supplies synthetic signed-chain
        # evidence and a child in another session. Actual verification/creation
        # still use the real Rust CLI; systemd really starts/stops both processes.
        severe = EvidenceTests.severe_bytes(self)
        (self.root / "severe.jsonl").write_bytes(severe)
        shim = self.root / "workload.py"
        shim.write_text("#!/usr/bin/python3\n" + "\n".join([
            "import os, pathlib, subprocess, sys, time",
            "args = sys.argv[1:]",
            "if 'agent' not in args:",
            "    os.execv(" + repr(str(PROJECT / "target/debug/aivm")) + ", [" + repr(str(PROJECT / "target/debug/aivm")) + "] + args)",
            "root = pathlib.Path(args[args.index('--root') + 1])",
            "name = args[args.index('agent') + 1]",
            "child = subprocess.Popen(['/bin/sleep', '120'], start_new_session=True)",
            "entry = next(line[3:] for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))",
            "group = (pathlib.Path('/sys/fs/cgroup') / entry.lstrip('/')).parent / 'test-child'",
            "group.mkdir()",
            "(group / 'cgroup.procs').write_text(str(child.pid))",
            "(root / name / 'child.pid').write_text(str(child.pid))",
            "source = " + repr(str(self.root / "severe.jsonl")),
            "if not name.endswith('-0'): source = " + repr(str(FIXTURES / "benign.jsonl")),
            "(root / name / 'audit.jsonl').write_bytes(pathlib.Path(source).read_bytes())",
            "time.sleep(120)", ""
        ]))
        shim.chmod(0o700)
        self.spec["binary"] = str(shim)
        self.wait_until(lambda instances: len(instances) == 2 and instances[0]["phase"] == "retired")
        old, new = self.store.load()["instances"]
        child_pid = (self.root / "instances" / old["id"] / "child.pid").read_text()
        proc = Path("/proc") / child_pid / "stat"
        self.assertTrue(not proc.exists() or proc.read_text().rsplit(")", 1)[1].strip().startswith("Z"))
        self.assertNotEqual(old["id"], new["id"])
        self.assertEqual((self.root / "instances" / old["id"] / "audit.jsonl").read_bytes(), severe)
        # A new controller adopts the live replacement rather than spawning again.
        self.evidence.close()
        self.evidence = sup.Evidence(self.root, self.spec)
        self.controller = sup.Controller(self.store, self.adapter, self.evidence, True)
        self.controller.reconcile()
        self.assertEqual(len(self.store.load()["instances"]), 2)


if __name__ == "__main__":
    unittest.main()
