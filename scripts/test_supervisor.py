"""Recovery invariants, real audit verification, and opt-in systemd integration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

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


class CourtPreviewTests(unittest.TestCase):
    NOW = 1793836800

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "aivm-cli"],
                       cwd=PROJECT, check=True, timeout=600)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = json.loads((PROJECT / "examples/supervisor.json").read_text())
        self.spec.update(binary=str(PROJECT / "target/debug/aivm"),
                         binary_sha256=sup.digest((PROJECT / "target/debug/aivm").read_bytes()))
        self.spec_path = self.root / "deployment.json"
        self.spec_path.write_text(json.dumps(self.spec))
        self.store = sup.Store(self.root, self.spec)
        self.adapter = FakeAdapter()
        sup.Controller(self.store, self.adapter, FakeEvidence(), True,
                       lambda: self.NOW - 20).reconcile()
        self.adapter.operations.clear()
        self.instance = self.store.load()["instances"][0]
        self.audit = self.root / "instances" / self.instance["id"] / "audit.jsonl"
        self.audit.parent.mkdir(parents=True)
        self.records = self.audit_records()
        self.audit.write_text("".join(json.dumps(row) + "\n" for row in self.records))
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.policy = {"law_version": sup.court.LAW_VERSION, "max_action": "replace",
                       "kill_switch": False, "budget_cases": 10}
        self.policy_path = self.root / "policy.json"
        self.ledger = self.root / "ledger.jsonl"
        events = [row["hash_entry"] for row in self.records]
        self.bundle = {
            "case": {"id": "case-1", "instance": self.instance["id"],
                     "session": "sess_" + self.instance["id"], "events": events,
                     "max_evidence_age_secs": 300, "min_sources": 2, "quorum": 2,
                     "requested_action": "quarantine", "supreme_violation": False},
            "evidences": [
                {"id": f"proof-{i}", "source": source, "origin": "trusted-host",
                 "event_ids": [events[i]], "instance": self.instance["id"],
                 "session": "sess_" + self.instance["id"], "age_secs": 0, "chain_ok": True}
                for i, source in enumerate(("audit", "rule"))],
            "allegations": [], "objections": [],
            "votes": [{"voter": f"j{i}", "origin": origin, "verdict": "guilty"}
                      for i, origin in enumerate(("rule", "runtime"))],
        }
        self.write_inputs()
        self.evidence = sup.Evidence(self.root, self.spec)
        self.addCleanup(self.evidence.close)
        self.preview = sup.CourtPreview(self.store, self.evidence, lambda: self.NOW)

    def audit_records(self, first_actor=None, last_session=None):
        template = sup.watch.audit.load_records((FIXTURES / "boundary.jsonl").read_bytes())[0]
        fields = ["hash_version", "seq", "timestamp", "agent", "session_id", "request_id", "state",
                  "action", "resource", "decision", "policy", "capability", "result",
                  "rule_matched", "state_transition", "hash_prev"]
        rows, previous = [], ""
        for i in range(2):
            row = {**template, "seq": i, "timestamp": self.NOW - 10 + i,
                   "agent": self.instance["id"], "session_id": "sess_" + self.instance["id"],
                   "hash_prev": previous}
            if i == 0 and first_actor:
                row["agent"] = first_actor
            if i == 1 and last_session:
                row["session_id"] = last_session
            row["hash_entry"] = hashlib.sha256(json.dumps(
                [row[key] for key in fields], separators=(",", ":")).encode()).hexdigest()
            rows.append(row)
            previous = row["hash_entry"]
        return rows

    def use_audit(self, records):
        self.records = records
        self.audit.write_text("".join(json.dumps(row) + "\n" for row in records))
        events = [row["hash_entry"] for row in records]
        self.bundle["case"]["events"] = events
        for i, evidence in enumerate(self.bundle["evidences"]):
            evidence["event_ids"] = [events[i]]
        self.write_inputs()

    def write_inputs(self):
        self.policy_path.write_text(json.dumps(self.policy))
        (self.corpus / "case.json").write_text(json.dumps(self.bundle))
        verdict = sup.court.judge(**self.bundle)
        created = datetime.fromtimestamp(self.NOW - 5, timezone.utc).isoformat()
        self.directive = sup.court.enforcement_directive(
            verdict, self.bundle, self.policy, created)
        self.ledger.write_text(json.dumps(self.directive) + "\n")

    def run_preview(self):
        before = self.store.path.read_bytes()
        audit_before = self.audit.read_bytes() if self.audit.exists() else None
        result = self.preview.preview(self.corpus, self.ledger, self.policy_path)
        self.assertEqual(self.store.path.read_bytes(), before)
        if audit_before is not None:
            self.assertEqual(self.audit.read_bytes(), audit_before)
        self.assertEqual(self.adapter.operations, [])
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["enforcement_enabled"])
        self.assertEqual(json.loads((self.root / "court-preview.json").read_text()), result)
        self.assertEqual((self.root / "court-preview.json").stat().st_mode & 0o777, 0o600)
        return result

    def assert_blocked(self, fragment):
        report = self.run_preview()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["cases"], [])
        self.assertIn(fragment, report["error"])

    def test_valid_directive_previews_and_replays_without_runtime_effects(self):
        report = self.run_preview()
        self.assertEqual(report["status"], "ready")
        plan, = report["cases"]
        self.assertEqual((plan["instance"], plan["session"], plan["directive"]),
                         (self.instance["id"], self.bundle["case"]["session"], "quarantine"))
        self.assertTrue(plan["would_apply"])
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["release_mode"], "policy-review")
        self.assertEqual(report["ledger_sha256"], sup.digest(self.ledger.read_bytes()))
        before = (self.root / "court-preview.json").read_bytes()
        self.assertEqual(self.run_preview(), report)
        self.assertEqual((self.root / "court-preview.json").read_bytes(), before)

    def test_forged_directive_fields_are_rejected_before_preview(self):
        for field, value in (("instance", "vm-b"), ("session", "old-session"),
                             ("directive", "grant"), ("action", "replace"),
                             ("release_mode", "automatic"), ("applied", False),
                             ("law_hash", "0" * 64), ("bundle_sha256", "0" * 64),
                             ("independent_sources", True), ("grant", ["process.exec"])):
            with self.subTest(field=field):
                self.ledger.write_text(json.dumps({**self.directive, field: value}) + "\n")
                self.assert_blocked("directive")

    def test_wrong_target_and_session_are_rejected_even_with_freshly_judged_bundle(self):
        for field, value, error in (("instance", "vm-b", "instance"),
                                   ("session", "old-session", "session")):
            with self.subTest(field=field):
                original = self.bundle["case"][field]
                self.bundle["case"][field] = value
                for evidence in self.bundle["evidences"]:
                    evidence[field] = value
                self.write_inputs()
                self.assert_blocked(error)
                self.bundle["case"][field] = original
                for evidence in self.bundle["evidences"]:
                    evidence[field] = original

    def test_receiver_uses_audit_time_instead_of_claimed_age(self):
        self.preview.now = lambda: self.NOW + 290
        self.assertEqual(self.run_preview()["status"], "ready")
        self.preview.now = lambda: self.NOW + 291
        self.assert_blocked("stale")

    def test_session_rollover_and_cross_actor_audit_events_are_rejected(self):
        self.use_audit(self.audit_records(last_session="new-session"))
        self.assert_blocked("session")
        self.use_audit(self.audit_records(first_actor="other-instance"))
        self.assert_blocked("binding")

    def test_persisted_audit_anchor_must_be_present_in_verified_snapshot(self):
        state = self.store.load()
        state["instances"][0]["audit_tip"] = self.records[0]["hash_entry"]
        self.store.save(state)
        self.assertEqual(self.run_preview()["status"], "ready")
        state["instances"][0]["audit_tip"] = "0" * 64
        self.store.save(state)
        self.assert_blocked("continuity")

    def test_missing_invented_or_corrupt_audit_cannot_authorize_a_plan(self):
        original = self.audit.read_bytes()
        self.audit.unlink()
        self.assert_blocked("audit")
        self.audit.write_bytes(original.replace(b"path-traversal", b"path-traversaL"))
        self.assert_blocked("audit")
        self.audit.write_bytes(original)
        self.bundle["case"]["events"] = ["invented"]
        for evidence in self.bundle["evidences"]:
            evidence["event_ids"] = ["invented"]
        self.write_inputs()
        self.assert_blocked("event")

    def test_retired_held_or_draining_instances_cannot_receive_plans(self):
        original = self.store.load()
        for flag in ("retired", "completed", "quarantining", "hold", "draining"):
            with self.subTest(flag=flag):
                state = json.loads(json.dumps(original))
                if flag == "draining":
                    state["draining"] = True
                elif flag == "hold":
                    state["instances"][0]["hold"] = True
                else:
                    state["instances"][0]["phase"] = flag
                self.store.save(state)
                self.assert_blocked("state")

    def test_current_policy_caps_and_kill_switch_suppress_old_directives(self):
        self.policy["max_action"] = "watch"
        self.policy_path.write_text(json.dumps(self.policy))
        plan, = self.run_preview()["cases"]
        self.assertEqual(plan["directive"], "watch")
        self.policy["kill_switch"] = True
        self.policy_path.write_text(json.dumps(self.policy))
        plan, = self.run_preview()["cases"]
        self.assertEqual(plan["directive"], "none")
        self.assertFalse(plan["would_apply"])
        self.assertEqual(plan["reason"], "kill-switch")

    def test_policy_expansion_cannot_raise_a_previously_capped_or_killed_directive(self):
        for cap, killed, expected in (("watch", False, "watch"), ("replace", True, "none")):
            with self.subTest(cap=cap, killed=killed):
                self.policy.update(max_action=cap, kill_switch=killed)
                self.write_inputs()
                self.policy.update(max_action="replace", kill_switch=False)
                self.policy_path.write_text(json.dumps(self.policy))
                plan, = self.run_preview()["cases"]
                self.assertEqual(plan["directive"], expected)

    def test_controller_lock_prevents_a_racing_preview(self):
        with self.store.locked():
            with self.assertRaises(BlockingIOError):
                self.preview.preview(self.corpus, self.ledger, self.policy_path)
        self.assertFalse((self.root / "court-preview.json").exists())

    def test_duplicate_or_invalid_last_record_blocks_the_entire_preview(self):
        row = json.dumps(self.directive)
        self.ledger.write_text(row + "\n" + row + "\n")
        self.assert_blocked("duplicate")
        self.ledger.write_text(row + "\n" + json.dumps({**self.directive, "case_id": "other"}) + "\n")
        self.assert_blocked("bundle")

    def test_future_creation_and_expired_review_never_mean_auto_release(self):
        self.preview.now = lambda: self.NOW - 6
        self.assert_blocked("future")
        self.preview.now = lambda: self.NOW + sup.court.REVIEW_HORIZON_SECS
        self.assert_blocked("review")

    def test_empty_oversized_symlink_and_duplicate_json_inputs_fail_closed(self):
        original = self.ledger.read_bytes()
        for raw, error in ((b"", "empty"), (b" " * (1024 * 1024 + 1), "limit"),
                           (b'{"case_id":"a","case_id":"b"}\n', "duplicate")):
            with self.subTest(error=error):
                self.ledger.write_bytes(raw)
                self.assert_blocked(error)
        self.ledger.unlink()
        source = self.root / "source.jsonl"
        source.write_bytes(original)
        self.ledger.symlink_to(source)
        self.assert_blocked("input")
        self.ledger.unlink()
        os.mkfifo(self.ledger)
        self.assert_blocked("regular file")

    def test_duplicate_bundle_identity_is_not_selected_by_file_order(self):
        (self.corpus / "duplicate.json").write_text(json.dumps(self.bundle))
        self.assert_blocked("duplicate court bundle")

    def test_budget_exceeded_blocks_all_cases_and_replaces_previous_preview(self):
        self.run_preview()
        self.policy["budget_cases"] = 0
        self.policy_path.write_text(json.dumps(self.policy))
        self.assert_blocked("budget")

    def cli(self, *extra):
        return subprocess.run(
            [sys.executable, str(Path(sup.__file__)), str(self.spec_path),
             "--state-dir", str(self.root), "--court-ledger", str(self.ledger),
             "--court-corpus", str(self.corpus), "--court-policy", str(self.policy_path), *extra],
            capture_output=True, text=True, timeout=10)

    def test_cli_emits_preview_and_blocked_exit_without_reconciling(self):
        # CLI ใช้นาฬิกาจริง จึงสร้าง audit และ directive ที่สดสำหรับรอบนี้
        self.NOW = int(time.time())
        self.use_audit(self.audit_records())
        state_before = self.store.path.read_bytes()
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["dry_run"])
        self.assertFalse(report["enforcement_enabled"])
        self.assertEqual(self.store.path.read_bytes(), state_before)
        self.ledger.write_text("{}\n")
        result = self.cli()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "blocked")
        self.assertEqual(self.store.path.read_bytes(), state_before)

    def test_cli_rejects_apply_watch_and_drain_before_creating_a_preview(self):
        for flag in ("--apply", "--watch", "--drain"):
            with self.subTest(flag=flag):
                result = self.cli(flag)
                self.assertEqual(result.returncode, 2)
                self.assertIn("incompatible", result.stderr)
                self.assertFalse((self.root / "court-preview.json").exists())


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
