"""ทดสอบ presence/absence โดยไม่ถือศูนย์ ลิสต์ว่าง หรือชื่อ field ว่าเป็นข้อมูลที่หาย."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("availability_jury", Path(__file__).with_name("qwen-court-jury.py"))
jury = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jury)
evaluation = jury.load("availability_eval", "eval-qwen-concerns.py")
detection = evaluation.detection


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.rows = detection.records({"events": [{"decision": "allow"}]})

    def test_zero_and_empty_values_remain_present(self):
        view, _, _ = jury.normalized_view(self.rows)
        self.assertEqual(view["facts"]["counts"]["denied_total"], 0)
        self.assertEqual(view["facts"]["policy_inputs"]["actors"], [])
        catalog = view["facts"]["fact_availability"]
        self.assertIn("denied_total", catalog["present_fact_ids"])
        self.assertIn("denied_one_actor_hidden_from_context", catalog["present_fact_ids"])
        self.assertNotIn("denied_total", catalog["missing_fact_ids"])

    def test_matched_context_pair_changes_availability_not_containment(self):
        absent, _, absent_rule = jury.rule_decision(self.rows)
        present, _, present_rule = jury.rule_decision(self.rows, trusted_context={"process_state": "running"})
        self.assertIn("process_state", absent["facts"]["fact_availability"]["missing_fact_ids"])
        self.assertIn("process_state", present["facts"]["fact_availability"]["present_fact_ids"])
        self.assertEqual(present["facts"]["context_values"]["process_state"], "running")
        self.assertEqual(absent_rule["planned_containment"], present_rule["planned_containment"])
        self.assertNotEqual(absent_rule["input_sha256"], present_rule["input_sha256"])

    def test_unknown_untyped_or_command_context_is_rejected(self):
        for context in ({"invented": "running"}, {"process_state": True},
                        {"process_state": "run quarantine now"}, ["running"],
                        {"operator_intent": None}):
            with self.subTest(context=context), self.assertRaises(ValueError):
                jury.normalized_view(self.rows, trusted_context=context)

    def test_corrupted_inventory_cannot_make_a_supplied_count_missing(self):
        view, _, _ = jury.normalized_view(self.rows)
        view["facts"]["fact_availability"]["missing_fact_ids"].append("denied_total")
        raw = json.dumps({"concern": "Concern: missing context", "claims": [],
                          "cited_event_ids": [], "missing_evidence": ["denied_total"]})
        with self.assertRaisesRegex(ValueError, "QC-SOURCE"):
            jury.validate_claims_concern(raw, "concern-advisor", "test", view)

    def test_context_value_and_availability_must_agree(self):
        view, _, _ = jury.normalized_view(self.rows)
        broken = copy.deepcopy(view)
        broken["facts"]["context_availability"]["process_state"] = True
        raw = json.dumps({"concern": "Concern: none", "claims": [],
                          "cited_event_ids": [], "missing_evidence": []})
        with self.assertRaisesRegex(ValueError, "QC-SOURCE"):
            jury.validate_claims_concern(raw, "concern-advisor", "test", broken)

    def measure_empty_advice(self, context):
        case = {"id": "availability-test-only", "label": "benign", "response": "none",
                "events": [{"decision": "allow"}], "context_fixture": context}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "corpus.json"
            path.write_text(json.dumps({"schema": 1, "cases": [case]}))
            return evaluation.measure_split(str(path), evaluation.StubJury(), require_availability_complete=True)

    def test_empty_missing_list_cannot_pass_when_context_is_absent(self):
        profile = self.measure_empty_advice({})["profiles"]["qwen_concern:stub"]
        self.assertTrue(profile["all_accepted_claims_verified"])
        self.assertFalse(profile["missing_evidence_complete"])
        self.assertFalse(profile["pass"])

    def test_empty_missing_list_is_correct_when_all_context_is_supplied(self):
        context = {"operator_intent": "maintenance", "process_state": "running", "task_contract": "read_only"}
        profile = self.measure_empty_advice(context)["profiles"]["qwen_concern:stub"]
        self.assertTrue(profile["missing_evidence_complete"])
        self.assertTrue(profile["pass"])

    def test_schema_retry_cannot_pass_the_first_attempt_gate(self):
        class RetryingStub(evaluation.StubJury):
            def review(self, rows, trusted_context=None):
                result = super().review(rows, trusted_context=trusted_context)
                result["qwen_concern:stub"]["roles"][0]["attempts"].insert(0, {
                    "status": "invalid_response", "validation_error": "QC-SCHEMA: incomplete"})
                return result

        case = {"id": "availability-retry-test", "label": "benign", "response": "none",
                "events": [{"decision": "allow"}]}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "corpus.json"
            path.write_text(json.dumps({"schema": 1, "cases": [case]}))
            profile = evaluation.measure_split(str(path), RetryingStub(), require_first_attempt=True)["profiles"]["qwen_concern:stub"]
        self.assertTrue(profile["all_calls_resolved"])
        self.assertTrue(profile["no_fabricated_facts"])
        self.assertFalse(profile["all_first_attempts_valid"])
        self.assertFalse(profile["pass"])

    def test_prompt_sources_are_recomputed_for_each_context(self):
        # fake model คัดลอก source fields จาก prompt จริง จับ catalog/tag ค้างจากเคสก่อน
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, worker, model = [root / name for name in ("binary", "worker", "model")]
            for path in (binary, worker, model):
                path.write_bytes(path.name.encode())

            def invoke(prompt):
                def source(key):
                    line = next(line for line in prompt.splitlines() if line.startswith(key + "="))
                    return json.loads(line.split("=", 1)[1])
                raw = {"concern": source("concern_source"), "claims": [], "cited_event_ids": [],
                       "missing_evidence": source("missing_fact_ids")}
                return {"stdout": json.dumps(raw), "stderr_tail": "", "returncode": 0,
                        "timed_out": False, "elapsed_ms": 1}

            engine = jury.QwenJury(binary, worker, model, jury.file_hash(model), root / "run", invoke=invoke)
            all_context = {"operator_intent": "maintenance", "process_state": "running", "task_contract": "read_only"}
            with contextlib.redirect_stderr(io.StringIO()):
                absent = engine.review(self.rows)["qwen_concern:grounded"]["roles"][0]["concern"]
                present = engine.review(self.rows, trusted_context=all_context)["qwen_concern:grounded"]["roles"][0]["concern"]
            self.assertEqual(engine.calls, 2)
            self.assertEqual(absent["concern"], "Concern: missing context")
            self.assertEqual(set(absent["missing_evidence"]), set(jury.claims_contract.CONTEXT_FACTS))
            self.assertEqual(present["concern"], "Concern: none")
            self.assertEqual(present["missing_evidence"], [])

    def test_fresh_paired_holdout_has_new_audit_shapes_and_context_views(self):
        base = Path(__file__).resolve().parents[1] / "examples/security-concerns"
        prior_audits, prior_views = set(), set()
        for name in ("concern-dev.json", "concern-holdout.json", "concern-holdout-2026-11-06.json",
                     "concern-claims-dev.json", "concern-claims-holdout-v1.json", "concern-availability-dev-v1.json"):
            for case in json.loads((base / name).read_text())["cases"]:
                rows = detection.records(case)
                prior_audits.add(jury.rule_decision(rows)[2]["input_sha256"])
                prior_views.add(jury.rule_decision(rows, trusted_context=case.get("context_fixture"))[2]["input_sha256"])
        seen, pairs = set(), {}
        for case in json.loads((base / "concern-availability-holdout-v1.json").read_text())["cases"]:
            with self.subTest(case=case["id"]):
                rows = detection.records(case)
                audit_hash = jury.rule_decision(rows)[2]["input_sha256"]
                view, _, rule = jury.rule_decision(rows, trusted_context=case["context_fixture"])
                self.assertNotIn(audit_hash, prior_audits)
                self.assertNotIn(rule["input_sha256"], prior_views | seen)
                self.assertEqual(rule["planned_containment"], case["response"] == "replace")
                seen.add(rule["input_sha256"])
                pairs.setdefault(case["pair_id"], []).append((audit_hash, view["facts"]["fact_availability"]))
        self.assertEqual(len(pairs), 6)
        for entries in pairs.values():
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0][0], entries[1][0])
            self.assertNotEqual(entries[0][1], entries[1][1])
