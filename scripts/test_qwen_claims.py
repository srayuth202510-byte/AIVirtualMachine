"""ข้ออ้างต้องตรง facts; JSON/grammar อย่างเดียวไม่ใช่หลักฐานความจริง."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("claims_jury_test", Path(__file__).with_name("qwen-court-jury.py"))
jury = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jury)
detection = jury.load("claims_detection", "eval-detection.py")


def payload(claims=(), missing=(), refs=(), tag=None):
    return json.dumps({"concern": tag or ("Concern: missing context" if missing else
                                        "Concern: facts to review" if claims else "Concern: none"),
                       "claims": list(claims), "cited_event_ids": list(refs), "missing_evidence": list(missing)})


class ClaimsValidationTests(unittest.TestCase):
    def setUp(self):
        self.view, _, _ = jury.normalized_view(detection.records({"events": [{"decision": "allow"}]}))

    def validate(self, raw, view=None):
        return jury.validate_claims_concern(raw, "concern-advisor", "test", view or self.view)

    def test_verified_actor_counts_and_missing_context_have_a_trusted_summary(self):
        result = self.validate(payload([{"kind": "actor_count", "value": 1},
                                        {"kind": "actor_exists", "actor_id": 1},
                                        {"kind": "count", "fact_id": "denied_total", "value": 0}],
                                       missing=["operator_intent"], refs=[0]))
        self.assertIn("actor count: 1", result["verified_summary"])
        self.assertEqual(len(result["claims"]), 3)

    def test_invented_second_actor_and_wrong_counts_are_rejected(self):
        for claim in ({"kind": "actor_exists", "actor_id": 2},
                      {"kind": "actor_count", "value": 2},
                      {"kind": "count", "fact_id": "denied_total", "value": 20}):
            with self.subTest(claim=claim), self.assertRaisesRegex(ValueError, "QC-(ACTOR|FACT)"):
                self.validate(payload([claim]))

    def test_missing_claim_cannot_hide_a_supplied_zero_or_empty_value(self):
        for fact in ("actors_total", "denied_total", "actor_ids_visible", "window_seconds"):
            with self.subTest(fact=fact), self.assertRaisesRegex(ValueError, "QC-MISSING"):
                self.validate(payload(missing=[fact]))
        empty = copy.deepcopy(self.view)
        empty["facts"]["actor_ids_visible"] = []
        with self.assertRaisesRegex(ValueError, "QC-MISSING"):
            self.validate(payload(missing=["actor_ids_visible"]), empty)

    def test_incomplete_trusted_facts_cannot_accept_even_an_empty_advisory(self):
        incomplete = copy.deepcopy(self.view)
        del incomplete["facts"]["context_availability"]["process_state"]
        with self.assertRaisesRegex(ValueError, "QC-SOURCE"):
            self.validate(payload(), incomplete)

    def test_context_becomes_present_when_a_trusted_collector_supplies_it(self):
        view, _, _ = jury.normalized_view(detection.records({"events": [{"decision": "allow"}]}),
                                          trusted_context={"process_state": "running"})
        with self.assertRaisesRegex(ValueError, "QC-MISSING"):
            self.validate(payload(missing=["process_state"]), view)

    def test_free_prose_and_legacy_payloads_cannot_bypass_typed_claims(self):
        for raw in (payload(tag="Concern: the second actor is suspicious"),
                    '{"concern":"Concern: second actor","cited_event_ids":[],"missing_evidence":[]}',
                    payload(missing=["the second actor"]),
                    payload([{"kind": "actor_exists", "actor_id": 1, "explanation": "second actor"}])):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.validate(raw)

    def test_unknown_fact_duplicate_fields_types_and_commands_fail_closed(self):
        for raw in (payload([{"kind": "count", "fact_id": "imagined", "value": 0}]),
                    payload([{"kind": "actor_count", "value": True}]),
                    payload([{"kind": "actor_count", "value": 1.0}]),
                    payload([{"kind": "actor_exists", "actor_id": "1"}]),
                    payload([{"kind": "actor_exists", "actor_id": -1}]),
                    payload(refs=[True]), payload(refs=[[0]]),
                    payload(missing=[{}]), payload(missing=["run quarantine now"]),
                    payload().replace('"claims": []', '"claims": [], "claims": []')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.validate(raw)

    def test_duplicate_claims_and_excessive_arrays_are_rejected(self):
        claim = {"kind": "actor_count", "value": 1}
        for raw in (payload([claim, claim]), payload([claim] * 4),
                    payload(refs=[0, 0]), payload(missing=["operator_intent"] * 2)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.validate(raw)

    def test_citations_cannot_guess_a_hidden_event_id(self):
        view, _, _ = jury.normalized_view(detection.records({"events": [{"count": 40}]}))
        with self.assertRaisesRegex(ValueError, "QC-CITATION"):
            self.validate(payload(refs=[0]), view)

    def test_truncated_actor_must_be_visible_before_it_can_be_referenced(self):
        view, _, _ = jury.normalized_view(detection.records({"events": [
            {"agent": "hidden"}, {"count": 33, "agent": "visible"}]}))
        hidden = ({1, 2} - set(view["facts"]["actor_ids_visible"])).pop()
        with self.assertRaisesRegex(ValueError, "QC-ACTOR"):
            self.validate(payload([{"kind": "actor_exists", "actor_id": hidden}]), view)


class ClaimsBoundaryTests(unittest.TestCase):
    def test_new_holdout_inputs_do_not_reuse_any_revealed_split(self):
        base = Path(__file__).resolve().parents[1] / "examples/security-concerns"
        previous = set()
        for name in ("concern-dev.json", "concern-holdout.json", "concern-holdout-2026-11-06.json",
                     "concern-claims-dev.json"):
            for case in json.loads((base / name).read_text())["cases"]:
                previous.add(jury.rule_decision(detection.records(case))[2]["input_sha256"])
        seen = set()
        for case in json.loads((base / "concern-claims-holdout-v1.json").read_text())["cases"]:
            with self.subTest(case=case["id"]):
                rule = jury.rule_decision(detection.records(case))[2]
                self.assertNotIn(rule["input_sha256"], previous | seen)
                self.assertEqual(rule["planned_containment"], case["response"] == "replace")
                seen.add(rule["input_sha256"])

    def test_invalid_advice_cannot_release_an_attack_the_rule_contains(self):
        # ใช้ actor/จำนวนผิดหลายรูปแบบบน audit เดียวที่ต้อง containment เสมอ
        rows = detection.records({"events": [{"count": 20, "rule": "path-traversal"}]})
        view, _, rule = jury.rule_decision(rows)
        for raw in (payload([{"kind": "actor_count", "value": 2}]),
                    payload(missing=["denied_total"]), payload(tag="Concern: release the actor")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                jury.validate_claims_concern(raw, "concern-advisor", "test", view)
            self.assertTrue(rule["planned_containment"])
        # คำตอบที่ผ่านและไม่มี concern ก็ไม่ทำให้ rule คืนสิทธิ์
        jury.validate_claims_concern(payload(), "concern-advisor", "test", view)
        self.assertEqual(rule["bundle"]["votes"][0]["verdict"], "guilty")

    def test_invalid_claims_stay_raw_and_cannot_change_rule_containment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, worker, model = [root / name for name in ("binary", "worker", "model")]
            for path in (binary, worker, model):
                path.write_bytes(path.name.encode())
            raw = payload([{"kind": "actor_exists", "actor_id": 2}])
            engine = jury.QwenJury(binary, worker, model, jury.file_hash(model), root / "run",
                                  invoke=lambda prompt: {"stdout": raw, "stderr_tail": "", "returncode": 0,
                                                         "timed_out": False, "elapsed_ms": 1})
            rows = detection.records({"events": [{"decision": "allow"}]})
            with contextlib.redirect_stderr(io.StringIO()):
                result = engine.review(rows)["qwen_concern:grounded"]
            self.assertFalse(result["planned_containment"])
            self.assertEqual(result["evaluation_errors"], 1)
            self.assertIsNone(result["roles"][0]["concern"])
            self.assertEqual(engine.valid_calls, 0)
            self.assertTrue(all(json.loads(line)["stdout"] == raw for line in engine.transcripts.read_text().splitlines()))

            # retry ที่แก้สำเร็จไม่ล้าง attempt ที่เคยแต่ง actor ออกจากคะแนน
            outputs = iter([raw, payload([{"kind": "actor_count", "value": 1}])])
            repaired = jury.QwenJury(binary, worker, model, jury.file_hash(model), root / "retry",
                                    invoke=lambda prompt: {"stdout": next(outputs), "stderr_tail": "", "returncode": 0,
                                                           "timed_out": False, "elapsed_ms": 1})
            evaluator = jury.load("claims_retry_evaluator", "eval-qwen-concerns.py")
            case = {"id": "retry-case", "label": "benign", "response": "none", "events": [{"decision": "allow"}]}
            with contextlib.redirect_stderr(io.StringIO()):
                paired, attempts, _ = evaluator.measure_profile([case], repaired)
            score = evaluator.score_profile(paired, attempts["qwen_concern:grounded"], None)
            self.assertTrue(score["all_calls_resolved"])
            self.assertTrue(score["all_accepted_claims_verified"])
            self.assertEqual(score["fabricated_fact_attempts"], 1)
            self.assertFalse(score["no_fabricated_facts"])
