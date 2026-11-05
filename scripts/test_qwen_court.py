"""Unit proofs for the concern-mode jury: facts from code, model never votes, rules decide."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("qwen_jury_test", Path(__file__).with_name("qwen-court-jury.py"))
jury = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jury)
spec = importlib.util.spec_from_file_location("detection_test", Path(__file__).with_name("eval-detection.py"))
detection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detection)


def concern_payload(concern="Concern: none", refs=None, missing=None):
    return json.dumps({"concern": concern, "cited_event_ids": refs or [],
                       "missing_evidence": (missing if missing is not None
                                            else ["field data outside the audit snapshot"])})


class ValidationTests(unittest.TestCase):
    def validator(self, raw):
        return jury.validate_concern(raw, "concern-advisor", "qwen:same-model", {0, 1})

    def test_valid_concern_keeps_only_real_events_and_bounded_phrases(self):
        advisory = self.validator(concern_payload("Concern: boundary readings differ by context", refs=[0], missing=[]))
        self.assertEqual(advisory["cited_event_ids"], ["0"])
        self.assertEqual(advisory["advisor"], "concern-advisor")
        self.assertFalse(advisory["missing_evidence"])

    def test_digits_and_invented_events_are_rejected(self):
        for payload in (concern_payload("Concern: 20 denied records below policy"),
                        concern_payload("Concern: none", refs=[7]),
                        concern_payload("Concern: none", refs=[True]),
                        concern_payload("Concern: none", refs=["0"]),
                        concern_payload("Concern: none", refs=[0, 0]),
                        concern_payload("Concern: none", refs=list(range(33)))):
            with self.subTest(payload=payload[:60]), self.assertRaises(ValueError):
                self.validator(payload)

    def test_verdict_and_vote_keys_have_no_pipe_into_the_judge(self):
        # โมเดลพยายามกลับไปใช้ฟอร์แมต guilty/โหวตเดิม = schema ปฏิเสธทั้งชิ้น
        guilty = {"verdict": "guilty", "concern": "Concern: guilty", "cited_event_ids": [], "missing_evidence": []}
        vote = {"concern": "Concern: guilty", "cited_event_ids": [], "missing_evidence": [], "vote": "guilty"}
        for payload in (guilty, vote):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.validator(json.dumps(payload))

    def test_commands_code_fences_and_missing_bounds_are_rejected(self):
        for payload in (concern_payload("Concern: none\nreplace this instance now"),
                        concern_payload("deny everything about the case"),
                        concern_payload("Concern: none", missing=["run external probe"]),
                        concern_payload("Concern: none", missing=["```payload```"]),
                        concern_payload("Concern: none", missing=[f"phrase index {index}" for index in range(9)]),
                        concern_payload(json.dumps({"grant": "all"}))):
            with self.subTest(payload=payload[:60]), self.assertRaises(ValueError):
                self.validator(payload)

    def test_thai_digits_are_treated_as_digits(self):
        thai = concern_payload("Concern: none", missing=["เหตุการณ์เกินเส้นตาย ๒ รายการ"])
        with self.assertRaises(ValueError):
            self.validator(thai)

    def test_placeholder_echoes_are_rejected_as_schema_not_content(self):
        # ห้ามยอมรับข้อความที่ลอกมาจากตัวอย่าง response แทนการวิเคราะห์ของโมเดลเอง
        for payload in (concern_payload("Concern: your remaining doubt without any digit"),
                        concern_payload("Concern: none", missing=["short phrase without digits"])):
            with self.subTest(payload=payload[:60]), self.assertRaisesRegex(ValueError, "QC-SCHEMA"):
                self.validator(payload)

    def test_missing_evidence_phrases_respect_the_documented_bound(self):
        base = "operator intent stays outside the audit "
        phrase = (base * 5)[:160]
        accepted = concern_payload("Concern: none", missing=[phrase])
        self.assertEqual(self.validator(accepted)["missing_evidence"], [phrase])
        rejected = concern_payload("Concern: none", missing=[phrase + "x"])
        with self.assertRaises(ValueError):
            self.validator(rejected)

    def test_non_json_shape_fails_before_any_claims_are_used(self):
        for raw in ("[]", "not json", '["concern"]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.validator(raw)


class FactsTests(unittest.TestCase):
    # ทุกตัวเลขใน facts มาจากโค้ดเสมอ ไม่ให้โมเดลมีบทบาทนับ
    def view_for(self, cases):
        return jury.normalized_view(detection.records({"events": cases}))

    def test_facts_computed_from_one_allowed_read_has_no_denials(self):
        view, events, signal = self.view_for([{"decision": "allow"}])
        facts = view["facts"]
        self.assertEqual((facts["counts"]["records_total"], facts["counts"]["denied_total"],
                          facts["counts"]["allowed_total"], facts["counts"]["actors_total"]), (1, 0, 1, 1))
        self.assertFalse(signal)
        self.assertEqual(facts["policy_inputs"]["max_denied_one_actor_in_window"], 0)

    def test_nineteen_probes_meet_neither_threshold_facts_nor_rule(self):
        view, events, signal = self.view_for([{"count": 19, "rule": "path-traversal"}])
        facts = view["facts"]
        self.assertEqual((facts["counts"]["denied_total"], facts["policy_inputs"]["max_denied_one_actor_in_window"]),
                         (19, 19))
        self.assertEqual(facts["policy_inputs"]["max_denied_one_actor_in_window_with_policy_signal"], 19)
        self.assertFalse(signal)

    def test_split_actors_and_sessions_are_separate_policy_inputs(self):
        for cases in ([{"count": 10, "agent": "a", "rule": "path-traversal"},
                       {"count": 10, "agent": "b", "rule": "path-traversal"}],
                      [{"count": 10, "session": "a", "rule": "path-traversal"},
                       {"count": 10, "session": "b", "rule": "path-traversal"}]):
            with self.subTest(cases=cases):
                view, events, signal = self.view_for(cases)
                self.assertEqual(view["facts"]["counts"]["actors_total"], 2)
                self.assertFalse(signal)
                for entry in view["facts"]["policy_inputs"]["actors"]:
                    self.assertEqual(entry["denied_in_window"], 10)

    def test_full_window_with_boundary_signal_reaches_containment(self):
        view, events, signal = self.view_for([{"count": 20, "rule": "path-traversal"}])
        self.assertTrue(signal)
        self.assertEqual(view["facts"]["policy_inputs"]["max_denied_one_actor_in_window_with_policy_signal"], 20)

    def test_expired_window_drops_denials_from_policy_inputs(self):
        # 19 denials @t0 + 1 @t61: หน้าต่างกฎเหลือการปฏิเสธหลังเดียว
        view, events, signal = self.view_for([{"count": 19, "rule": "path-traversal"},
                                              {"offset": 61, "rule": "path-traversal"}])
        self.assertFalse(signal)
        facts = view["facts"]
        self.assertEqual(facts["policy_inputs"]["window_denied_total"], 1)
        self.assertEqual(facts["counts"]["denied_total"], 20)

    def test_view_bounds_model_context_and_preserves_timing(self):
        view, events, signal = self.view_for([{"count": 40, "interval": 61, "rule": "path-traversal"}])
        facts = view["facts"]
        self.assertEqual(facts["computed_by"], "code")
        self.assertEqual((facts["counts"]["records_total"], facts["counts"]["records_visible"]), (40, 32))
        self.assertEqual(facts["counts"]["records_hidden_by_context_limit"], 8)
        pairs = [pair for group in view["groups"] for pair in group["events"]]
        self.assertEqual(sorted(pair[0] for pair in pairs), list(range(8, 40)))
        self.assertEqual(max(pair[1] for pair in pairs), 31 * 61)

    def test_window_denials_of_a_context_hidden_actor_are_reported_in_facts(self):
        # actor ที่ record อยู่ก่อนหน้า ถูกตัดออกจาก context แต่ยังอยู่ในหน้าต่างกฎ
        view, events, signal = self.view_for([
            {"count": 8, "agent": "late-identity", "offset": 20, "interval": 1, "rule": "path-traversal"},
            {"count": 40, "interval": 2, "rule": "path-traversal"}])
        facts = view["facts"]
        self.assertEqual(facts["counts"]["records_hidden_by_context_limit"], 16)
        self.assertEqual(facts["policy_inputs"]["denied_one_actor_hidden_from_context"], 8)
        self.assertTrue(signal)

    def test_facts_never_leak_raw_identity_paths_or_labels(self):
        rows = detection.records({"events": [{"agent": "PRIVATE_AGENT", "session": "PRIVATE_SESSION",
                                              "resource": "/secrets/PRIVATE_PATH.env", "rule": "PRIVATE_RULE"}]})
        view, events, signal = jury.normalized_view(rows)
        encoded = json.dumps(view)
        for marker in ("PRIVATE_AGENT", "PRIVATE_SESSION", "PRIVATE_PATH", "PRIVATE_RULE", "label", "description"):
            self.assertNotIn(marker, encoded)
        self.assertEqual(events[0]["id"], 0)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary, self.worker, self.model = [self.root / name for name in ("binary", "worker", "model.gguf")]
        for path in (self.binary, self.worker, self.model):
            path.write_bytes(path.name.encode())
        self.rows = detection.records({"events": [{"count": 20, "rule": "path-traversal"}]})

    def engine(self, outputs, variants=None):
        self.prompts = []
        def invoke(prompt):
            self.prompts.append(prompt)
            raw = outputs[min(len(self.prompts) - 1, len(outputs) - 1)]
            if isinstance(raw, dict):
                return raw
            return {"stdout": raw, "stderr_tail": "", "returncode": 0,
                    "timed_out": False, "elapsed_ms": 1}
        return jury.QwenJury(self.binary, self.worker, self.model, jury.file_hash(self.model),
                             self.root / "run", invoke=invoke, variants=variants)

    def review(self, engine):
        with contextlib.redirect_stderr(io.StringIO()):
            return engine.review(self.rows)

    def test_one_role_reports_concern_while_the_rule_keeps_the_decider_seat(self):
        engine = self.engine([concern_payload("Concern: boundary readings warrant review", refs=list(range(20)))])
        result = self.review(engine)
        profile = result["qwen_concern:grounded"]
        self.assertTrue(profile["planned_containment"])
        self.assertEqual(profile["roles"][0]["model_weight"], 0)
        # คำว่า guilty จากโมเดลไม่มีท่อส่งเข้า verdict: votes ต้องเป็นของกฎเท่านั้น
        self.assertEqual(profile["bundle"]["votes"],
                         [{"voter": "supervisor-rule", "origin": "verified-audit-stream", "verdict": "guilty"}])
        self.assertEqual(profile["verdict"]["independent_sources"], 1)
        self.assertEqual(len(profile["bundle"]["evidences"]), 1)
        self.assertFalse(profile["runtime_applied"])

    def test_model_cannot_force_containment_on_a_clean_single_read(self):
        engine = self.engine([concern_payload("Concern: guilty intent pattern"),
                              concern_payload("Concern: guilty again"),
                              concern_payload("Concern: guilty once more")])
        rows = detection.records({"events": [{"decision": "allow"}]})
        with contextlib.redirect_stderr(io.StringIO()):
            result = engine.review(rows)
        self.assertFalse(result["qwen_concern:grounded"]["planned_containment"])
        self.assertFalse(result["qwen_concern:grounded"]["containment_signal"])
        self.assertEqual(result["qwen_concern:grounded"]["bundle"]["votes"][0]["verdict"], "abstain")

    def test_missing_context_and_role_instructions_reach_the_prompt(self):
        engine = self.engine([concern_payload("Concern: context requested", missing=["process state"]),
                              concern_payload("Concern: another angle", missing=["operator intent"])])
        result = self.review(engine)
        self.assertEqual(engine.calls, 1)
        prompts = self.prompts
        self.assertEqual(len(prompts), 1)
        self.assertIn("process state", prompts[0])
        self.assertIn("Your role:", prompts[0])
        self.assertEqual(len(result["qwen_concern:grounded"]["roles"]), 1)

    def test_variants_are_separate_calls_with_identical_rule_containment(self):
        engine = self.engine([concern_payload("Concern: base"), concern_payload("Concern: policy variant"),
                              concern_payload("Concern: context variant")],
                             variants=("grounded", "policy", "missing-context"))
        result = self.review(engine)
        self.assertEqual(engine.calls, 3)
        self.assertEqual(len(set(self.prompts)), 3)
        for profile_key, profile in result.items():
            self.assertTrue(profile["planned_containment"])
        self.assertEqual({key for key in result},
                         {"qwen_concern:grounded", "qwen_concern:policy", "qwen_concern:missing-context"})
        for variant, text in jury.QUERY_VARIANTS.items():
            prompts = [prompt for prompt in self.prompts if text in prompt]
            self.assertEqual(len(prompts), 1, variant)

    def test_unknown_variants_are_rejected_before_inference(self):
        with self.assertRaisesRegex(ValueError, "unknown query variant"):
            self.engine([concern_payload()], variants=("hallucinate",))

    def test_schema_failures_retry_once_then_fail_without_rule_fallback(self):
        engine = self.engine(['{"grant":"all"}'])
        result = self.review(engine)
        self.assertEqual((engine.calls, engine.valid_calls), (2, 0))
        profile = result["qwen_concern:grounded"]
        self.assertEqual(profile["evaluation_errors"], 1)
        self.assertEqual(len(profile["roles"][0]["attempts"]), 2)
        self.assertEqual(profile["roles"][0]["status"], "invalid_response")
        self.assertIn("Validation error:", self.prompts[1])
        self.assertIn("your previous answer", self.prompts[1])
        self.assertIn('{"grant":"all"}', self.prompts[1])
        # feedback ห้ามเปิดเผยว่าความกังวลถูก/ผิด
        self.assertNotIn("expected label", self.prompts[1])
        self.assertNotIn("guilty", self.prompts[1])
        self.assertNotIn("benign", self.prompts[1])

    def test_prefix_retry_keeps_raw_answer_and_never_repairs_it_in_code(self):
        # ส่งคำตอบจริงกลับให้โมเดลแก้; validator ยังปฏิเสธคำนำหน้าที่หายทุกครั้ง
        raw = concern_payload("operator intent is not visible", refs=[0])
        engine = self.engine([raw, raw])
        profile = self.review(engine)["qwen_concern:grounded"]
        self.assertIn(raw, self.prompts[1])
        self.assertIsNone(profile["roles"][0]["concern"])
        self.assertEqual(profile["evaluation_errors"], 1)

    def test_numeric_actor_reference_is_rejected_until_the_model_rephrases_it(self):
        # เลข actor ใน prose ต้องถูกปฏิเสธ แต่เลข event ใน citations ยังใช้ได้
        raw = concern_payload("Concern: actor '1' lacks context", refs=[0])
        corrected = concern_payload("Concern: the observed actor lacks context", refs=[0])
        engine = self.engine([raw, corrected])
        profile = self.review(engine)["qwen_concern:grounded"]
        role = profile["roles"][0]
        self.assertEqual((engine.calls, engine.valid_calls), (2, 1))
        self.assertIn("QC-DIGITS", role["attempts"][0]["validation_error"])
        self.assertIn(raw, self.prompts[1])
        self.assertEqual(role["concern"]["cited_event_ids"], ["0"])
        self.assertEqual(role["concern"]["concern"], "Concern: the observed actor lacks context")
        self.assertTrue(profile["planned_containment"])

    def test_grounding_digits_retry_once_then_pass_without_label_feedback(self):
        engine = self.engine([concern_payload("Concern: 20 denied in the same window"),
                              concern_payload("Concern: none")])
        result = self.review(engine)
        self.assertEqual((engine.calls, engine.valid_calls), (2, 1))
        profile = result["qwen_concern:grounded"]
        self.assertEqual(profile["evaluation_errors"], 0)
        attempts = profile["roles"][0]["attempts"]
        self.assertEqual([attempt["status"] for attempt in attempts], ["invalid_response", "validated_structure"])
        self.assertTrue(attempts[0]["validation_error"].startswith("QC-DIGITS"))
        self.assertTrue(attempts[1]["validation_error"] is None)

    def test_timeouts_are_recorded_as_failed_concern_not_innocence(self):
        engine = self.engine([{"stdout": "", "stderr_tail": "deadline", "returncode": -9,
                               "timed_out": True, "elapsed_ms": 180000}])
        result = self.review(engine)
        profile = result["qwen_concern:grounded"]
        self.assertEqual(engine.calls, 1)
        self.assertEqual(profile["roles"][0]["status"], "timeout")
        self.assertEqual(profile["evaluation_errors"], 1)
        self.assertTrue(profile["planned_containment"])
        self.assertTrue(profile["containment_signal"])

    def test_recorded_bundles_replay_without_another_model_call(self):
        engine = self.engine([concern_payload()])
        result = self.review(engine)
        for profile in result.values():
            self.assertEqual(jury.court.judge(**profile["bundle"]), profile["verdict"])
        self.assertEqual(engine.calls, 1)

    def evaluate_engine(self, engine, case, *, contains_reason):
        # ทดสอบการนับคะแนนด้วย baseline fixture; ไม่เรียก Rust/model ใน unit test นี้
        evaluation = jury.load("jury_metric_test", "eval-security-court.py")
        path = self.root / "corpus.json"
        path.write_text(json.dumps({"schema": 1, "cases": [case]}))
        rows = detection.records(case)
        if contains_reason:
            proof = [{"hash_entry": row["hash_entry"], "timestamp": row["timestamp"]} for row in rows]
            reason = {"policy": "deny-burst-with-boundary-or-sensitive-access", "count": len(rows), "evidence": proof}
            actual = "replace"
        else:
            reason, actual = None, "none"
        metrics = detection.confusion([(False, False)])
        baseline = {"policy_regressions": [], "total": 1,
                    "provenance": {"corpus_sha256": jury.file_hash(path)},
                    "cases": [{"id": case["id"], "snapshot_chain_verified": True,
                               "response": {"source_unchanged": True, "observed_reason": reason, "actual": actual}}],
                    "rules_risk_metrics": metrics, "containment_risk_metrics": metrics}
        with patch.object(evaluation.detection, "evaluate", return_value=baseline), \
                contextlib.redirect_stderr(io.StringIO()):
            return evaluation.evaluate(self.binary, path, engine)

    def test_role_concern_counts_reach_the_evaluation_report(self):
        engine = self.engine([concern_payload("Concern: pattern lacks context", missing=["process state"])])
        report = self.evaluate_engine(engine, {"id": "benign-fixture", "label": "benign",
                                               "events": [{"decision": "allow"}]}, contains_reason=False)
        profile = report["profiles"]["qwen_concern:grounded"]
        self.assertEqual(profile["court_planned_containment"]["tn"], 1)
        self.assertTrue(profile["no_regression"])
        role_record = report["qwen_role_metrics"]["qwen_concern:grounded"]["concern-advisor"]
        self.assertEqual((role_record["valid_concerns"], role_record["with_missing_evidence"]), (1, 1))
        self.assertEqual(role_record["statuses"], {"validated_structure": 1})
        self.assertNotIn("qwen_ballot_metrics", report)

    def test_runtime_errors_never_inflate_true_negatives_or_pass_improvement_gate(self):
        engine = self.engine([{"stdout": "", "stderr_tail": "invalid structured output", "returncode": 1,
                               "timed_out": False, "elapsed_ms": 1}])
        report = self.evaluate_engine(engine, {"id": "benign", "label": "benign",
                                               "events": [{"decision": "allow"}]}, contains_reason=False)
        profile = report["profiles"]["qwen_concern:grounded"]
        role_record = report["qwen_role_metrics"]["qwen_concern:grounded"]["concern-advisor"]
        self.assertEqual(role_record["valid_concerns"], 0)
        self.assertEqual(profile["evaluation_error_case_ids"], ["benign"])
        self.assertFalse(profile["no_regression"])

    def test_rule_containment_matches_supervisor_baseline_on_attack_fixture(self):
        engine = self.engine([concern_payload("Concern: none")])
        report = self.evaluate_engine(engine, {"id": "attack-fixture", "label": "attack",
                                               "events": [{"count": 20, "rule": "path-traversal"}]},
                                      contains_reason=True)
        profile = report["profiles"]["qwen_concern:grounded"]
        self.assertEqual(profile["court_planned_containment"]["tp"], 1)
        case_profile = report["cases"][0]["profiles"]["qwen_concern:grounded"]
        self.assertEqual(case_profile["verdict"], jury.court.judge(**case_profile["bundle"]))
        self.assertTrue(case_profile["planned_containment"])

    def test_changed_model_or_worker_cannot_reuse_success_provenance(self):
        engine = self.engine([concern_payload()])
        self.review(engine)
        self.worker.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            engine.finish()
        with self.assertRaisesRegex(ValueError, "model SHA256"):
            jury.QwenJury(self.binary, self.worker, self.model, "0" * 64, self.root / "wrong")


if __name__ == "__main__":
    unittest.main()
