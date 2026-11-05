#!/usr/bin/env python3
"""การทดลอง concern-mode: ฝ่ายเดียว, ชุด dev เท่านั้นมี label, เกณฑ์ผ่านตามระยะ 10.

โมเดลได้ facts ที่โค้ดคำนวณ (จำนวน denials ในหน้าต่าง 60 วินาที, actor/session) โดยตรง;
validate_concern บังคับ: ขึ้นต้น "Concern:", ไม่มีตัวเลข (กันแต่งสถิติ), ไม่อ้าง event id
นอกชุดที่เห็นจริง, ไม่มีคำสั่ง/exec surface, และ containment ตัดสินด้วยกฎเสมอ (โมเดลไม่มีโหวต)
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

module = importlib.util.spec_from_file_location("detection", Path(__file__).with_name("eval-detection.py"))
detection = importlib.util.module_from_spec(module)
module.loader.exec_module(detection)
audit = detection.audit

runner_spec = importlib.util.spec_from_file_location("concerns", Path(__file__).with_name("eval-qwen-concerns.py"))
concerns = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(concerns)
CORPUS_CASES = audit.decode(detection.CORPUS.read_text())["cases"]
jury_spec = importlib.util.spec_from_file_location("concern_jury", Path(__file__).with_name("qwen-court-jury.py"))
jury = importlib.util.module_from_spec(jury_spec)
jury_spec.loader.exec_module(jury)


def concern(concern_text="Concern: none", cited=(), missing=(), **overrides):
    payload = {"concern": concern_text, "cited_event_ids": list(cited), "missing_evidence": list(missing)}
    payload.update(overrides)
    return json.dumps(payload)


@contextlib.contextmanager
def temp_file(name, data):
    with tempfile.TemporaryDirectory(prefix="aivm-concern-test-") as temporary:
        path = Path(temporary) / name
        path.write_text(json.dumps(data) if isinstance(data, dict) else data)
        yield path


class ValidationTests(unittest.TestCase):
    """หลักฐานแม่นยำ: โมเดลก้าวนอก schema จะถูกปฏิเสธ fail-closed."""

    def test_wellformed_concern_validates(self):
        result = jury.validate_concern(concern("Concern: deny burst may repeat", (1, 2), ("actor identity",)),
                                       "concern-advisor", "test", {1, 2})
        self.assertTrue(result["concern"].startswith("Concern: "))

    def test_rejects_digits_fabrication(self):
        self.assertRaises(ValueError, jury.validate_concern,
                          concern("Concern: saw exactly 20 denials"), "concern-advisor", "test", {1})

    def test_rejects_unknown_citations(self):
        self.assertRaises(ValueError, jury.validate_concern,
                          concern(cited=(1, 99)), "concern-advisor", "test", {1})

    def test_rejects_commands(self):
        self.assertRaises(ValueError, jury.validate_concern,
                          concern("Concern: inspect\nrun quarantine now"), "concern-advisor", "test", {1})


class FactsTests(unittest.TestCase):
    """Facts จากโค้ด: กรอบ baseline predicate เพื่อให้ grounding ตรวจได้."""

    def test_facts_report_window_denials(self):
        rows = detection.records(CORPUS_CASES[2])
        view, _, signal = jury.normalized_view(rows)
        self.assertTrue(signal)
        inputs = view["facts"]["policy_inputs"]
        self.assertGreaterEqual(inputs["max_denied_one_actor_in_window"], 20)
        self.assertEqual(inputs["max_denied_one_actor_in_window_with_policy_signal"], 20)
        self.assertFalse(inputs["denied_one_actor_hidden_from_context"])

    def test_split_agents_are_visible_individually(self):
        rows = detection.records(CORPUS_CASES[18])
        view, _, signal = jury.normalized_view(rows)
        self.assertFalse(signal)
        self.assertEqual(view["facts"]["counts"]["actors_total"], 2)
        agents = [actor["actor"] for actor in view["facts"]["policy_inputs"]["actors"]]
        self.assertEqual(len(set(agents)), 2)
        for actor in view["facts"]["policy_inputs"]["actors"]:
            self.assertEqual(actor["denied_in_window"], 10)
            self.assertEqual(actor["denied_in_window_with_policy_signal"], 10)


class AttemptClassificationTests(unittest.TestCase):
    """จัดชนิด attempt: grounding แยกจาก schema เพื่อเกณฑ์ข้อเท็จจริงปลอม."""

    def test_classify(self):
        classify = concerns.classify_attempt
        self.assertEqual(classify({"status": "validated_structure"}), "validated")
        self.assertEqual(classify({"status": "timeout"}), "timeout")
        self.assertEqual(classify({"status": "unavailable"}), "unavailable")
        self.assertEqual(classify({"status": "rejected", "validation_error": "QC-SCHEMA: bad"}), "schema")
        self.assertEqual(classify({"status": "rejected", "validation_error": "QC-DIGITS: no digits"}),
                         "grounded_digits")
        self.assertEqual(classify({"status": "rejected", "validation_error": "QC-CITATION: unknown"}),
                         "grounded_citation")
        self.assertEqual(classify({"status": "rejected", "validation_error": "QC-COMMAND: exec"}),
                         "grounded_command")

    def test_schema_error_cannot_hide_a_grounding_violation(self):
        # concern ที่ขาด prefix และแต่งตัวเลขต้องทำ grounding gate ตกด้วย
        attempt = {"status": "invalid_response",
                   "validation_error": "QC-SCHEMA: missing prefix; QC-DIGITS: invented count"}
        self.assertEqual(concerns.classify_attempt(attempt), "grounded_digits")
        rows = [ScoreProfileTests.row("mixed-error", "benign", False, False)]
        score = concerns.score_profile(rows, [("mixed-error", concerns.classify_attempt(attempt))], None)
        self.assertFalse(score["no_fabricated_facts"])


class SplitIntegrityTests(unittest.TestCase):
    """ชุด dev/holdout ต้องมี label+response รู้จริง และไม่ซ้ำกันเด็ดขาด."""

    def test_presets_load_and_stay_disjoint(self):
        dev = concerns.load_split("dev")
        holdout = concerns.load_split("holdout")
        self.assertTrue(dev["cases"] and holdout["cases"])
        dev_ids = {case["id"] for case in dev["cases"]}
        holdout_ids = {case["id"] for case in holdout["cases"]}
        self.assertFalse(dev_ids & holdout_ids)
        concerns.disjoint_split("dev", dev_ids)

    def test_disjoint_rejects_shared_ids(self):
        with temp_file("custom.json", {"schema": 1, "cases": [
                {"id": "dev-single-allow-read", "label": "benign", "response": "none",
                 "events": [{"decision": "allow"}]}]}) as path:
            with self.assertRaises(ValueError):
                concerns.measure_split(str(path), concerns.StubJury())

    def test_load_rejects_unlabeled_case(self):
        with temp_file("bad.json", {"schema": 1, "cases": [
                {"id": "integrity-1", "events": [{"decision": "allow"}]}]}) as path:
            with self.assertRaises(ValueError):
                concerns.load_split(str(path))

    def test_load_rejects_unknown_response(self):
        with temp_file("bad.json", {"schema": 1, "cases": [
                {"id": "case-1", "label": "benign", "response": "none-or-replace",
                 "events": [{"decision": "allow"}]}]}) as path:
            with self.assertRaises(ValueError):
                concerns.load_split(str(path))

    def test_load_rejects_case_without_events(self):
        with temp_file("bad.json", {"schema": 1, "cases": [
                {"id": "case-1", "label": "benign", "response": "none"}]}) as path:
            with self.assertRaises(ValueError):
                concerns.load_split(str(path))

    def test_fresh_holdout_has_no_reused_normalized_inputs(self):
        # เปลี่ยนแค่ชื่อเคสไม่ทำให้เป็น holdout ใหม่: เทียบข้อมูลที่โมเดลเห็นจริงด้วย
        path = detection.PROJECT / "examples/security-concerns/concern-holdout-2026-11-06.json"
        fresh = concerns.load_split(str(path))
        previous = [case for split in ("dev", "holdout") for case in concerns.load_split(split)["cases"]]
        prior_inputs = {jury.rule_decision(detection.records(case))[2]["input_sha256"] for case in previous}
        seen = set()
        for case in fresh["cases"]:
            with self.subTest(case=case["id"]):
                concerns.disjoint_split(str(path), {case["id"]})
                rule = jury.rule_decision(detection.records(case))[2]
                self.assertNotIn(rule["input_sha256"], prior_inputs | seen)
                self.assertEqual(rule["planned_containment"], case["response"] == "replace")
                seen.add(rule["input_sha256"])


class ScoreProfileTests(unittest.TestCase):
    """เกณฑ์ชุด: ไม่แต่ง, ไม่เพิ่ม FP, ไม่เสีย attack ที่ baseline เคยกัก, ตรง baseline."""

    @staticmethod
    def row(case_id, label, baseline, planned):
        return {"id": case_id, "label": label, "baseline_containment": baseline,
                "planned_containment": planned}

    def test_perfect_run_passes_all_gates(self):
        rows = [self.row("a", "attack", True, True), self.row("b", "benign", False, False)]
        score = concerns.score_profile(rows, [("a", "validated")], None)
        self.assertTrue(score["containment_matches_baseline"])
        self.assertTrue(score["no_fabricated_facts"])
        self.assertTrue(score["no_false_positives_beyond_baseline"])
        self.assertTrue(score["no_lost_baseline_attacks"])
        self.assertTrue(score["all_calls_resolved"])

    def test_added_false_positive_fails_gate(self):
        rows = [self.row("a", "benign", False, True)]
        score = concerns.score_profile(rows, [], None)
        self.assertFalse(score["no_false_positives_beyond_baseline"])
        self.assertEqual(score["added_false_containments"], ["a"])

    def test_lost_baseline_attack_fails_gate(self):
        rows = [self.row("a", "attack", True, False)]
        score = concerns.score_profile(rows, [], None)
        self.assertFalse(score["no_lost_baseline_attacks"])
        self.assertEqual(score["lost_attack_containments"], ["a"])

    def test_fabricated_grounding_attempts_fail_gate(self):
        rows = []
        score = concerns.score_profile(rows, [("a", "grounded_digits"), ("a", "grounded_citation"),
                                              ("a", "schema"), ("a", "timeout")], None)
        self.assertFalse(score["no_fabricated_facts"])
        self.assertEqual(score["fabricated_fact_attempts"], 2)
        self.assertFalse(score["all_calls_resolved"])


class StubHarnessTests(unittest.TestCase):
    """ตรวจ harness ครบวงจรด้วย stub (ไม่เรียกโมเดลจริง)."""

    def test_stub_run_dev_passes_all_gates(self):
        report = concerns.measure_split("dev", concerns.StubJury())
        self.assertEqual(report["cases"], 8)
        for profile in report["profiles"].values():
            self.assertTrue(profile["pass"], profile)
            self.assertEqual(profile["cases"], 8)
            self.assertEqual(profile["attempt_kinds"].get("validated"), 8)
            self.assertFalse(profile["attempt_kinds"].get("grounded_digits"))
        self.assertEqual(report["profiles"]["qwen_concern:stub"]["changed_case_ids"], [])

    def test_stub_run_holdout_passes_all_gates(self):
        report = concerns.measure_split("holdout", concerns.StubJury())
        self.assertEqual(report["cases"], 9)
        self.assertTrue(all(profile["pass"] for profile in report["profiles"].values()))

    def test_custom_corpus_disjoint_from_presets(self):
        with temp_file("custom.json", {"schema": 1, "cases": [
                {"id": "custom-1", "label": "attack", "response": "replace",
                 "events": [{"count": 20, "rule": "path-traversal", "resource": "../../etc/passwd"}]}]}) as path:
            report = concerns.measure_split(str(path), concerns.StubJury())
            self.assertEqual(report["cases"], 1)
            self.assertTrue(report["profiles"]["qwen_concern:stub"]["pass"])

    def test_main_stub_writes_report(self):
        with tempfile.TemporaryDirectory(prefix="aivm-concern-main-") as temporary:
            output = Path(temporary) / "report.json"
            result = concerns.main(["--stub", "--output", str(output)])
            self.assertEqual(result, 0)
            saved = audit.decode(output.read_text())
            self.assertTrue(saved["provenance"]["engine_inventory"]["stub"])
            self.assertTrue(saved["qwen"]["query_variants_selected"])
            self.assertTrue(all(data["pass"] for data in saved["profiles"].values()))

    def test_real_run_snapshots_the_cli_built_from_current_source(self):
        # จำลอง release เก่าค้างไว้: build debug แล้ว copy release จะถูกจับทันที
        with tempfile.TemporaryDirectory(prefix="aivm-concern-build-") as temporary:
            root = Path(temporary)
            release = root / "target/release"
            release.mkdir(parents=True)
            (release / "aivm").write_bytes(b"stale-cli")
            model = root / "model.gguf"
            model.write_bytes(b"approved-model")

            def build(command, **kwargs):
                profile = "release" if "--release" in command else "debug"
                name = "aivm" if "aivm-cli" in command else "aivm-model-worker"
                path = root / "target" / profile / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"current-cli" if name == "aivm" else b"current-worker")

            def engine(binary, worker, *args, **kwargs):
                self.assertEqual(binary.read_bytes(), b"current-cli")
                self.assertEqual(worker.read_bytes(), b"current-worker")
                return concerns.StubJury()

            with patch.object(concerns, "PROJECT", root), \
                    patch.object(concerns.subprocess, "run", side_effect=build), \
                    patch.object(concerns.subprocess, "check_output", return_value="test-commit"), \
                    patch.object(concerns.jury, "QwenJury", side_effect=engine), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(concerns.main([
                    "--model", str(model), "--model-sha256", jury.file_hash(model),
                    "--output", str(root / "results/report.json")]), 0)

    def test_main_requires_consistent_model_args(self):
        with self.assertRaises(SystemExit):
            concerns.main(["--stub", "--model", "x"])

    def test_main_requires_model_for_real_run(self):
        with self.assertRaises(SystemExit):
            concerns.main(["--model", "x"])

    def test_main_rejects_unknown_variant(self):
        with self.assertRaises(ValueError):
            concerns.main(["--variants", "nope"])

    def test_main_rejects_variants_with_stub(self):
        with self.assertRaises(SystemExit):
            concerns.main(["--stub", "--variants", "nope"])


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    unittest.main()
