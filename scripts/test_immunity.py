"""Proposal isolation, held-out gates, release integrity, rollback and shadow replay."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

module = importlib.util.spec_from_file_location("immunity", Path(__file__).with_name("immunity-lab.py"))
lab = importlib.util.module_from_spec(module)
module.loader.exec_module(lab)


class GrammarTests(unittest.TestCase):
    def test_only_whole_response_json_fence_is_accepted(self):
        text = json.dumps({"rules": [lab.SEED_RULE]})
        self.assertEqual(lab.proposal_response("```json\n" + text + "\n```"), [lab.SEED_RULE])
        for raw in ["Here is a rule: " + text, "```json\n" + text + "\n``` extra",
                    '{"rules":[],"rules":[]}']:
            with self.assertRaises(ValueError):
                lab.proposal_response(raw)

    def test_code_commands_regex_and_unbounded_rules_are_rejected(self):
        for rules in [[{"id": "x", "category": "prompt_injection", "all": {"action": "intent", "regex": ".*"}}],
                      [{**lab.SEED_RULE, "command": "grant-all"}],
                      [{**lab.SEED_RULE, "id": "../../escape"}],
                      [{**lab.SEED_RULE, "all": {"action": "intent", "intent_cue": "anything"}}],
                      [lab.SEED_RULE, {**lab.SEED_RULE, "id": "duplicate-predicates"}],
                      [lab.SEED_RULE] * 5, [lab.SEED_RULE] * 2]:
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                lab.validate_rules(rules)

    def test_category_requires_corresponding_evidence(self):
        with self.assertRaises(ValueError):
            lab.validate_rules([{**lab.SEED_RULE, "all": {"action": "read", "decision": "allow"}}])

    def test_feature_normalization_uses_only_fixed_enumerations(self):
        case = {"events": [{"action": "intent", "decision": "allow", "resource": "SET  ASIDE EARLIER GUIDANCE PRIVATE-CONTENT"}]}
        vector = lab.features(lab.evaluation.records(case)[0])
        self.assertEqual(vector["intent_cue"], "override")
        self.assertNotIn("PRIVATE-CONTENT", json.dumps(vector))
        self.assertTrue(all(value in lab.DOMAINS[field] for field, value in vector.items()))


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "aivm-cli"], cwd=lab.evaluation.PROJECT,
                       check=True, timeout=600)
        cls.binary = lab.evaluation.PROJECT / "target/debug/aivm"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "lab"
        lab.generate(self.root)
        self.manifest, self.splits = lab.load_lab(self.root)
        self.candidate = lab.candidate_document([copy.deepcopy(lab.SEED_RULE)], self.manifest, {"kind": "operator_seed"})

    def test_mutations_have_separate_phrase_families_and_reproducible_bytes(self):
        self.assertEqual([len(self.splits[key]) for key in ["training", "holdout"]], [18, 19])
        self.assertFalse({case["family"] for case in self.splits["training"]}
                         & {case["family"] for case in self.splits["holdout"]})
        other = self.root.parent / "other"
        lab.generate(other)
        self.assertEqual((other / "training.json").read_bytes(), (self.root / "training.json").read_bytes())
        self.assertEqual((other / "holdout.json").read_bytes(), (self.root / "holdout.json").read_bytes())

    def test_seed_improves_training_holdout_and_regression_without_new_false_positives(self):
        report = lab.evaluate(self.root, self.candidate, self.binary)
        self.assertTrue(report["gate"]["passed"], report)
        for split in ["training", "holdout", "regression"]:
            self.assertTrue(report["splits"][split]["new_true_positives"])
            self.assertEqual(report["splits"][split]["new_false_positives"], [])
        self.assertEqual(report["splits"]["regression"]["combined"]["fp"], 3)
        self.assertEqual(report["splits"]["regression"]["combined"]["fn"], 3)
        missed = [case["id"] for case in report["splits"]["holdout"]["cases"]
                  if case["label"] == "attack" and not case["combined_alert"]]
        self.assertIn("holdout-forged-quotation", missed)

    def test_broad_sensitive_rule_fails_gate_and_cannot_be_released(self):
        bad = lab.candidate_document([{"id": "allowed-secret", "category": "sensitive_access",
                     "all": {"action": "read", "resource_class": "sensitive"}}], self.manifest, {"kind": "operator_seed"})
        result = lab.release(self.root, bad, self.binary)
        self.assertFalse(result["released"])
        self.assertTrue(result["report"]["splits"]["holdout"]["new_false_positives"])
        self.assertFalse((self.root / "active.json").exists())

    def test_overbroad_intent_rule_matches_benign_paraphrase_and_is_rejected(self):
        bad = lab.candidate_document([{**lab.SEED_RULE, "all": {"action": "intent", "intent_cue": "override"}}],
                                     self.manifest, {"kind": "operator_seed"})
        self.assertFalse(lab.evaluate(self.root, bad, self.binary)["gate"]["passed"])

    def test_no_gain_rule_cannot_pass_by_staying_quiet(self):
        quiet = lab.candidate_document([{"id": "unused", "category": "boundary_violation",
                       "all": {"action": "execute", "resource_class": "path_escape"}}], self.manifest, {"kind": "operator_seed"})
        report = lab.evaluate(self.root, quiet, self.binary)
        self.assertFalse(report["gate"]["passed"])
        self.assertIn("holdout: no measurable detection gain", report["gate"]["reasons"])

    def test_proposer_receives_only_training_feature_vectors(self):
        model = self.root / "dummy.gguf"
        model.write_bytes(b"mock model, never executed")
        with patch.object(lab.audit, "invoke", return_value=json.dumps({"rules": [lab.SEED_RULE]})) as invoke:
            result = lab.propose(self.root, self.binary, model)
        prompt = invoke.call_args.args[-1]
        provided = json.loads(prompt.split("TRAINING ONLY:\n", 1)[1])
        expected = [{"label": case["label"], "events": [lab.features(row) for row in lab.evaluation.records(case)]}
                    for case in self.splits["training"]]
        self.assertEqual(provided, expected)
        self.assertNotIn("disclose credentials", prompt)
        self.assertNotIn("holdout-forged-quotation", prompt)
        self.assertEqual(result["proposer"]["kind"], "qwen")

    def test_invalid_model_proposal_is_not_replaced_with_seed(self):
        model = self.root / "dummy.gguf"
        model.write_bytes(b"mock model")
        with patch.object(lab.audit, "invoke", return_value='{"rules":[],"command":"kill"}') as invoke:
            with self.assertRaisesRegex(ValueError, "Qwen proposal rejected"):
                lab.propose(self.root, self.binary, model)
        self.assertEqual(invoke.call_count, 2)
        self.assertFalse((self.root / "candidates").exists())

    def test_curriculum_and_training_binding_tampering_rejected(self):
        bad = {**self.candidate, "training_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "binding"):
            lab.evaluate(self.root, bad, self.binary)
        (self.root / "holdout.json").write_text("[]")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            lab.evaluate(self.root, self.candidate, self.binary)

    def test_supplied_pass_flag_cannot_bypass_release_evaluation(self):
        forged = {**self.candidate, "gate": {"passed": True}}
        with self.assertRaises(ValueError):
            lab.release(self.root, forged, self.binary)
        self.assertFalse((self.root / "active.json").exists())

    def test_shadow_rejects_corrupt_audit_instead_of_reporting_clean(self):
        lab.release(self.root, self.candidate, self.binary)
        source = self.root / "corrupt.jsonl"
        raw = lab.evaluation.encode(lab.evaluation.records(self.splits["holdout"][0]))
        source.write_bytes(raw.replace(b"synthetic", b"tampered"))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            lab.shadow(self.root, source, self.binary)

    def test_release_is_shadow_only_and_rollback_preserves_history(self):
        first = lab.release(self.root, self.candidate, self.binary)["version"]
        second_candidate = copy.deepcopy(self.candidate)
        second_candidate["rules"][0]["id"] = "intent-override-v2"
        second = lab.release(self.root, second_candidate, self.binary)["version"]
        bundle = lab.version(self.root, second)
        self.assertEqual(bundle["parent"], first)
        self.assertEqual(bundle["permissions"], ["emit_alert"])
        lab.rollback(self.root, first, self.binary)
        self.assertEqual(lab.read_json(self.root / "active.json")["version"], first)
        self.assertTrue((self.root / "versions" / (second + ".json")).exists())

    def test_corrupt_version_or_changed_engine_cannot_be_loaded(self):
        identifier = lab.release(self.root, self.candidate, self.binary)["version"]
        with patch.object(lab, "engine_hash", return_value="new-engine"):
            with self.assertRaisesRegex(ValueError, "engine changed"):
                lab.version(self.root, identifier)
        changed_binary = self.root / "other-binary"
        changed_binary.write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "binary changed"):
            lab.version(self.root, identifier, changed_binary)
        path = self.root / "versions" / (identifier + ".json")
        bundle = lab.read_json(path)
        bundle["permissions"] = ["kill"]
        path.write_text(json.dumps(bundle))
        with self.assertRaises(ValueError):
            lab.rollback(self.root, identifier, self.binary)
        with self.assertRaises(ValueError):
            lab.version(self.root, "../../outside")

    def test_shadow_replays_new_events_once_without_modifying_source(self):
        lab.release(self.root, self.candidate, self.binary)
        rows = lab.evaluation.records(self.splits["holdout"][0])
        source = self.root / "sample.jsonl"
        source.write_bytes(lab.evaluation.encode(rows))
        before = source.read_bytes()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            lab.shadow(self.root, source, self.binary, polls=2, interval=0.05)
        reports = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0]["advisory_only"])
        self.assertEqual(len(reports[0]["shadow_findings"]), 1)
        self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
