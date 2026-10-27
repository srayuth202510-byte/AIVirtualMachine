"""Regression checks for the prompt comparison's evidence and strict scores."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("quality", Path(__file__).with_name("eval-model-quality.py"))
QUALITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY)


class QualityTests(unittest.TestCase):
    def test_oracle_rejects_markdown_wrong_paths_extra_fields_and_wrong_json_types(self):
        self.assertTrue(QUALITY.score({"json": {"enabled": False, "count": 2}}, '{"count":2,"enabled":false}'))
        self.assertFalse(QUALITY.score({"json": {"enabled": False}}, '{"enabled":0}'))
        self.assertFalse(QUALITY.score({"json": {"count": 2}}, '{"count":2.0}'))
        self.assertFalse(QUALITY.score({"json": [2, 5, 9]}, '```json\n[2,5,9]\n```'))
        self.assertFalse(QUALITY.score({"json": {"path": "src/seed.txt"}}, '{"path":".env"}'))
        self.assertFalse(QUALITY.score({"json": {"count": 2}}, '{"count":2,"extra":true}'))
        self.assertFalse(QUALITY.score({"exact": "42"}, 'Answer: 42'))
        self.assertFalse(QUALITY.score({"exact": "42"}, None))

    def test_stale_partial_or_falsely_scored_evidence_cannot_pass(self):
        for corpus in QUALITY.CORPORA:
            for style in ("raw", "strict"):
                cases = json.loads(QUALITY.CORPORA[corpus].read_text())["cases"]
                suffix = json.loads(QUALITY.PROFILE.read_text())["suffix"] if style == "strict" else ""
                rows = [{"id": case["id"], "infrastructure_passed": True, "task_correct": True,
                         "prompt": case["prompt"] + suffix,
                         "output": case["exact"] if "exact" in case else json.dumps(case["json"])} for case in cases]
                report = {"schema": 1, "completed": len(rows), "total": len(rows), "task_correct": len(rows),
                          "config_sha256": "a" * 64, "corpus": corpus, "prompt_style": style,
                          "corpus_sha256": QUALITY.HOST.digest(QUALITY.CORPORA[corpus]),
                          "prompt_profile_sha256": QUALITY.HOST.digest(QUALITY.PROFILE) if style == "strict" else None,
                          "cases": rows}
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "evidence.json"
                    path.write_text(json.dumps(report))
                    self.assertTrue(QUALITY.valid_report(path, corpus, style, "a" * 64))
                    invalids = [{**report, field: "stale"} for field in
                                ("config_sha256", "corpus_sha256", "prompt_profile_sha256", "prompt_style", "corpus")]
                    for field, value in (("output", "wrong answer"), ("prompt", "changed task"),
                                         ("infrastructure_passed", False)):
                        changed = copy.deepcopy(report)
                        changed["cases"][0][field] = value
                        invalids.append(changed)
                    invalids.append({**report, "cases": rows[:-1]})
                    for invalid in invalids:
                        path.write_text(json.dumps(invalid))
                        self.assertFalse(QUALITY.valid_report(path, corpus, style, "a" * 64))

    def test_comparison_reports_regressions_even_when_total_improves(self):
        def report(scores):
            return {"task_correct": sum(scores), "total": len(scores),
                    "cases": [{"id": str(i), "task_correct": value} for i, value in enumerate(scores)]}
        result = QUALITY.compare(report([True, False, False]), report([False, True, True]))
        self.assertEqual(result["improved"], ["1", "2"])
        self.assertEqual(result["regressed"], ["0"])

    def test_structured_evidence_rechecks_output_schema_and_completion(self):
        # format ผ่านไม่ได้ทำให้คำตอบถูก และ report ปลอม schema/grammar ไม่ได้
        case = {"id": "different-read-intent"}
        valid = {"output_mode": "agent_intent", "grammar_id": "aivm-agent-intent-v1",
                 "termination": "completed", "format_valid": True, "schema_valid": True,
                 "output": '{"tool":"filesystem.read","path":".env"}'}
        self.assertTrue(QUALITY.structured_evidence(case, valid))
        for output in ('{"done":true,"done":true}', '{"done":false}',
                       '{"tool":"shell.exec","path":"sh"}',
                       '{"tool":"filesystem.write","path":"x"}',
                       '{"tool":"process.exec","path":"cc","content":{"argv":[],"extra":1}}',
                       '```json\n{"done":true}\n```', '{"done":true'):
            self.assertFalse(QUALITY.structured_evidence(case, {**valid, "output": output}))
        for key, value in (("grammar_id", None), ("output_mode", "text"),
                           ("termination", "length"), ("schema_valid", False)):
            self.assertFalse(QUALITY.structured_evidence(case, {**valid, key: value}))
        for output in ('{"tool":"process.exec","path":"cc","content":{"argv":[]}}',
                       '{"tool":"filesystem.write","path":"x","content":["a","b"]}'):
            self.assertTrue(QUALITY.structured_evidence(case, {**valid, "output": output}))
        self.assertEqual(QUALITY.task_mode({"id": "nested-extract", "json": {}}), "text")


if __name__ == "__main__":
    unittest.main()
