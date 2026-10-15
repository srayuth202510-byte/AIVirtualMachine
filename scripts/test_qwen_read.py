"""Regression tests for evidence validation; no LLM or network required."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("qwen_read", Path(__file__).with_name("qwen-read.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class EvidenceVerificationTests(unittest.TestCase):
    def run_result(self, summary="actual", outcome="OK filesystem.read src/evidence.txt :: actual"):
        return {"stopped": "done", "summary": summary,
                "steps": [{"action": "filesystem.read src/evidence.txt", "outcome": outcome}]}

    def test_rejects_hallucination_despite_successful_read(self):
        self.assertEqual(reader.verify(self.run_result("sample text"), "actual"),
                         "answer-does-not-match-file")

    def test_correct_answer_without_tool_read_is_rejected(self):
        result = self.run_result()
        result["steps"] = []
        self.assertEqual(reader.verify(result, "actual"), "missing-successful-read")

    def test_denied_read_and_unfinished_run_are_rejected(self):
        self.assertEqual(reader.verify(self.run_result(outcome="DENY filesystem.read"), "actual"),
                         "missing-successful-read")
        result = self.run_result()
        result["stopped"] = "max-steps"
        self.assertEqual(reader.verify(result, "actual"), "not-finished")

    def test_exact_answer_after_read_is_accepted(self):
        self.assertIsNone(reader.verify(self.run_result(), "actual"))


if __name__ == "__main__":
    unittest.main()
