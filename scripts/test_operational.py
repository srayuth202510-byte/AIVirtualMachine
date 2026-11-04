#!/usr/bin/env python3
"""Unit tests for scripts/eval-operational.py: fail-closed aggregation + detection parsing."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

module = importlib.util.spec_from_file_location(
    "eval_operational", Path(__file__).with_name("eval-operational.py"))
oev = importlib.util.module_from_spec(module)
module.loader.exec_module(oev)

eval_operational = oev


def passing_stage(name):
    return {"name": name, "command": ["true"], "returncode": 0,
            "passed": True, "elapsed_seconds": 0.1, "summaries": [],
            "log": f"{name}.log", "log_sha256": "0" * 64}


class AggregationFailClosed(unittest.TestCase):
    def setUp(self):
        self.record = passing_stage("detection")

    def test_empty_stage_list_is_failure(self):
        report = eval_operational.build_report([], "2026-11-04T00:00:00+00:00")
        self.assertFalse(report["passed"])
        self.assertEqual(report["schema"], eval_operational.SCHEMA)

    def test_all_passed_requires_every_stage_passed_true(self):
        self.assertTrue(eval_operational.build_report([self.record], "t")["passed"])
        broken = dict(self.record, passed=False)
        self.assertFalse(
            eval_operational.build_report([broken], "t")["passed"])
        # passed ที่ไม่ใช่ True อย่างชัดเจน (False/ไม่มี field) ต้องไม่ถูกนับผ่าน
        self.assertFalse(
            eval_operational.build_report(
                [{"name": "x", "returncode": 0}], "t")["passed"])

    def test_report_carries_commit_stage_and_limitations(self):
        report = eval_operational.build_report([self.record], "t")
        self.assertEqual(len(report["commit"]), 40)
        self.assertIn("synthetic detection corpus", report["limitations"][0])
        self.assertEqual([stage["name"] for stage in report["stages"]],
                         ["detection"])


class NamedTestsRequirement(unittest.TestCase):
    def green(self, names, summaries=None):
        return {"name": "x", "passed": True, "summaries": summaries or [
            "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.03s" % len(names)],
            "tests_ok": ["microvm::tests::" + n for n in names]}

    def test_all_names_present_multiple_binaries_ok(self):
        stage = self.green(["a", "b"], summaries=[
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"])
        self.assertTrue(eval_operational.require_named_tests(stage, ["a", "b"])["passed"])

    def test_failed_or_ignored_summary_rejected(self):
        bad = ["test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured"]
        self.assertFalse(
            eval_operational.require_named_tests(self.green(["a"], bad), ["a"])["passed"])
        ignored = ["test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured"]
        self.assertFalse(
            eval_operational.require_named_tests(self.green(["a"], ignored), ["a"])["passed"])
        self.assertFalse(
            eval_operational.require_named_tests(
                self.green(["a"], ["garbage line"]), ["a"])["passed"])

    def test_missing_name_or_typo_is_fail_closed(self):
        self.assertFalse(
            eval_operational.require_named_tests(self.green(["a"]), ["a", "typo"])["passed"])
        # exit 0 แต่เทสต์ 0 ตัว = ชื่อผิด ต้องตก ไม่ใช่ผ่านเงียบ
        self.assertFalse(
            eval_operational.require_named_tests(self.green([]), ["a"])["passed"])


class DetectionReportParsing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def write_report(self, data, name="detection.json"):
        path = self.root / name
        path.write_text(json.dumps(data))
        return path

    def valid_report(self, **overrides):
        data = {"schema": eval_operational.SCHEMA, "provenance": {"corpus_sha256": "a" * 64},
                "policy_regressions": [], "total": 30, "counts": {"tp": 10, "fp": 2},
                "precision": 0.8333}
        data.update(overrides)
        return data

    def test_valid_report_yields_metrics(self):
        path = self.write_report(self.valid_report())
        data = eval_operational.parse_detection_report(path)
        self.assertEqual(data["counts"]["tp"], 10)

    def test_schema_mismatch_and_regressions_are_rejected(self):
        with self.assertRaises(ValueError):
            eval_operational.parse_detection_report(
                self.write_report(self.valid_report(provenance=None)))
        with self.assertRaises(ValueError):
            eval_operational.parse_detection_report(
                self.write_report(self.valid_report(policy_regressions=["regress"])))
        with self.assertRaises(ValueError):
            eval_operational.parse_detection_report(
                self.write_report(self.valid_report(total=0)))
        # JSON เสีย/ไม่เป็น object ต้องไม่ทำให้ harness ว่าผ่าน (fail-closed)
        broken = self.root / "broken.json"
        broken.write_text("[not json")
        with self.assertRaises(ValueError):
            eval_operational.parse_detection_report(broken)

    def test_detection_stage_fail_closed_without_file(self):
        with patch.object(eval_operational, "run_stage") as fake:
            fake.return_value = {"name": "detection", "returncode": 0,
                                 "passed": True, "summaries": []}
            record = eval_operational.detection_stage(self.root)
            # ไฟล์ evidence ไม่ถูกสร้างเพราะ run_stage ถูกแทน — ต้องตก
            self.assertFalse(record["passed"])
            self.assertIn("detection evidence invalid", record["error"])


if __name__ == "__main__":
    unittest.main()
