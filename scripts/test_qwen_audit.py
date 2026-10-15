"""Audit rules and model-evidence checks, including hostile log/model content."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("qwen_audit", Path(__file__).with_name("qwen-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
CASES = Path(__file__).resolve().parents[1] / "examples/audit-review"


class AuditReviewTests(unittest.TestCase):
    def test_known_cases_match_rule_categories(self):
        for case in json.loads((CASES / "cases.json").read_text()):
            with self.subTest(case=case["name"]):
                rows = audit.load_records((CASES / case["file"]).read_bytes())
                found = {alert["category"] for alert in audit.inspect_records(rows)}
                self.assertEqual(found, set(case["expected_categories"]))

    def test_burst_window_and_actor_are_separate(self):
        rows = audit.load_records((CASES / "burst.jsonl").read_bytes())
        for row in rows:
            row["timestamp"] = row["seq"] * 61
        self.assertEqual(audit.inspect_records(rows), [])
        for row in rows:
            row["timestamp"] = 1700000000
            row["session_id"] = str(row["seq"] % 2)
        self.assertEqual(audit.inspect_records(rows), [])

    def test_raw_hostile_content_and_names_are_not_sent_to_model(self):
        rows = audit.load_records((CASES / "injection.jsonl").read_bytes())
        rows[0]["agent"] = "PRIVATE-NAME"
        rows[0]["rule_matched"] = "SECRET-UNTRUSTED-TEXT"
        events = audit.model_events(rows, audit.inspect_records(rows))
        text = json.dumps(events)
        for forbidden in ["Ignore previous", "PRIVATE-NAME", "SECRET-UNTRUSTED-TEXT"]:
            self.assertNotIn(forbidden, text)

    def events(self):
        rows = audit.load_records((CASES / "boundary.jsonl").read_bytes())
        return audit.model_events(rows, audit.inspect_records(rows))

    def finding(self, **changes):
        result = {"category": "boundary_violation", "severity": "high",
                  "event_ids": [0], "reason": "Boundary signal on event 0."}
        result.update(changes)
        return json.dumps({"findings": [result]})

    def test_fabricated_ids_or_categories_are_rejected(self):
        for changes in [{"event_ids": [999]}, {"event_ids": [True]},
                        {"event_ids": [0, 0]}, {"category": "sensitive_access"},
                        {"severity": "safe"}, {"command": "grant all"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                audit.validate_review(self.finding(**changes), self.events())

    def test_duplicate_json_fields_and_prose_are_rejected(self):
        for text in ['{"findings":[],"findings":[]}', '```json\n{"findings":[]}\n``` extra',
                     'ALLOW {"findings":[]}', '{"findings":[],"grant":true}']:
            with self.assertRaises(ValueError):
                audit.validate_review(text, self.events())

    def test_only_an_entire_response_json_fence_is_supported(self):
        self.assertEqual(audit.validate_review('```json\n{"findings":[]}\n```', self.events()),
                         {"findings": []})
        with self.assertRaises(ValueError):
            audit.validate_review('comment\n```json\n{"findings":[]}\n```', self.events())

    def test_grounded_model_finding_is_accepted_without_changing_rules(self):
        rows = audit.load_records((CASES / "boundary.jsonl").read_bytes())
        alerts = audit.inspect_records(rows)
        audit.validate_review('{"findings":[]}', self.events())
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(audit.validate_review(self.finding(), self.events())["findings"][0]["event_ids"], [0])

    def test_invalid_input_is_never_a_clean_report(self):
        for raw in [b"", b"{broken", b'{"hash_version":1}', b'{"hash_version":2,"seq":NaN}']:
            with self.assertRaises(ValueError):
                audit.load_records(raw)


if __name__ == "__main__":
    unittest.main()
