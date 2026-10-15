"""Phase 1 proof: unanimous votes cannot override supreme law; bad evidence never empowers."""
import importlib.util
import unittest
from pathlib import Path

module = importlib.util.spec_from_file_location(
    "security_court", Path(__file__).with_name("security-court.py"))
court = importlib.util.module_from_spec(module)
module.loader.exec_module(court)


def base_case(**over):
    case = {"id": "case-1", "instance": "vm-a", "session": "s-1",
            "events": ["e1", "e2"], "max_evidence_age_secs": 300,
            "min_sources": 2, "quorum": 2,
            "requested_action": "quarantine", "supreme_violation": False}
    case.update(over)
    return case


def ev(eid, source="audit", origin="host", events=None, age=10, chain=True):
    return {"id": eid, "source": source, "origin": origin,
            "event_ids": events or ["e1"], "instance": "vm-a",
            "session": "s-1", "age_secs": age, "chain_ok": chain}


def vote(voter, verdict="guilty", origin="rule"):
    return {"voter": voter, "origin": origin, "verdict": verdict}


class JudgeTests(unittest.TestCase):
    def test_unanimous_votes_cannot_override_supreme_law(self):
        verdict = court.judge(
            base_case(supreme_violation=True), [ev("v1"), ev("v2", source="rule")],
            [{"id": "a1", "event_ids": ["e1"], "requested_action": "replace"}],
            [], [vote("j1"), vote("j2"), vote("j3")])
        self.assertEqual((verdict["outcome"], verdict["action"]),
                         ("rejected-supreme-law", "none"))

    def test_stale_chainbroken_and_invented_evidence_are_excluded(self):
        verdict = court.judge(
            base_case(), [ev("good-1"), ev("good-2", source="rule"),
                          ev("old", age=9999), ev("broken", chain=False),
                          ev("fake", events=["nope"])],
            [], [],
            [vote("j1"), vote("j2", origin="rule-b")])
        reasons = {e["id"]: e["reason"] for e in verdict["evidence_excluded"]}
        self.assertEqual(reasons, {"old": "stale", "broken": "chain-broken",
                                   "fake": "invented-event"})
        self.assertEqual(verdict["evidence_used"], ["good-1", "good-2"])

    def test_wrong_instance_binding_is_excluded(self):
        bad = ev("x1")
        bad["session"] = "other-session"
        verdict = court.judge(base_case(), [ev("v1"), bad], [], [],
                              [vote("j1"), vote("j2", origin="o2")])
        self.assertEqual(verdict["outcome"], "insufficient-evidence")

    def test_same_model_twice_counts_once_and_abstention_counts_nothing(self):
        verdict = court.judge(
            base_case(min_sources=2, quorum=2),
            [ev("v1", source="model-advisory", origin="qwen"),
             ev("v2", source="model-advisory", origin="qwen")],
            [], [],
            [vote("qwen", origin="qwen"), vote("qwen", origin="qwen"),
             vote("q2", origin="qwen2"), vote("a1", verdict="abstain")])
        self.assertEqual(verdict["votes"], {"guilty": 2, "not_guilty": 0, "abstained": 1})
        # โหวตถึง quorum แต่แหล่งอิสระมี 1 (origin ซ้ำนับครั้งเดียว) -> หลักฐานไม่พอ
        self.assertEqual(verdict["outcome"], "insufficient-evidence")

    def test_below_quorum_watches_and_veto_downgrades(self):
        verdict = court.judge(
            base_case(), [ev("v1"), ev("v2", source="rule")], [], [], [vote("j1")])
        self.assertEqual((verdict["outcome"], verdict["action"]), ("below-quorum", "watch"))
        verdict = court.judge(
            base_case(), [ev("v1"), ev("v2", source="rule")], [], 
            [{"id": "o1", "kind": "veto", "ref_evidence_ids": ["v1"]}],
            [vote("j1"), vote("j2", origin="o2")])
        self.assertEqual((verdict["outcome"], verdict["action"]), ("decided", "restrict"))

    def test_replay_is_deterministic(self):
        args = (base_case(), [ev("v1"), ev("v2", source="rule")], [],
                [{"id": "o1", "kind": "alternate-cause", "ref_evidence_ids": []}],
                [vote("j1"), vote("j2", origin="o2")])
        self.assertEqual(court.judge(*args), court.judge(*args))

    def test_malformed_bundles_fail_closed(self):
        with self.assertRaises(ValueError):
            court.judge({**base_case(), "extra": 1}, [], [], [], [])
        dup = [ev("v1"), ev("v1")]
        with self.assertRaises(ValueError):
            court.judge(base_case(), dup, [], [], [])
        with self.assertRaises(ValueError):
            court.judge(base_case(), [ev("v1", source="ouija")], [], [], [])


    def test_decision_table_pins_supreme_law_first(self):
        table = court.decision_table()
        self.assertEqual(table[0]["outcome"], "rejected-supreme-law")
        self.assertIn("unanimous", table[0]["note"])


if __name__ == "__main__":
    unittest.main()
