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
        self.assertEqual(verdict["votes"], {"guilty": 2, "not_guilty": 0, "abstained": 1,
                                              "timed_out": 0})
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

    def test_timed_out_votes_empower_nothing(self):
        votes = court.simulate_jury(
            [{"voter": "j1", "origin": "r1", "verdict": "guilty", "latency_secs": 5},
             {"voter": "j2", "origin": "r2", "verdict": "guilty", "latency_secs": 999}],
            timeout_secs=10)
        self.assertEqual([v["verdict"] for v in votes], ["guilty", "timeout"])
        verdict = court.judge(base_case(), [ev("v1"), ev("v2", source="rule")],
                              [], [], votes)
        self.assertEqual(verdict["votes"]["timed_out"], 1)
        self.assertEqual(verdict["outcome"], "below-quorum")

    def test_contested_tie_downgrades_one_level(self):
        votes = [vote("j1"), vote("j2", origin="o2"),
                 vote("n1", verdict="not-guilty", origin="o3"),
                 vote("n2", verdict="not-guilty", origin="o4")]
        verdict = court.judge(base_case(), [ev("v1"), ev("v2", source="rule")],
                              [], [], votes)
        self.assertEqual((verdict["outcome"], verdict["action"]), ("decided", "restrict"))
        self.assertTrue(any(c.startswith("contested-tie:") for c in verdict["conditions"]))

    def test_simulate_jury_rejects_malformed_specs(self):
        with self.assertRaises(ValueError):
            court.simulate_jury([], timeout_secs=10)
        with self.assertRaises(ValueError):
            court.simulate_jury([{"voter": "j1"}], timeout_secs=10)

    def test_advisory_with_outside_events_or_commands_is_dropped(self):
        with self.assertRaises(ValueError):
            court.advisory_to_votes(
                [{"advisor": "q", "origin": "qwen", "verdict": "guilty",
                  "reason": "looks bad", "cited_event_ids": ["invented"]}], ["e1"])
        with self.assertRaises(ValueError):
            court.advisory_to_votes(
                [{"advisor": "q", "origin": "qwen", "verdict": "guilty",
                  "reason": "run quarantine now", "cited_event_ids": ["e1"]}], ["e1"])
        with self.assertRaises(ValueError):
            court.advisory_to_votes(
                [{"advisor": "q", "origin": "qwen", "verdict": "guilty",
                  "reason": "```quarantine```", "cited_event_ids": ["e1"]}], ["e1"])
        votes = court.advisory_to_votes(
            [{"advisor": "q", "origin": "qwen", "verdict": "guilty",
              "reason": "two independent host signals agree", "cited_event_ids": ["e1"]}],
            ["e1"])
        self.assertEqual(votes, [{"voter": "q", "origin": "qwen", "verdict": "guilty"}])

    def test_shadow_corpus_matches_labels_and_replays(self):
        import tempfile
        corpus = Path(__file__).resolve().parent.parent / "examples" / "security-court"
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "v1.jsonl")
            summary = court.shadow_judge(str(corpus), out)
            self.assertEqual(summary["mismatches"], [])
            self.assertEqual(summary["counts"], {"decided": 2, "insufficient-evidence": 1})
            out2 = str(Path(tmp) / "v2.jsonl")
            court.shadow_judge(str(corpus), out2)
            self.assertEqual(Path(out).read_bytes(), Path(out2).read_bytes())
            self.assertEqual(court.diff_runs(out, out2)["changed"], [])

    def test_policy_cap_killswitch_and_version_pin(self):
        verdict = court.judge(base_case(), [ev("v1"), ev("v2", source="rule")], [],
                              [], [vote("j1"), vote("j2", origin="o2")])
        capped = court.apply_policy(
            verdict, {"law_version": court.LAW_VERSION, "max_action": "watch",
                      "kill_switch": False, "budget_cases": 10})
        self.assertEqual(capped["action"], "watch")
        self.assertTrue(any(c.startswith("policy-cap:") for c in capped["conditions"]))
        killed = court.apply_policy(
            verdict, {"law_version": court.LAW_VERSION, "max_action": "replace",
                      "kill_switch": True, "budget_cases": 10})
        self.assertEqual((killed["outcome"], killed["action"]), ("killed", "none"))
        with self.assertRaises(ValueError):
            court.apply_policy(verdict, {"law_version": "other", "max_action": "watch",
                                         "kill_switch": False, "budget_cases": 10})


class EnforcementTests(unittest.TestCase):
    NOW = "2026-11-04T00:00:00+00:00"

    def shadow_in(self, tmp):
        corpus = Path(__file__).resolve().parent.parent / "examples" / "security-court"
        out = Path(tmp) / "verdicts.jsonl"
        court.shadow_judge(str(corpus), str(out))
        return corpus, out

    def policy(self, **over):
        policy = {"law_version": court.LAW_VERSION, "max_action": "replace",
                  "kill_switch": False, "budget_cases": 10}
        policy.update(over)
        return policy

    def read_ledger(self, path):
        return [__import__("json").loads(line)
                for line in Path(path).read_text().splitlines() if line.strip()]

    def test_examples_translate_to_restrictive_directives_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            summary = court.enforce_run(str(corpus), str(verdicts), self.policy(),
                                        str(ledger), self.NOW)
            self.assertEqual((summary["cases"], summary["appended"], summary["killed"]),
                             (3, 3, 0))
            self.assertEqual(summary["directives"], {"none": 1, "quarantine": 1, "restrict": 1})
            records = {r["case_id"]: r for r in self.read_ledger(ledger)}
            self.assertEqual(set(records), {"clear-exfil", "weak-signal", "contested-access"})
            self.assertEqual(records["clear-exfil"]["directive"], "quarantine")
            self.assertEqual(records["clear-exfil"]["release_mode"], "policy-review")
            self.assertTrue(records["clear-exfil"]["applied"])
            self.assertEqual(records["contested-access"]["directive"], "restrict")
            self.assertEqual(records["weak-signal"]["directive"], "none")
            self.assertEqual(records["weak-signal"]["reason"], "outcome:insufficient-evidence")
            self.assertFalse(records["weak-signal"]["applied"])
            self.assertTrue(records["clear-exfil"]["review_deadline_utc"]
                            > records["clear-exfil"]["created_utc"])
            for record in records.values():
                self.assertEqual(set(record), court.DIRECTIVE_FIELDS)
                self.assertEqual(record["rollback"], "recovery-policy")
                self.assertLessEqual(court.SEVERITY[record["directive"]],
                                     court.SEVERITY[court.ACTIONS[-1]])
                self.assertFalse({k for k in record
                                  if "capability" in k or "grant" in k or "permission" in k})

    def test_kill_switch_blocks_every_directive(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            summary = court.enforce_run(
                str(corpus), str(verdicts), self.policy(kill_switch=True),
                str(ledger), self.NOW)
            self.assertEqual((summary["applied"], summary["killed"]), (0, 3))
            self.assertEqual(summary["directives"], {"none": 3})
            for record in self.read_ledger(ledger):
                self.assertEqual((record["directive"], record["reason"]),
                                 ("none", "kill-switch"))

    def test_replay_is_deterministic_and_ledger_is_idempotent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger_a, ledger_b = Path(tmp) / "a.jsonl", Path(tmp) / "b.jsonl"
            first = court.enforce_run(str(corpus), str(verdicts), self.policy(),
                                      str(ledger_a), self.NOW)
            court.enforce_run(str(corpus), str(verdicts), self.policy(),
                              str(ledger_b), self.NOW)
            self.assertEqual(ledger_a.read_bytes(), ledger_b.read_bytes())
            same = court.enforce_run(str(corpus), str(verdicts), self.policy(),
                                     str(ledger_a), self.NOW)
            self.assertEqual((same["appended"], same["duplicates"]), (0, 3))
            self.assertEqual(same["ledger_sha256"], first["ledger_sha256"])

    def test_tampered_or_escalated_verdicts_fail_closed(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            rows = [json.loads(line) for line in verdicts.read_text().splitlines()]
            ledger = Path(tmp) / "ledger.jsonl"
            bad_hash = json.loads(json.dumps(rows))
            for row in bad_hash:
                row["verdict"]["law_hash"] = "0" * 64
            bad = Path(tmp) / "bad-hash.jsonl"
            bad.write_text("\n".join(json.dumps(r) for r in bad_hash) + "\n")
            with self.assertRaises(ValueError):
                court.enforce_run(str(corpus), str(bad), self.policy(),
                                  str(ledger), self.NOW)
            escalated = json.loads(json.dumps(rows))
            for row in escalated:
                if row["verdict"]["case_id"] == "weak-signal":
                    row["verdict"]["action"] = "replace"
            bad_action = Path(tmp) / "bad-action.jsonl"
            bad_action.write_text("\n".join(json.dumps(r) for r in escalated) + "\n")
            with self.assertRaises(ValueError):
                court.enforce_run(str(corpus), str(bad_action), self.policy(),
                                  str(ledger), self.NOW)
            self.assertFalse(ledger.exists())

    def test_budget_and_evidence_binding_fail_closed(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            with self.assertRaises(ValueError):
                court.enforce_run(str(corpus), str(verdicts),
                                  self.policy(budget_cases=2), str(ledger), self.NOW)
            self.assertFalse(ledger.exists())
            rows = [json.loads(line) for line in verdicts.read_text().splitlines()]
            rows[0]["verdict"]["evidence_used"] = ["invented-evidence"]
            tampered = Path(tmp) / "tampered.jsonl"
            tampered.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            with self.assertRaises(ValueError):
                court.enforce_run(str(corpus), str(tampered), self.policy(),
                                  str(ledger), self.NOW)
            self.assertFalse(ledger.exists())

    def test_enforcement_table_cannot_grant(self):
        table = court.enforcement_table()
        self.assertEqual([row["action"] for row in table], list(court.ACTIONS))
        for row in table:
            self.assertEqual(set(row), {"action", "directive", "release_mode"})
            self.assertNotIn("allow", row["directive"].split())
        self.assertEqual(
            [row["release_mode"] for row in table if row["action"] in
             ("restrict", "quarantine", "replace")],
            ["policy-review"] * 3)


if __name__ == "__main__":
    unittest.main()
