"""Security court proofs: supreme law, evidence binding, replay and restrictive directives."""
import importlib.util
import copy
import itertools
import json
import multiprocessing
import shutil
import tempfile
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


def enforce_child(corpus, verdicts, policy, ledger, now, started, read, release, results):
    # หยุด writer แรกหลังอ่าน ledger เพื่อบังคับให้ writer ที่สองชนช่วง read/write จริง
    original = court._read_ledger

    def paused_read(path):
        rows = original(path)
        read.set()
        if release is not None and not release.wait(10):
            raise RuntimeError("timed out waiting to release ledger reader")
        return rows

    court._read_ledger = paused_read
    started.set()
    try:
        results.put(court.enforce_run(corpus, verdicts, policy, ledger, now))
    except Exception as error:
        results.put({"error": repr(error)})


class JudgeTests(unittest.TestCase):
    def test_duplicate_votes_do_not_change_counts_or_decision(self):
        votes = [vote("j1"), vote("j2"), vote("n1", "not-guilty"),
                 vote("a1", "abstain"), vote("t1", "timeout")]
        args = (base_case(), [ev("v1"), ev("v2", source="rule")], [], [])
        expected = court.judge(*args, votes)
        for item in votes:
            with self.subTest(verdict=item["verdict"]):
                actual = court.judge(*args, votes + [dict(item)])
                # bundle hash ต่างได้เพราะรับข้อมูลซ้ำมา แต่ผลตัดสินต้องไม่เปลี่ยน
                for key in ("action", "outcome", "votes", "conditions"):
                    self.assertEqual(actual[key], expected[key])

    def test_conflicting_votes_from_one_juror_are_rejected_in_any_order(self):
        for first, second in itertools.permutations(
                ("guilty", "not-guilty", "abstain", "timeout"), 2):
            with self.subTest(first=first, second=second):
                with self.assertRaisesRegex(ValueError, "conflicting vote"):
                    court.judge(base_case(), [ev("v1"), ev("v2", source="rule")],
                                [], [], [vote("j1"), vote("j2"),
                                         vote("duplicate", first), vote("duplicate", second)])

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

    def test_boolean_juror_timings_are_rejected(self):
        spec = {"voter": "j1", "origin": "rule", "verdict": "guilty", "latency_secs": 1}
        for value in (False, True):
            with self.subTest(field="timeout_secs", value=value):
                with self.assertRaisesRegex(ValueError, "timeout_secs"):
                    court.simulate_jury([spec], timeout_secs=value)
            with self.subTest(field="latency_secs", value=value):
                with self.assertRaisesRegex(ValueError, "latency_secs"):
                    court.simulate_jury([{**spec, "latency_secs": value}], timeout_secs=10)

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

    def strong_bundle(self):
        return {"case": base_case(),
                "evidences": [ev("audit-1"), ev("rule-1", source="rule")],
                "allegations": [], "objections": [],
                "votes": [vote("j1"), vote("j2", origin="runtime")]}

    def write_bundle_run(self, tmp, bundle):
        # ใช้เส้นทางไฟล์จริงตั้งแต่ corpus ถึง ledger ไม่ข้าม validation ของ enforce
        corpus = Path(tmp) / "corpus"
        corpus.mkdir(exist_ok=True)
        (corpus / "case.json").write_text(json.dumps(bundle))
        verdicts = Path(tmp) / "verdicts.jsonl"
        verdicts.write_text(json.dumps({"bundle": "case.json",
                                        "verdict": court.judge(**bundle)}) + "\n")
        return corpus, verdicts

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

    def test_bad_evidence_cannot_produce_containment_even_with_unanimous_votes(self):
        attacks = [
            ("wrong-instance", {"instance": "vm-b"}, "wrong-binding"),
            ("wrong-session", {"session": "s-2"}, "wrong-binding"),
            ("stale", {"age_secs": 301}, "stale"),
            ("broken-chain", {"chain_ok": False}, "chain-broken"),
            ("invented-event", {"event_ids": ["invented"]}, "invented-event"),
        ]
        for name, fields, reason in attacks:
            with self.subTest(attack=name), tempfile.TemporaryDirectory() as tmp:
                bundle = self.strong_bundle()
                bundle["evidences"][1].update(fields)
                corpus, verdicts = self.write_bundle_run(tmp, bundle)
                verdict = self.read_ledger(verdicts)[0]["verdict"]
                self.assertEqual(verdict["votes"]["guilty"], 2)
                self.assertEqual(verdict["evidence_excluded"],
                                 [{"id": "rule-1", "reason": reason}])
                ledger = Path(tmp) / "ledger.jsonl"
                summary = court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
                self.assertEqual((summary["applied"], summary["directives"]),
                                 (0, {"none": 1}))
                record, = self.read_ledger(ledger)
                self.assertEqual(record["outcome"], "insufficient-evidence")
                self.assertEqual(record["evidence_used"], ["audit-1"])
                self.assertEqual(record["independent_sources"], 1)

    def test_evidence_age_boundary_is_enforced_before_translation(self):
        for age, expected in ((300, "quarantine"), (301, "none")):
            with self.subTest(age=age):
                bundle = self.strong_bundle()
                bundle["evidences"][1]["age_secs"] = age
                record = court.enforcement_directive(
                    court.judge(**bundle), bundle, self.policy(), self.NOW)
                self.assertEqual(record["directive"], expected)

    def test_duplicate_sources_cannot_manufacture_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self.strong_bundle()
            bundle["evidences"] = [ev(f"copy-{i}") for i in range(10)]
            corpus, verdicts = self.write_bundle_run(tmp, bundle)
            ledger = Path(tmp) / "ledger.jsonl"
            summary = court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            self.assertEqual(summary["directives"], {"none": 1})
            record, = self.read_ledger(ledger)
            self.assertEqual(record["independent_sources"], 1)

    def test_permission_fields_in_any_bundle_section_fail_before_ledger_write(self):
        for section in ("case", "evidences", "allegations", "objections", "votes"):
            for field, value in (("grant", "process.exec"),
                                 ("capabilities", ["filesystem.write"]),
                                 ("permissions", {"network": True})):
                with self.subTest(section=section, field=field), \
                        tempfile.TemporaryDirectory() as tmp:
                    bundle = self.strong_bundle()
                    bundle["allegations"] = [{"id": "a1", "event_ids": ["e1"],
                                               "requested_action": "quarantine"}]
                    bundle["objections"] = [{"id": "o1", "kind": "alternate-cause",
                                              "ref_evidence_ids": ["audit-1"]}]
                    corpus, verdicts = self.write_bundle_run(tmp, bundle)
                    item = bundle[section] if section == "case" else bundle[section][0]
                    item[field] = value
                    (corpus / "case.json").write_text(json.dumps(bundle))
                    # hash ใหม่กันการผ่านเทสต์เพียงเพราะ digest เก่าไม่ตรง
                    rows = self.read_ledger(verdicts)
                    rows[0]["verdict"]["bundle_sha256"] = court.bundle_hash(bundle)
                    verdicts.write_text(json.dumps(rows[0]) + "\n")
                    ledger = Path(tmp) / "ledger.jsonl"
                    with self.assertRaisesRegex(ValueError, "fields"):
                        court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
                    self.assertFalse(ledger.exists())

    def test_permission_fields_in_verdict_policy_or_ledger_are_rejected(self):
        for target in ("verdict", "policy", "ledger"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                corpus, verdicts = self.write_bundle_run(tmp, self.strong_bundle())
                ledger = Path(tmp) / "ledger.jsonl"
                policy = self.policy()
                before = None
                if target == "verdict":
                    rows = self.read_ledger(verdicts)
                    rows[0]["verdict"]["grant"] = ["process.exec"]
                    verdicts.write_text(json.dumps(rows[0]) + "\n")
                elif target == "policy":
                    policy["grant"] = ["process.exec"]
                else:
                    court.enforce_run(corpus, verdicts, policy, ledger, self.NOW)
                    rows = self.read_ledger(ledger)
                    rows[0]["grant"] = ["process.exec"]
                    ledger.write_text(json.dumps(rows[0]) + "\n")
                    before = ledger.read_bytes()
                with self.assertRaisesRegex(ValueError, "fields"):
                    court.enforce_run(corpus, verdicts, policy, ledger, self.NOW)
                if before is None:
                    self.assertFalse(ledger.exists())
                else:
                    self.assertEqual(ledger.read_bytes(), before)

    def test_allegations_cannot_escalate_beyond_case_request(self):
        for requested, allegation in itertools.product(court.ACTIONS, repeat=2):
            if court.SEVERITY[allegation] <= court.SEVERITY[requested]:
                continue
            with self.subTest(requested=requested, allegation=allegation):
                bundle = self.strong_bundle()
                bundle["case"]["requested_action"] = requested
                bundle["allegations"] = [{"id": "a1", "event_ids": ["e1"],
                                           "requested_action": allegation}]
                # verdict ถูก judge สร้างจริงก็ต้องผ่านเพดาน case ก่อนแปล
                with self.assertRaisesRegex(ValueError, "exceeds case requested_action"):
                    court.enforcement_directive(
                        court.judge(**bundle), bundle, self.policy(), self.NOW)

    def test_policy_caps_every_action_and_preserves_policy_review(self):
        for requested, cap in itertools.product(court.ACTIONS, repeat=2):
            with self.subTest(requested=requested, cap=cap):
                bundle = self.strong_bundle()
                bundle["case"]["requested_action"] = requested
                record = court.enforcement_directive(
                    court.judge(**bundle), bundle, self.policy(max_action=cap), self.NOW)
                self.assertEqual(record["directive"],
                                 min((requested, cap), key=court.SEVERITY.__getitem__))
                self.assertEqual(record["applied"], record["directive"] != "none")
                if record["directive"] in ("restrict", "quarantine", "replace"):
                    self.assertEqual(record["release_mode"], "policy-review")
                    self.assertEqual(record["rollback"], "recovery-policy")

    def test_invalid_last_verdict_never_partially_updates_existing_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            rows = self.read_ledger(verdicts)
            first = Path(tmp) / "first.jsonl"
            first.write_text(json.dumps(rows[0]) + "\n")
            ledger = Path(tmp) / "ledger.jsonl"
            court.enforce_run(corpus, first, self.policy(), ledger, self.NOW)
            before = ledger.read_bytes()
            rows[-1]["verdict"]["action"] = "replace"
            verdicts.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaises(ValueError):
                court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            self.assertEqual(ledger.read_bytes(), before)

    def test_boolean_source_count_cannot_impersonate_replayed_integer(self):
        bundle = self.strong_bundle()
        bundle["case"]["min_sources"] = 1
        bundle["evidences"] = bundle["evidences"][:1]
        verdict = court.judge(**bundle)
        self.assertEqual(verdict["independent_sources"], 1)
        verdict["independent_sources"] = True
        # Python ถือ True == 1 จึงต้องตรวจชนิดก่อนเทียบ replay
        with self.assertRaisesRegex(ValueError, "independent_sources"):
            court.enforcement_directive(verdict, bundle, self.policy(), self.NOW)

    def test_boolean_limits_are_not_accepted_as_integer_thresholds(self):
        for field, value in itertools.product(
                ("max_evidence_age_secs", "min_sources", "quorum"), (False, True)):
            with self.subTest(field=field, value=value):
                bundle = self.strong_bundle()
                bundle["case"][field] = value
                with self.assertRaisesRegex(ValueError, field):
                    court.judge(**bundle)
        for value in (False, True):
            with self.subTest(field="age_secs", value=value):
                bundle = self.strong_bundle()
                bundle["evidences"][0]["age_secs"] = value
                with self.assertRaisesRegex(ValueError, "age_secs"):
                    court.judge(**bundle)
            with self.subTest(field="budget_cases", value=value):
                bundle = self.strong_bundle()
                with self.assertRaisesRegex(ValueError, "budget_cases"):
                    court.enforcement_directive(court.judge(**bundle), bundle,
                                                self.policy(budget_cases=value), self.NOW)

    def test_stale_verdict_rejects_changes_to_every_bundle_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, verdicts = self.shadow_in(tmp)
            corpus = Path(tmp) / "corpus"
            shutil.copytree(source, corpus)
            path = corpus / "clear-quarantine.json"
            original = json.loads(path.read_text())
            changes = [
                ("instance", lambda b: b["case"].update(instance="vm-b")),
                ("session", lambda b: b["case"].update(session="s-2")),
                ("events", lambda b: b["case"].update(events=["e3"])),
                ("freshness", lambda b: b["case"].update(max_evidence_age_secs=0)),
                ("supreme-law", lambda b: b["case"].update(supreme_violation=True)),
                ("evidence", lambda b: b["evidences"][0].update(chain_ok=False)),
                ("allegation", lambda b: b["allegations"][0].update(event_ids=["e2"])),
                ("objection", lambda b: b["objections"].append(
                    {"id": "o1", "kind": "veto", "ref_evidence_ids": ["audit-1"]})),
                ("vote", lambda b: b["votes"][0].update(verdict="not-guilty")),
            ]
            for name, mutate in changes:
                with self.subTest(change=name):
                    changed = copy.deepcopy(original)
                    mutate(changed)
                    path.write_text(json.dumps(changed))
                    ledger = Path(tmp) / f"{name}.jsonl"
                    with self.assertRaisesRegex(ValueError, "bundle"):
                        court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
                    self.assertFalse(ledger.exists())

    def test_directive_checks_bundle_and_replays_verdict(self):
        bundle = {"case": base_case(), "evidences": [ev("v1"), ev("v2", source="rule")],
                  "allegations": [], "objections": [], "votes": [vote("j1"), vote("j2")]}
        verdict = court.judge(**bundle)
        record = court.enforcement_directive(verdict, bundle, self.policy(), self.NOW)
        self.assertEqual(record["bundle_sha256"], verdict["bundle_sha256"])
        changed = copy.deepcopy(bundle)
        changed["case"]["session"] = "s-2"
        with self.assertRaisesRegex(ValueError, "bundle"):
            court.enforcement_directive(verdict, changed, self.policy(), self.NOW)
        tampered = copy.deepcopy(verdict)
        tampered["votes"]["guilty"] += 1
        with self.assertRaisesRegex(ValueError, "replay"):
            court.enforcement_directive(tampered, bundle, self.policy(), self.NOW)

    def test_legacy_verdicts_and_ledgers_require_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            rows = self.read_ledger(verdicts)
            for row in rows:
                row["verdict"].pop("bundle_sha256", None)
            legacy = Path(tmp) / "legacy-verdicts.jsonl"
            legacy.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaises(ValueError):
                court.enforce_run(corpus, legacy, self.policy(), ledger, self.NOW)
            self.assertFalse(ledger.exists())
            court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            rows = self.read_ledger(ledger)
            for row in rows:
                row.pop("bundle_sha256", None)
            ledger.write_text("".join(json.dumps(row) + "\n" for row in rows))
            before = ledger.read_bytes()
            with self.assertRaises(ValueError):
                court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            self.assertEqual(ledger.read_bytes(), before)

    def test_same_case_id_with_changed_bundle_cannot_be_silently_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, verdicts = self.shadow_in(tmp)
            corpus = Path(tmp) / "corpus"
            shutil.copytree(source, corpus)
            ledger = Path(tmp) / "ledger.jsonl"
            court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            before = ledger.read_bytes()
            path = corpus / "clear-quarantine.json"
            bundle = json.loads(path.read_text())
            bundle["evidences"][0]["age_secs"] += 1
            path.write_text(json.dumps(bundle))
            court.shadow_judge(corpus, verdicts)
            with self.assertRaisesRegex(ValueError, "case_id.*different bundle"):
                court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
            self.assertEqual(ledger.read_bytes(), before)

    def test_concurrent_processes_serialize_the_entire_ledger_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, verdicts = self.shadow_in(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            context = multiprocessing.get_context("fork")
            release = context.Event()
            results = context.Queue()
            started = [context.Event(), context.Event()]
            read = [context.Event(), context.Event()]
            processes = [context.Process(
                target=enforce_child,
                args=(corpus, verdicts, self.policy(), ledger, self.NOW,
                      started[i], read[i], release if i == 0 else None, results),
            ) for i in range(2)]
            try:
                processes[0].start()
                self.assertTrue(read[0].wait(5), "first writer did not read ledger")
                processes[1].start()
                self.assertTrue(started[1].wait(5), "second writer did not start")
                self.assertFalse(read[1].wait(0.3), "second writer read an unlocked ledger")
                release.set()
                for process in processes:
                    process.join(10)
                    self.assertEqual(process.exitcode, 0)
                summaries = [results.get(timeout=2) for _ in processes]
                self.assertTrue(all("error" not in s for s in summaries), summaries)
                self.assertEqual(sorted(s["appended"] for s in summaries), [0, 3])
                self.assertEqual(sorted(s["duplicates"] for s in summaries), [0, 3])
                records = court._read_ledger(ledger)
                self.assertEqual(len(records), 3)
                self.assertEqual(len({r["case_id"] for r in records}), 3)
                again = court.enforce_run(corpus, verdicts, self.policy(), ledger, self.NOW)
                self.assertEqual((again["appended"], again["duplicates"]), (0, 3))
                self.assertTrue(all(s["ledger_sha256"] == again["ledger_sha256"]
                                    for s in summaries))
            finally:
                release.set()
                for process in processes:
                    if process.pid is not None:
                        process.join(2)
                        if process.is_alive():
                            process.kill()
                            process.join(2)
                results.close()
                results.join_thread()

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
