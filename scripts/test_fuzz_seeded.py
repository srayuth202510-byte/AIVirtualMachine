"""Seeded fuzz: สุ่ม bundle 200 เคส judge ต้องไม่พังนอกจาก ValueError + replay ได้."""
import importlib.util
import random
import unittest
from pathlib import Path

module = importlib.util.spec_from_file_location(
    "security_court", Path(__file__).with_name("security-court.py"))
court = importlib.util.module_from_spec(module)
module.loader.exec_module(court)

SEED = 20261015
ROUNDS = 200
OUTCOMES = {"rejected-supreme-law", "insufficient-evidence", "below-quorum",
            "decided", "killed"}


def rand_id(rng, bad_chance=0.1):
    # ปน id ผิดรูปแบบบ้าง (fail-closed ต้องจับได้ ไม่ใช่ crash แบบอื่น)
    if rng.random() < bad_chance:
        return rng.choice(["", "UPPER", "has space", "x" * 50])
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
    return rng.choice("abcdef") + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))


def rand_bundle(rng, hostile):
    events = [f"e{i}" for i in range(rng.randint(1, 3))]
    case = {"id": rand_id(rng, 0.0 if not hostile else 0.1), "instance": "vm-a",
            "session": "s-1", "events": events,
            "max_evidence_age_secs": rng.choice([60, 300] if not hostile else [0, 60, 300, 99999]),
            "min_sources": rng.randint(1, 2), "quorum": rng.randint(1, 2),
            "requested_action": rng.choice(list(court.ACTIONS) * 3 + ["explode"])
            if hostile else rng.choice(list(court.ACTIONS)),
            "supreme_violation": rng.random() < 0.2}
    evidences = []
    for i in range(rng.randint(1, 4)):
        evidences.append({
            "id": f"ev-{i}-{rng.randint(0, 999999)}",
            "source": rng.choice(list(court.SOURCES) * 4 + ["ouija"])
            if hostile else rng.choice(list(court.SOURCES)),
            "origin": rng.choice(["host", "qwen", ""])
            if hostile else rng.choice(["host", "qwen"]),
            "event_ids": [rng.choice(events + ["ghost"])] if hostile else [rng.choice(events)],
            "instance": rng.choice(["vm-a"] * 4 + ["vm-b"]) if hostile else "vm-a",
            "session": rng.choice(["s-1"] * 4 + ["s-2"]) if hostile else "s-1",
            "age_secs": rng.choice([0, 10, 400, -1]) if hostile else rng.choice([0, 10]),
            "chain_ok": rng.random() < 0.8 if hostile else True})
    votes = []
    for i in range(rng.randint(1, 5)):
        votes.append({"voter": f"v-{i}-{rng.randint(0, 999999)}",
                      "origin": rng.choice(["r1", "r2", ""])
                      if hostile else rng.choice(["r1", "r2"]),
                      "verdict": rng.choice(["guilty", "not-guilty", "abstain",
                                             "timeout", "maybe"])
                      if hostile else rng.choice(["guilty", "not-guilty", "abstain"])})
    if hostile and rng.random() < 0.1 and evidences:
        # ยัด id ซ้ำบ้าง (fail-closed ต้องจับได้)
        evidences.append(dict(evidences[0]))
    return case, evidences, [], [], votes


class SeededFuzzTests(unittest.TestCase):
    def check_bundle(self, case, evidences, allegations, objections, votes):
        try:
            first = court.judge(case, evidences, allegations, objections, votes)
        except ValueError:
            return False  # input ผิด = ปฏิเสธทั้งก้อน ถูกต้องตาม fail-closed
        except Exception as exc:  # noqa: BLE001 - fuzz ต้องจับทุกอย่างที่ไม่ใช่ ValueError
            self.fail(f"non-ValueError crash: {type(exc).__name__}: {exc}")
        # verdict ที่ออกมาต้องมีรูปร่างครบ + replay ได้
        self.assertIn(first["outcome"], OUTCOMES)
        self.assertIn(first["action"], court.ACTIONS)
        self.assertEqual(first["law_version"], court.LAW_VERSION)
        second = court.judge(case, evidences, allegations, objections, votes)
        self.assertEqual(first, second)
        return True

    def test_hostile_inputs_never_crash(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            self.check_bundle(*rand_bundle(rng, hostile=True))

    def test_kind_inputs_always_decide(self):
        rng = random.Random(SEED + 1)
        decided = sum(self.check_bundle(*rand_bundle(rng, hostile=False))
                      for _ in range(ROUNDS))
        # kind ป้อนของถูกเป็นส่วนใหญ่ ต้องตัดสินได้เกือบหมด (ที่เหลือคือเคสผูกไม่ตรงโดยตั้งใจ)
        self.assertGreaterEqual(decided, ROUNDS - 20)


if __name__ == "__main__":
    unittest.main()
