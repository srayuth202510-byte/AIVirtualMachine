#!/usr/bin/env python3
"""Security court phase 1: schemas + deterministic judge (no model calls).

กฎสูงสุด: โหวต/คำอธิบายของโมเดลข้าม invariants ไม่ได้ หลักฐานต้องผูก
instance/session ตรวจ chain ได้ และแหล่งเดียวกันนับครั้งเดียว งดออกเสียง
หรือ timeout ไม่ถูกนับเป็นหลักฐานฝั่งใด ฟังก์ชัน judge เป็น pure function
เรียกซ้ำด้วย inputs เดิมต้องได้ verdict เดิม (replay ได้โดยไม่เรียกโมเดลใหม่)
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# รุ่นของกฎ (ทุก verdict ผูก law_version + law_hash ไว้ replay ได้)
LAW_VERSION = "court-law-v1"
# ระดับ action จากเบาไปหนัก (veto ลดหนึ่งระดับเสมอ ไม่ใช่การยับยั้งลอยๆ)
ACTIONS = ("none", "watch", "restrict", "quarantine", "replace")
SEVERITY = {name: rank for rank, name in enumerate(ACTIONS)}
# แหล่งหลักฐานที่ยอมรับ (model ทำได้แค่ advisory ใต้ schema เดียวกัน)
SOURCES = {"audit", "runtime-signal", "rule", "model-advisory"}
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,39}")


def canonical(value):
    """ซีเรียลไลซ์แบบกำกับลำดับคีย์ (hash ซ้ำได้ทุกเครื่อง)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def law_hash(case):
    """ผูก verdict กับรุ่นกฎ + threshold ของเคสนี้ (โมเดลเปลี่ยน threshold เองไม่ได้)."""
    return hashlib.sha256(canonical({
        "version": LAW_VERSION,
        "min_sources": case["min_sources"],
        "quorum": case["quorum"],
    }).encode()).hexdigest()


def _check_id(value, field):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"invalid {field}: {value!r}")


def validate_case(case):
    """schema ของ case (ฟิลด์เกิน/ขาด ชนิดผิด enum ผิด = ValueError ทันที)."""
    if not isinstance(case, dict) or set(case) != {
            "id", "instance", "session", "events", "max_evidence_age_secs",
            "min_sources", "quorum", "requested_action", "supreme_violation"}:
        raise ValueError("case fields must be exactly id, instance, session, events, "
                         "max_evidence_age_secs, min_sources, quorum, requested_action, "
                         "supreme_violation")
    _check_id(case["id"], "case id")
    for field in ("instance", "session"):
        if not isinstance(case[field], str) or not case[field]:
            raise ValueError(f"invalid {field}")
    if (not isinstance(case["events"], list) or not case["events"]
            or any(not isinstance(e, str) or not e for e in case["events"])):
        raise ValueError("events must be a non-empty string list")
    if (not isinstance(case["max_evidence_age_secs"], int)
            or not 0 <= case["max_evidence_age_secs"] <= 86400):
        raise ValueError("max_evidence_age_secs must be 0..86400")
    for field in ("min_sources", "quorum"):
        if not isinstance(case[field], int) or not 1 <= case[field] <= 9:
            raise ValueError(f"{field} must be 1..9")
    if case["requested_action"] not in ACTIONS:
        raise ValueError("unknown requested_action")
    if not isinstance(case["supreme_violation"], bool):
        raise ValueError("supreme_violation must be bool")
    return case


def validate_evidence(evidence):
    """schema ของหลักฐานหนึ่งชิ้น (model-advisory ใช้ schema เดียวกัน ไม่มีข้อยกเว้น)."""
    if not isinstance(evidence, dict) or set(evidence) != {
            "id", "source", "origin", "event_ids", "instance",
            "session", "age_secs", "chain_ok"}:
        raise ValueError("evidence fields must be exactly id, source, origin, event_ids, "
                         "instance, session, age_secs, chain_ok")
    _check_id(evidence["id"], "evidence id")
    if evidence["source"] not in SOURCES:
        raise ValueError("unknown evidence source")
    if not isinstance(evidence["origin"], str) or not evidence["origin"]:
        raise ValueError("invalid evidence origin")
    if (not isinstance(evidence["event_ids"], list) or not evidence["event_ids"]
            or any(not isinstance(e, str) or not e for e in evidence["event_ids"])):
        raise ValueError("event_ids must be a non-empty string list")
    if not isinstance(evidence["age_secs"], int) or evidence["age_secs"] < 0:
        raise ValueError("age_secs must be >= 0")
    if not isinstance(evidence["chain_ok"], bool):
        raise ValueError("chain_ok must be bool")
    return evidence


def validate_allegation(item):
    if not isinstance(item, dict) or set(item) != {"id", "event_ids", "requested_action"}:
        raise ValueError("allegation fields must be exactly id, event_ids, requested_action")
    _check_id(item["id"], "allegation id")
    if item["requested_action"] not in ACTIONS:
        raise ValueError("unknown requested_action")
    return item


def validate_objection(item):
    if not isinstance(item, dict) or set(item) != {"id", "kind", "ref_evidence_ids"}:
        raise ValueError("objection fields must be exactly id, kind, ref_evidence_ids")
    _check_id(item["id"], "objection id")
    if item["kind"] not in {"evidence-gap", "alternate-cause", "stale", "veto"}:
        raise ValueError("unknown objection kind")
    if (not isinstance(item["ref_evidence_ids"], list)
            or any(not isinstance(e, str) for e in item["ref_evidence_ids"])):
        raise ValueError("ref_evidence_ids must be a string list")
    return item


def validate_vote(item):
    if not isinstance(item, dict) or set(item) != {"voter", "origin", "verdict"}:
        raise ValueError("vote fields must be exactly voter, origin, verdict")
    _check_id(item["voter"], "voter")
    if not isinstance(item["origin"], str) or not item["origin"]:
        raise ValueError("invalid vote origin")
    if item["verdict"] not in {"guilty", "not-guilty", "abstain", "timeout"}:
        raise ValueError("unknown vote verdict")
    return item


def simulate_jury(specs, timeout_secs):
    """ลูกขุนจำลองระยะ 2: ช้ากว่าเส้นตายกลายเป็น timeout (ไม่นับฝั่งใด) determinism ล้วน."""
    if not isinstance(timeout_secs, int) or timeout_secs < 0:
        raise ValueError("timeout_secs must be >= 0")
    if not isinstance(specs, list) or not specs:
        raise ValueError("specs must be a non-empty list")
    votes = []
    for spec in sorted(specs, key=lambda s: (s.get("voter", ""), s.get("origin", ""))):
        if not isinstance(spec, dict) or set(spec) != {"voter", "origin", "verdict", "latency_secs"}:
            raise ValueError("juror spec fields must be exactly voter, origin, verdict, latency_secs")
        if spec["verdict"] not in {"guilty", "not-guilty", "abstain"}:
            raise ValueError("unknown juror verdict")
        if not isinstance(spec["latency_secs"], int) or spec["latency_secs"] < 0:
            raise ValueError("latency_secs must be >= 0")
        verdict = "timeout" if spec["latency_secs"] > timeout_secs else spec["verdict"]
        votes.append({"voter": spec["voter"], "origin": spec["origin"], "verdict": verdict})
    return votes


def _unique_ids(items, field):
    seen = set()
    for item in items:
        key = item["id"] if field == "id" else item[field]
        if key in seen:
            raise ValueError(f"duplicate {field}: {key!r}")
        seen.add(key)


def judge(case, evidences, allegations, objections, votes):
    """ผู้พิพากษา deterministic: inputs เดิม + กฎรุ่นเดิม = verdict เดิมเสมอ."""
    case = validate_case(dict(case))
    evidences = [validate_evidence(dict(e)) for e in evidences]
    allegations = [validate_allegation(dict(a)) for a in allegations]
    objections = [validate_objection(dict(o)) for o in objections]
    votes = [validate_vote(dict(v)) for v in votes]
    _unique_ids(evidences, "id")
    _unique_ids(allegations, "id")
    _unique_ids(objections, "id")
    known_events = set(case["events"])

    # แยกหลักฐานใช้ได้/ใช้ไม่ได้ (ของเสียไม่หายเงียบ อยู่ใน excluded พร้อมเหตุผล)
    usable, excluded = [], []
    for ev in sorted(evidences, key=lambda e: e["id"]):
        if not ev["chain_ok"]:
            excluded.append({"id": ev["id"], "reason": "chain-broken"})
        elif ev["age_secs"] > case["max_evidence_age_secs"]:
            excluded.append({"id": ev["id"], "reason": "stale"})
        elif ev["instance"] != case["instance"] or ev["session"] != case["session"]:
            excluded.append({"id": ev["id"], "reason": "wrong-binding"})
        elif any(e not in known_events for e in ev["event_ids"]):
            # โมเดลสร้าง event ID เองต้องไม่เพิ่มอำนาจในการลงมือ
            excluded.append({"id": ev["id"], "reason": "invented-event"})
        else:
            usable.append(ev)
    # แหล่งอิสระนับ (source, origin) ซ้ำครั้งเดียว (เรียกโมเดลตัวเดิมหลายรอบไม่นับซ้ำ)
    sources = sorted({(e["source"], e["origin"]) for e in usable})

    # นับโหวตต่อ (voter, origin) ซ้ำครั้งเดียว งดออกเสียง/timeout ไม่นับฝั่งใด
    guilty_keys, not_guilty, abstained, timed_out = set(), 0, 0, 0
    for v in votes:
        key = (v["voter"], v["origin"])
        if v["verdict"] == "abstain":
            abstained += 1
        elif v["verdict"] == "timeout":
            timed_out += 1
        elif v["verdict"] == "guilty":
            guilty_keys.add(key)
        else:
            not_guilty += 1
    guilty = len(guilty_keys)
    requested = case["requested_action"]
    for allegation in allegations:
        if SEVERITY[allegation["requested_action"]] > SEVERITY[requested]:
            requested = allegation["requested_action"]

    conditions = []
    # กฎสูงสุดมาก่อนเสมอ: โหวตเอกฉันท์ก็ข้ามไม่ได้
    if case["supreme_violation"]:
        conditions.append("supreme-law-conflict:rejected")
        action, outcome = "none", "rejected-supreme-law"
    elif len(sources) < case["min_sources"]:
        conditions.append(f"independent-sources:{len(sources)}<min:{case['min_sources']}")
        action, outcome = "none", "insufficient-evidence"
    elif guilty == 0:
        conditions.append("guilty-votes:0")
        action, outcome = "none", "insufficient-evidence"
    elif guilty < case["quorum"]:
        conditions.append(f"guilty-votes:{guilty}<quorum:{case['quorum']}")
        action, outcome = "watch", "below-quorum"
    else:
        conditions.append(f"guilty-votes:{guilty}>=quorum:{case['quorum']}")
        conditions.append(f"independent-sources:{len(sources)}>=min:{case['min_sources']}")
        action, outcome = requested, "decided"
        vetoes = [o for o in objections if o["kind"] == "veto"]
        if vetoes and SEVERITY[action] > 0:
            # veto ลดความแรงหนึ่งระดับ (ไม่ใช่การยับยั้งลอยๆ ตรวจซ้ำได้)
            action = ACTIONS[SEVERITY[action] - 1]
            conditions.append(f"veto:{len(vetoes)}:downgraded-to:{action}")
        if not_guilty >= guilty and SEVERITY[action] > SEVERITY["watch"]:
            # คะแนนเท่ากัน (contested) ลดหนึ่งระดับ แยกเสี่ยงพอเฝ้าดูจากยืนยันว่าถูกยึด
            action = ACTIONS[SEVERITY[action] - 1]
            conditions.append(f"contested-tie:{guilty}v{not_guilty}:downgraded-to:{action}")

    return {
        "case_id": case["id"],
        "law_version": LAW_VERSION,
        "law_hash": law_hash(case),
        "outcome": outcome,
        "action": action,
        "conditions": conditions,
        "evidence_used": sorted(e["id"] for e in usable),
        "evidence_excluded": excluded,
        "independent_sources": len(sources),
        "votes": {"guilty": guilty, "not_guilty": not_guilty,
                  "abstained": abstained, "timed_out": timed_out},
    }


# ระยะ 3: รับความเห็นโมเดลเป็น advisory เท่านั้น (ไม่ส่งคำสั่งจากข้อความโมเดลเข้า runtime)
# - schema เข้มเหมือนเดิม ฟิลด์เกิน/ชนิดผิด/อ้าง event นอกเคส = ทิ้งทั้งชิ้น (ValueError)
# - reason ที่มีลักษณะคำสั่ง (code fence หรือบรรทัดสั่งการ) = ทิ้งทั้งชิ้น
_COMMAND_RE = re.compile(r"(?m)^\s*(run|exec|allow|deny|quarantine|replace|approve)\b")


def validate_advisory(item, known_events):
    """schema ของความเห็นโมเดลหนึ่งชิ้น (advisory ไม่มีสิทธิ์เพิ่ม permissions)."""
    if not isinstance(item, dict) or set(item) != {
            "advisor", "origin", "verdict", "reason", "cited_event_ids"}:
        raise ValueError("advisory fields must be exactly advisor, origin, verdict, "
                         "reason, cited_event_ids")
    _check_id(item["advisor"], "advisor")
    if not isinstance(item["origin"], str) or not item["origin"]:
        raise ValueError("invalid advisory origin")
    if item["verdict"] not in {"guilty", "not-guilty", "abstain"}:
        raise ValueError("unknown advisory verdict")
    if not isinstance(item["reason"], str) or not item["reason"] or len(item["reason"]) > 2000:
        raise ValueError("reason must be 1..2000 chars")
    if "```" in item["reason"] or _COMMAND_RE.search(item["reason"]):
        # ข้อความโมเดลห้ามมีคำสั่ง/โค้ดที่อาจถูกส่งต่อเข้า runtime
        raise ValueError("advisory reason must not contain commands or code fences")
    if (not isinstance(item["cited_event_ids"], list) or not item["cited_event_ids"]
            or any(not isinstance(e, str) for e in item["cited_event_ids"])):
        raise ValueError("cited_event_ids must be a non-empty string list")
    if any(e not in known_events for e in item["cited_event_ids"]):
        # อ้าง event นอกเคส = หลักฐานเท็จ ไม่นับและไม่ส่งต่อ
        raise ValueError("advisory cites events outside the case")
    return item


def advisory_to_votes(advisories, known_events):
    """แปลง advisories เป็น votes (ที่ปรึกษาซ้ำนับครั้งเดียว แหล่งร่วมต้องระบุ)."""
    if not isinstance(advisories, list):
        raise ValueError("advisories must be a list")
    votes, seen = [], set()
    for advisory in advisories:
        item = validate_advisory(dict(advisory), set(known_events))
        key = (item["advisor"], item["origin"])
        if key in seen:
            raise ValueError(f"duplicate advisory source: {key!r}")
        seen.add(key)
        votes.append({"voter": item["advisor"], "origin": item["origin"],
                      "verdict": item["verdict"]})
    return votes


# ระยะ 4: shadow evaluation (บันทึกคำตัดสินโดยไม่เปลี่ยน runtime เปรียบเทียบ baseline)
def shadow_judge(corpus_dir, out_path):
    """รัน judge ทุก bundle ใน corpus เขียน verdicts JSONL + สรุป (deterministic)."""
    corpus = Path(corpus_dir)
    bundles = sorted(corpus.glob("*.json"))
    if not bundles or (len(bundles) == 1 and bundles[0].name == "labels.json"):
        raise ValueError("corpus has no bundles")
    labels = {}
    labels_path = corpus / "labels.json"
    if labels_path.exists():
        labels = json.loads(labels_path.read_bytes().decode())
    lines, counts, mismatches = [], {}, []
    for bundle_path in bundles:
        if bundle_path.name == "labels.json":
            continue
        bundle = read_bundle(bundle_path)
        verdict = judge(bundle["case"], bundle["evidences"], bundle["allegations"],
                        bundle["objections"], bundle["votes"])
        lines.append(canonical({"bundle": bundle_path.name, "verdict": verdict}))
        counts[verdict["outcome"]] = counts.get(verdict["outcome"], 0) + 1
        expected = labels.get(bundle_path.name)
        if expected is not None and [verdict["outcome"], verdict["action"]] != expected:
            mismatches.append({"bundle": bundle_path.name, "expected": expected,
                               "got": [verdict["outcome"], verdict["action"]]})
    Path(out_path).write_text("\n".join(lines) + "\n")
    return {"bundles": len(lines), "counts": counts, "mismatches": mismatches,
            "law_version": LAW_VERSION}


def diff_runs(old_path, new_path):
    """เทียบ verdicts สองรัน (replay/เปลี่ยนกฎต้องอธิบายทุกเคสที่คำตัดสินเปลี่ยน)."""
    def load(path):
        rows = {}
        for line in Path(path).read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                rows[row["bundle"]] = [row["verdict"]["outcome"], row["verdict"]["action"]]
        return rows
    old, new = load(old_path), load(new_path)
    changed = [{"bundle": name, "old": old[name], "new": new[name]}
               for name in sorted(set(old) & set(new)) if old[name] != new[name]]
    only_old = sorted(set(old) - set(new))
    only_new = sorted(set(new) - set(old))
    return {"changed": changed, "only_old": only_old, "only_new": only_new}


# ระยะ 5: ทบทวนก่อนเชื่อม enforcement (policy gate + kill switch + cap)
def validate_policy(policy):
    """schema ของ deployment policy (kill switch, เพดาน action, budget)."""
    if not isinstance(policy, dict) or set(policy) != {
            "law_version", "max_action", "kill_switch", "budget_cases"}:
        raise ValueError("policy fields must be exactly law_version, max_action, "
                         "kill_switch, budget_cases")
    if policy["law_version"] != LAW_VERSION:
        raise ValueError("policy law_version mismatch (fail-closed)")
    if policy["max_action"] not in ACTIONS:
        raise ValueError("unknown max_action")
    if not isinstance(policy["kill_switch"], bool):
        raise ValueError("kill_switch must be bool")
    if not isinstance(policy["budget_cases"], int) or policy["budget_cases"] < 0:
        raise ValueError("budget_cases must be >= 0")
    return policy


def apply_policy(verdict, policy):
    """ครอบ verdict ด้วย policy: kill switch หยุดทุก action เพดานกด action ลง."""
    policy = validate_policy(dict(policy))
    if verdict.get("law_version") != LAW_VERSION:
        raise ValueError("verdict law_version mismatch (fail-closed)")
    result = dict(verdict)
    result["conditions"] = list(verdict.get("conditions", []))
    if policy["kill_switch"]:
        result["conditions"].append("policy:kill-switch:on")
        result.update(action="none", outcome="killed")
        return result
    if SEVERITY[verdict["action"]] > SEVERITY[policy["max_action"]]:
        result["conditions"].append(f"policy-cap:{verdict['action']}->{policy['max_action']}")
        result["action"] = policy["max_action"]
    return result


def review_verdicts(verdicts_path, policy):
    """ทบทวนไฟล์ verdicts: law ตรงรุ่นทุกแถว สรุป outcome/abstain/timeout (ไม่คืนสิทธิ์เอง)."""
    policy = validate_policy(dict(policy))
    outcomes, abstained, timed_out, checked = {}, 0, 0, 0
    for line in Path(verdicts_path).read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        verdict = apply_policy(row["verdict"], policy)
        outcomes[verdict["outcome"]] = outcomes.get(verdict["outcome"], 0) + 1
        abstained += verdict["votes"].get("abstained", 0)
        timed_out += verdict["votes"].get("timed_out", 0)
        checked += 1
        if checked > policy["budget_cases"]:
            raise ValueError("review budget exceeded")
    return {"cases": checked, "outcomes": outcomes,
            "abstained_votes": abstained, "timed_out_votes": timed_out,
            "policy": {"max_action": policy["max_action"],
                       "kill_switch": policy["kill_switch"]}}


def decision_table():
    """ตารางตัดสิน (ตรวจทานได้ ไม่ให้โมเดลเปลี่ยน threshold ระหว่างพิจารณา)."""
    return [
        {"when": "requested action conflicts supreme law", "outcome": "rejected-supreme-law",
         "action": "none", "note": "unanimous votes cannot override"},
        {"when": "independent sources < min_sources", "outcome": "insufficient-evidence",
         "action": "none", "note": "shared source counted once; stale/chain-broken/wrong-binding/invented excluded"},
        {"when": "guilty votes == 0", "outcome": "insufficient-evidence",
         "action": "none", "note": "abstention and timeout count for neither side"},
        {"when": "guilty votes < quorum", "outcome": "below-quorum",
         "action": "watch", "note": "suspicious enough to watch, not to contain"},
        {"when": "quorum met, no veto", "outcome": "decided",
         "action": "<requested>", "note": "capped at requested_action severity"},
        {"when": "quorum met, veto present", "outcome": "decided",
         "action": "<requested downgraded one level>", "note": "veto downgrades, never silently drops"},
        {"when": "quorum met but not-guilty >= guilty", "outcome": "decided",
         "action": "<requested downgraded one level, floor watch>", "note": "contested tie is not confirmation"},
        {"when": "juror exceeds timeout", "outcome": "(per table)",
         "action": "(vote recorded as timeout)", "note": "timeout counts for neither side"},
        {"when": "model advisory cites outside events/commands", "outcome": "(rejected)",
         "action": "(advisory dropped)", "note": "advisory never adds permissions"},
        {"when": "policy kill_switch on", "outcome": "killed",
         "action": "none", "note": "review only; never auto-restores quarantine"},
        {"when": "verdict action exceeds policy max_action", "outcome": "(kept)",
         "action": "<capped at max_action>", "note": "policy-cap recorded in conditions"},
    ]


def read_bundle(path):
    """อ่าน bundle 1 เคส (เกิน 1 MiB ปฏิเสธก่อน parse กัน resource abuse)."""
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("bundle exceeds 1 MiB")
    bundle = json.loads(raw.decode())
    if not isinstance(bundle, dict) or set(bundle) != {
            "case", "evidences", "allegations", "objections", "votes"}:
        raise ValueError("bundle fields must be exactly case, evidences, allegations, "
                         "objections, votes")
    return bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description="security court phase 1 (deterministic)")
    sub = parser.add_subparsers(dest="command", required=True)
    judge_cmd = sub.add_parser("judge", help="ตัดสิน bundle หนึ่งเคสแล้วพิมพ์ verdict JSON")
    judge_cmd.add_argument("bundle")
    sub.add_parser("decision-table", help="พิมพ์ตารางตัดสินที่ตรวจทานแล้ว")
    shadow_cmd = sub.add_parser("shadow", help="รันทุก bundle ใน corpus โดยไม่เปลี่ยน runtime")
    shadow_cmd.add_argument("corpus_dir")
    shadow_cmd.add_argument("out_jsonl")
    review_cmd = sub.add_parser("review", help="ทบทวน verdicts ภายใต้ policy (ไม่คืนสิทธิ์เอง)")
    review_cmd.add_argument("verdicts_jsonl")
    review_cmd.add_argument("policy_json")
    args = parser.parse_args(argv)
    if args.command == "decision-table":
        print(json.dumps(decision_table(), indent=2))
        return
    if args.command == "shadow":
        print(json.dumps(shadow_judge(args.corpus_dir, args.out_jsonl), indent=2, sort_keys=True))
        return
    if args.command == "review":
        policy = json.loads(Path(args.policy_json).read_bytes().decode())
        print(json.dumps(review_verdicts(args.verdicts_jsonl, policy), indent=2, sort_keys=True))
        return
    bundle = read_bundle(args.bundle)
    print(json.dumps(judge(bundle["case"], bundle["evidences"], bundle["allegations"],
                           bundle["objections"], bundle["votes"]), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
