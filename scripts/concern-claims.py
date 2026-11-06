"""คอนแทรกต์ข้ออ้างปิดชุด: ตรวจ facts ก่อนสร้างข้อความสรุป ไม่มี free prose ที่อ้างว่า verified."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("claims_audit", Path(__file__).with_name("qwen-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

CONTRACT = "concern-claims-v1"
TAGS = ("Concern: none", "Concern: facts to review", "Concern: missing context")
COUNT_FACT_PATHS = {
    **{key: ("counts", key) for key in (
        "records_total", "records_visible", "records_hidden_by_context_limit",
        "denied_total", "allowed_total", "other_decision_total")},
    **{key: ("policy_inputs", key) for key in (
        "window_seconds", "denials_required_same_actor", "window_denied_total",
        "max_denied_one_actor_in_window", "max_denied_one_actor_in_window_with_policy_signal",
        "denied_one_actor_hidden_from_context")},
}
CONTEXT_FACTS = ("operator_intent", "process_state", "task_contract")
FACT_IDS = (*COUNT_FACT_PATHS, "actors_total", "actor_ids_visible", *CONTEXT_FACTS)
MAX_UINT = 999999999


def fail(code, message):
    raise ValueError(code + ": " + message)


def uint(value):
    return type(value) is int and 0 <= value <= MAX_UINT


def validate(raw, role, origin, view):
    """ตรวจรูปแบบและความจริงของข้ออ้างกับ view ที่โค้ดสร้าง; ไม่รับ prose สำรอง."""
    item = audit.decode(raw)
    if not isinstance(item, dict) or set(item) != {"concern", "claims", "cited_event_ids", "missing_evidence"}:
        fail("QC-SCHEMA", "expected exactly concern, claims, cited_event_ids, missing_evidence")
    tag, claims, refs, missing = (item[key] for key in ("concern", "claims", "cited_event_ids", "missing_evidence"))
    if not isinstance(tag, str) or not tag.startswith("Concern:"):
        fail("QC-SCHEMA", "concern must start with 'Concern:'")
    if tag not in TAGS:
        fail("QC-TEXT", "free prose is not a verified claim; select a defined concern tag")
    if not isinstance(claims, list) or len(claims) > 3:
        fail("QC-SCHEMA", "claims must be a list of at most three typed claims")
    if (not isinstance(refs, list) or len(refs) > 3 or any(not uint(ref) for ref in refs)
            or len(set(refs)) != len(refs)):
        fail("QC-CITATION", "citations must be up to three unique unsigned event IDs")
    if (not isinstance(missing, list) or len(missing) > 3 or any(not isinstance(key, str) for key in missing)
            or len(set(missing)) != len(missing)):
        fail("QC-SCHEMA", "missing_evidence must be up to three unique fact IDs")
    try:
        facts = view["facts"]
        counts = {key: facts[section][field] for key, (section, field) in COUNT_FACT_PATHS.items()}
        actors_total = facts["counts"]["actors_total"]
        actors = facts["actor_ids_visible"]
        context = facts["context_availability"]
        visible = view["events_visible"]
        if (not all(uint(value) for value in (*counts.values(), actors_total))
                or not isinstance(actors, list) or any(not uint(actor) or actor == 0 for actor in actors)
                or not isinstance(visible, list) or any(not uint(ref) for ref in visible)
                or any(type(context[key]) is not bool for key in CONTEXT_FACTS)):
            raise ValueError("invalid computed fact types")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("QC-SOURCE: incomplete code-computed facts") from error
    if any(ref not in visible for ref in refs):
        fail("QC-CITATION", "citations must reference visible events, not guessed hidden IDs")
    verified, sentences, seen = [], [], set()
    for claim in claims:
        if not isinstance(claim, dict):
            fail("QC-SCHEMA", "each claim must be a typed object")
        kind = claim.get("kind")
        if kind == "actor_count" and set(claim) == {"kind", "value"} and uint(claim["value"]):
            if claim["value"] != actors_total:
                fail("QC-FACT", "actor_count differs from code-computed actors_total")
            sentence = "actor count: " + str(actors_total)
        elif kind == "actor_exists" and set(claim) == {"kind", "actor_id"} and uint(claim["actor_id"]):
            if claim["actor_id"] not in actors:
                fail("QC-ACTOR", "actor_id is not present in the visible facts")
            sentence = "observed actor: " + str(claim["actor_id"])
        elif kind == "count" and set(claim) == {"kind", "fact_id", "value"} and uint(claim["value"]):
            key = claim["fact_id"]
            if not isinstance(key, str) or key not in counts:
                fail("QC-FACT", "unknown numeric fact_id")
            if claim["value"] != counts[key]:
                fail("QC-FACT", "count differs from code-computed " + key)
            sentence = key + ": " + str(counts[key])
        else:
            fail("QC-SCHEMA", "unknown claim fields, kind, or unsigned integer type")
        encoded = json.dumps(claim, sort_keys=True)
        if encoded in seen:
            fail("QC-SCHEMA", "duplicate typed claim")
        seen.add(encoded)
        verified.append(dict(claim))
        sentences.append(sentence)
    for key in missing:
        if key not in FACT_IDS:
            fail("QC-MISSING", "unknown missing-evidence fact_id")
        # ศูนย์/ลิสต์ว่างยังเป็นข้อมูลที่ให้มาแล้ว ไม่ใช่หลักฐานที่ขาด
        if key not in CONTEXT_FACTS or context[key]:
            fail("QC-MISSING", "missing-evidence fact is already supplied: " + key)
        sentences.append("missing " + key)
    if ((tag == "Concern: missing context") != bool(missing)
            or (tag == "Concern: facts to review" and not claims)):
        fail("QC-SCHEMA", "concern tag must agree with claims and missing evidence")
    return {"advisor": role, "origin": origin, "contract": CONTRACT, "concern": tag,
            "claims": verified, "cited_event_ids": [str(ref) for ref in refs],
            "missing_evidence": list(missing),
            "verified_summary": "Concern: " + ("; ".join(sentences) if sentences else "none")}
