"""ตรวจว่ารายงานปลอม คะแนนผิด และ audit ที่ถูกแก้ไม่ผ่าน validator"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("semantic", Path(__file__).with_name("eval-semantic-quality.py"))
SEMANTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEMANTIC)


class SemanticEvidenceTests(unittest.TestCase):
    def test_schema_and_semantic_failures_are_separate(self):
        task = {"kind": "sort", "values": [3, -2, 3, 0]}
        self.assertTrue(SEMANTIC.schema_valid(task, "[0,-2,3,3]"))
        self.assertFalse(SEMANTIC.task_correct(task, "[0,-2,3,3]"))
        for output in ("[false,-2,3,3]", "[0.0,-2,3,3]", '["0",-2,3,3]', "[" + ",".join(["0"] * 65) + "]"):
            self.assertFalse(SEMANTIC.schema_valid(task, output))
        add = {"kind": "c_add", "left": -8, "right": 3}
        self.assertTrue(SEMANTIC.schema_valid(add, "11"))
        self.assertFalse(SEMANTIC.task_correct(add, "11"))
        self.assertTrue(SEMANTIC.task_correct(add, "-5"))
        for output in ("false", '"-5"', "NaN", "-5.0", "-5 -5"):
            self.assertFalse(SEMANTIC.schema_valid(add, output))

    def test_evidence_rejects_changed_scores_identity_receipts_and_audit(self):
        corpus = json.loads(SEMANTIC.CORPUS.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = []
            for case in corpus["cases"]:
                receipt = {"status": "verified", "exit_code": 0, "contract_sha256": "a" * 64,
                           "executable_sha256": "b" * 64, "workspace_sha256": "c" * 64,
                           "reason": "verified", "audit_id": ""}
                audit_rows = []
                def append(action, value, rule=""):
                    audit = dict.fromkeys(SEMANTIC.AUDIT_FIELDS, "")
                    audit.update(hash_version=2, seq=len(audit_rows), timestamp=1, action=action,
                        resource=case["id"], rule_matched=rule, decision="allow",
                        hash_prev=audit_rows[-1]["hash_entry"] if audit_rows else "",
                        result=json.dumps(value, separators=(",", ":")))
                    canonical = json.dumps([audit[key] for key in SEMANTIC.AUDIT_FIELDS], separators=(",", ":"))
                    audit["hash_entry"] = hashlib.sha256(canonical.encode()).hexdigest()
                    audit_rows.append(audit)
                    return audit["hash_entry"]
                task_contract = {"schema":1, "task_id":case["id"], "revision":1, "task_digest":"sha256:"+"d"*64,
                                 "base_workspace_digest":"sha256:"+"c"*64, "audit_id":""}
                task_contract["audit_id"] = append("task", task_contract, "task-start")
                receipt["audit_id"] = append("verification", receipt)
                outcome = {"schema":1,"task_id":case["id"],"task_revision":1,"execution":"completed",
                    "verification":"passed","solution_origin":"tool_solver","tested_workspace_digest":"sha256:"+"c"*64,
                    "current_workspace_digest":"sha256:"+"c"*64,"receipt_ids":[receipt["audit_id"]],"reason":"verified","audit_id":""}
                outcome["audit_id"] = append("task", outcome, "task-outcome")
                audit_file = root / f'{case["id"]}.audit.jsonl'
                audit_file.write_text("".join(json.dumps(audit)+"\n" for audit in audit_rows))
                attempt = {"prompt": case["prompt"], "output": case["initial_candidate"],
                           "format_valid": True, "schema_valid": True, "task_correct": False,
                           "infrastructure_status": "completed", "termination": "completed"}
                rows.append({"id": case["id"], "task": case["task"], "prompt": case["prompt"],
                             "candidate_origin": case["candidate_origin"], "first_correct": False,
                             "assisted_correct": True, "audit_file": audit_file.name,
                             "audit_sha256": SEMANTIC.digest(audit_file),
                             "run": {"task": case["task"], "attempts": [attempt], "output": json.dumps(case["expected"]),
                                     "origin": "tool_solver", "status": "verified", "termination": "verified",
                                     "task_contract":task_contract, "outcome":outcome,
                                     "verification": receipt,
                                     "actions": [{"phase": phase, "ok": True, "verification": receipt}
                                                 for phase in ("tool_solver", "semantic_verifier")]}})
            report = {"schema": 1, "mode": "replay", "model_config_sha256": None,
                      "corpus_sha256": SEMANTIC.digest(SEMANTIC.CORPUS), "completed": len(rows),
                      "total": len(rows), "first_correct": 0, "assisted_correct": len(rows), "cases": rows}
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps(report))
            self.assertTrue(SEMANTIC.validate_report(evidence, "replay"))
            mutations = []
            for field, value in (("first_correct", 8), ("first_correct", False), ("corpus_sha256", "stale"),
                                 ("mode", "fresh_model"), ("completed", 1)):
                mutations.append({**report, field: value})
            for field, value in (("id", "wrong"), ("prompt", "changed"), ("first_correct", True),
                                 ("candidate_origin", "fresh_model"), ("audit_file", "../audit.jsonl")):
                changed = copy.deepcopy(report)
                changed["cases"][0][field] = value
                mutations.append(changed)
            for field, value in (("output", "[0,-2,3,3]"), ("status", "failed"), ("origin", "model_with_verifier")):
                changed = copy.deepcopy(report)
                changed["cases"][0]["run"][field] = value
                mutations.append(changed)
            changed = copy.deepcopy(report)
            changed["cases"][0]["run"]["verification"]["exit_code"] = False
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed["cases"][0]["run"]["verification"]["audit_id"] = "f" * 64
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed["cases"][0]["run"]["attempts"][0]["schema_valid"] = False
            mutations.append(changed)
            for changed in mutations:
                evidence.write_text(json.dumps(changed))
                self.assertFalse(SEMANTIC.validate_report(evidence, "replay"))
            evidence.write_text(json.dumps(report))
            audit_file = root / rows[0]["audit_file"]
            audit_file.write_text(audit_file.read_text().replace('"decision": "allow"', '"decision": "deny"'))
            self.assertFalse(SEMANTIC.validate_report(evidence, "replay"))
