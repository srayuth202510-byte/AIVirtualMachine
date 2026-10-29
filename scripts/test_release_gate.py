"""Exercise the gate against actual protected-verifier control evidence and tampering."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tempfile
import unittest
from unittest import mock
import release_evidence as evidence

SPEC = importlib.util.spec_from_file_location("release_gate", Path(__file__).with_name("release-gate.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
RUNNER_SPEC = importlib.util.spec_from_file_location("repair_runner", Path(__file__).with_name("run-repair-benchmark.py"))
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)


class SourceIdentityTests(unittest.TestCase):
    def test_interpretation_selection_uses_validated_failed_unchanged_sources(self):
        corpus = evidence.load(evidence.PROJECT / "examples/repair-benchmark.json")["cases"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = {"source_identity":{},"model_config_sha256":"a"*64,
                "cases":[{"task_success":i > 1} for i, _ in enumerate(corpus)]}
            path = root / "report.json"
            path.write_text(json.dumps(baseline))
            for i, case in enumerate(corpus):
                directory = root / case["id"]; directory.mkdir()
                (directory / "source.c").write_text(case["reference"] if i == 1 else case["buggy"].rstrip("\n"))
            with mock.patch.object(evidence, "validate_benchmark") as validate:
                _, selected = RUNNER.interpretation_cases(path)
                self.assertEqual(selected, [corpus[0]["id"]])
                validate.assert_called_once_with(path, {}, "a"*64)
            with mock.patch.object(evidence, "validate_benchmark", side_effect=ValueError("changed audit")):
                with self.assertRaisesRegex(ValueError, "changed audit"):
                    RUNNER.interpretation_cases(path)

    def test_interpretation_transcript_must_match_input_schema_and_repair_task(self):
        case = {"description":"Return zero for zero.","buggy":"int signum(int x){return x>=0?1:-1;}"}
        parsed = {"expected_behavior":"Zero returns zero.","suspected_bug":"Zero returns one.","planned_change":"Handle zero."}
        trace = {"system":"Describe the task briefly.","prompt":json.dumps({"bug_report":case["description"],"source":case["buggy"]}),
            "raw":json.dumps(parsed),"parsed":parsed,"error":None,"advisory_only":True}
        suffix = "\nYour preliminary task interpretation (untrusted model proposal; verify it against the source and test results): "
        task = "Fix the source." + suffix + json.dumps(parsed)
        evidence.validate_interpretation(trace, case, task)
        changes = [("raw", '{"done":true}'), ("prompt", '{}'), ("advisory_only", False),
            ("parsed", {**parsed,"expected_behavior":""}), ("error", "model failure"),
            ("raw", json.dumps(parsed)[:-1]+',"planned_change":"Handle zero."}')]
        for field, value in changes:
            with self.assertRaises((ValueError, TypeError), msg=field):
                evidence.validate_interpretation({**trace,field:value},case,task)
        with self.assertRaisesRegex(ValueError, "not supplied"):
            evidence.validate_interpretation(trace, case, "Fix the source.")
        evidence.validate_interpretation({**trace,"raw":None,"parsed":None,"error":"invalid output"},case,"Fix the source.")

    def test_benchmark_timeout_stops_its_child_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pid_file = root / "child.pid"
            program = ("import subprocess,sys,time;from pathlib import Path;"
                       "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
                       "Path(sys.argv[1]).write_text(str(child.pid));time.sleep(60)")
            with (root / "run.log").open("w") as log:
                code = RUNNER.run_group([sys.executable,"-c",program,str(pid_file)],dict(os.environ),log,1)
            self.assertEqual(code,124)
            pid = int(pid_file.read_text())
            for _ in range(50):
                stat = Path(f"/proc/{pid}/stat")
                try:
                    state = stat.read_text().split(")",1)[1].split()[0]
                except (FileNotFoundError, ProcessLookupError):
                    break
                if state == "Z": break
                time.sleep(0.02)
            else: self.fail("benchmark descendant still running after timeout")

    def test_identity_includes_untracked_files_and_rejects_dirty_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "source.c").write_text("original")
            subprocess.run(["git", "add", "source.c"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], cwd=root, check=True)
            original = evidence.source_identity(root)
            self.assertTrue(original["clean"])
            (root / "new.c").write_text("untracked")
            changed = evidence.source_identity(root)
            self.assertFalse(changed["clean"])
            self.assertNotEqual(original["source_sha256"], changed["source_sha256"])
            self.assertIn("new.c", changed["files"])
            with mock.patch.object(evidence, "source_identity", return_value=changed):
                with self.assertRaisesRegex(ValueError, "clean source tree"):
                    GATE.evaluate(changed["commit"], None, None, None, None, 0)

    def test_json_duplicates_and_pin_substitution_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model, worker, config = root / "model", root / "worker", root / "config.json"
            model.write_bytes(b"approved model"); worker.write_bytes(b"approved worker")
            value = {"provider":"local", "local":{"model_path":str(model),"model_sha256":evidence.digest(model),
                "worker_path":str(worker),"worker_sha256":evidence.digest(worker)}}
            config.write_text(json.dumps(value))
            evidence.candidate_config(config)
            worker.write_bytes(b"changed worker")
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                evidence.candidate_config(config)
            config.write_text('{"status":"passed","status":"failed"}')
            with self.assertRaises(ValueError): evidence.load(config)


class HostGateTests(unittest.TestCase):
    def test_exact_source_config_pins_logs_and_quality_threshold_are_all_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = {"commit":"a"*40,"clean":True,"source_sha256":"b"*64,"files":{"source.rs":"c"*64}}
            artifacts = {}
            for name in ("model","worker","kernel","rootfs","binary"):
                file = root / name; file.write_bytes(name.encode())
                artifacts[name] = {"path":str(file),"sha256":evidence.digest(file)}
            config = root / "candidate.json"
            config.write_text(json.dumps({"provider":"local","local":{"model_path":artifacts["model"]["path"],
                "model_sha256":artifacts["model"]["sha256"],"worker_path":artifacts["worker"]["path"],
                "worker_sha256":artifacts["worker"]["sha256"]}}))
            pins = root / "pins.json"; pins.write_text(json.dumps({key:artifacts[key] for key in ("kernel","rootfs","binary")}))
            names = ["build-worker","candidate-worker","protected-loader"] + [f"{prefix}-{tier}" for prefix in ("worker","failure-recovery") for tier in ("process_namespace","container","microvm")]
            rows = []
            for name in names:
                log = root / f"{name}.log"; log.write_text("test result: ok. 1 passed; 0 failed; 0 ignored;\n")
                row = {"name":name,"passed":True,"returncode":0,"exact":True,"log":log.name,"log_sha256":evidence.digest(log)}
                if name.startswith("failure-recovery"):
                    recovery = root / f"{name}.json"
                    recovery.write_text(json.dumps([{"case":case,"passed":True,"descendants_reaped":True,"staging_clean":True,
                        "observed_processes":{"123":456},"verification":"verified","stream_deltas":0,"error":"specific resource failure",
                        "elapsed_ms":10,"timeout_ms":100,"memory_mb":128,"memory_failure_kind":"allocation-failure"}
                        for case in ("timeout","recovery-after-timeout","memory","recovery-after-memory")]))
                    row.update(evidence=recovery.name,evidence_sha256=evidence.digest(recovery))
                rows.append(row)
            host = {"schema":1,"worker_build_profile":"release","built_worker_sha256":artifacts["worker"]["sha256"],"source_before":current,"source_after":current,"candidate_config_sha256":evidence.digest(config),
                "pins_sha256":evidence.digest(pins),"artifacts_before":artifacts,"artifacts_after":copy.deepcopy(artifacts),"results":rows,"passed":True}
            path = root / "host.json"; path.write_text(json.dumps(host))
            benchmark = root / "benchmark.json"; benchmark.write_text("{}")
            with mock.patch.object(evidence,"source_identity",return_value=current), mock.patch.object(evidence,"validate_benchmark",return_value={"successes":1,"total":24,"cost_per_success_ms":100}):
                self.assertTrue(GATE.evaluate(current["commit"],config,pins,path,benchmark,1)["passed"])
                with self.assertRaisesRegex(ValueError,"threshold"):
                    GATE.evaluate(current["commit"],config,pins,path,benchmark,2)
                for field, value in (("candidate_config_sha256","wrong"),("pins_sha256","wrong"),("source_after",{**current,"commit":"f"*40}),("results",rows[:-1])):
                    path.write_text(json.dumps({**host,field:value}))
                    with self.assertRaises(ValueError,msg=field): GATE.evaluate(current["commit"],config,pins,path,benchmark,1)
                path.write_text(json.dumps(host))
                (root / "candidate-worker.log").write_text("test result: ok. 0 passed; 0 failed; 1 ignored;\n")
                with self.assertRaisesRegex(ValueError,"log changed"):
                    GATE.evaluate(current["commit"],config,pins,path,benchmark,1)


class RepairEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.original = cls.root / "original"
        cls.source = evidence.source_identity()
        env = dict(os.environ, AIVM_REPAIR_BENCHMARK_OUT=str(cls.original), AIVM_SOURCE_IDENTITY=json.dumps(cls.source))
        result = subprocess.run(["cargo","test","--locked","-q","-p","aivm-runtime","--test","coding_workflow",
            "repair_benchmark::repair_corpus_baselines_and_reference_controls","--","--exact"],
            cwd=evidence.PROJECT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stdout.decode(errors="replace")[-6000:])

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def setUp(self):
        self.work = self.root / self._testMethodName
        shutil.copytree(self.original, self.work)
        self.path = self.work / "report.json"
        self.report = evidence.load(self.path)

    def validate(self):
        return evidence.validate_benchmark(self.path, self.source, None, allow_control=True)

    def test_complete_controls_are_valid_but_never_model_quality(self):
        self.assertEqual(self.validate()["successes"], 24)
        with self.assertRaises(ValueError):
            evidence.validate_benchmark(self.path, self.source, None)
        self.report["mode"] = "fresh_model"
        self.path.write_text(json.dumps(self.report))
        with self.assertRaisesRegex(ValueError,"release profile"):
            evidence.validate_benchmark(self.path,self.source,None)

    def test_interpretation_experiments_are_rejected_by_normal_release_validation(self):
        self.report.update(schema=3,mode="interpretation_experiment",build_profile="release")
        self.path.write_text(json.dumps(self.report))
        for allow_control in (False, True):
            with self.assertRaisesRegex(ValueError,"identity, mode"):
                evidence.validate_benchmark(self.path,self.source,None,allow_control=allow_control)
        for ids in ([], ["missing"], ["add", "add"]):
            with self.assertRaisesRegex(ValueError,"selection"):
                evidence.validate_benchmark(self.path,self.source,None,experiment_case_ids=ids)

    def test_canonical_outcome_task_revision_and_receipt_tampering_is_rejected(self):
        for field, value in [("task_id","another-task"),("task_revision",99),("solution_origin","model_repair"),
                             ("tested_workspace_digest","sha256:"+"0"*64),("receipt_ids",["forged"])]:
            report = copy.deepcopy(self.report)
            report["cases"][0]["outcome"][field] = value
            self.path.write_text(json.dumps(report))
            with self.assertRaises(ValueError, msg=field): self.validate()

    def test_patch_source_and_audit_changes_are_rejected(self):
        first = self.report["cases"][0]["id"]
        for filename in ("patch.diff", "source.c", "audit.jsonl"):
            path = self.work / first / filename
            original = path.read_bytes()
            path.write_bytes(original+b"changed")
            with self.assertRaises((ValueError, json.JSONDecodeError), msg=filename): self.validate()
            path.write_bytes(original)

    def test_partial_runs_false_scores_baseline_and_costs_are_rejected(self):
        mutations = []
        for field, value in (("completed",23),("task_successes",25),("cost_per_success_ms",0)):
            report = copy.deepcopy(self.report); report[field] = value; mutations.append(report)
        report = copy.deepcopy(self.report); report["cases"][0]["baseline"][3]["ok"] = True; mutations.append(report)
        report = copy.deepcopy(self.report); report["cases"][0]["task_success"] = False; mutations.append(report)
        for report in mutations:
            self.path.write_text(json.dumps(report))
            with self.assertRaises(ValueError): self.validate()


if __name__ == "__main__": unittest.main()
