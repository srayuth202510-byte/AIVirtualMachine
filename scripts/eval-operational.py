#!/usr/bin/env python3
"""Operational evaluation harness — รวม replay ระดับการปฏิบัติจริงให้ทำซ้ำได้

รองรับข้อ 5 ของลำดับความสำคัญใน docs/open-weight-security-roadmap.md:
prompt injection (ผ่าน detection corpus), artifact tampering, resource exhaustion
และความไม่ตรงกันระหว่าง summary กับผลจริง แต่ละมิติใช้หลักฐานเดิมที่มีอยู่แล้ว
ทำซ้ำได้แบบ deterministic ไม่ต้องมีโมเดลจริง รายงานรวมเขียนที่ target/operational-eval/

ข้อจำกัดที่รายงานโดยตรง: corpus สังเคราะห์ห้ามนับเป็น production traffic,
detection ครอบคลุม rules+สัญญาณเดิม, resource ชุดนี้ครอบคลุมขั้น deterministic
(summary ไม่ครอบคลุม failure/recovery จริง ซึ่งต้องรัน host validation แบบ --model)
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import time

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_evidence

PROJECT = Path(__file__).resolve().parent.parent
SCHEMA = 1
DEFAULT_STAGES = "detection,tamper,summary,exhaustion"

# ชุดตัวกรองรายชื่อเทสต์แบบ deterministic (ไม่ต้อง KVM/โมเดล; microvm gates
# ปฏิเสธตั้งแต่ประตู artifact/pin จึงรันได้ทุกเครื่อง)
TAMPER_FILTERS = [
    "tampered_artifact_fails_closed_as_invalid",
    "tampered_alt_artifact_fails_closed_as_invalid",
    "wrong_fc_pin_fails_closed_as_invalid",
    "garbage_kernel_fails_closed",
    "missing_artifact_fails_closed_as_invalid",
]
SUMMARY_FILTERS = [
    "semantic_budget_and_gateway_denials_cannot_produce_verified_results",
    "semantic_refuses_model_writable_or_mismatched_operator_sources",
    "operator_verifier_builds_after_edit_and_repairs_a_failed_test_without_model_build_commands",
    "generated_tests_cannot_write_sources_create_files_or_read_private_data",
]
DETECTION_METRIC_KEYS = [
    "tp", "fp", "tn", "fn", "abstained_positive", "abstained_negative",
    "precision", "recall", "false_positive_rate", "classified_fraction",
]
STAGE_TIMEOUTS = {"detection": 300, "tamper": 900, "summary": 900, "exhaustion": 300}


def run_command(command, timeout, log_path):
    """รันคำสั่งเดียวเงียบ บันทึก log คืน exit code (124 เมื่อ timeout)"""
    start = time.monotonic()
    try:
        code = subprocess.run(command, cwd=PROJECT, stdout=log_path,
                              stderr=subprocess.STDOUT, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        code = 124
    return code, round(time.monotonic() - start, 2)


def run_stage(name, command, out, timeout):
    """รัน stage เดียว; ผิดพลาดใดก็ตามกลายเป็น failed เพียงอย่างเดียว (fail-closed, ไม่หยุดชุด)"""
    log_path = out / f"{name}.log"
    try:
        with log_path.open("w") as log:
            code, elapsed = run_command(command, timeout, log)
        content = log_path.read_text(errors="replace")
        return {
            "name": name, "command": command, "returncode": code,
            "elapsed_seconds": elapsed, "passed": code == 0,
            "summaries": re.findall(r"^test result:.*$", content, re.M),
            "tests_ok": re.findall(r"^test (\S+) \.\.\. ok$", content, re.M),
            "log": log_path.name, "log_sha256": release_evidence.digest(log_path),
        }
    except (OSError, ValueError) as error:
        return {"name": name, "command": command, "returncode": None,
                "passed": False,
                "error": f"runner failure: {error.__class__.__name__}: {error}"}


def parse_detection_report(path):
    """ยกผล detection-eval มาพร้อมเงื่อนไข: policy_regressions ว่าง + provenance ครบ"""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("provenance"), dict):
        raise ValueError("detection report provenance missing")
    if data.get("policy_regressions"):
        raise ValueError("detection report carries policy regressions")
    if not isinstance(data.get("total"), int) or data["total"] <= 0:
        raise ValueError("detection report missing case total")
    return data


def require_named_tests(stage, filters):
    """บังคับว่าทุกชื่อที่ขอถูกรันและผ่านจริงจาก log (ไม่แค่ exit 0)

    cargo อาจรันหลาย test binary ในครั้งเดียว แต่ทุก summary ต้อง ok/0 failed/0 ignored
    และชื่อที่ขอทุกตัวต้องปรากฏเป็น "test <ชื่อ> ... ok" — ชื่อพิมพ์ผิดหรือถูก
    ignored ต้องไม่กลายเป็นผ่านเงียบ
    """
    if stage.get("passed") is not True:
        return stage
    for summary in stage.get("summaries") or []:
        match = re.match(r"^test result: (?P<ok>ok|FAILED)\. (?P<n>\d+) passed; "
                         r"(?P<f>\d+) failed; (?P<i>\d+) ignored", summary)
        if not match:
            stage["passed"] = False
            stage["error"] = f"unparsable test summary: {summary}"
            return stage
        if (match.group("ok") != "ok" or match.group("f") != "0"
                or int(match.group("i")) != 0):
            stage["passed"] = False
            stage["error"] = f"test suite not green: {summary}"
            return stage
    # ชื่อใน log มักอยู่ในเส้นทาง module เต็ม (เช่น microvm::tests::<ชื่อ>)
    # จึงเทียบด้วยชื่อสุดท้ายของ path ทุกตัว
    tests_ok = {name.rsplit("::", 1)[-1] for name in (stage.get("tests_ok") or [])}
    missing = [name for name in filters if name not in tests_ok]
    if missing:
        stage["passed"] = False
        stage["error"] = f"named tests missing from log: {missing}"
    return stage


def detection_stage(out):
    """detection replay: รัน eval-detection.py แบบ rules-only (ไม่มีโมเดล)"""
    target = out / "detection.json"
    command = [sys.executable, str(PROJECT / "scripts/eval-detection.py"),
               "--output", str(target)]
    record = run_stage("detection", command, out, STAGE_TIMEOUTS["detection"])
    try:
        missing = record.get("passed") is not True
        report = parse_detection_report(target)
        metrics = report.get("rules_risk_metrics")
        if not isinstance(metrics, dict):
            raise ValueError("rules_risk_metrics missing")
        record["detection"] = {key: metrics.get(key) for key in DETECTION_METRIC_KEYS}
        record["detection_report_sha256"] = release_evidence.digest(target)
        if missing:
            record["passed"] = False
    except (OSError, ValueError, TypeError, KeyError) as error:
        record["passed"] = False
        record["error"] = f"detection evidence invalid: {error}"
    return record


def build_report(stages, started_utc):
    """ผลรวม: ผ่านเมื่อทุก stage ที่ขอรับ passed; ไม่มี = ตก (fail-closed)"""
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=PROJECT, text=True).strip()
    return {
        "schema": SCHEMA,
        "started_utc": started_utc,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "source_identity": release_evidence.source_identity(),
        "stages": stages,
        "passed": bool(stages) and all(
            stage.get("passed") is True for stage in stages),
        "limitations": [
            "synthetic detection corpus: not production traffic accuracy",
            "detection uses existing rule signals; not independent-from-rules review",
            "resource exhaustion here covers deterministic quota layers; tiered "
            "timeout/memory/recovery needs the model host validation runner",
            "summary-vs-reality covers verifier/gateway denials, not correctness "
            "of repaired code on live compilers",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stages", default=DEFAULT_STAGES,
                        help="comma list from: detection,tamper,summary,exhaustion")
    parser.add_argument("--out", type=Path, default=PROJECT / "target/operational-eval")
    args = parser.parse_args()

    valid = {"detection", "tamper", "summary", "exhaustion"}
    requested = [name.strip() for name in args.stages.split(",") if name.strip()]
    unknown = set(requested) - valid
    if not requested or unknown:
        print(f"invalid stages {requested} — valid set {sorted(valid)}",
              file=sys.stderr)
        return 2

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    # ลบ report เก่าทิ้ง กันผู้ใช้อ่านไฟล์ค้างจากรันก่อน (fail-closed)
    (out / "report.json").unlink(missing_ok=True)
    started_utc = datetime.now(timezone.utc).isoformat()

    stages = []
    if "detection" in requested:
        stage = detection_stage(out)
        stages.append(stage)
        print(f"END detection: passed={stage['passed']}", flush=True)
    if "tamper" in requested:
        # microvm feature จำเป็นเพราะชุดตัวกรองอยู่ในหน่วย microvm;
        # filter หลายชื่อต้องส่งหลัง -- มากกว่า (cargo รับ TESTNAME positional แค่ชื่อเดียว)
        command = ["cargo", "test", "-p", "aivm-sandbox", "--features", "microvm",
                   "--", *TAMPER_FILTERS]
        stage = run_stage("tamper", command, out, STAGE_TIMEOUTS["tamper"])
        stage = require_named_tests(stage, TAMPER_FILTERS)
        stages.append(stage)
        print(f"END tamper: passed={stage['passed']}", flush=True)
    if "summary" in requested:
        command = ["cargo", "test", "-p", "aivm-runtime", "--test",
                   "coding_workflow", "--", *SUMMARY_FILTERS]
        stage = run_stage("summary", command, out, STAGE_TIMEOUTS["summary"])
        stage = require_named_tests(stage, SUMMARY_FILTERS)
        stages.append(stage)
        print(f"END summary: passed={stage['passed']}", flush=True)
    if "exhaustion" in requested:
        command = [sys.executable, "-m", "unittest", "discover", "-s", "scripts",
                   "-p", "test_fuzz_seeded.py"]
        stage = run_stage("exhaustion", command, out, STAGE_TIMEOUTS["exhaustion"])
        stages.append(stage)
        print(f"END exhaustion: passed={stage['passed']}", flush=True)

    report = build_report(stages, started_utc)
    report_path = out / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"operational-eval: {'all green' if report['passed'] else 'FAILED'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"runner error: {error.__class__.__name__}: {error}", file=sys.stderr)
        sys.exit(2)
