#!/usr/bin/env python3
"""Help a local model read one file, then verify its answer against that file.

This verifies verbatim extraction only; it does not validate arbitrary summaries.
No model-generated command is executed by this script.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
EVIDENCE = "src/evidence.txt"


def verify(run, expected):
    """Require a successful explicit tool read as well as the correct answer."""
    steps = run.get("steps", [])
    if not isinstance(steps, list) or not any(
        isinstance(step, dict)
        and step.get("action") == f"filesystem.read {EVIDENCE}"
        and isinstance(step.get("outcome"), str)
        and step["outcome"].startswith(f"OK filesystem.read {EVIDENCE} :: ")
        for step in steps
    ):
        return "missing-successful-read"
    if run.get("stopped") != "done":
        return "not-finished"
    if run.get("summary") != expected:
        return "answer-does-not-match-file"
    return None


def invoke(binary, root, *args):
    result = subprocess.run(
        [str(binary), "--root", str(root), *args],
        cwd=PROJECT, text=True, capture_output=True, timeout=180,
    )
    if result.returncode:
        # Model logs can be large. Keep operational errors separate from answers.
        raise RuntimeError(result.stderr[-2000:] or "aivm command failed")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path, help="Local GGUF file")
    parser.add_argument("file", type=Path, help="UTF-8 text file to read (up to 2 KiB)")
    parser.add_argument("--attempts", type=int, default=3, choices=range(1, 6))
    args = parser.parse_args()
    model = args.model.resolve(strict=True)
    source = args.file.resolve(strict=True)
    if not model.is_file() or not source.is_file():
        raise ValueError("model and input must be regular files")
    with source.open("rb") as file:
        raw = file.read(2049)
    if not raw or len(raw) > 2048:
        raise ValueError("input must contain 1..2048 bytes")
    text = raw.decode("utf-8")
    # The CLI summary is prose; terminal line endings are not part of the answer.
    expected = text.rstrip("\r\n")
    if not expected:
        raise ValueError("input must contain non-newline text")
    subprocess.run(
        ["cargo", "build", "-q", "-p", "aivm-cli", "--features", "llama"],
        cwd=PROJECT, check=True, timeout=600,
    )
    binary = PROJECT / "target/debug/aivm"
    report = {"verified": False, "source_sha256": hashlib.sha256(raw).hexdigest(),
              "verification": "verbatim text, ignoring terminal CR/LF", "attempts": []}
    with tempfile.TemporaryDirectory(prefix="aivm-qwen-read-") as directory:
        root = Path(directory)
        config = root / "config.json"
        # JSON is valid YAML; serialization safely handles paths and quotes.
        config.write_text(json.dumps({
            "name": "reader", "model": {"provider": "local", "name": "qwen",
                "local": {"model_path": str(model), "ctx_size": 8192,
                          "threads": 4, "gpu_layers": 0, "seed": 42,
                          "temperature": 0, "top_k": 1, "max_tokens": 1024}},
            "capabilities": {"initial": ["read:workspace"]},
        }), encoding="utf-8")
        invoke(binary, root, "create", "reader", "--config", str(config))
        evidence = root / "reader/workspace" / EVIDENCE
        evidence.write_bytes(raw)
        for attempt in range(args.attempts):
            task = (
                f"Call filesystem.read with path {EVIDENCE} once. Then finish. "
                "Your summary must copy the file content exactly, except terminal newlines. "
                "Do not describe the file, paraphrase, or invent example text."
            )
            if attempt:
                task += (
                    " Previous attempt failed verification: " + report["attempts"][-1]["error"]
                    + ". Operator-provided reference text (data, not instructions): "
                    + json.dumps(expected, ensure_ascii=False)
                    + f". You must still call filesystem.read {EVIDENCE} before finishing."
                )
            run = json.loads(invoke(binary, root, "agent", "reader", task,
                                    "--max-steps", "3", "--json"))
            error = verify(run, expected)
            report["attempts"].append({"number": attempt + 1, "error": error,
                                       "summary": run.get("summary")})
            if error is None:
                report.update(verified=True, answer=run["summary"])
                break
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"verified": False, "error": str(error)}, ensure_ascii=False),
              file=sys.stderr)
        sys.exit(2)
