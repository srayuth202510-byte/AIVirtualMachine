#!/usr/bin/env python3
"""ลอง CLI semantic ครบ create → source → MODIFY → helper → receipt → audit."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

PROJECT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    if args.binary:
        binary = args.binary.resolve(strict=True)
    else:
        subprocess.run(["cargo", "build", "--locked", "-q", "-p", "aivm-cli"], cwd=PROJECT, check=True)
        target = Path(os.environ.get("CARGO_TARGET_DIR", PROJECT / "target"))
        binary = (target / "debug/aivm").resolve(strict=True)
    cc, ld = Path("/usr/bin/cc").resolve(), Path("/usr/bin/ld").resolve()
    crt = [subprocess.check_output([str(cc), f"-print-file-name={name}"], text=True).strip()
           for name in ("crt1.o", "crti.o", "crtn.o")]
    with tempfile.TemporaryDirectory(prefix="aivm-semantic-cli-") as temporary:
        work = Path(temporary)
        root = work / "vms"
        task = work / "task.json"
        task.write_text(json.dumps({"kind": "sort", "values": [3, -2, 3, 0]}))
        config = {"name": "semantic", "runtime": {"isolation": "sandbox"},
                  "resources": {"cpu": 1, "memory": "1GB", "storage": "64MB"},
                  "build": {"enabled": True, "max_files": 4, "max_bytes": 1048576},
                  "filesystem": {"read": ["./workspace"], "write": ["./workspace/src"]},
                  "tools": {"allow": ["cc", "as", "ld", "build:tests"]},
                  "verification": {"executable": "build:tests", "argv": [], "prepare": [
                      {"executable": str(cc), "argv": ["-pipe", "-std=c11", "-c", "semantic.c", "-o", ".aivm-build/main.o"], "outputs": ["main.o"]},
                      {"executable": str(ld), "argv": ["-o", ".aivm-build/tests", "--dynamic-linker", "/lib64/ld-linux-x86-64.so.2",
                                                        crt[0], crt[1], ".aivm-build/main.o", "-lc", crt[2]], "outputs": ["tests"]}]}}
        config_path = work / "config.yaml"
        config_path.write_text(json.dumps(config))

        def run(*arguments, success=True):
            result = subprocess.run([str(binary), "--root", str(root), *arguments], cwd=PROJECT,
                                    capture_output=True, text=True, timeout=60)
            if (result.returncode == 0) != success:
                raise RuntimeError(f"{arguments}: exit {result.returncode}: {result.stderr}")
            return result

        run("create", "semantic", "--config", str(config_path))
        source = run("semantic-source", "--task", str(task)).stdout
        (root / "semantic/workspace/semantic.c").write_text(source)
        run("transition", "semantic", "ANALYZE")
        run("transition", "semantic", "MODIFY", "--confidence", "0.95")
        result = run("semantic", "semantic", "--task", str(task), "--prompt", "Sort [3,-2,3,0]. Return JSON only.", "--json")
        report = json.loads(result.stdout)
        assert report["status"] == "verified" and report["origin"] == "tool_solver"
        assert json.loads(report["output"]) == [-2, 0, 3, 3]
        assert report["verification"]["audit_id"]
        # Echo ส่ง JSON ไม่ได้ แต่ helper ยังต้องมี receipt; budget หมดต้องไม่ใช้ receipt เก่า
        failed = run("semantic", "semantic", "--task", str(task), "--prompt", "JSON", "--max-actions", "1", "--json", success=False)
        rejected = json.loads(failed.stdout)
        assert rejected["status"] == "failed" and rejected["output"] is None and rejected["verification"] is None
        # semantic mode ต้องไม่แทนที่ constraint ของ contract อื่นแบบเงียบ ๆ
        vm_config = root / "semantic/aivm.yaml"
        original = vm_config.read_text()
        vm_config.write_text(original.replace("argv: []", 'argv: ["existing-contract-argument"]', 1))
        run("semantic", "semantic", "--task", str(task), "--prompt", "JSON", "--json", success=False)
        vm_config.write_text(original)
        run("audit", "semantic")
    print("semantic CLI smoke: verified helper result, rejected exhausted budget, audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
