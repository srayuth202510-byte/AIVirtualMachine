"""Local model replay: seed เดิม + prompt เดิมต้องได้ output ตรงกันทุกครั้ง."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

# โมเดลหลักของ repo (ตรงกับ docs/host-validation) หรือ AIVM_GGUF ถ้าตั้งไว้
PROJECT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = Path.home() / "Downloads" / "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
PROMPT = '{"tool":"filesystem.read","path":"src/seed.txt"}'
REPEATS = 3


def model_path():
    override = os.environ.get("AIVM_GGUF")
    candidate = Path(override) if override else DEFAULT_MODEL
    return candidate if candidate.is_file() else None


class LlamaReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model = model_path()
        if model is None:
            raise unittest.SkipTest("no GGUF model (set AIVM_GGUF) — skip honestly")
        for tool in ("cmake", "g++"):
            if shutil.which(tool) is None:
                raise unittest.SkipTest(f"no {tool} — skip honestly")
        cls.model = str(model)
        build = subprocess.run(
            ["cargo", "build", "-q", "-p", "aivm-cli", "--features", "llama"],
            cwd=PROJECT, capture_output=True, text=True, timeout=1800)
        if build.returncode != 0:
            raise unittest.SkipTest(f"llama build unavailable: {build.stderr[-300:]}")
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = Path(cls.tmp.name) / "replay.yaml"
        cfg.write_text(
            "name: replay\nruntime:\n  isolation: sandbox\nmodel:\n"
            f"  provider: local\n  name: replay\n  local:\n    model_path: {cls.model}\n"
            "    ctx_size: 512\n    threads: 4\n    seed: 42\n    temperature: 0.0\n"
            "    top_p: 0.1\n    top_k: 1\n    max_tokens: 32\n"
            "filesystem:\n  read: [./workspace]\n  write: [./workspace/src]\n"
            "network:\n  allow: []\ntools:\n  allow: [filesystem.read]\n"
            "capabilities:\n  initial: [read:workspace]\n")
        cls.cfg = str(cfg)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def infer_once(self):
        proc = subprocess.run(
            ["cargo", "run", "-q", "-p", "aivm-cli", "--features", "llama",
             "--", "reason", "--config", self.cfg, "--prompt", PROMPT],
            cwd=PROJECT, capture_output=True, text=True, timeout=600)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertTrue(proc.stdout.strip(), "empty model output")
        return proc.stdout

    def test_same_seed_same_output(self):
        first = self.infer_once()
        for _ in range(REPEATS - 1):
            self.assertEqual(self.infer_once(), first)


if __name__ == "__main__":
    unittest.main()
