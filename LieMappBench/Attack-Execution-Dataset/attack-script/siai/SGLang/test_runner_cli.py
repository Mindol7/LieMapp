"""Read-only CLI validation; no native model or experiment is executed."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("run.py")
ROOT = next(p for p in SCRIPT.resolve().parents if (p / "LieMappBench").is_dir())
ORIGINAL_SHA256 = "3564b8a17cb584778f6e094af6def5bd18fbbb5d771e553e432528197632ffd9"


class RunnerCliTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--run-id", "unit-test-never-created", *args],
                              capture_output=True, text=True, timeout=20)

    def test_custom_seed_rejected_before_dataset_io(self):
        result = self.invoke("--seed", "123", "--dataset", "/missing-test-input.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice: 123", result.stderr)
        self.assertNotIn("FileNotFoundError", result.stderr)

    def test_custom_seed_rejected_in_child_cli_too(self):
        result = self.invoke("--seed", "0", "--child-cases", "/missing-test-input.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice: 0", result.stderr)
        self.assertNotIn("ModuleNotFoundError", result.stderr)

    def check_accepted_seed_reaches_read_only_dataset_validation(self, *args):
        with tempfile.TemporaryDirectory(prefix="liemapp-seed-unit-") as temporary:
            missing = str(Path(temporary) / "missing.json")
            result = self.invoke(*args, "--dataset", missing)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FileNotFoundError", result.stderr)
        self.assertNotIn("invalid choice", result.stderr)

    def test_default_seed_accepted(self):
        self.check_accepted_seed_reaches_read_only_dataset_validation()

    def test_explicit_fixed_seed_accepted(self):
        self.check_accepted_seed_reaches_read_only_dataset_validation("--seed", "20260906")

    def test_original_snapshot_preserved_and_only_guard_and_output_layout_changed(self):
        snapshot = ROOT / "LieMappBench/Logging-Dataset/siai/SGLang/source-snapshots" / (ORIGINAL_SHA256 + "-run.py")
        original = snapshot.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), ORIGINAL_SHA256)
        expected = original.replace(b"parser.add_argument('--seed',type=int,default=20260906)",
                                    b"parser.add_argument('--seed',type=int,default=20260906,choices=[20260906])")
        expected = expected.replace(b"directory=ROOT/'LieMappAnalyzer/LogFile/siai/SGLang'/args.run_id",
                                    b"directory=ROOT/'.evidence/raw/siai/SGLang'/args.run_id")
        self.assertNotEqual(expected, original)
        self.assertEqual(SCRIPT.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
