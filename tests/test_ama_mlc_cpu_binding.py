"""Content binding tests only; synthetic bytes are never native experiment data."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm/native_runtime.py"
spec = importlib.util.spec_from_file_location("mlc_cpu_binding_tests", SOURCE)
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class CPUProofBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mlc-proof-unit-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic-proof-input"
        self.path.write_bytes(b"not model data")
        self.descriptor = {"path": str(self.path), "bytes": self.path.stat().st_size,
                           "sha256": R.sha256(self.path)}

    def test_nested_artifact_is_bound(self):
        self.assertEqual(R.proof_files({"proofs": [{"nested": self.descriptor}]}), {self.path})

    def test_changed_artifact_is_rejected(self):
        self.path.write_bytes(b"different data")
        with self.assertRaises(ValueError):
            R.proof_files({"proofs": [self.descriptor]})

    def test_wrong_declared_size_is_rejected(self):
        self.descriptor["bytes"] += 1
        with self.assertRaises(ValueError):
            R.proof_files(self.descriptor)
