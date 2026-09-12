"""Offline contract tests for the new public adapter; no inference/network."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/llamacpp"
SPEC = importlib.util.spec_from_file_location("llama_public_contract_runner", HERE / "run_public.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
NATIVE = RUN.load(HERE / "native_public_runtime.py", "llama_public_contract_native")
PROTOCOL = RUN.load(RUN.SHARED, "llama_public_contract_protocol")
MAPPING = RUN.load(ROOT / "LieMappBench/Logging-Dataset/ama/llamacpp/public-http-v1/freeze_mapping.py", "llama_public_mapping_contract")


class PublicAdapterTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"seed": 20260911, "temperature": 0.2, "max_tokens": 192}
        self.settings = {"seed": 20260911, "temperature": 0.20000000298023224,
                         "top_p": 1.0, "top_k": 0, "min_p": 0.0,
                         "repeat_penalty": 1.0, "presence_penalty": 0.0,
                         "frequency_penalty": 0.0, "dynatemp_range": 0.0,
                         "mirostat": 0, "max_tokens": 192, "samplers": ["temperature"]}
        self.response = {"__verbose": {"content": "synthetic", "generation_settings": self.settings,
                                        "truncated": False},
                         "usage": {"prompt_tokens_details": {"cached_tokens": 0}}}

    def test_shared_dataset_and_fixed_plan(self):
        self.assertEqual(RUN.SOURCE, ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/SGLang/public-http-v1")
        dataset = PROTOCOL.strict_json((RUN.SOURCE / "fixtures.json").read_text())
        PROTOCOL.validate_dataset(dataset)
        jobs = PROTOCOL.schedule(dataset, RUN.parse_args([]))
        self.assertEqual(len(jobs), 128)

    def test_effective_sampling_checks_float32_rounding(self):
        NATIVE.checked_generation(self.response, self.payload)

    def test_effective_sampling_rejects_wrong_filter(self):
        self.settings["min_p"] = 0.05
        with self.assertRaises(ValueError):
            NATIVE.checked_generation(self.response, self.payload)

    def test_effective_sampling_rejects_wrong_seed(self):
        self.settings["seed"] += 1
        with self.assertRaises(ValueError):
            NATIVE.checked_generation(self.response, self.payload)

    def test_cached_prompt_rejected(self):
        self.response["usage"]["prompt_tokens_details"]["cached_tokens"] = 1
        with self.assertRaises(ValueError):
            NATIVE.checked_generation(self.response, self.payload)

    def test_truncated_prompt_rejected(self):
        self.response["__verbose"]["truncated"] = True
        with self.assertRaises(ValueError):
            NATIVE.checked_generation(self.response, self.payload)

    def test_missing_native_diagnostics_rejected(self):
        with self.assertRaises(ValueError):
            NATIVE.checked_generation({}, self.payload)

    def test_native_defaults_do_not_repurpose_legacy_files(self):
        self.assertEqual(NATIVE.MANIFEST, ROOT / "LieMappBench/Logging-Dataset/ama/llamacpp/public-http-v1/native-build-manifest.json")
        self.assertEqual(NATIVE.BINARY, ROOT / "Instrumented-LIE/ama/llamacpp/build-liemapp/bin/llama-server")


class PublicMappingTests(unittest.TestCase):
    def _reviews(self, key):
        source = HERE / "model-public.json"
        original = {"path": str(source.relative_to(ROOT)), "sha256": RUN.digest(source),
                    "finding": "Test fixture: metadata is not a runtime event"}
        mapping = {key: [original]}
        with tempfile.TemporaryDirectory(prefix="llama-public-map-test-") as directory:
            output = Path(directory)
            results = MAPPING.preserved_supporting_sources(mapping, output)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertNotIn("source_snapshot", original)
            self.assertFalse(Path(result["source_snapshot"]).is_absolute())
            stored = output / result["source_snapshot"]
            self.assertTrue(stored.is_file())
            self.assertEqual(stored.read_bytes(), source.read_bytes())
            self.assertEqual(RUN.digest(stored), result["sha256"])
            self.assertEqual(result["evidence_kind"], "static_review_of_uninstrumented_supporting_source_not_an_observed_logging_point")

    def test_legacy_reviewed_uninstrumented_schema_supported(self):
        self._reviews("reviewed_uninstrumented_supporting_sites")

    def test_normalized_schema_retains_self_contained_snapshots(self):
        self._reviews("supporting_sources")

    def test_missing_supporting_review_rejected(self):
        with tempfile.TemporaryDirectory(prefix="llama-public-map-test-") as directory:
            with self.assertRaisesRegex(ValueError, "supporting-source"):
                MAPPING.preserved_supporting_sources({}, Path(directory))

    def test_changed_source_hash_rejected(self):
        source = HERE / "model-public.json"
        mapping = {"reviewed_uninstrumented_supporting_sites": [
            {"path": str(source.relative_to(ROOT)), "sha256": "0" * 64}]}
        with tempfile.TemporaryDirectory(prefix="llama-public-map-test-") as directory:
            with self.assertRaisesRegex(ValueError, "Exact source bytes unavailable"):
                MAPPING.preserved_supporting_sources(mapping, Path(directory))

    def test_completed_development_preview_has_self_contained_references(self):
        run = ROOT / ".evidence/raw/ama/llamacpp/ama-llamacpp-public-development-20260911-001"
        if not (run / "seal.json").is_file():
            self.skipTest("Preserved development evidence unavailable")
        legacy = ROOT / "LieMappBench/Logging-Dataset/ama/llamacpp/logging-points.json"
        before = RUN.digest(legacy)
        with tempfile.TemporaryDirectory(prefix="llama-map-preview-test-", dir=ROOT / ".evidence/audits") as directory:
            output = Path(directory)
            subprocess.run([sys.executable, "-B", str(MAPPING.__file__), "--run-dir", str(run),
                            "--output-dir", str(output)], cwd=ROOT, check=True, capture_output=True, text=True)
            result = PROTOCOL.strict_json((output / "logging-points.json").read_text())
            self.assertNotIn("runtime_evidence", result)
            self.assertNotIn("reviewed_uninstrumented_supporting_sites", result)
            self.assertEqual(len(result["supporting_sources"]), 3)
            self.assertEqual(result["source_run"]["run_id"], run.name)
            self.assertEqual(result["observed_counts"]["completed_requests"], 4)
            references = []

            def inspect_references(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key in {"source_snapshot", "snapshot", "utility_snapshot", "native_patch_snapshot"} and isinstance(item, str):
                            self.assertFalse(Path(item).is_absolute())
                            self.assertTrue((output / item).is_file(), item)
                            references.append(item)
                        inspect_references(item)
                elif isinstance(value, list):
                    for item in value:
                        inspect_references(item)

            inspect_references(result)
            self.assertGreater(len(references), 30)
            for item in result["supporting_sources"] + result["code_dependency_snapshots"]:
                self.assertEqual(RUN.digest(output / item["source_snapshot"]), item["sha256"])
            for item in result["logging_points"]:
                self.assertEqual(RUN.digest(output / item["source_snapshot"]), item["source"]["sha256"])
        self.assertEqual(RUN.digest(legacy), before)


if __name__ == "__main__":
    unittest.main()
