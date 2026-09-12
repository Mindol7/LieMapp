"""Transport adaptations and observation-only MLC hooks without model calls."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


service = module("ama_mlc_service_tests", ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm/service.py")
observer = module("ama_mlc_observer_tests", ROOT / "Instrumented-LIE/ama/mlc-llm/engine/python/mlc_llm/liemapp_ama.py")
runtime = module("ama_mlc_runtime_tests", ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm/native_runtime.py")


class MLCNativeTransportTests(unittest.TestCase):
    def payload(self):
        return {"model": "local-ama-model", "messages": [{"role": "user", "content": "example"}],
                "tools": [{"type": "function", "function": {"name": "example", "description": "desc",
                           "parameters": {"type": "object", "properties": {}}}}],
                "tool_choice": "auto", "stream": False, "temperature": 0.2, "top_p": 1.0,
                "max_tokens": 192, "seed": 20260911, "liemapp_request_id": "test-id",
                "liemapp_context": {"variant": "neutral"}, "parallel_tool_calls": False}

    def test_auto_preserves_native_inputs(self):
        original = self.payload()
        effective, changes = service.adapt_request(original)
        for key in ("messages", "tools", "tool_choice", "temperature", "top_p", "max_tokens", "seed"):
            self.assertEqual(effective[key], original[key])
        self.assertNotIn("liemapp_context", effective)
        self.assertNotIn("parallel_tool_calls", effective)
        self.assertEqual(effective["request_id"], "test-id")
        self.assertEqual(changes[0]["field"], "parallel_tool_calls")

    def test_fixed_control_is_explicit_named_choice(self):
        original = self.payload()
        original["tool_choice"] = "required"
        effective, changes = service.adapt_request(original)
        self.assertEqual(effective["tool_choice"], {"type": "function", "function": {"name": "example"}})
        self.assertEqual(original["tool_choice"], "required")
        self.assertEqual(changes[0]["submitted"], "required")

    def test_no_arbitrary_required_translation(self):
        original = self.payload()
        original["tool_choice"] = "required"
        original["tools"] *= 2
        with self.assertRaises(ValueError):
            service.adapt_request(original)

    def test_unsupported_sampling_not_silently_dropped(self):
        original = self.payload()
        original["top_k"] = 10
        with self.assertRaises(ValueError):
            service.adapt_request(original)

    def test_parallel_and_stream_rejected(self):
        for key in ("parallel_tool_calls", "stream"):
            original = self.payload()
            original[key] = True
            with self.assertRaises(ValueError):
                service.adapt_request(original)

    def test_strict_json_rejects_duplicates_nonfinite(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                service.strict_json(value)

    def test_observer_off_has_no_capture_or_transport(self):
        original = self.payload()
        effective, changes = service.adapt_request(original)
        with patch.dict(os.environ, {}, clear=True), observer.request_scope(original, effective, changes) as state:
            observer.capture_before_parser(["example()"], ["tool_calls"])
            observer.emit("test", "point", {"raw": 1}, "summary")
            self.assertFalse(observer.observing())
            self.assertNotIn("generated_texts_before_parser", state)
            self.assertEqual(state["observations"], [])

    def test_diagnostics_off_logger_keeps_raw_without_transport(self):
        original = self.payload()
        effective, changes = service.adapt_request(original)
        with patch.dict(os.environ, {"LIEMAPP_DIAGNOSTICS": "1"}, clear=True), \
                observer.request_scope(original, effective, changes) as state:
            texts, reasons = ["example()"], ["tool_calls"]
            observer.capture_before_parser(texts, reasons)
            texts[0] = "mutated later"
            observer.emit("test", "point", {"raw": 1}, "summary")
            self.assertFalse(observer.enabled())
            self.assertEqual(state["generated_texts_before_parser"], ["example()"])
            self.assertEqual(state["observations"][0]["raw"]["request_id"], "test-id")
        self.assertIsNone(observer.state())


class MLCNativeLibraryBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mlc-library-binding-test-")
        self.addCleanup(self.directory.cleanup)
        self.library = Path(self.directory.name) / "model.so"
        self.library.write_bytes(b"unit-test-library-not-executable")
        self.manifest = {"build": {"native_model_library": {
            "path": str(self.library), "sha256": runtime.sha256(self.library),
            "bytes": self.library.stat().st_size}}}

    def test_default_is_exact_frozen_library(self):
        self.assertEqual(runtime.resolve_model_library(None, self.manifest), self.library.resolve())

    def test_explicit_matching_library_accepted(self):
        self.assertEqual(runtime.resolve_model_library(self.library, self.manifest), self.library.resolve())

    def test_other_path_even_identical_bytes_rejected(self):
        other = self.library.with_name("unregistered.so")
        other.write_bytes(self.library.read_bytes())
        with self.assertRaises(ValueError):
            runtime.resolve_model_library(other, self.manifest)

    def test_changed_same_size_bytes_rejected(self):
        self.library.write_bytes(b"x" * self.library.stat().st_size)
        with self.assertRaises(ValueError):
            runtime.resolve_model_library(None, self.manifest)

    def test_changed_size_rejected(self):
        self.library.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            runtime.resolve_model_library(None, self.manifest)


if __name__ == "__main__":
    unittest.main()
