"""Synthetic vLLM AMA preparation/runner contracts; no model download or inference.

I/O: pinned file records become verified cache files and explicit run metadata.
Guard failures: wrong bytes, unsafe paths, accidental overwrite, and misleading
engine/sampling labels. Temporary files and mocked transport are sufficient.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/vllm"


def import_file(name, filename):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = import_file("test_ama_vllm_prepare", "prepare_model.py")
runner = import_file("test_ama_vllm_run", "run.py")
parity = import_file("test_ama_vllm_parity", "verify_runtime.py")


class AMAVLLMRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ama-vllm-runner-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.here = self.root / "scripts"
        self.here.mkdir()
        self.cache = self.root / ".evidence/models/ama/synthetic/revision"
        self.cache.mkdir(parents=True)
        self.body = b"synthetic-model-bytes-not-real-weights"
        self.record = {"path": "model.safetensors", "bytes": len(self.body),
                       "sha256": hashlib.sha256(self.body).hexdigest()}
        self.spec = {"repository": "synthetic/model", "revision": "a" * 40,
                     "cache_path": str(self.cache.relative_to(self.root)),
                     "format": "safetensors", "weights_dtype": "bfloat16",
                     "runtime_dtype": "float32", "files": [self.record]}

    def save_manifest(self, spec=None):
        (self.here / "model.json").write_text(json.dumps(self.spec if spec is None else spec))

    def checked(self):
        with patch.object(runner, "ROOT", self.root), patch.object(runner, "HERE", self.here):
            return runner.checked_model()

    def fetch(self, record=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return prepare.fetch(self.spec, self.cache, record or self.record)

    def test_verified_model_returns_actual_dtype_and_rejects_same_length_changed_bytes(self):
        self.save_manifest()
        target = self.cache / self.record["path"]
        target.write_bytes(self.body)
        metadata, directory = self.checked()
        self.assertEqual(directory, self.cache)
        self.assertEqual(metadata["name"], "synthetic/model")
        self.assertEqual(metadata["dtype"], "float32")
        self.assertEqual(metadata["weights_dtype"], "bfloat16")
        target.write_bytes(b"x" * len(self.body))
        with self.assertRaises(ValueError):
            self.checked()

    def test_checked_model_requires_nonempty_unique_file_records_within_cache(self):
        (self.cache / self.record["path"]).write_bytes(self.body)
        cases = [dict(self.spec, files=[]), dict(self.spec, files=[self.record, self.record]),
                 dict(self.spec, cache_path=str(self.here))]
        (self.here / self.record["path"]).write_bytes(self.body)
        for spec in cases:
            with self.subTest(spec=spec):
                self.save_manifest(spec)
                with self.assertRaises(ValueError):
                    self.checked()

    def test_checked_model_rejects_symlink_to_bytes_outside_model_cache(self):
        outside = self.root / "outside-data"
        outside.write_bytes(self.body)
        (self.cache / self.record["path"]).symlink_to(outside)
        self.save_manifest()
        with self.assertRaises(ValueError):
            self.checked()
        self.assertEqual(outside.read_bytes(), self.body)

    def test_prepare_existing_valid_file_needs_no_transport_and_wrong_file_is_retained(self):
        target = self.cache / self.record["path"]
        target.write_bytes(self.body)
        with patch.object(prepare.subprocess, "run", side_effect=AssertionError("No network")):
            self.fetch()
            target.write_bytes(b"wrong")
            with self.assertRaises(ValueError):
                self.fetch()
        self.assertEqual(target.read_bytes(), b"wrong")

    def test_prepare_resumes_partial_and_promotes_only_verified_complete_bytes(self):
        target = self.cache / self.record["path"]
        partial = self.cache / (self.record["path"] + ".download")
        partial.write_bytes(self.body[:9])

        def finish(command, **kwargs):
            self.assertEqual(command[0], "curl")
            self.assertEqual(command[command.index("--continue-at") + 1], "-")
            self.assertEqual(command[command.index("--output") + 1], str(partial))
            self.assertEqual(command[-1], "https://huggingface.co/synthetic/model/resolve/" + "a" * 40 + "/model.safetensors")
            self.assertNotIn("shell", kwargs)
            self.assertIs(kwargs["check"], True)
            self.assertEqual(partial.read_bytes(), self.body[:9])
            partial.write_bytes(self.body)

        with patch.object(prepare.subprocess, "run", side_effect=finish) as download:
            self.fetch()
        download.assert_called_once()
        self.assertEqual(target.read_bytes(), self.body)
        self.assertFalse(partial.exists())

    def test_prepare_complete_valid_partial_is_promoted_without_range_request(self):
        partial = self.cache / (self.record["path"] + ".download")
        partial.write_bytes(self.body)
        with patch.object(prepare.subprocess, "run", side_effect=AssertionError("No EOF range request")):
            self.fetch()
        self.assertEqual((self.cache / self.record["path"]).read_bytes(), self.body)
        self.assertFalse(partial.exists())

    def test_prepare_bad_download_is_retained_and_never_published_as_model(self):
        partial = self.cache / (self.record["path"] + ".download")

        def invalid_download(command, **kwargs):
            partial.write_bytes(b"x" * len(self.body))

        with patch.object(prepare.subprocess, "run", side_effect=invalid_download), self.assertRaises(ValueError):
            self.fetch()
        self.assertEqual(partial.read_bytes(), b"x" * len(self.body))
        self.assertFalse((self.cache / self.record["path"]).exists())

    def test_prepare_refuses_destination_that_appears_during_download(self):
        target = self.cache / self.record["path"]
        partial = self.cache / (self.record["path"] + ".download")

        def racing_writer(command, **kwargs):
            partial.write_bytes(self.body)
            target.write_bytes(b"other-owner-content")

        with patch.object(prepare.subprocess, "run", side_effect=racing_writer), self.assertRaises(FileExistsError):
            self.fetch()
        self.assertEqual(target.read_bytes(), b"other-owner-content")
        self.assertEqual(partial.read_bytes(), self.body)

    def test_prepare_rejects_traversal_oversized_partial_and_symlinks_before_transport(self):
        with patch.object(prepare.subprocess, "run", side_effect=AssertionError("No network")):
            for name in ("../outside", "/outside", "subdir/model", ".", "..", ""):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.fetch({**self.record, "path": name})
            partial = self.cache / (self.record["path"] + ".download")
            partial.write_bytes(b"x" * (len(self.body) + 1))
            with self.assertRaises(ValueError):
                self.fetch()
            self.assertTrue(partial.exists())
            partial.unlink()
            outside = self.root / "outside"
            outside.write_bytes(b"prefix")
            partial.symlink_to(outside)
            with self.assertRaises(ValueError):
                self.fetch()
            self.assertEqual(outside.read_bytes(), b"prefix")
            partial.unlink()
            (self.cache / self.record["path"]).symlink_to(outside)
            with self.assertRaises(ValueError):
                self.fetch()

    def test_prepare_main_rejects_outside_cache_and_duplicate_records(self):
        for spec in (dict(self.spec, cache_path=str(self.here)),
                     dict(self.spec, files=[self.record, self.record])):
            with self.subTest(spec=spec):
                self.save_manifest(spec)
                with patch.object(prepare, "ROOT", self.root), patch.object(prepare, "HERE", self.here), \
                     patch.object(prepare, "fetch", side_effect=AssertionError("No fetching")), self.assertRaises(ValueError):
                    prepare.main()

    def test_run_metadata_identifies_vllm_fp32_and_engine_specific_sampling_without_cache_request_field(self):
        args = SimpleNamespace(temperature=0.2, max_tokens=192, run_id="synthetic-vllm-test",
                               dataset=runner.FIXTURES, threads=6, split="held_out", seeds=[11, 12],
                               orders=["normal_first", "sink_first"], schedule_seed=11,
                               context_size=4096, limit=None)
        model = {"name": "Qwen/Qwen2.5-3B-Instruct", "dtype": "float32", "weights_dtype": "bfloat16"}
        with patch.object(runner, "digest", return_value="0" * 64), \
             patch.object(runner.subprocess, "check_output", return_value="a1541f5742a29864a80087af313ad460066a1524\n"):
            metadata = runner.build_metadata(args, {"dataset_id": "frozen-llamacpp-origin"}, [None] * 128, model, {"synthetic": True})
        self.assertEqual(metadata["engine"]["id"], "vllm")
        self.assertEqual(metadata["engine"]["name"], "vLLM")
        self.assertEqual(metadata["model"]["dtype"], "float32")
        self.assertEqual(metadata["protocol"]["requested_count"], 128)
        self.assertIs(metadata["protocol"]["cross_engine_precision_controlled"], False)
        settings = metadata["protocol"]["request_settings"]
        self.assertEqual(settings["top_k"], -1)
        self.assertNotIn("cache_prompt", settings)
        self.assertEqual(metadata["protocol"]["tool_parser"], "hermes")
        self.assertIs(metadata["protocol"]["prefix_cache_enabled"], False)
        self.assertIn("not newly unseen", metadata["dataset"]["reuse_scope"])
        self.assertIn("Q4_K_M", " ".join(metadata["limitations"]))
        self.assertIn("final answer quality", " ".join(metadata["limitations"]))

    def test_invalid_run_ids_and_nonfinite_limits_fail_before_loading_runtime(self):
        cases = [["--run-id", "../escape"], ["--run-id", "."], ["--run-id", ".."],
                 ["--threads", "0"], ["--limit", "0"], ["--temperature", "nan"],
                 ["--timeout", "nan"], ["--startup-timeout", "inf"],
                 ["--seeds", "1", "1"], ["--orders", "normal_first", "normal_first"]]
        with patch.object(runner, "load", side_effect=AssertionError("Do not load engine")):
            for argv in cases:
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    runner.main(argv)


class AMAVLLMParityTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads(runner.FIXTURES.read_text(encoding="utf-8"))
        self.payload = parity.payloads(self.dataset, 20260911, 192)[0]
        self.response = {"id": "synthetic-response", "created": 1, "choices": [{
            "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": "synthetic-call", "type": "function", "function": {
                    "name": "research_lookup", "arguments": '{"query":"synthetic"}'}}]}}]}

    def test_null_calls_normalized_for_comparison_without_modifying_raw_response(self):
        response = {"choices": [{"message": {"role": "assistant", "content": "text", "tool_calls": None},
                                  "finish_reason": "stop"}]}
        normalized = parity.semantics(response)
        self.assertEqual(normalized["tool_calls"], [])
        self.assertIsNone(response["choices"][0]["message"]["tool_calls"])

    def test_response_ids_are_ignored_but_literal_argument_and_content_changes_are_not(self):
        other = json.loads(json.dumps(self.response))
        other["id"], other["created"] = "other", 99
        other["choices"][0]["message"]["tool_calls"][0]["id"] = "other-call"
        self.assertEqual(parity.semantics(other), parity.semantics(self.response))
        other["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"query": "synthetic"}'
        self.assertNotEqual(parity.semantics(other), parity.semantics(self.response))

    def test_malformed_or_duplicate_arguments_reject_semantic_parity(self):
        for text in ('{"query":"one","query":"two"}', '[]', 'null', '{"query":NaN}'):
            other = json.loads(json.dumps(self.response))
            other["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                parity.semantics(other)

    def test_payloads_use_only_development_and_explicit_vllm_sampling(self):
        requests = parity.payloads(self.dataset, 20260911, 192)
        self.assertEqual(len(requests), 2)
        self.assertEqual([p["liemapp_context"]["variant"] for p in requests], ["neutral", "attractive_targeted"])
        for payload in requests:
            self.assertEqual(payload["liemapp_context"]["task_id"], "research-dev-01")
            self.assertEqual(payload["top_k"], -1)
            self.assertEqual(payload["repetition_penalty"], 1.0)
            self.assertEqual(payload["temperature"], 0.0)
            self.assertNotIn("cache_prompt", payload)
            self.assertNotIn(payload["liemapp_request_id"], json.dumps(payload["messages"]))

    def native_events(self):
        request_id = self.payload["liemapp_request_id"]
        rendered = "\n".join(t["function"]["name"] + " " + t["function"]["description"] for t in self.payload["tools"])
        raw = [{"tools": self.payload["tools"]}, {"rendered_prompt": rendered},
               {"response": self.response, "response_text": json.dumps(self.response)}]
        return [{"event_id": f"synthetic-event-{i}", "context": {"request_id": request_id},
                 "stage": stage, "raw": value} for i, (stage, value) in enumerate(zip(parity.PROTOCOL.NATIVE_STAGES, raw))]

    def test_extra_native_events_do_not_change_three_stage_contract(self):
        events = self.native_events()
        events.append({"event_id": "synthetic-extra", "context": self.payload["liemapp_context"],
                       "stage": "ama_native_generated_text", "raw": {"text": "synthetic"}})
        native, all_events = parity.verify_native_events(events, self.payload, self.response, json.dumps(self.response), True)
        self.assertEqual(len(native), 3)
        self.assertEqual(len(all_events), 4)
        with self.assertRaises(ValueError):
            parity.verify_native_events(events, self.payload, self.response, json.dumps(self.response), False)

    def test_duplicate_native_stage_or_trace_id_in_prompt_fails(self):
        events = self.native_events()
        with self.assertRaises(ValueError):
            parity.verify_native_events(events + events[:1], self.payload, self.response, json.dumps(self.response), True)
        events[1]["raw"]["rendered_prompt"] += self.payload["liemapp_request_id"]
        with self.assertRaises(ValueError):
            parity.verify_native_events(events, self.payload, self.response, json.dumps(self.response), True)


if __name__ == "__main__":
    unittest.main()
