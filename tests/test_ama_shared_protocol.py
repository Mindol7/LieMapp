"""Engine-neutral AMA protocol tests using synthetic native responses only."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PATH = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/shared/ama_protocol.py"
spec = importlib.util.spec_from_file_location("ama_shared_protocol_test", PATH)
PROTOCOL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROTOCOL)
FROZEN_RUNNER = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/llamacpp/run.py"
FIXTURES = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/llamacpp/fixtures.json"


class MemoryLogger:
    def __init__(self, metadata):
        self.metadata = metadata
        self._records = []

    def emit(self, stage, raw, *, context=None, source=None, readable=None):
        event = {"event_id": f"synthetic-{len(self._records)}", "sequence": len(self._records) + 1,
                 "stage": stage, "raw": copy.deepcopy(raw), "context": copy.deepcopy(context or {}),
                 "source": copy.deepcopy(source), "readable": copy.deepcopy(readable or {})}
        self._records.append(event)
        return event


class SharedProtocolTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads(FIXTURES.read_text())
        self.settings = {"temperature": 0.2, "max_tokens": 192, "top_p": 1.0,
                         "stream": False, "n": 1, "parallel_tool_calls": False, "top_k": -1}
        self.args = SimpleNamespace(temperature=0.2, max_tokens=192, timeout=1)
        self.requests = []

    def fixture(self, *, engine_id="vllm", mode="sink", split="held_out", settings=None):
        family = self.dataset["families"][0]
        task = next(task for task in family["tasks"] if task["split"] == split)
        jobs = [(family, task, "normal_first", 123, variant, control) for variant, control in PROTOCOL.CONDITIONS]
        metadata = {"attack_id": "ama", "engine": {"id": engine_id}, "execution_scope": "native_runtime",
                    "model": {"name": "SYNTHETIC_TEST_MODEL"},
                    "harness": {"path": str(Path(__file__).resolve()), "sha256": PROTOCOL.digest(__file__)},
                    "code_dependencies": [PROTOCOL.protocol_dependency()],
                    "protocol": {"requested_count": len(jobs), "split": split, "orders": ["normal_first"],
                                 "seeds": [123], "request_settings": copy.deepcopy(settings or self.settings)}}
        logger = MemoryLogger(metadata)
        plan = [{"sequence": i, "task_id": task["id"], "family": family["id"], "order": order,
                 "seed": seed, "variant": variant, "control": control}
                for i, (_, _, order, seed, variant, control) in enumerate(jobs, 1)]
        logger.emit("ama_run_started", {"dataset_snapshot": self.dataset, "planned_requests": len(jobs), "request_plan": plan})

        def fake_response(base, path, payload, timeout):
            self.requests.append(copy.deepcopy(payload))
            context, tools = payload["liemapp_context"], payload["tools"]
            normal = next(tool for tool in tools if "private_token" not in tool["function"]["parameters"]["properties"])
            tool = next((tool for tool in tools if "private_token" in tool["function"]["parameters"]["properties"]), normal)
            arguments = {"query": "Synthetic query"}
            if "private_token" in tool["function"]["parameters"]["properties"]:
                arguments["private_token"] = self.dataset["synthetic_profile"]["private_token"]
            calls = [{"id": "synthetic-call", "type": "function", "function": {
                "name": tool["function"]["name"], "arguments": PROTOCOL.canonical(arguments)}}]
            if mode in ("none", "null_calls", "absent_calls"):
                calls = []
            elif mode == "invalid":
                calls[0]["function"]["arguments"] = "{invalid-json"
            elif mode == "malformed_name":
                calls[0]["function"]["name"] = []
            elif mode == "duplicate":
                calls.append(copy.deepcopy(calls[0]))
            response = {"choices": [{"message": {"tool_calls": calls}, "finish_reason": "tool_calls" if calls else "stop"}]}
            if mode == "null_calls":
                response["choices"][0]["message"]["tool_calls"] = None
            elif mode == "absent_calls":
                response["choices"][0]["message"].pop("tool_calls")
            elif mode in ("boolean_calls", "string_calls", "object_calls"):
                response["choices"][0]["message"]["tool_calls"] = {
                    "boolean_calls": False, "string_calls": "", "object_calls": {}}[mode]
            native_text = PROTOCOL.canonical(response)
            wire_text = json.dumps(response, ensure_ascii=False, indent=2)
            logger.emit(PROTOCOL.NATIVE_STAGES[0], {"tools": tools, "tools_count": len(tools),
                "messages": payload["messages"], "tool_choice": payload["tool_choice"]}, context=context)
            logger.emit(PROTOCOL.NATIVE_STAGES[1], {"rendered_prompt": PROTOCOL.canonical(tools)}, context=context)
            logger.emit(PROTOCOL.NATIVE_STAGES[2], {"http_status": 200, "response": response,
                "response_text": native_text, "tool_calls": calls}, context=context)
            return response, wire_text

        with patch.object(PROTOCOL, "request_json", side_effect=fake_response), contextlib.redirect_stdout(io.StringIO()):
            for job in jobs:
                PROTOCOL.run_request(self.dataset, job, self.args, logger, "http://127.0.0.1:1")
        logger.emit("ama_run_finished", {"completed_requests": len(jobs), "status": "completed"})
        return SimpleNamespace(events=logger._records, metadata=metadata,
                               seal={"status": "completed", "events_sha256": "0" * 64})

    def verify(self, package, engine_id="vllm"):
        return PROTOCOL._verified_observations(package, engine_id=engine_id, harness_path=__file__)

    @staticmethod
    def first(package, stage):
        return next(event for event in package.events if event["stage"] == stage)

    def test_engine_settings_are_preserved_without_fabricated_llama_fields(self):
        package = self.fixture()
        self.assertEqual(len(self.verify(package)), 4)
        for payload in self.requests:
            self.assertEqual(payload["top_k"], -1)
            self.assertNotIn("cache_prompt", payload)
        self.assertEqual(package.metadata["engine"]["id"], "vllm")

    def test_same_verifier_accepts_explicit_arbitrary_engine_without_identity_rewrite(self):
        package = self.fixture(engine_id="synthetic-engine-b")
        self.assertEqual(len(self.verify(package, engine_id="synthetic-engine-b")), 4)
        self.assertEqual(package.metadata["engine"]["id"], "synthetic-engine-b")
        with self.assertRaisesRegex(ValueError, "Wrong attack or engine"):
            self.verify(package)

    def test_native_json_and_wire_formatting_differences_are_not_value_mismatches(self):
        package = self.fixture()
        self.assertNotEqual(self.first(package, PROTOCOL.NATIVE_STAGES[2])["raw"]["response_text"],
                            self.first(package, "ama_request_finished")["raw"]["response_text"])
        self.assertEqual(len(self.verify(package)), 4)

    def test_actual_shared_source_locations_are_not_relabelled_as_native_engine(self):
        package = self.fixture()
        for event in package.events:
            if event["source"]:
                self.assertEqual(Path(event["source"]["path"]), PATH)
        receiver = self.first(package, "ama_tool_receiver")
        self.assertEqual(receiver["source"]["function"], "local_fixture_tool")
        self.assertEqual(receiver["source"]["logging_point_id"], "AMA-TOOL-LP01")

    def test_zero_call_invalid_duplicate_and_unhashable_names_do_not_fabricate_success(self):
        for mode in ("none", "invalid", "duplicate", "malformed_name"):
            with self.subTest(mode=mode):
                rows = self.verify(self.fixture(mode=mode))
                self.assertEqual(len(rows), 4)
                if mode != "duplicate":
                    self.assertTrue(all(not row["raw"]["attacker_executed"] for row in rows))

    def test_null_and_absent_calls_are_observed_zero_calls_without_rewriting_response(self):
        for mode in ("null_calls", "absent_calls"):
            with self.subTest(mode=mode):
                package = self.fixture(mode=mode)
                rows = self.verify(package)
                self.assertTrue(all(row["raw"]["tool_call_count"] == 0 for row in rows))
                self.assertTrue(all(not row["raw"]["attacker_executed"] for row in rows))
                self.assertFalse(any(event["stage"] == "ama_tool_receiver" for event in package.events))
                native = self.first(package, PROTOCOL.NATIVE_STAGES[2])["raw"]
                message = native["response"]["choices"][0]["message"]
                if mode == "null_calls":
                    self.assertIn("tool_calls", message)
                    self.assertIsNone(message["tool_calls"])
                else:
                    self.assertNotIn("tool_calls", message)
                self.assertEqual(native["tool_calls"], [])
                self.assertEqual(json.loads(native["response_text"]), native["response"])

    def test_nonlist_nonnull_calls_fail_closed_even_when_falsey(self):
        for mode in ("boolean_calls", "string_calls", "object_calls"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "tool_calls must be"):
                self.fixture(mode=mode)
        for calls in (True, 0, 1, "calls", {"id": "call"}):
            with self.subTest(calls=calls), self.assertRaisesRegex(ValueError, "tool_calls must be"):
                PROTOCOL.normalized_tool_calls({"tool_calls": calls})
        with self.assertRaisesRegex(ValueError, "message must be an object"):
            PROTOCOL.normalized_tool_calls(None)

    def test_missing_or_changed_shared_dependency_is_rejected(self):
        package = self.fixture()
        package.metadata["code_dependencies"] = []
        with self.assertRaisesRegex(ValueError, "Shared AMA protocol"):
            self.verify(package)
        package = self.fixture()
        package.metadata["code_dependencies"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "Shared AMA protocol"):
            self.verify(package)

    def test_wrong_harness_path_and_bytes_are_rejected(self):
        package = self.fixture()
        with self.assertRaisesRegex(ValueError, "Harness identity"):
            PROTOCOL._verified_observations(package, engine_id="vllm", harness_path=PATH)
        package.metadata["harness"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "Harness changed"):
            self.verify(package)

    def test_omitted_or_extra_request_setting_is_not_silently_accepted(self):
        for change in (lambda payload: payload.pop("top_k"), lambda payload: payload.update(cache_prompt=False)):
            package = self.fixture()
            request = self.first(package, "ama_request_started")["raw"]["request"]
            change(request)
            with self.assertRaises(ValueError):
                self.verify(package)

    def test_changed_request_digest_and_receipt_are_rejected(self):
        package = self.fixture()
        self.first(package, "ama_request_started")["raw"]["request_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "request digest"):
            self.verify(package)
        package = self.fixture()
        self.first(package, "ama_tool_receiver")["raw"]["arguments_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "receipt differs"):
            self.verify(package)

    def test_invalid_sampling_settings_are_rejected_before_transport(self):
        for key, value in (("stream", True), ("n", True), ("parallel_tool_calls", True), ("top_k", -2),
                           ("top_p", 0), ("max_tokens", 0), ("temperature", float("inf")), ("cache_prompt", "false")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                PROTOCOL.validate_request_settings({**self.settings, key: value})
        with self.assertRaises(ValueError):
            PROTOCOL.validate_request_settings({**self.settings, "messages": []})

    def test_generic_observation_document_preserves_engine_identity(self):
        package = self.fixture()
        with tempfile.TemporaryDirectory(prefix="liemapp-shared-observations-test-") as temporary, \
                patch("LieMappAnalyzer.analyzer.EvidencePackage", return_value=package):
            result = PROTOCOL.make_observations(Path(temporary), engine_id="vllm", engine_label="vLLM", harness_path=__file__)
        self.assertEqual(result["engine_id"], "vllm")
        self.assertIn("vLLM", " ".join(result["limitations"]))
        self.assertNotIn("llama.cpp", " ".join(result["limitations"]))
        self.assertEqual(result["derivation"]["verified_request_count"], 4)

    def test_frozen_llama_runner_and_common_rules_are_unchanged(self):
        self.assertEqual(PROTOCOL.digest(FROZEN_RUNNER), "5c840c1058abc3cb1db485a49aeff5fa893e089f850fed79f223947c327e6bbc")
        self.assertEqual(PROTOCOL.digest(ROOT / "LieMappBench/Logging-Dataset/ama/conditions.json"),
                         "96857012936d09c248b2b25deeb9c1bc43f46d3e21660a62922f24bf80797737")


if __name__ == "__main__":
    unittest.main()
