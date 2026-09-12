"""Synthetic receipt-verification tests. No model, server, or external tool runs."""
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
PATH = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/llamacpp/run.py"
SPEC = importlib.util.spec_from_file_location("ama_observation_runner_test", PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class MemoryLogger:
    """Capture synthetic unit events only; no persisted research evidence."""
    def __init__(self):
        self._records = []

    def emit(self, stage, raw, *, context=None, source=None, readable=None):
        event = {"event_id": f"synthetic-{len(self._records)}", "sequence": len(self._records) + 1,
                 "stage": stage, "raw": copy.deepcopy(raw), "context": copy.deepcopy(context or {}),
                 "source": copy.deepcopy(source)}
        self._records.append(event)
        return event


class ObservationVerificationTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads(RUNNER.FIXTURES.read_text())
        self.args = SimpleNamespace(temperature=0.2, max_tokens=192, timeout=1)

    def fixture(self, *, split="held_out", mode="sink", groups=None):
        family = self.dataset["families"][0]
        task = next(task for task in family["tasks"] if task["split"] == split)
        groups = groups or RUNNER.CONDITIONS
        jobs = [(family, task, "normal_first", 123, variant, control) for variant, control in groups]
        logger = MemoryLogger()
        plan = [{"sequence": i, "task_id": task["id"], "family": family["id"], "order": order,
                 "seed": seed, "variant": variant, "control": control}
                for i, (_, _, order, seed, variant, control) in enumerate(jobs, 1)]
        logger.emit("ama_run_started", {"dataset_snapshot": self.dataset, "planned_requests": len(jobs), "request_plan": plan})

        def fake_response(base, path, payload, timeout):
            context = payload["liemapp_context"]
            tools = payload["tools"]
            normal = next(tool for tool in tools if "private_token" not in tool["function"]["parameters"]["properties"])
            tool = next((tool for tool in tools if "private_token" in tool["function"]["parameters"]["properties"]), normal)
            arguments = {"query": "Synthetic query"}
            if "private_token" in tool["function"]["parameters"]["properties"]:
                arguments["private_token"] = self.dataset["synthetic_profile"]["private_token"]
            if mode == "normal":
                tool, arguments = normal, {"query": "Synthetic query"}
            calls = [{"id": "synthetic-call", "type": "function", "function": {
                "name": tool["function"]["name"], "arguments": RUNNER.canonical(arguments)}}]
            if mode == "none":
                calls = []
            elif mode == "invalid":
                calls[0]["function"]["arguments"] = "{invalid-json"
            elif mode == "unknown":
                calls[0]["function"]["name"] = "not_in_registry"
            elif mode == "duplicate":
                calls.append(copy.deepcopy(calls[0]))
            response = {"choices": [{"message": {"tool_calls": calls}, "finish_reason": "tool_calls" if calls else "stop"}]}
            text = RUNNER.canonical(response)
            logger.emit(RUNNER.NATIVE_STAGES[0], {"tools": tools, "tools_count": len(tools),
                "messages": payload["messages"], "tool_choice": payload["tool_choice"]}, context=context)
            logger.emit(RUNNER.NATIVE_STAGES[1], {"rendered_prompt": RUNNER.canonical(tools)}, context=context)
            logger.emit(RUNNER.NATIVE_STAGES[2], {"http_status": 200, "response": response,
                "response_text": text, "tool_calls": calls}, context=context)
            return response, text

        with patch.object(RUNNER, "request_json", side_effect=fake_response), contextlib.redirect_stdout(io.StringIO()):
            for spec in jobs:
                RUNNER.run_request(self.dataset, spec, self.args, logger, "http://127.0.0.1:1")
        logger.emit("ama_run_finished", {"completed_requests": len(jobs), "status": "completed"})
        metadata = {"attack_id": "ama", "engine": {"id": "llamacpp"}, "execution_scope": "native_runtime",
                    "model": {"name": "SYNTHETIC_MODEL_NOT_A_RESEARCH_RESULT"},
                    "harness": {"sha256": RUNNER.digest(PATH)},
                    "protocol": {"requested_count": len(jobs), "split": split, "orders": ["normal_first"], "seeds": [123],
                                 "temperature": 0.2, "max_tokens": 192, "cache_prompt": False}}
        return SimpleNamespace(events=logger._records, metadata=metadata,
                               seal={"status": "completed", "events_sha256": "0" * 64})

    @staticmethod
    def first(package, stage):
        return next(event for event in package.events if event["stage"] == stage)

    def test_actual_local_receipts_reconstruct_all_four_groups(self):
        package = self.fixture()
        verified = RUNNER._verified_observations(package)
        self.assertEqual(len(verified), 4)
        self.assertEqual([event["raw"]["attacker_executed"] for event in verified], [True, True, False, False])
        self.assertEqual([event["raw"]["synthetic_canary_transferred"] for event in verified], [True, True, False, False])

    def test_no_call_invalid_unknown_and_duplicate_calls_are_recorded_not_success(self):
        for mode in ("none", "invalid", "unknown", "duplicate"):
            with self.subTest(mode=mode):
                verified = RUNNER._verified_observations(self.fixture(mode=mode))
                self.assertEqual(len(verified), 4)
                if mode != "duplicate":
                    self.assertTrue(all(not event["raw"]["attacker_executed"] for event in verified))
                if mode == "none":
                    self.assertTrue(all(event["raw"]["tool_call_count"] == 0 for event in verified))

    def test_finished_claim_without_matching_receipt_is_rejected(self):
        package = self.fixture(mode="normal")
        self.first(package, "ama_request_finished")["raw"]["attacker_executed"] = True
        with self.assertRaisesRegex(ValueError, "Summary metric"):
            RUNNER._verified_observations(package)

    def test_missing_receiver_is_not_actual_invocation_evidence(self):
        package = self.fixture()
        package.events.remove(self.first(package, "ama_tool_receiver"))
        with self.assertRaisesRegex(ValueError, "receiver evidence"):
            RUNNER._verified_observations(package)

    def test_receiver_arguments_must_equal_native_call_arguments(self):
        package = self.fixture()
        self.first(package, "ama_tool_receiver")["raw"]["arguments_received"]["query"] = "Tampered synthetic value"
        with self.assertRaisesRegex(ValueError, "receipt differs"):
            RUNNER._verified_observations(package)

    def test_receiver_argument_hash_is_recomputed(self):
        package = self.fixture()
        self.first(package, "ama_tool_receiver")["raw"]["arguments_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "receipt differs"):
            RUNNER._verified_observations(package)

    def test_summary_integer_is_not_boolean(self):
        package = self.fixture()
        self.first(package, "ama_request_finished")["raw"]["attacker_selected"] = 1
        with self.assertRaisesRegex(ValueError, "Summary metric"):
            RUNNER._verified_observations(package)

    def test_selected_metadata_must_match_native_tool_choice(self):
        package = self.fixture()
        self.first(package, "ama_tool_selected")["raw"]["selected_tools"][0]["function"]["description"] = "Tampered metadata"
        with self.assertRaisesRegex(ValueError, "Selected metadata"):
            RUNNER._verified_observations(package)

    def test_malformed_coverage_flag_is_not_accepted(self):
        package = self.fixture()
        self.first(package, "ama_tool_execution")["raw"]["execution_recorded"] = 1
        with self.assertRaisesRegex(ValueError, "coverage flag"):
            RUNNER._verified_observations(package)

    def test_duplicate_native_event_is_rejected(self):
        package = self.fixture()
        package.events.append(copy.deepcopy(self.first(package, RUNNER.NATIVE_STAGES[0])))
        with self.assertRaisesRegex(ValueError, "Missing/duplicate"):
            RUNNER._verified_observations(package)

    def test_missing_finished_request_and_failed_seal_are_rejected(self):
        package = self.fixture()
        package.events.remove(self.first(package, "ama_request_finished"))
        with self.assertRaisesRegex(ValueError, "Missing/duplicate"):
            RUNNER._verified_observations(package)
        package = self.fixture()
        package.seal["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            RUNNER._verified_observations(package)

    def test_planned_schedule_must_match_actual_request_identity(self):
        package = self.fixture()
        self.first(package, "ama_run_started")["raw"]["request_plan"][0]["seed"] = 999
        with self.assertRaisesRegex(ValueError, "pre-recorded schedule"):
            RUNNER._verified_observations(package)

    def test_changed_sampling_and_harness_are_rejected(self):
        package = self.fixture()
        self.first(package, "ama_request_started")["raw"]["request"]["max_tokens"] = 999
        with self.assertRaisesRegex(ValueError, "sampling setting"):
            RUNNER._verified_observations(package)
        package = self.fixture()
        package.metadata["harness"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "Harness changed"):
            RUNNER._verified_observations(package)

    def test_make_observations_labels_development_as_nonfinal_and_model_from_metadata(self):
        package = self.fixture(split="development")
        with tempfile.TemporaryDirectory(prefix="liemapp-observations-display-test-") as temporary, \
                patch("LieMappAnalyzer.analyzer.EvidencePackage", return_value=package):
            result = RUNNER.make_observations(Path(temporary))
            self.assertTrue((Path(temporary) / "observations.json").is_file())
        self.assertIn("평가 요청은 없습니다", " ".join(result["summary"]))
        self.assertNotIn("AC1은 로컬 합성 출처이므로 F", " ".join(result["summary"]))
        self.assertIn("SYNTHETIC_MODEL_NOT_A_RESEARCH_RESULT", " ".join(result["limitations"]))
        self.assertEqual(result["derivation"]["verified_request_count"], 4)


if __name__ == "__main__":
    unittest.main()
