"""Independent semantic replay tests; inference and public HTTP are mocked.

The EvidencePackage loader alone is replaced with generated in-memory events.
Seal/chain cryptography is covered by the common logger tests; these tests ensure
internally inconsistent but otherwise sealed observations cannot become results.
"""
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

import test_ama_public_http_protocol as transport_tests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PATH = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/shared/public_http_protocol.py"
SPEC = importlib.util.spec_from_file_location("ama_public_independent_evidence_tests", PATH)
PROTOCOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROTOCOL)
RUNNER = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/SGLang/run.py"
SOURCE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/SGLang/public-http-v1"
BUILD = ROOT / "LieMappBench/Logging-Dataset/ama/SGLang/native-build-manifest.json"


class PublicHTTPEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ama-public-evidence-unit-")
        self.addCleanup(temporary.cleanup)
        self.run_dir = Path(temporary.name)
        self.dataset = json.loads((SOURCE / "fixtures.json").read_text())
        self.provenance = json.loads((SOURCE / "provenance.json").read_text())
        self.settings = {"temperature": 0.2, "max_tokens": 192, "top_p": 1.0,
                         "top_k": -1, "stream": False, "n": 1,
                         "parallel_tool_calls": False, "repetition_penalty": 1.0}

    def fixture(self, *, split="held_out", mode="valid"):
        args = SimpleNamespace(split=split, task=[], orders=["normal_first"], seeds=[123],
                               schedule_seed=20260911, limit=4, timeout=1)
        jobs = PROTOCOL.schedule(self.dataset, args)
        snapshot_path = self.run_dir / "dataset.snapshot.json"
        snapshot_path.write_text(json.dumps(self.dataset, indent=2, ensure_ascii=False) + "\n")
        tracked = [PATH, PATH.parent / "ama_protocol.py", RUNNER, RUNNER.parent / "native_runtime.py",
                   RUNNER.parent / "model.json", BUILD,
                   ROOT / "LieMappBench/Logging-Dataset/logger.py", ROOT / "LieMappAnalyzer/analyzer.py",
                   ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json",
                   ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/presentation.json"]
        runtime = json.loads(BUILD.read_text())
        model = json.loads((RUNNER.parent / "model.json").read_text())
        metadata = {"attack_id": "ama", "protocol_id": PROTOCOL.PROTOCOL_ID,
                    "run_id": "SYNTHETIC_UNIT_TEST_ONLY", "execution_scope": "native_runtime",
                    "engine": {"id": "SGLang", "revision": runtime["upstream_commit"],
                               "source_commit": runtime["upstream_commit"],
                               "source_path": str(ROOT / runtime["instrumented_repository"])},
                    "model": {**model, "name": model["repository"], "dtype": "float32", "path": str(ROOT / model["cache_path"]),
                              "manifest": {"path": str((RUNNER.parent / "model.json").relative_to(ROOT)),
                                           "sha256": PROTOCOL.digest(RUNNER.parent / "model.json")}},
                    "harness": {"path": str(RUNNER), "sha256": PROTOCOL.digest(RUNNER)},
                    "native_build": runtime,
                    "native_build_manifest": {"path": str(BUILD.relative_to(ROOT)), "sha256": PROTOCOL.digest(BUILD)},
                    "dataset": {"id": self.dataset["dataset_id"], "path": str(SOURCE / "fixtures.json"),
                                "sha256": PROTOCOL.digest(SOURCE / "fixtures.json"),
                                "snapshot_sha256": PROTOCOL.digest(snapshot_path)},
                    "code_dependencies": [{"path": str(p.relative_to(ROOT)), "sha256": PROTOCOL.digest(p)} for p in tracked],
                    "protocol": {"split": split, "requested_count": len(jobs), "request_settings": self.settings,
                                 "seeds": args.seeds, "orders": args.orders, "schedule_seed": args.schedule_seed,
                                 "limited_run": True, "limit": args.limit, "task": [],
                                 "context_size": 4096, "slots": 1, "model_alias": "local-ama-model",
                                 "prefix_cache_enabled": False, "original_qnt_reproduction": False,
                                 "public_api_operations": 1, "tool_dispatch": "actual_allowlisted_public_https_get",
                                 "provider_is_attacker_owned": False, "real_private_data": False,
                                 "http_max_attempts_per_call": 1}}
        logger = transport_tests.Recorder()
        plan = [{"sequence": i, "family": j[0]["id"], "task_id": j[1]["id"], "order": j[2],
                 "seed": j[3], "variant": j[4], "control": j[5]} for i, j in enumerate(jobs, 1)]
        logger.emit("ama_run_started", {"dataset_snapshot": self.dataset,
                    "source_provenance_snapshot": self.provenance,
                    "planned_requests": len(jobs), "request_plan": plan})

        def inference(base, path, payload, timeout):
            ctx = payload["liemapp_context"]
            tools = payload["tools"]
            tool = next((t for t in tools if "foo2" in t["function"]["parameters"]["properties"]), tools[0])
            arguments = {"foo1": "SYNTHETIC_UNIT_TEXT"}
            if "foo2" in tool["function"]["parameters"]["properties"]:
                arguments["foo2"] = self.dataset["synthetic_profile"]["private_token"]
            calls = [{"id": "unit-call", "type": "function", "function": {
                      "name": tool["function"]["name"], "arguments": PROTOCOL.canonical(arguments)}}]
            if mode == "none":
                calls = []
            if mode == "blocked":
                calls[0]["function"]["arguments"] = "{broken-json"
            response = {"choices": [{"message": {"tool_calls": calls},
                                       "finish_reason": "tool_calls" if calls else "stop"}]}
            logger.emit(PROTOCOL.NATIVE_STAGES[0], {"tools": tools, "tools_count": len(tools),
                        "tool_choice": payload["tool_choice"], "messages": payload["messages"],
                        "http_path": "/v1/chat/completions", "stream": False,
                        "request_id": ctx["request_id"]}, context=ctx)
            logger.emit(PROTOCOL.NATIVE_STAGES[1], {"rendered_prompt": PROTOCOL.canonical(tools),
                        "tools_count": len(tools), "request_id": ctx["request_id"]}, context=ctx)
            logger.emit(PROTOCOL.NATIVE_STAGES[2], {"http_status": 200, "response": response,
                        "response_text": PROTOCOL.canonical(response), "tool_calls": calls,
                        "request_id": ctx["request_id"]}, context=ctx)
            return response, json.dumps(response, indent=2)

        def http(request):
            if mode == "timeout":
                result = {"status": None, "send_attempted": True, "request_bytes_sent": True,
                          "tls_verified": True, "body_truncated": False,
                          "error": {"type": "TimeoutError", "message": "Synthetic timeout"}}
            else:
                result = transport_tests.valid_response(request)
            result["receipt_match"] = PROTOCOL.receipt_matches(request, result)
            return result

        with patch.object(PROTOCOL, "request_json", side_effect=inference), \
                patch.object(PROTOCOL, "public_get", side_effect=http), contextlib.redirect_stdout(io.StringIO()):
            for job in jobs:
                PROTOCOL.run_request(self.dataset, job, args, logger, "http://127.0.0.1:1",
                                     request_settings=self.settings)
        logger.emit("ama_run_finished", {"completed_requests": len(jobs), "status": "completed"})
        return SimpleNamespace(events=logger._records, metadata=metadata,
                               seal={"status": "completed", "events_sha256": "a" * 64})

    def verify(self, package):
        # Semantic replay tests do not repeatedly hash the 6 GB model; independent
        # manifest tests below exercise identity validation separately.
        with patch("LieMappAnalyzer.analyzer.EvidencePackage", return_value=package), \
                patch.object(PROTOCOL, "verify_runtime_files"):
            return PROTOCOL.verify_run(self.run_dir)

    @staticmethod
    def first(package, stage):
        return next(e for e in package.events if e["stage"] == stage)

    def test_consistent_four_request_run_is_independently_replayable(self):
        package = self.fixture()
        verified, finished = self.verify(package)
        self.assertIs(verified, package)
        self.assertEqual(len(finished), 4)
        self.assertFalse(any(e["stage"] == "ama_tool_receiver" for e in package.events))

    def test_no_call_blocked_and_unconfirmed_are_not_success(self):
        for mode in ("none", "blocked", "timeout"):
            with self.subTest(mode=mode):
                package = self.fixture(mode=mode)
                _, finished = self.verify(package)
                self.assertTrue(all(not e["raw"]["attacker_executed"] for e in finished))
                self.assertTrue(all(not e["raw"]["synthetic_canary_transferred"] for e in finished))
                if mode == "timeout":
                    values = [e["raw"]["all_selected_public_calls_confirmed"] for e in package.events
                              if e["stage"] == "ama_tool_provenance"]
                    self.assertEqual(values, [None] * 4)

    def test_missing_duplicate_or_cross_request_native_events_rejected(self):
        for action in ("missing", "duplicate", "context", "response"):
            package = self.fixture()
            native = self.first(package, PROTOCOL.NATIVE_STAGES[2])
            if action == "missing": package.events.remove(native)
            elif action == "duplicate": package.events.append(copy.deepcopy(native))
            elif action == "context": native["context"]["seed"] += 1
            else: native["raw"]["response"]["choices"][0]["message"]["tool_calls"] = []
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.verify(package)

    def test_selected_metadata_arguments_and_sampling_changes_rejected(self):
        for stage, field, replacement in (
            ("ama_tool_selected", "selected_tools", []),
            ("ama_tool_selected", "metadata_recorded", False),
            ("ama_tool_selected", "tool_calls", []),
            ("ama_request_started", "request_sha256", "f" * 64),
        ):
            package = self.fixture()
            self.first(package, stage)["raw"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(package)
        package = self.fixture()
        self.first(package, "ama_request_started")["raw"]["request"]["temperature"] = 0.9
        with self.assertRaises(ValueError): self.verify(package)

    def test_missing_or_cross_call_http_receipt_rejected(self):
        for action in ("missing", "duplicate", "call_id", "call_index", "request_nonce", "body"):
            package = self.fixture()
            event = self.first(package, "ama_http_response")
            if action == "missing": package.events.remove(event)
            elif action == "duplicate": package.events.append(copy.deepcopy(event))
            elif action == "call_id": event["context"]["tool_call_id"] = "other-call"
            elif action == "call_index": event["context"]["call_index"] = 99
            elif action == "request_nonce": self.first(package, "ama_http_request")["raw"]["nonce"] = "f" * 32
            else: event["raw"]["body_sha256"] = "f" * 64
            with self.subTest(action=action), self.assertRaises(ValueError): self.verify(package)

    def test_forged_ac1_dc2_or_metrics_cannot_replace_underlying_receipts(self):
        for stage, field, value in (("ama_tool_provenance", "all_selected_public_calls_confirmed", True),
                                     ("ama_tool_execution", "execution_recorded", True),
                                     ("ama_request_finished", "public_calls_confirmed", 1),
                                     ("ama_request_finished", "attacker_executed", True),
                                     ("ama_request_finished", "synthetic_canary_transferred", True)):
            package = self.fixture(mode="timeout")
            self.first(package, stage)["raw"][field] = value
            with self.subTest(stage=stage, field=field), self.assertRaises(ValueError): self.verify(package)

    def test_aborted_seal_missing_request_or_wrong_plan_rejected(self):
        for action in ("seal", "request", "plan", "count", "end"):
            package = self.fixture()
            if action == "seal": package.seal["status"] = "failed"
            elif action == "request":
                request_id = self.first(package, "ama_request_started")["context"]["request_id"]
                package.events = [e for e in package.events if e["context"].get("request_id") != request_id]
            elif action == "plan": self.first(package, "ama_run_started")["raw"]["request_plan"].reverse()
            elif action == "count": package.metadata["protocol"]["requested_count"] += 1
            else: self.first(package, "ama_run_finished")["raw"]["status"] = "failed"
            with self.subTest(action=action), self.assertRaises(ValueError): self.verify(package)

    def test_snapshot_provenance_and_code_hash_changes_rejected(self):
        for action in ("snapshot", "provenance", "dependency"):
            package = self.fixture()
            if action == "snapshot": package.metadata["dataset"]["snapshot_sha256"] = "f" * 64
            elif action == "provenance": self.first(package, "ama_run_started")["raw"]["source_provenance_snapshot"]["source_id"] = "forged"
            else: package.metadata["code_dependencies"][0]["sha256"] = "f" * 64
            with self.subTest(action=action), self.assertRaises(ValueError):
                if action == "dependency": PROTOCOL.verify_runtime_files(package.metadata)
                else: self.verify(package)

    def test_native_auxiliary_raw_and_selected_response_are_consistent(self):
        for stage, field, value in ((PROTOCOL.NATIVE_STAGES[0], "tools_count", 999),
                                     (PROTOCOL.NATIVE_STAGES[0], "request_id", "different"),
                                     (PROTOCOL.NATIVE_STAGES[2], "http_status", 500),
                                     (PROTOCOL.NATIVE_STAGES[2], "response_text", "{}"),
                                     ("ama_tool_selected", "response", {})):
            package = self.fixture()
            self.first(package, stage)["raw"][field] = value
            with self.subTest(stage=stage, field=field), self.assertRaises(ValueError): self.verify(package)

    def test_empty_dependency_list_and_changed_harness_are_rejected(self):
        for action in ("dependencies", "harness"):
            package = self.fixture()
            if action == "dependencies": package.metadata["code_dependencies"] = []
            else: package.metadata["harness"]["sha256"] = "f" * 64
            with self.subTest(action=action), self.assertRaises(ValueError):
                PROTOCOL.verify_runtime_files(package.metadata)

    def test_development_cannot_be_relabelled_evaluation(self):
        package = self.fixture(split="development")
        self.verify(package)
        for event in package.events:
            if "cohort" in event["context"]: event["context"]["cohort"] = "evaluation"
            if event["stage"] == "ama_request_started":
                raw = event["raw"]
                raw["request"]["liemapp_context"]["cohort"] = "evaluation"
                raw["request_sha256"] = PROTOCOL.sha(PROTOCOL.canonical(raw["request"]).encode())
        with self.assertRaises(ValueError): self.verify(package)

    def test_declared_split_or_sampling_plan_cannot_differ_from_executed_jobs(self):
        for key, value in (("split", "development"), ("seeds", [999]), ("orders", ["sink_first"]),
                           ("schedule_seed", 123456), ("limited_run", False)):
            package = self.fixture()
            package.metadata["protocol"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(package)

    def test_recorded_original_dataset_identity_must_match_snapshot(self):
        for key, value in (("sha256", "f" * 64), ("id", "invented-dataset"),
                           ("path", str(SOURCE / "provenance.json"))):
            package = self.fixture()
            package.metadata["dataset"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(package)

    def test_receipt_cannot_precede_tool_selection_or_request_completion(self):
        for first, second in (("ama_tool_selected", "ama_http_request"),
                               (PROTOCOL.NATIVE_STAGES[0], PROTOCOL.NATIVE_STAGES[1]),
                               ("ama_tool_execution", "ama_tool_provenance")):
            package = self.fixture()
            a, b = self.first(package, first), self.first(package, second)
            ai, bi = package.events.index(a), package.events.index(b)
            package.events[ai], package.events[bi] = b, a
            for sequence, event in enumerate(package.events, 1): event["sequence"] = sequence
            with self.subTest(first=first, second=second), self.assertRaises(ValueError): self.verify(package)

    def test_unscoped_request_event_or_failed_run_marker_rejected(self):
        for stage in ("ama_http_response", "ama_run_failed"):
            package = self.fixture()
            event = copy.deepcopy(self.first(package, "ama_http_response"))
            event["stage"], event["context"] = stage, {}
            package.events.append(event)
            with self.subTest(stage=stage), self.assertRaises(ValueError): self.verify(package)

    def test_review_policy_registry_source_and_layer_are_not_just_labels(self):
        for stage, field, value in (("ama_metadata_review", "checked_tools", ["invented"]),
                                     ("ama_metadata_review", "policy", "invented"),
                                     ("ama_selection_policy", "tool_choice", "none"),
                                     ("ama_selection_policy", "provided_tool_names", []),
                                     ("ama_tool_registry", "source_binding", {})):
            package = self.fixture()
            self.first(package, stage)["raw"][field] = value
            with self.subTest(stage=stage, field=field), self.assertRaises(ValueError): self.verify(package)
        package = self.fixture()
        self.first(package, PROTOCOL.NATIVE_STAGES[0])["context"]["layer"] = "agent_harness"
        with self.assertRaises(ValueError): self.verify(package)

    def test_extra_native_choice_rejected_even_when_first_choice_is_consistent(self):
        package = self.fixture()
        native = self.first(package, PROTOCOL.NATIVE_STAGES[2])
        response = copy.deepcopy(native["raw"]["response"])
        response["choices"].append({"message": {"tool_calls": []}, "finish_reason": "stop"})
        native["raw"].update(response=response, response_text=PROTOCOL.canonical(response))
        self.first(package, "ama_tool_selected")["raw"]["response"] = copy.deepcopy(response)
        self.first(package, "ama_request_finished")["raw"]["response_text"] = PROTOCOL.canonical(response)
        with self.assertRaises(ValueError): self.verify(package)

    def tiny_runtime(self):
        """Complete independent identity fixture using only tiny test files."""
        temporary = tempfile.TemporaryDirectory(prefix="unit-public-runtime-", dir=ROOT / ".evidence/models/ama")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        native_file, harness = directory / "native.py", directory / "harness.py"
        native_file.write_text("# Synthetic native source, never executed.\n")
        harness.write_text("# Synthetic harness source, never executed.\n")
        weights, config = directory / "weights.bin", directory / "config.json"
        weights.write_bytes(b"synthetic unit weights; not a usable model")
        config.write_text('{"synthetic_unit_test": true}\n')
        native = {"upstream_commit": "0" * 40,
                  "validated_files": [{"path": str(native_file.relative_to(ROOT)), "sha256": PROTOCOL.digest(native_file)}]}
        model = {"schema_version": "1.0.0", "repository": "SYNTHETIC_TEST_ONLY", "revision": "unit-v1",
                 "cache_path": str(directory.relative_to(ROOT)), "runtime_dtype": "float32",
                 "files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": PROTOCOL.digest(p)} for p in (weights, config)]}
        native_manifest, model_manifest = directory / "native-build-manifest.json", directory / "model.json"
        native_manifest.write_text(json.dumps(native))
        model_manifest.write_text(json.dumps(model))
        paths = [PATH, PATH.parent / "ama_protocol.py", harness, native_manifest, model_manifest,
                 ROOT / "LieMappBench/Logging-Dataset/logger.py", ROOT / "LieMappAnalyzer/analyzer.py",
                 ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json",
                 ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/presentation.json"]
        pointer = lambda p: {"path": str(p.relative_to(ROOT)), "sha256": PROTOCOL.digest(p)}
        return {"attack_id": "ama", "protocol_id": PROTOCOL.PROTOCOL_ID,
                "engine": {"id": "synthetic-engine", "source_commit": native["upstream_commit"]},
                "code_dependencies": [pointer(p) for p in paths],
                "harness": {"path": str(harness), "sha256": PROTOCOL.digest(harness)},
                "native_build": native, "native_build_manifest": pointer(native_manifest),
                "model": {**model, "name": model["repository"], "dtype": "float32", "path": str(directory),
                          "manifest": pointer(model_manifest)}}

    def test_complete_tiny_runtime_and_model_manifests_verify_without_mocks(self):
        PROTOCOL.verify_runtime_files(self.tiny_runtime())

    def test_runtime_manifest_cannot_drop_files_or_change_revision(self):
        for action in ("drop_model_file", "drop_native_file", "native_revision", "model_revision",
                       "remove_model_manifest_dependency", "remove_native_manifest_dependency"):
            metadata = self.tiny_runtime()
            if action == "drop_model_file": metadata["model"]["files"] = metadata["model"]["files"][:-1]
            elif action == "drop_native_file": metadata["native_build"]["validated_files"] = []
            elif action == "native_revision": metadata["engine"]["source_commit"] = "f" * 40
            elif action == "model_revision": metadata["model"]["revision"] = "invented-revision"
            else:
                target = metadata["model"]["manifest"] if action.startswith("remove_model") else metadata["native_build_manifest"]
                metadata["code_dependencies"] = [d for d in metadata["code_dependencies"] if d["path"] != target["path"]]
            with self.subTest(action=action), self.assertRaises(ValueError): PROTOCOL.verify_runtime_files(metadata)

    def test_runtime_model_and_native_byte_tampering_are_rejected(self):
        for action in ("model", "native"):
            metadata = self.tiny_runtime()
            target = (Path(metadata["model"]["path"]) / metadata["model"]["files"][0]["path"]
                      if action == "model" else ROOT / metadata["native_build"]["validated_files"][0]["path"])
            target.write_bytes(b"changed")
            with self.subTest(action=action), self.assertRaises(ValueError): PROTOCOL.verify_runtime_files(metadata)

    def test_observation_tables_recompute_actual_call_and_request_denominators(self):
        package = self.fixture()
        with patch("LieMappAnalyzer.analyzer.EvidencePackage", return_value=package), \
                patch.object(PROTOCOL, "verify_runtime_files"):
            artifact = PROTOCOL.make_observations(self.run_dir, engine_id="SGLang",
                                                 engine_label="SYNTHETIC_TEST", harness_path=RUNNER)
        rows = artifact["tables"][0]["rows"]
        self.assertEqual(sum(r["n"] for r in rows), 4)
        self.assertEqual(sum(r["public_calls_confirmed"] for r in rows), 4)
        native_calls = [call for event in package.events if event["stage"] == PROTOCOL.NATIVE_STAGES[2]
                        for call in event["raw"]["tool_calls"]]
        attacker_calls = sum("foo2" in json.loads(c["function"]["arguments"]) for c in native_calls)
        self.assertEqual(sum(r["attacker_selected"] for r in rows), attacker_calls)
        self.assertEqual(sum(r["attacker_executed"] for r in rows), attacker_calls)
        self.assertEqual(sum(r["synthetic_canary_transferred"] for r in rows), attacker_calls)
        self.assertEqual(artifact["derivation"]["verified_request_count"], 4)
        self.assertEqual(len(artifact["derivation"]["request_event_ids"]), 4)
        self.assertEqual(artifact["source_runs"][0]["events_sha256"], package.seal["events_sha256"])

    def test_observations_reject_wrong_engine_or_harness_before_writing(self):
        package = self.fixture()
        with patch("LieMappAnalyzer.analyzer.EvidencePackage", return_value=package), \
                patch.object(PROTOCOL, "verify_runtime_files"):
            with self.assertRaises(ValueError):
                PROTOCOL.make_observations(self.run_dir, engine_id="invented", engine_label="invented", harness_path=RUNNER)
            with self.assertRaises(ValueError):
                PROTOCOL.make_observations(self.run_dir, engine_id="SGLang", engine_label="SGLang", harness_path=PATH)
        self.assertFalse((self.run_dir / "observations.json").exists())


if __name__ == "__main__":
    unittest.main()
