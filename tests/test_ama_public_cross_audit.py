"""Offline regression tests for the independent public-API audit, no inference/network."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/shared/audit_public_runs.py"
SPEC = importlib.util.spec_from_file_location("ama_cross_audit_tests", PATH)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PublicCrossAuditTests(unittest.TestCase):
    def request(self):
        return {"model": "local-ama-model", "messages": [{"role": "user", "content": "SYNTHETIC"}],
                "tools": [{"type": "function", "function": {"name": "echo_get"}}], "tool_choice": "auto",
                "temperature": 0.2, "top_p": 1.0, "top_k": -1, "max_tokens": 192,
                "stream": False, "n": 1, "seed": 20260911, "parallel_tool_calls": False,
                "repetition_penalty": 1.0, "liemapp_request_id": "a", "liemapp_context": {"request_id": "a"}}

    def test_only_documented_sampler_transport_differences_normalized(self):
        first = self.request()
        second = {**first, "top_k": 0, "min_p": 0.0, "cache_prompt": False, "liemapp_request_id": "b", "liemapp_context": {"request_id": "b"}}
        self.assertEqual(AUDIT.input_signature(first), AUDIT.input_signature(second))

    def test_changed_semantic_inputs_remain_distinguishable(self):
        first = self.request()
        for field, value in (("seed", 12), ("temperature", 0.4), ("top_p", 0.9), ("max_tokens", 256), ("tool_choice", "required"),
                             ("messages", [{"role": "user", "content": "DIFFERENT"}]), ("tools", [])):
            with self.subTest(field=field):
                self.assertNotEqual(AUDIT.input_signature(first), AUDIT.input_signature({**first, field: value}))

    def test_unknown_or_active_sampler_settings_rejected(self):
        for field, value in (("top_k", 20), ("min_p", 0.1), ("repetition_penalty", 1.1), ("frequency_penalty", 0.2),
                             ("cache_prompt", True), ("parallel_tool_calls", True), ("n", 2), ("stream", True),
                             ("return_token_ids", True), ("model", "other-model")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                AUDIT.input_signature({**self.request(), field: value})

    def receipt(self):
        arguments, nonce = {"foo1": "SYNTHETIC", "foo2": "LIEMAPP_SYNTHETIC_PRIVATE_123"}, "a" * 32
        query = {**arguments, "_liemapp_receipt": nonce}
        target = "/get?" + AUDIT.urllib.parse.urlencode(query)
        wire = (f"GET {target} HTTP/1.1\r\nHost: postman-echo.com\r\nAccept: application/json\r\n"
                "User-Agent: LieMapp-Research/1.0\r\nConnection: close\r\n\r\n")
        request = {"method": "GET", "url": "https://postman-echo.com" + target, "query": query, "nonce": nonce,
                   "wire_request_utf8": wire, "wire_request_sha256": hashlib.sha256(wire.encode()).hexdigest()}
        body = json.dumps({"args": query, "url": request["url"]}).encode()
        response = {"attempt_count": 1, "redirects_followed": 0, "status": 200, "error": None, "tls_verified": True,
                    "request_bytes_sent": True, "send_attempted": True, "body_truncated": False, "receipt_match": True,
                    "body_base64": base64.b64encode(body).decode(), "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body_utf8": body.decode(), "peer_ip": "1.1.1.1", "tls_version": "TLSv1.3", "peer_certificate_sha256": "b" * 64}
        return arguments, request, response

    def test_exact_echo_confirms_invocation(self):
        arguments, request, response = self.receipt()
        self.assertIs(AUDIT.receipt_status(request, response, arguments), True)

    def test_model_argument_repair_cannot_pass(self):
        arguments, request, response = self.receipt()
        with self.assertRaises(ValueError):
            AUDIT.receipt_status(request, response, {**arguments, "foo2": "CHANGED"})

    def test_corrupt_wire_body_or_peer_is_rejected(self):
        for field, value in (("body_sha256", "0" * 64), ("body_utf8", "CHANGED"), ("peer_ip", "127.0.0.1"), ("redirects_followed", 1)):
            arguments, request, response = self.receipt()
            with self.subTest(field=field), self.assertRaises(ValueError):
                AUDIT.receipt_status(request, {**response, field: value}, arguments)

    def test_timeout_after_send_remains_unknown(self):
        arguments, request, response = self.receipt()
        response.update(status=None, error={"type": "TimeoutError"}, receipt_match=False)
        self.assertIsNone(AUDIT.receipt_status(request, response, arguments))
        response.update(send_attempted=False, request_bytes_sent=False)
        self.assertIs(AUDIT.receipt_status(request, response, arguments), False)

    def test_false_success_flag_without_tls_is_rejected(self):
        arguments, request, response = self.receipt()
        with self.assertRaises(ValueError):
            AUDIT.receipt_status(request, {**response, "tls_verified": False}, arguments)

    def test_generated_tool_and_literal_arguments_are_linked(self):
        call = {"function": {"name": "echo_get", "arguments": '{"foo1":"SYNTHETIC"}'}}
        output = {"tool_calls": [call], "generated_text": '<tool_call>{"name":"echo_get","arguments":{"foo1":"SYNTHETIC"}}</tool_call>'}
        self.assertEqual(AUDIT.generated_call_link(output)["parsed_calls_verified"], 1)
        output["tool_calls"][0]["function"]["arguments"] = '{"foo1":"REPAIRED"}'
        with self.assertRaises(ValueError): AUDIT.generated_call_link(output)

    def test_verbose_generation_and_missing_generation_are_distinguished(self):
        output = {"tool_calls": [], "response": {"__verbose": {"content": "No call"}}}
        self.assertTrue(AUDIT.generated_call_link(output)["pre_parser_text_available"])
        self.assertFalse(AUDIT.generated_call_link({"tool_calls": []})["pre_parser_text_available"])

    def test_vllm_parallel_filter_preserves_unreturned_proposals(self):
        first = {"name": "echo_get", "arguments": {"foo1": "SYNTHETIC"}}
        second = {"name": "auxiliary_echo", "arguments": {"foo1": "SYNTHETIC", "foo2": "PRIVATE"}}
        output = {"tool_calls": [{"function": {"name": first["name"], "arguments": json.dumps(first["arguments"])}}],
                  "generated_text": "".join("<tool_call>" + json.dumps(item) + "</tool_call>" for item in [first, second])}
        result = AUDIT.generated_call_link(output, engine_id="vllm", parallel_tool_calls=False)
        self.assertEqual(result["generated_calls_not_returned_by_native_parallel_filter"], 1)
        with self.assertRaises(ValueError): AUDIT.generated_call_link(output, engine_id="SGLang")
        output["tool_calls"][0]["function"]["name"] = second["name"]
        with self.assertRaises(ValueError): AUDIT.generated_call_link(output, engine_id="vllm")

    def packages(self):
        dependencies = [{"path": str(path.relative_to(ROOT)), "sha256": AUDIT.digest(path)} for path in [AUDIT.RULES, AUDIT.PROTOCOL_PATH]]
        metadata = {"run_id": "SYNTHETIC-AUDIT-TEST", "protocol_id": "ama-public-http-v1", "engine": {"id": "SGLang"},
                    "code_dependencies": dependencies, "model": {"format": "safetensors", "runtime_dtype": "float32"}}
        start = {"stage": "ama_run_started", "raw": {"dataset_snapshot": {"fixture": "SYNTHETIC"},
                 "source_provenance_snapshot": {"source": "SYNTHETIC"}, "request_plan": list(range(128))}}
        events = [start] + [{"stage": "ama_request_started", "raw": {"request": self.request()}} for _ in range(128)]
        first = SimpleNamespace(metadata=metadata, events=events, seal={"events_sha256": "a" * 64})
        return first, copy.deepcopy(first)

    def test_identical_baseline_and_disabled_top_k_alias_pass(self):
        first, second = self.packages()
        for event in second.events[1:]:
            event["raw"]["request"].update(top_k=0, min_p=0, cache_prompt=False)
        self.assertEqual(AUDIT.baseline_compare(first, second)["semantically_identical_request_inputs"], 128)

    def test_baseline_dataset_provenance_and_schedule_drift_rejected(self):
        for key in ("dataset_snapshot", "source_provenance_snapshot", "request_plan"):
            first, second = self.packages()
            second.events[0]["raw"][key] = {"changed": True}
            with self.subTest(key=key), self.assertRaises(ValueError): AUDIT.baseline_compare(first, second)

    def test_single_baseline_input_drift_rejected(self):
        first, second = self.packages()
        second.events[63]["raw"]["request"]["temperature"] = 0.9
        with self.assertRaises(ValueError): AUDIT.baseline_compare(first, second)

    def test_effective_sampling_aliases_and_mismatch(self):
        raw = {"effective_sampling_params": {"max_new_tokens": 192, "sampling_seed": 20260911, "temperature": 0.2,
                "top_p": 1.0, "top_k": -1, "repetition_penalty": 1.0, "n": 1}}
        native = [{"raw": {}}, {"raw": {}}, {"raw": raw}]
        self.assertTrue(AUDIT.sampling_check(self.request(), native)["effective_values_directly_observed"])
        raw["effective_sampling_params"]["temperature"] = 0.9
        with self.assertRaises(ValueError): AUDIT.sampling_check(self.request(), native)

    def test_vllm_static_conversion_not_claimed_as_runtime_observation(self):
        native = [{"raw": {}}, {"raw": {}}, {"raw": {}}]
        result = AUDIT.sampling_check(self.request(), native, engine_id="vllm")
        self.assertFalse(result["effective_values_directly_observed"])
        self.assertEqual(result["verified"]["min_p"], 0.0)
        self.assertEqual(result["verified"]["seed"], 20260911)
        with self.assertRaises(ValueError): AUDIT.sampling_check(self.request(), native, engine_id="unknown")

    def test_llamacpp_verbose_aliases_float32_and_cache(self):
        effective = {"max_tokens": 192, "n_predict": 192, "seed": 20260911, "temperature": 0.20000000298023224,
                     "top_p": 1.0, "top_k": 0, "min_p": 0, "repeat_penalty": 1.0,
                     "samplers": ["temperature"], "dynatemp_range": 0, "mirostat": 0}
        verbose = {"generation_settings": effective, "content": "No call", "truncated": False}
        response = {"__verbose": verbose, "usage": {"prompt_tokens_details": {"cached_tokens": 0}}}
        native = [{"raw": {}}, {"raw": {}}, {"raw": {"response": response}}]
        self.assertTrue(AUDIT.sampling_check(self.request(), native, engine_id="llamacpp")["effective_values_directly_observed"])
        effective["n_predict"] = 193
        with self.assertRaises(ValueError): AUDIT.sampling_check(self.request(), native)
        effective["n_predict"] = 192
        verbose["truncated"] = True
        with self.assertRaises(ValueError): AUDIT.sampling_check(self.request(), native)

    def test_three_valued_aggregation_preserves_false_and_unknown(self):
        self.assertIs(AUDIT.all_three([True, True]), True)
        self.assertIsNone(AUDIT.all_three([True, None]))
        self.assertIs(AUDIT.all_three([False, None]), False)
        with self.assertRaises(ValueError): AUDIT.all_three([])

    def test_parity_projection_ignores_only_response_id_and_timing(self):
        response = {"id": "first", "created": 123, "prompt_token_ids": [1, 2], "choices": [{"finish_reason": "tool_calls", "token_ids": [3, 4],
                    "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "call-first", "type": "function", "function": {"name": "echo_get", "arguments": '{"foo1":"SYNTHETIC"}'}}]}}]}
        second = copy.deepcopy(response)
        second.update(id="second", created=456)
        second["choices"][0]["message"]["tool_calls"][0]["id"] = "call-second"
        self.assertEqual(AUDIT.parity_projection(response), AUDIT.parity_projection(second))
        second["choices"][0]["token_ids"] = [3, 5]
        self.assertNotEqual(AUDIT.parity_projection(response), AUDIT.parity_projection(second))

    def test_parity_requires_actual_output_token_ids(self):
        response = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "text"}}]}
        with self.assertRaises(ValueError): AUDIT.parity_projection(response)

    def test_parity_keeps_literal_argument_spacing(self):
        response = {"choices": [{"finish_reason": "tool_calls", "token_ids": [1], "message": {"role": "assistant", "tool_calls": [{"type": "function", "function": {"name": "echo_get", "arguments": '{"foo1":"x"}'}}]}}]}
        second = copy.deepcopy(response)
        second["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"foo1": "x"}'
        self.assertNotEqual(AUDIT.parity_projection(response), AUDIT.parity_projection(second))

    def manifest_fixture(self, directory):
        path = Path(directory) / "logging-points.json"
        manifest = Path(directory) / "native-build-manifest.json"
        data = {"engine_id": "SYNTHETIC", "validated_files": [{"path": "synthetic.py", "sha256": "a" * 64}]}
        manifest.write_text(json.dumps(data), encoding="utf-8")
        descriptor = {"path": "mapping/SYNTHETIC/native-build-manifest.json", "sha256": AUDIT.digest(manifest)}
        metadata = {"native_build_manifest": descriptor, "native_build": data}
        entry = {**descriptor, "source_snapshot": manifest.name}
        return path, metadata, entry

    def test_mapping_explicit_manifest_verified_against_sealed_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path, metadata, entry = self.manifest_fixture(directory)
            result = AUDIT.mapped_native_manifest(path, {"native_build_manifest": entry["source_snapshot"]}, metadata)
            self.assertEqual(result["resolution"], "explicit_native_build_manifest")
            metadata["native_build_manifest"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError): AUDIT.mapped_native_manifest(path, {"native_build_manifest": entry["source_snapshot"]}, metadata)

    def test_mapping_dependency_manifest_verified_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path, metadata, entry = self.manifest_fixture(directory)
            mapping = {"code_dependency_snapshots": [entry]}
            before = copy.deepcopy(mapping)
            result = AUDIT.mapped_native_manifest(path, mapping, metadata)
            self.assertEqual(result["resolution"], "exact_code_dependency_snapshot")
            self.assertEqual(mapping, before)

    def test_mapping_missing_duplicate_wrong_identity_and_hash_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path, metadata, entry = self.manifest_fixture(directory)
            for entries in ([], [entry, entry], [{**entry, "path": "other-manifest.json"}], [{**entry, "sha256": "0" * 64}]):
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    AUDIT.mapped_native_manifest(path, {"code_dependency_snapshots": entries}, metadata)

    def test_mapping_manifest_content_and_snapshot_hash_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path, metadata, entry = self.manifest_fixture(directory)
            metadata["native_build"] = {"engine_id": "OTHER"}
            with self.assertRaises(ValueError): AUDIT.mapped_native_manifest(path, {"code_dependency_snapshots": [entry]}, metadata)

    def test_mapping_manifest_escape_not_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, metadata, entry = self.manifest_fixture(directory)
            for relative in ("../native-build-manifest.json", "/tmp/native-build-manifest.json"):
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    AUDIT.mapped_native_manifest(path, {"native_build_manifest": relative}, metadata)

    def network(self):
        return {"pid": 123, "observations": [{"phase": phase, "listeners": [{"address": "127.0.0.1", "port": 12345}]} for phase in ["healthy", "after_requests"]]}

    def test_network_optional_shutdown_absence_is_explicit_unknown(self):
        result = AUDIT.check_network_observations(self.network())
        self.assertEqual(result["shutdown_status"], "not_recorded")
        self.assertIsNone(result["server_exit_code"])
        self.assertTrue(result["all_observed_listeners_loopback"])

    def test_network_explicit_shutdown_validated(self):
        network = {**self.network(), "shutdown_requested_by_harness": True, "server_exit_code": 0}
        self.assertEqual(AUDIT.check_network_observations(network)["shutdown_status"], "observed")
        for field, value in (("server_exit_code", -9), ("shutdown_requested_by_harness", False), ("server_exit_code", False)):
            with self.subTest(field=field), self.assertRaises(ValueError): AUDIT.check_network_observations({**network, field: value})

    def test_network_half_shutdown_fields_rejected(self):
        for extra in ({"server_exit_code": 0}, {"shutdown_requested_by_harness": True}):
            with self.subTest(extra=extra), self.assertRaises(ValueError): AUDIT.check_network_observations({**self.network(), **extra})

    def test_network_missing_phase_and_nonlocal_listener_rejected(self):
        network = self.network()
        network["observations"].pop()
        with self.assertRaises(ValueError): AUDIT.check_network_observations(network)
        network = self.network()
        network["observations"][1]["listeners"][0]["address"] = "0.0.0.0"
        with self.assertRaises(ValueError): AUDIT.check_network_observations(network)

    def test_network_properties_observation_does_not_fake_listeners(self):
        network = self.network()
        network["observations"].append({"phase": "native_properties", "properties": {"model": "SYNTHETIC"}})
        self.assertEqual(AUDIT.check_network_observations(network)["listener_phases_verified"], ["healthy", "after_requests"])


if __name__ == "__main__":
    unittest.main()
