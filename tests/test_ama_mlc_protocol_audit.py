"""Independent MLC protocol contract checks; no model or network execution."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm"
spec = importlib.util.spec_from_file_location("mlc_protocol_independent_tests", SCRIPT / "mlc_protocol.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class MLCProtocolAuditTests(unittest.TestCase):
    def call(self, arguments=None, name="echo_get", identifier="test-call"):
        return {"id": identifier, "type": "function", "function": {
            "name": name, "arguments": {"foo1": "literal-value"} if arguments is None else arguments}}

    def record(self):
        return {"internal_id": "normal_echo", "function": {"name": "echo_get", "description": "test",
                "parameters": {"type": "object", "properties": {"foo1": {"type": "string"}},
                               "required": ["foo1"], "additionalProperties": False}}}

    def test_https_implementation_is_exact_frozen_function(self):
        for name in ("public_get", "wire_request", "receipt_matches", "classify_response"):
            self.assertIs(getattr(P, name), getattr(P.base_protocol, name))

    def test_predicates_and_workbook_definitions_match_parent(self):
        parent = json.loads((ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json").read_text())
        variant = json.loads((ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/public-http-native-v1/conditions.json").read_text())
        self.assertEqual(variant["library"], parent["library"])
        self.assertEqual(variant["conditions"], parent["conditions"])

    def test_dict_arguments_remain_unmodified(self):
        call = self.call()
        original = copy.deepcopy(call)
        result = P.parsed_call(call, [self.record()], set())
        self.assertIsNone(result["blocked_reason"])
        self.assertEqual(result["raw_arguments"], original["function"]["arguments"])
        self.assertEqual(result["arguments"], original["function"]["arguments"])
        self.assertEqual(call, original)
        self.assertFalse(result["actually_invoked"])

    def test_no_string_to_dict_repair(self):
        result = P.parsed_call(self.call('{"foo1":"literal-value"}'), [self.record()], set())
        self.assertIsNotNone(result["blocked_reason"])
        self.assertIsNone(result["arguments"])

    def test_no_missing_parameter_or_canary_injection(self):
        result = P.parsed_call(self.call({}), [self.record()], set())
        self.assertIsNotNone(result["blocked_reason"])
        self.assertEqual(result["raw_arguments"], {})
        self.assertEqual(result["arguments"], {})

    def test_second_call_never_gets_network_budget(self):
        result = P.parsed_call(self.call(), [self.record()], set(), 1)
        self.assertIn("one-external-call", result["blocked_reason"])
        self.assertFalse(result["actually_invoked"])

    def test_outside_allowlist_and_duplicate_id_blocked(self):
        for call, seen in ((self.call(name="unlisted"), set()), (self.call(), {"test-call"})):
            result = P.parsed_call(call, [self.record()], seen)
            self.assertIsNotNone(result["blocked_reason"])

    def test_python_keyword_call_and_native_dict_correspond(self):
        P.audit_python_calls(['echo_get(foo1="literal-value")'], [self.call()])

    def test_multiple_native_call_strings_preserved_in_order(self):
        calls = [self.call(), self.call({"foo1": "second"}, identifier="test-second")]
        text = repr(['echo_get(foo1="literal-value")', 'echo_get(foo1="second")'])
        P.audit_python_calls([text], calls)
        with self.assertRaises(ValueError):
            P.audit_python_calls([text], list(reversed(calls)))

    def test_native_parser_loss_and_nonliteral_argument_rejected(self):
        examples = [
            'echo_get("discarded", foo1="literal-value")',
            'echo_get(foo1="discarded", foo1="literal-value")',
            'echo_get(**{"foo1":"literal-value"})',
            'echo_get(foo1=unexecuted_function())',
            'other(foo1="literal-value")',
            'echo_get(foo1="changed")',
        ]
        for text in examples:
            with self.subTest(text=text), self.assertRaises(ValueError):
                P.audit_python_calls([text], [self.call()])

    def test_no_call_parser_errors_are_retained(self):
        for text in ("I cannot select a function.", '<tool_call>{"name":"echo_get"}</tool_call>'):
            P.audit_python_calls([text], [])

    def test_actual_native_positional_loss_is_blocked_not_removed(self):
        call = self.call()
        issue = P.audit_python_calls(['echo_get("discarded", foo1="literal-value")'],
                                     [call], allow_loss=True)
        result = P.parsed_call(call, [self.record()], set(), native_parse_issue=issue)
        self.assertIn("positional", result["blocked_reason"])
        self.assertFalse(result["actually_invoked"])
        self.assertEqual(result["arguments"], {"foo1": "literal-value"})

    def test_actual_native_duplicate_loss_is_blocked(self):
        issue = P.audit_python_calls(['echo_get(foo1="first", foo1="literal-value")'],
                                     [self.call()], allow_loss=True)
        self.assertIn("duplicate", issue)

    def test_allow_loss_never_accepts_different_actual_dictionary(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls(['echo_get("discarded", foo1="changed")'], [self.call()], allow_loss=True)

    def test_fixed_choice_only_accepts_one_candidate(self):
        payload = {"tool_choice": "required", "tools": [{"function": {"name": "echo_get"}}]}
        self.assertEqual(P.expected_native_choice(payload), {"type": "function", "function": {"name": "echo_get"}})
        payload["tools"] *= 2
        with self.assertRaises(ValueError):
            P.expected_native_choice(payload)


class MLCNativeEvidenceBindingAuditTests(unittest.TestCase):
    """Synthetic evidence-unit tests only; these are never experiment artifacts."""

    def example(self):
        tool = {"type": "function", "function": {"name": "echo_get", "description": "test-description",
                "parameters": {"type": "object", "properties": {"foo1": {"type": "string"}},
                               "required": ["foo1"], "additionalProperties": False}}}
        payload = {"model": "local-ama-model", "tools": [tool],
                   "messages": [{"role": "user", "content": "literal task"}],
                   "tool_choice": "auto", "stream": False, "n": 1, "temperature": 0.2,
                   "top_p": 1.0, "max_tokens": 192, "seed": 20260911,
                   "parallel_tool_calls": False, "liemapp_request_id": "unit-test-id", "liemapp_context": {}}
        effective = {key: value for key, value in payload.items()
                     if key not in {"parallel_tool_calls", "liemapp_request_id", "liemapp_context"}}
        effective["request_id"] = "unit-test-id"
        parsed = {key: value for key, value in effective.items() if key != "request_id"}
        call = {"id": "unit-call", "type": "function", "function": {
            "name": "echo_get", "arguments": {"foo1": "literal-value"}}}
        response = {"choices": [{"message": {"role": "assistant", "tool_calls": [call]},
                                  "finish_reason": "tool_calls"}]}
        cfg = {key: payload[key] for key in ("temperature", "top_p", "max_tokens", "seed")}
        native_cfg = {**cfg, "repetition_penalty": 1.0}
        intake = {"request_id": "unit-test-id", "submitted_request": copy.deepcopy(payload),
                  "effective_request": copy.deepcopy(effective), "parsed_request": copy.deepcopy(parsed),
                  "tools": copy.deepcopy(payload["tools"]), "messages": copy.deepcopy(payload["messages"]),
                  "tool_choice": "auto", "tools_count": 1, "http_path": "/v1/chat/completions", "stream": False,
                  "adaptations": [{"field": "parallel_tool_calls", "submitted": False,
                                    "effective": "not a native MLC argument"}]}
        rendered = {"request_id": "unit-test-id", "tools_count": 1, "input_token_ids": [1, 2],
                    "rendered_prompt": "echo_get test-description", "generation_config": cfg}
        output = {"request_id": "unit-test-id", "http_status": 200, "response": response,
                  "response_text": json.dumps(response), "tool_calls": [call],
                  "native_generation_config": native_cfg, "native_generation_config_json": json.dumps(native_cfg),
                  "output_token_ids": [3], "generated_texts_before_parser": ['echo_get(foo1="literal-value")']}
        records = [{"function": tool["function"]}]
        events = [{"stage": stage, "raw": raw} for stage, raw in zip(P.NATIVE_STAGES, (intake, rendered, output))]
        return events, payload, response, records

    def test_complete_native_binding_passes(self):
        P.check_native(*self.example())

    def test_changed_effective_native_request_rejected(self):
        events, payload, response, records = self.example()
        events[0]["raw"]["effective_request"]["temperature"] = 0.3
        with self.assertRaises(ValueError):
            P.check_native(events, payload, response, records)

    def test_changed_parsed_request_rejected(self):
        events, payload, response, records = self.example()
        events[0]["raw"]["parsed_request"]["messages"][0]["content"] = "different task"
        with self.assertRaises(ValueError):
            P.check_native(events, payload, response, records)

    def test_missing_adaptation_rejected(self):
        events, payload, response, records = self.example()
        events[0]["raw"]["adaptations"] = []
        with self.assertRaises(ValueError):
            P.check_native(events, payload, response, records)

    def test_unobserved_native_output_tokens_rejected(self):
        events, payload, response, records = self.example()
        events[2]["raw"]["output_token_ids"] = []
        with self.assertRaises(ValueError):
            P.check_native(events, payload, response, records)

    def test_cxx_sampler_setting_change_rejected(self):
        events, payload, response, records = self.example()
        cfg = events[2]["raw"]["native_generation_config"]
        cfg["repetition_penalty"] = 1.05
        events[2]["raw"]["native_generation_config_json"] = json.dumps(cfg)
        with self.assertRaises(ValueError):
            P.check_native(events, payload, response, records)


if __name__ == "__main__":
    unittest.main()
