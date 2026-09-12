"""MLC native API adaptation must not alter frozen tasks or HTTP semantics."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm"
SPEC = importlib.util.spec_from_file_location("test_ama_mlc_protocol", HERE / "mlc_protocol.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SOURCE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/SGLang/public-http-v1"


class MLCProtocolTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads((SOURCE / "fixtures.json").read_text())
        self.family = self.dataset["families"][0]
        self.records = P.base_protocol.tools_for(self.dataset, self.family, "attractive_targeted")
        self.call = {"id": "native-1", "type": "function", "function": {
            "name": self.records[0]["function"]["name"], "arguments": {"foo1": "public-test"}}}

    def test_native_protocol_is_explicit_version(self):
        self.assertNotEqual(P.PROTOCOL_ID, P.base_protocol.PROTOCOL_ID)
        P.validate_dataset(self.dataset)

    def test_frozen_schedule_same_128(self):
        args = SimpleNamespace(split="held_out", task=[], seeds=[20260911, 20260912],
            orders=["normal_first", "sink_first"], schedule_seed=20260911, limit=None)
        self.assertEqual(len(P.schedule(self.dataset, args)), 128)
        self.assertEqual(P.schedule(self.dataset, args), P.base_protocol.schedule(self.dataset, args))

    def test_https_safety_implementation_shared_unchanged(self):
        for name in ("public_get", "wire_request", "receipt_matches", "classify_response",
                     "verify_provenance", "execution_coverage", "metrics", "provenance_result"):
            self.assertIs(getattr(P, name), getattr(P.base_protocol, name))

    def test_workbook_predicates_unchanged(self):
        parent = json.loads((ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json").read_text())
        child = json.loads((ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/public-http-native-v1/conditions.json").read_text())
        self.assertEqual(child["conditions"], parent["conditions"])
        self.assertEqual(child["library"], parent["library"])
        self.assertEqual(child["protocol_id"], P.PROTOCOL_ID)

    def test_native_dict_arguments_remain_raw_dict(self):
        result = P.parsed_call(self.call, self.records, set())
        self.assertIsNone(result["blocked_reason"])
        self.assertEqual(result["raw_arguments"], {"foo1": "public-test"})
        self.assertEqual(result["arguments"], result["raw_arguments"])
        self.assertIsNot(result["arguments"], result["raw_arguments"])

    def test_json_string_not_mislabelled_as_native_dict(self):
        self.call["function"]["arguments"] = '{"foo1":"public-test"}'
        result = P.parsed_call(self.call, self.records, set())
        self.assertIsNotNone(result["blocked_reason"])
        self.assertFalse(result["actually_invoked"])

    def test_invalid_fields_never_repaired(self):
        self.call["function"]["arguments"]["unknown"] = "not-allowed"
        result = P.parsed_call(self.call, self.records, set())
        self.assertIsNotNone(result["blocked_reason"])
        self.assertIn("unknown", result["raw_arguments"])

    def test_call_budget_preserved(self):
        result = P.parsed_call(self.call, self.records, set(), 1)
        self.assertIn("one-external-call", result["blocked_reason"])

    def test_missing_argument_no_canary_injection(self):
        self.call["function"] = {"name": self.records[1]["function"]["name"], "arguments": {"foo1": "public-test"}}
        result = P.parsed_call(self.call, self.records, set())
        self.assertIsNotNone(result["blocked_reason"])
        self.assertNotIn("foo2", result["arguments"])

    def test_native_ast_exact_literal_kwargs(self):
        P.audit_python_calls([self.call["function"]["name"] + "(foo1='public-test')"], [self.call])

    def test_native_ast_literal_list_of_call_strings(self):
        P.audit_python_calls([repr([self.call["function"]["name"] + "(foo1='public-test')"])], [self.call])

    def test_native_ast_positional_loss_rejected(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls([self.call["function"]["name"] + "('lost', foo1='public-test')"], [self.call])

    def test_native_ast_duplicate_keyword_loss_rejected(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls([self.call["function"]["name"] + "(foo1='lost', foo1='public-test')"], [self.call])

    def test_native_ast_dict_expansion_rejected(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls([self.call["function"]["name"] + "(**{'foo1':'public-test'})"], [self.call])

    def test_native_ast_different_argument_rejected(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls([self.call["function"]["name"] + "(foo1='different')"], [self.call])

    def test_native_ast_never_evaluates_generated_code(self):
        with self.assertRaises(ValueError):
            P.audit_python_calls([self.call["function"]["name"] + "(foo1=__import__('os').getcwd())"], [self.call])

    def test_no_call_no_completion_fabrication(self):
        P.audit_python_calls(["I will not call a tool."], [])
        self.assertFalse(P.execution_coverage([], []))
        self.assertFalse(P.provenance_result([], [], [])["all_selected_public_calls_confirmed"])

    def test_explicit_named_control_translation(self):
        payload = {"tools": [{"function": {"name": "echo_get"}}], "tool_choice": "required"}
        self.assertEqual(P.expected_native_choice(payload), {"type": "function", "function": {"name": "echo_get"}})
        payload["tools"].append({"function": {"name": "another"}})
        with self.assertRaises(ValueError):
            P.expected_native_choice(payload)

    def test_auto_not_forced(self):
        self.assertEqual(P.expected_native_choice({"tool_choice": "auto"}), "auto")


if __name__ == "__main__":
    unittest.main()
