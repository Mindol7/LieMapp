"""Acceptance rules, not simulated evidence for model/compiler equivalence."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


K = load("mlc_cpu_kernel_tests", "verify_cpu_kernels.py")
V = K.V
F = load("mlc_cpu_validation_finalizer_tests", "verify_cpu_validation.py")


class NumericalAcceptanceTests(unittest.TestCase):
    def compare(self, left, right):
        return K.numeric_comparison(np.asarray(left, dtype=np.float32),
                                    np.asarray(right, dtype=np.float32), V.SPECIFICATION["kernel_float32"])

    def test_exact_bits_reported(self):
        result = self.compare([1, 0, -1], [1, 0, -1])
        self.assertTrue(result["passed"])
        self.assertTrue(result["bitwise_equal"])
        self.assertEqual(result["max_absolute_error"], 0)

    def test_tolerance_is_fixed_absolute_plus_relative(self):
        self.assertTrue(self.compare([1], [1.00015])["passed"])
        self.assertFalse(self.compare([1], [1.0003])["passed"])
        self.assertFalse(self.compare([0], [0.00011])["passed"])

    def test_nonfinite_cannot_pass_even_when_identical(self):
        with np.errstate(invalid="ignore"):
            for value in (float("nan"), float("inf"), -float("inf")):
                self.assertFalse(self.compare([value], [value])["passed"])

    def test_shape_and_dtype_cannot_change(self):
        self.assertFalse(self.compare([1], [[1]])["passed"])
        self.assertFalse(K.numeric_comparison(np.array([1], np.float32), np.array([1], np.float64),
                                              V.SPECIFICATION["kernel_float32"])["passed"])

    def test_integer_values_are_exact(self):
        baseline = np.array([100000000], dtype=np.int64)
        self.assertFalse(K.numeric_comparison(baseline, baseline + 1, V.SPECIFICATION["kernel_float32"])["passed"])

    def test_one_failed_value_fails_entire_tensor(self):
        left, right = np.zeros(1000, dtype=np.float32), np.zeros(1000, dtype=np.float32)
        right[-1] = 1
        self.assertFalse(K.numeric_comparison(left, right, V.SPECIFICATION["kernel_float32"])["passed"])


class NativeScoreAcceptanceTests(unittest.TestCase):
    def scores(self, token="a", logprob=-1.0):
        return {"content": [{"token": token, "logprob": logprob, "top_logprobs": []}]}

    def compare(self, left, right):
        return V.compare_scores(left, right, V.SPECIFICATION["model_available_logprobs"])

    def test_native_score_values_toleranced(self):
        self.assertTrue(self.compare(self.scores(), self.scores(logprob=-1.001))["passed"])
        self.assertFalse(self.compare(self.scores(), self.scores(logprob=-1.003))["passed"])

    def test_token_identity_is_not_ignored(self):
        with self.assertRaises(ValueError):
            self.compare(self.scores(), self.scores(token="b"))

    def test_missing_scores_are_not_assumed_pass(self):
        for value in ({}, None, {"content": []}):
            with self.assertRaises(ValueError):
                self.compare(value, value)

    def test_boolean_nan_infinite_scores_rejected(self):
        for value in (True, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                self.compare(self.scores(), self.scores(logprob=value))

    def test_top_candidate_order_preserved(self):
        left = self.scores()
        left["content"][0]["top_logprobs"] = [{"token": "a", "logprob": -1.}, {"token": "b", "logprob": -2.}]
        right = copy.deepcopy(left)
        right["content"][0]["top_logprobs"].reverse()
        with self.assertRaises(ValueError):
            self.compare(left, right)


class PreregistrationTests(unittest.TestCase):
    def test_policy_cannot_be_reinterpreted_after_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registration.json"
            document = {"specification": copy.deepcopy(V.SPECIFICATION)}
            path.write_text(json.dumps(document))
            V.validate_registration(path)
            document["specification"]["kernel_float32"]["atol"] = 0.1
            path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                V.validate_registration(path)

    def test_declared_shapes_cover_channel_and_reduction_tails(self):
        self.assertEqual(V.SPECIFICATION["kernel_dynamic_n"], [1, 2, 7, 16, 31])
        shapes = V.SPECIFICATION["synthetic_matmul_shapes"]
        self.assertTrue(any(n % 8 for _, n, _ in shapes))
        self.assertTrue(any(k % 8 for _, _, k in shapes))
        self.assertEqual(len(V.SPECIFICATION["model_cases"]), 2)


class SupplementalScoreSealingTests(unittest.TestCase):
    def reject_policy(self, specification):
        with tempfile.TemporaryDirectory() as temporary:
            registration = Path(temporary) / "registration.json"
            comparison = Path(temporary) / "comparison.json"
            registration.write_text(json.dumps({"specification": specification}))
            comparison.write_text("{}")
            with self.assertRaises(ValueError):
                F.score_evidence(registration, comparison, {}, {})

    def policy(self):
        value = copy.deepcopy(V.SPECIFICATION)
        value["policy_id"] = "ama-mlc-cpu-equivalence-native-scores-v1"
        value["model_settings"].update(temperature=1.0, max_tokens=1)
        return value

    def test_greedy_registration_cannot_be_called_nondegenerate_scores(self):
        self.reject_policy(copy.deepcopy(V.SPECIFICATION))

    def test_actual_probabilistic_setting_is_mandatory(self):
        value = self.policy()
        value["model_settings"]["temperature"] = 0.0
        self.reject_policy(value)

    def test_final_seal_rejects_relaxed_score_tolerance(self):
        value = self.policy()
        value["model_available_logprobs"]["atol"] = 0.1
        self.reject_policy(value)


if __name__ == "__main__":
    unittest.main()
