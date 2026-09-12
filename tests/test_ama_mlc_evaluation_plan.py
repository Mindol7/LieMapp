"""Replay checks for the fixed MLC evaluation plan; no inference or network."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm"
spec = importlib.util.spec_from_file_location("mlc_plan_tests", HERE / "mlc_protocol.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class MLCEvaluationPlanTests(unittest.TestCase):
    def example(self):
        plan_path = HERE / "evaluation-plan.json"
        plan = json.loads(plan_path.read_text())
        dataset = json.loads((ROOT / plan["dataset"]["path"]).read_text())
        expected = plan["evaluation"]
        protocol = {"split": "held_out", "task": [], "limit": None,
                    **{key: expected[key] for key in ("seeds", "orders", "schedule_seed")},
                    "request_settings": {key: expected[key] for key in ("temperature", "top_p", "max_tokens")},
                    "repetition_penalty": 1.0}
        descriptor = {"path": str(plan_path.relative_to(ROOT)), "sha256": P.digest(plan_path)}
        metadata = {"evaluation_plan": descriptor, "code_dependencies": [copy.deepcopy(descriptor)],
                    "dataset": {"sha256": plan["dataset"]["sha256"]}, "protocol": protocol}
        return metadata, dataset, P.schedule(dataset, SimpleNamespace(**protocol))

    def test_exact_full_plan_passes(self):
        metadata, dataset, jobs = self.example()
        self.assertEqual(len(jobs), 128)
        P.verify_evaluation_plan(metadata, dataset, jobs)

    def test_truncated_or_changed_cohorts_rejected(self):
        metadata, dataset, jobs = self.example()
        for changed in (jobs[:-1], [jobs[0]] * 128):
            with self.assertRaises(ValueError):
                P.verify_evaluation_plan(metadata, dataset, changed)

    def test_changed_sampler_or_schedule_rejected(self):
        for key, value in (("seeds", [7, 8]), ("task", ["echo-test"]), ("limit", 128),
                           ("repetition_penalty", 1.05)):
            metadata, dataset, jobs = self.example()
            metadata["protocol"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.verify_evaluation_plan(metadata, dataset, jobs)
        metadata, dataset, jobs = self.example()
        metadata["protocol"]["request_settings"]["temperature"] = 0
        with self.assertRaises(ValueError):
            P.verify_evaluation_plan(metadata, dataset, jobs)

    def test_unbound_plan_rejected(self):
        metadata, dataset, jobs = self.example()
        metadata["code_dependencies"] = []
        with self.assertRaises(ValueError):
            P.verify_evaluation_plan(metadata, dataset, jobs)

    def test_development_can_use_limited_schedule(self):
        metadata, dataset, jobs = self.example()
        metadata["protocol"]["split"] = "development"
        P.verify_evaluation_plan(metadata, dataset, jobs[:4])
