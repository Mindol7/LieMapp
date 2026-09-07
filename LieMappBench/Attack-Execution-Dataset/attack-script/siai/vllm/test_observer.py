"""Synthetic native-observer tests; no production evidence is generated.

The observer transports exact tensors to logger.py. The cheapest unit checks
guard profile exclusion, raw dtype fidelity, intervention locality, and the
single-request/process boundary before any native model execution.
"""
from __future__ import annotations

import importlib.util
import ast
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import torch


ROOT = next(p for p in Path(__file__).resolve().parents if (p / "LieMappBench").is_dir())
PATH = ROOT / "Instrumented-LIE/siai/vllm/vllm/liemapp_observer.py"


class Client:
    def __init__(self):
        self.events = []

    def emit(self, stage, raw, **kwargs):
        self.events.append({"stage": stage, "raw": raw, **kwargs})


class ObserverTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("synthetic_vllm_observer", PATH)
        self.observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.observer)
        self.client = Client()
        self.environment = patch.dict(os.environ, {
            "LIEMAPP_LOGGER_PATH": str(ROOT / "LieMappBench/Logging-Dataset/logger.py")})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def activate(self, zero=False):
        self.observer.activate({"request_id": "synthetic-unit-request"}, zero_visual=zero)
        self.observer._client = self.client
        self.addCleanup(self.observer.deactivate)

    def test_constructor_profile_is_completely_unobserved(self):
        self.observer.emit_tensor("encoder_input", object(), "synthetic")
        self.observer.capture_logits(object())
        self.observer.before_forward(object())
        self.observer.after_forward(object())
        self.assertEqual(self.client.events, [])

    def test_inactive_processor_hook_does_not_read_a_missing_image_key(self):
        source = (ROOT / "Instrumented-LIE/siai/vllm/vllm/model_executor/models/idefics3.py").read_text()
        tree = ast.parse(source)
        guards = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                  and isinstance(node.test, ast.Call)
                  and isinstance(node.test.func, ast.Attribute)
                  and node.test.func.attr == "active"
                  and any(isinstance(child, ast.Constant) and child.value == "processor_output"
                          for child in ast.walk(node))]
        self.assertEqual(len(guards), 1)
        code = compile(ast.fix_missing_locations(ast.Module(body=guards, type_ignores=[])),
                       "synthetic-inactive-processor-guard", "exec")
        exec(code, {"liemapp_observer": self.observer, "processed_data": {}})
        self.assertEqual(self.client.events, [])

    def test_zero_intervention_preserves_projection_and_logs_actual_consumed_rows(self):
        self.activate(zero=True)
        projected = torch.ones((2, 3), dtype=torch.float32)
        mask = torch.tensor([False, True, True])
        replaced = self.observer.before_merge([projected], mask)
        self.assertTrue(torch.equal(projected, torch.ones_like(projected)))
        self.assertEqual(int(torch.count_nonzero(replaced[0])), 0)
        fused = torch.tensor([[9.0, 9.0, 9.0], [0.0, 0.0, 0.0], [0.0, 0.0, 0.0]])
        self.observer.before_forward(fused)
        fused.fill_(99.0)  # Simulate an in-place implementation inside the decoder.
        self.observer.after_forward(fused)
        event = self.client.events[0]
        self.assertEqual(event["stage"], "decoder_input")
        self.assertTrue(event["raw"]["intervention"])
        self.assertEqual(event["tensors"]["values"].shape, (2, 3))
        self.assertEqual(float(event["tensors"]["values"].max()), 0)
        self.assertEqual(event["source"]["path"], str(Path(__file__).resolve()))

    def test_first_logits_are_not_replaced_by_later_token_logits(self):
        self.activate()
        self.observer.capture_logits(torch.tensor([[1.0, 2.0, 3.0]]))
        self.observer.capture_logits(torch.tensor([[99.0, 98.0, 97.0]]))
        output = SimpleNamespace(text="Synthetic output", token_ids=[1, 2],
                                 finish_reason="length", stop_reason=None)
        result = SimpleNamespace(outputs=[output], request_id="engine-unit", prompt_token_ids=[5])
        self.observer.finish_generation(result)
        event = self.client.events[-1]
        self.assertEqual(event["tensors"]["logits"].tolist(), [1.0, 2.0, 3.0])
        self.assertEqual(event["raw"]["generated_text"], "Synthetic output")
        self.assertEqual(event["raw"]["first_logits_source"]["logging_point_id"], "siai.vllm.first-token-logits")
        self.assertEqual(event["raw"]["generation_output_source"]["logging_point_id"], "siai.vllm.public-generate-result")

    def test_process_escape_and_overlapping_merge_fail_closed(self):
        self.activate()
        with patch.object(self.observer.os, "getpid", return_value=-1):
            with self.assertRaisesRegex(RuntimeError, "process boundary"):
                self.observer.active()
        self.observer.before_merge([torch.ones(1, 2)], torch.tensor([True]))
        with self.assertRaisesRegex(RuntimeError, "not consumed"):
            self.observer.before_merge([torch.ones(1, 2)], torch.tensor([True]))

    def test_nonrepresentable_dtype_is_not_silently_cast(self):
        self.activate()
        with self.assertRaisesRegex(RuntimeError, "losslessly"):
            self.observer.emit_tensor("encoder_input", torch.ones(2, dtype=torch.bfloat16), "synthetic")
        self.assertEqual(self.client.events, [])

    def test_sequential_request_activation_clears_previous_logits_and_mask(self):
        self.activate(zero=True)
        self.observer.capture_logits(torch.tensor([[1.0, 2.0]]))
        self.observer.before_merge([torch.ones(1, 2)], torch.tensor([True]))
        self.observer.deactivate()
        self.observer.activate({"request_id": "second-synthetic-request"})
        self.assertIsNone(self.observer._first_logits)
        self.assertIsNone(self.observer._pending_mask)
        self.assertFalse(self.observer._zero_visual)
        self.assertEqual(self.observer._context["request_id"], "second-synthetic-request")

    def test_missing_logits_and_decoder_shape_mismatch_fail_closed(self):
        self.activate()
        with self.assertRaisesRegex(RuntimeError, "Incomplete"):
            self.observer.finish_generation(SimpleNamespace())
        self.observer.before_merge([torch.ones(1, 2)], torch.tensor([True]))
        with self.assertRaisesRegex(RuntimeError, "decoder shape"):
            self.observer.before_forward(torch.ones(2, 2))


if __name__ == "__main__":
    unittest.main()
