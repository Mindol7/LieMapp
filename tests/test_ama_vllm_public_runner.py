"""Offline contract checks: no model, subprocess, download or external API call."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUN = load(BASE / "vllm/run_public.py", "test_vllm_public_runner")
PARITY = load(BASE / "vllm/verify_public_runtime.py", "test_vllm_public_parity")
SGLANG = load(BASE / "SGLang/run.py", "test_vllm_public_sglang_runner")
MAP = load(ROOT / "LieMappBench/Logging-Dataset/ama/vllm/public-http-v1/freeze_mapping.py", "test_vllm_public_mapping")
PROTOCOL = PARITY.PROTOCOL
DATASET = PROTOCOL.strict_json((RUN.SOURCE / "fixtures.json").read_text())


class PublicRunnerContract(unittest.TestCase):
    def test_original_runner_is_not_imported(self):
        self.assertEqual(RUN.SHARED, BASE / "shared/public_http_protocol.py")
        self.assertNotEqual(RUN.SHARED, BASE / "shared/ama_protocol.py")

    def test_exact_shared_dataset_paths(self):
        self.assertEqual(RUN.SOURCE, SGLANG.SOURCE)
        self.assertEqual(RUN.digest(RUN.SOURCE / "fixtures.json"), SGLANG.digest(SGLANG.SOURCE / "fixtures.json"))
        self.assertEqual(RUN.digest(RUN.SOURCE / "provenance.json"), DATASET["source_binding"]["provenance_sha256"])

    def test_exact_default_schedule_and_settings(self):
        ours, reference = RUN.parse_args([]), SGLANG.parse_args([])
        for field in ("split", "task", "limit", "seeds", "orders", "schedule_seed", "temperature", "max_tokens", "context_size", "threads"):
            self.assertEqual(getattr(ours, field), getattr(reference, field), field)
        jobs = PROTOCOL.schedule(DATASET, ours)
        self.assertEqual(jobs, PROTOCOL.schedule(DATASET, reference))
        self.assertEqual(len(jobs), 128)

    def test_development_four_requests(self):
        args = RUN.parse_args(["--split", "development", "--task", "echo-dev-02", "--seeds", "20260911", "--orders", "normal_first", "--limit", "4"])
        jobs = PROTOCOL.schedule(DATASET, args)
        self.assertEqual(len(jobs), 4)
        self.assertEqual({(j[4], j[5]) for j in jobs}, {("neutral", "none"), ("attractive_targeted", "none"), ("attractive_targeted", "fixed"), ("attractive_targeted", "metadata_review")})

    def test_invalid_arguments_rejected(self):
        for args in (["--threads", "7"], ["--temperature", "nan"], ["--timeout", "inf"], ["--limit", "0"],
                     ["--run-id", "../escape"], ["--seeds", "1", "1"], ["--seeds", "-1"],
                     ["--orders", "normal_first", "normal_first"], ["--task", "same", "--task", "same"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                RUN.parse_args(args)

    def test_model_is_legacy_pinned_manifest(self):
        model = PROTOCOL.strict_json((RUN.HERE / "model.json").read_text())
        self.assertEqual(model["revision"], "aa8e72537993ba99e69dfaafa59ed015b17504d1")
        self.assertEqual(model["runtime_dtype"], "float32")
        self.assertEqual(RUN.BUILD, ROOT / "LieMappBench/Logging-Dataset/ama/vllm/native-build-manifest.json")


class PublicParityContract(unittest.TestCase):
    def setUp(self):
        self.response = {"prompt_token_ids": [1, 2], "choices": [{"finish_reason": "tool_calls", "stop_reason": 3, "token_ids": [4, 5],
            "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "random", "type": "function", "function": {"name": "echo_get", "arguments": '{"foo1":"hello"}'}}]}}]}

    def test_exact_vllm_token_locations(self):
        result = PARITY.semantics(self.response)
        self.assertEqual(result["prompt_token_ids"], [1, 2])
        self.assertEqual(result["response_token_ids"], [4, 5])
        self.assertEqual(result["stop_reason"], 3)

    def test_missing_or_invalid_tokens_rejected(self):
        for field, value in (("prompt_token_ids", None), ("token_ids", []), ("token_ids", [True])):
            changed = copy.deepcopy(self.response)
            target = changed if field == "prompt_token_ids" else changed["choices"][0]
            target[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                PARITY.semantics(changed)

    def test_call_ids_ignored_but_literal_arguments_preserved(self):
        changed = copy.deepcopy(self.response)
        changed["choices"][0]["message"]["tool_calls"][0]["id"] = "another"
        self.assertEqual(PARITY.semantics(changed), PARITY.semantics(self.response))
        changed["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{ "foo1": "hello" }'
        self.assertNotEqual(PARITY.semantics(changed), PARITY.semantics(self.response))

    def test_development_payloads_use_unchanged_protocol_constructor(self):
        payloads = PARITY.payloads(DATASET, 20260911, 192)
        self.assertEqual(len(payloads), 2)
        for payload, records in payloads:
            self.assertTrue(payload["return_token_ids"])
            self.assertEqual(payload["liemapp_context"]["task_id"], "echo-dev-02")
            self.assertEqual(payload["liemapp_context"]["cohort"], "development")
            self.assertEqual(payload["temperature"], 0.0)
            self.assertEqual(payload["tools"], [{"type": "function", "function": r["function"]} for r in records])

    def test_disabled_mode_rejects_any_native_event(self):
        with self.assertRaises(ValueError):
            PARITY.verify_native([{"stage": "unexpected"}], {}, {}, "", [], False)


class PublicMappingContract(unittest.TestCase):
    def test_legacy_mapping_read_only_parent(self):
        self.assertEqual(MAP.LEGACY, ROOT / "LieMappBench/Logging-Dataset/ama/vllm")
        self.assertNotEqual(MAP.HERE, MAP.LEGACY)

    def test_all_sixteen_non_native_points_resolve(self):
        found = {}
        for path in MAP.EXPECTED_SOURCES:
            found.update(MAP.static_points(path, path))
        self.assertEqual(set(found), set(MAP.SPEC))
        self.assertEqual(len(found), 16)
        self.assertEqual(found["AMA-VLLM-RUN01"]["path"], str(BASE / "vllm/run_public.py"))
        self.assertEqual(found["AMA-HTTP-LP02"]["path"], str(BASE / "shared/public_http_protocol.py"))

    def test_legacy_native_points_can_be_preserved(self):
        old = PROTOCOL.strict_json((MAP.LEGACY / "logging-points.json").read_text())
        native = [p for p in old["logging_points"] if p["layer"] == "native_inference_engine"]
        self.assertEqual({p["logging_point_id"] for p in native}, {"AMA-VLLM-LP01", "AMA-VLLM-LP02", "AMA-VLLM-LP03"})
        for point in native:
            self.assertEqual(MAP.digest(point["source"]["path"]), point["source"]["sha256"])


if __name__ == "__main__":
    unittest.main()
