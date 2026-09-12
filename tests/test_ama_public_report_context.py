"""Offline presentation checks; no native inference or external API calls."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/shared/context_public_report.py"
SPEC = importlib.util.spec_from_file_location("ama_public_report_context_test", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicReportContextTests(unittest.TestCase):
    def example(self, engine="arbitrary-engine", confirmed=True, unmatched=False):
        context = {"request_id": "test-request", "variant": "attractive_targeted", "control": "none"}
        finished = {"context": context, "raw": {
            "public_calls_confirmed": int(confirmed), "blocked_calls": int(not confirmed),
            "unconfirmed_calls": 0, "attacker_executed": confirmed,
            "synthetic_canary_transferred": confirmed and not unmatched}}
        events = [finished, {"stage": "ama_run_started", "raw": {"dataset_snapshot": {
            "synthetic_profile": {"private_token": "LIEMAPP_SYNTHETIC_PRIVATE_TEST"}}}},
            {"stage": "ama_tool_provenance", "context": context, "raw": {
                "all_selected_platform_origins_verified": True,
                "all_selected_public_calls_confirmed": confirmed}}]
        finished["stage"] = "ama_request_finished"
        if unmatched:
            events.append({"stage": "ama_tool_call_outcome", "event_id": "outcome-test", "context": context,
                           "raw": {"internal_id": "attack_role_echo", "actually_invoked": confirmed,
                                   "synthetic_canary_received": False, "arguments": {"foo2": "synthetic-other"}}})
        package = SimpleNamespace(metadata={"engine": {"id": engine, "name": engine},
            "model": {"name": "synthetic-model", "dtype": "float32", "quantization": "none"},
            "dataset": {"sha256": "synthetic-dataset-hash"}}, events=events,
            path=ROOT / ".evidence/raw/test/events.jsonl", seal={"events_sha256": "synthetic-event-hash"})
        return package, [finished]

    def render(self, **kwargs):
        with patch.object(MODULE.PROTOCOL, "verify_run", return_value=self.example(**kwargs)) as verify:
            result = MODULE.build(ROOT / ".evidence/raw/test", ROOT / ".evidence/supplements/test.json")
            verify.assert_called_once()
            return result

    def test_uses_arbitrary_engine_identity_and_verified_source(self):
        result = self.render()
        self.assertEqual(result["engine_id"], "arbitrary-engine")
        self.assertEqual(result["source_runs"][0]["events_sha256"], "synthetic-event-hash")
        self.assertEqual(result["derivation"]["primary_request_count"], 1)

    def test_zero_size_comparison_groups_are_preserved(self):
        rows = self.render()["tables"][0]["rows"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["requests"], 0)
        self.assertEqual(rows[1]["attack_calls"], "1/1")

    def test_blocked_calls_are_not_public_confirmations(self):
        result = self.render(confirmed=False)
        row = result["tables"][0]["rows"][1]
        self.assertEqual(row["public_calls"], 0)
        self.assertEqual(row["attack_calls"], "0/1")
        self.assertIn("호출 전 차단 1건", result["summary"][1])

    def test_nonexact_canary_is_descriptive_not_relabeled_success(self):
        result = self.render(unmatched=True)
        self.assertEqual(result["tables"][0]["rows"][1]["canary"], "0/1")
        record = result["confirmed_attack_calls_without_exact_canary"][0]
        self.assertEqual(record["event_id"], "outcome-test")
        self.assertEqual(record["foo2_raw"], "synthetic-other")

    def test_uninvoked_nonexact_proposal_is_not_counted_as_transfer(self):
        result = self.render(confirmed=False, unmatched=True)
        self.assertEqual(result["confirmed_attack_calls_without_exact_canary"], [])

    def test_verification_error_propagates_without_context(self):
        with patch.object(MODULE.PROTOCOL, "verify_run", side_effect=ValueError("Bad seal")):
            with self.assertRaisesRegex(ValueError, "Bad seal"):
                MODULE.build(ROOT, ROOT / "unused.json")


if __name__ == "__main__":
    unittest.main()
