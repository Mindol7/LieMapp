"""Synthetic tests only: these fixtures are not research observations."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ANALYZER_PATH = Path(__file__).resolve().parents[1] / "LieMappAnalyzer" / "analyzer.py"
SPEC = importlib.util.spec_from_file_location("liemapp_analyzer_test_target", ANALYZER_PATH)
analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analyzer)

try:
    import numpy as np
except ImportError:
    np = None


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="liemapp-analyzer-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "synthetic_run"
        self.run.mkdir()
        self.events = []

    def event(self, stage="encode", raw=None, *, role="clean", pair_id="p1", transform="identity",
              request_id="r1", engine="synthetic-engine-a", scope="native_runtime", source=True):
        event = {
            "schema_version": "1.0.0", "event_id": f"synthetic-event-{len(self.events) + 1}",
            "run_id": "synthetic-unit-run", "sequence": len(self.events) + 1,
            "timestamp_utc": "2026-09-06T01:02:03.000000+00:00",
            "metadata": {"attack_id": "synthetic-attack", "engine": {"id": engine, "revision": "test"},
                         "model": {"id": "synthetic-model"}, "execution_scope": scope},
            "stage": stage,
            "context": {"request_id": request_id, "input_id": "i1", "role": role,
                        "pair_id": pair_id, "transform": transform},
            "source": {"path": "synthetic/source.cc", "function": "synthetic_encode", "line": 42,
                       "logging_point_id": "LP-test", "sha256": "1" * 64} if source else None,
            "raw": raw if raw is not None else {"ok": True}, "readable": {"ok": "NOT A RULE INPUT"},
            "artifacts": {}, "previous_event_hash": None,
        }
        self.events.append(event)
        return event

    def tensor(self, event, values, name="embedding"):
        path = self.run / f"{event['event_id']}-{name}.npy"
        array = np.asarray(values)
        np.save(path, array, allow_pickle=False)
        event["artifacts"][name] = {"path": path.name, "sha256": analyzer.file_sha256(path),
                                    "shape": list(array.shape), "dtype": str(array.dtype),
                                    "bytes": path.stat().st_size}

    def seal(self, status="completed"):
        previous = None
        for number, event in enumerate(self.events, 1):
            event["sequence"] = number
            event["previous_event_hash"] = previous
            event.pop("event_hash", None)
            event["event_hash"] = hashlib.sha256(analyzer.canonical_json(event)).hexdigest()
            previous = event["event_hash"]
        path = self.run / "events.jsonl"
        path.write_text("".join(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n"
                                for event in self.events), encoding="utf-8")
        (self.run / "seal.json").write_text(json.dumps({
            "schema_version": "1.0.0", "run_id": "synthetic-unit-run", "event_count": len(self.events),
            "last_event_hash": previous, "status": status, "events_sha256": analyzer.file_sha256(path),
            "reason": None if status == "completed" else "Synthetic unavailable dependency",
        }), encoding="utf-8")
        return path

    def rules(self, *rules):
        rule_path = self.root / "rules.json"
        rule_path.write_text(json.dumps({
            "attack_id": "synthetic-attack", "attack_name": "Synthetic test — not a real attack",
            "library": {"path": "synthetic.xlsx", "sha256": "0" * 64, "sheet": "test", "row": 1},
            "conditions": [{"id": f"AC{i + 1}", "kind": "AC", "text": "Synthetic condition",
                            "source_cell": "A1", "rule": rule} for i, rule in enumerate(rules)]
        }), encoding="utf-8")
        return rule_path

    def interpret(self, rule):
        return analyzer.RuleInterpreter(analyzer.EvidencePackage(self.seal())).evaluate(rule)

    @staticmethod
    def pair_rule(**updates):
        rule = {"op": "pairwise_tensor_distance", "metric": "l2",
                "left": {"select": {"stage": "encode", "context": {"role": "clean"}}, "artifact": "embedding"},
                "right": {"select": {"stage": "encode", "context": {"role": "attack"}}, "artifact": "embedding"},
                "join_by": ["context.pair_id", "context.transform"], "cmp": "gt", "value": 0}
        rule.update(updates)
        return rule

    def test_same_rule_and_analyzer_for_two_arbitrary_engines(self):
        rule = {"op": "compare", "select": {"stage": "encode"}, "field": "raw.ok", "cmp": "eq", "value": True}
        for engine in ("synthetic-engine-a", "entirely-different-engine-b"):
            with self.subTest(engine=engine):
                self.events = []
                self.event(engine=engine)
                result = analyzer.analyze(self.seal(), self.rules(rule), self.root / engine)
                self.assertIs(result["conditions"][0]["value"], True)
                self.assertEqual(result["metadata"]["engine"]["id"], engine)
                report = (self.root / engine / "report.md").read_text(encoding="utf-8")
                self.assertIn('"ok": true', report)
                self.assertIn("LP-test", report)

    def test_missing_event_and_count_zero_are_unknown(self):
        self.event()
        for rule in ({"op": "exists", "select": {"stage": "absent"}},
                     {"op": "count", "select": {"stage": "absent"}, "cmp": "eq", "value": 0}):
            self.assertIsNone(self.interpret(rule)["value"])

    def test_explicit_contrary_raw_is_false_readable_ignored(self):
        self.event(raw={"ok": False})["readable"] = {"ok": True}
        result = self.interpret({"op": "compare", "field": "raw.ok", "cmp": "eq", "value": True})
        self.assertIs(result["value"], False)

    def test_readable_comparison_and_selector_rejected(self):
        self.event()
        for rule in ({"op": "compare", "field": "readable.ok", "cmp": "eq", "value": True},
                     {"op": "exists", "select": {"readable": {"ok": True}}}):
            with self.assertRaises(analyzer.RuleError):
                self.interpret(rule)

    def test_missing_raw_and_null_are_unknown(self):
        self.event(raw={"null_field": None})
        for field in ("raw.absent", "raw.null_field"):
            self.assertIsNone(self.interpret({"op": "compare", "field": field, "cmp": "eq", "value": True})["value"])

    def test_boolean_is_not_integer(self):
        self.event(raw={"ok": True})
        self.assertIs(self.interpret({"op": "compare", "field": "raw.ok", "cmp": "eq", "value": 1})["value"], False)

    def test_runtime_rule_cannot_pass_on_static_review(self):
        self.event(scope="static_review")
        self.assertIsNone(self.interpret({"op": "exists", "scope": "runtime"})["value"])

    def test_join_does_not_combine_unrelated_requests(self):
        self.event(stage="encode", request_id="first")
        self.event(stage="decode", request_id="second")
        rule = {"op": "all", "join_by": ["context.request_id"],
                "rules": [{"op": "exists", "select": {"stage": "encode"}},
                          {"op": "exists", "select": {"stage": "decode"}}]}
        self.assertIsNone(self.interpret(rule)["value"])

    def test_join_allows_a_single_complete_request(self):
        self.event(stage="encode")
        self.event(stage="decode")
        rule = {"op": "all", "join_by": ["context.request_id"],
                "rules": [{"op": "exists", "select": {"stage": "encode"}},
                          {"op": "exists", "select": {"stage": "decode"}}]}
        self.assertIs(self.interpret(rule)["value"], True)

    def test_composite_select_is_applied_before_request_join(self):
        self.event(stage="encode", role="attack", request_id="attack-request")
        self.event(stage="decode", role="attack", request_id="attack-request")
        self.event(stage="unrelated", role="clean", request_id="clean-request")
        rule = {"op": "all", "select": {"context": {"role": "attack"}},
                "join_by": ["context.request_id"], "reduce": "all",
                "rules": [{"op": "exists", "select": {"stage": "encode"}},
                          {"op": "exists", "select": {"stage": "decode"}}]}
        self.assertIs(self.interpret(rule)["value"], True)
        # A second attack request is incomplete and cannot borrow the first decode.
        self.event(stage="encode", role="attack", request_id="second-attack-request")
        self.assertIsNone(self.interpret(rule)["value"])
        rule["select"]["context"]["role"] = "absent-role"
        self.assertIsNone(self.interpret(rule)["value"])

    def test_selected_events_without_join_keys_are_not_silently_omitted(self):
        self.event(stage="encode")
        self.event(stage="encode", request_id=None)
        rule = {"op": "all", "join_by": ["context.request_id"],
                "rules": [{"op": "exists", "select": {"stage": "encode"}}]}
        self.assertIsNone(self.interpret(rule)["value"])

    def test_hash_tampering_rejected(self):
        self.event()
        path = self.seal()
        path.write_text(path.read_text().replace('"ok": true', '"ok": false'))
        with self.assertRaisesRegex(analyzer.EvidenceError, "hash mismatch"):
            analyzer.EvidencePackage(path)

    def test_truncation_and_seal_removal_rejected(self):
        self.event()
        self.event()
        path = self.seal()
        lines = path.read_text().splitlines()
        path.write_text(lines[0] + "\n")
        with self.assertRaisesRegex(analyzer.EvidenceError, "Seal"):
            analyzer.EvidencePackage(path)
        path = self.seal()
        (self.run / "seal.json").unlink()
        with self.assertRaisesRegex(analyzer.EvidenceError, "seal.json"):
            analyzer.EvidencePackage(path)

    def test_duplicate_event_and_mixed_metadata_rejected(self):
        first = self.event()
        second = self.event()
        second["event_id"] = first["event_id"]
        with self.assertRaisesRegex(analyzer.EvidenceError, "Duplicate event_id"):
            analyzer.EvidencePackage(self.seal())
        second["event_id"] = "unique-id"
        second["metadata"]["engine"]["id"] = "different"
        with self.assertRaisesRegex(analyzer.EvidenceError, "Mixed"):
            analyzer.EvidencePackage(self.seal())

    def test_invalid_schema_rejected(self):
        self.event()["schema_version"] = "9.9.9"
        with self.assertRaisesRegex(analyzer.EvidenceError, "schema_version"):
            analyzer.EvidencePackage(self.seal())

    def test_duplicate_json_keys_and_overflowed_numeric_literals_rejected(self):
        for content in ('{"value": 1, "value": 2}', '{"value": 1e999}'):
            with self.assertRaises(analyzer.EvidenceError):
                analyzer._json(content, "synthetic fixture")

    def test_invalid_evidence_does_not_create_report(self):
        self.event()
        path = self.seal()
        (self.run / "seal.json").unlink()
        output = self.root / "should-not-exist"
        with self.assertRaises(analyzer.EvidenceError):
            analyzer.analyze(path, self.rules({"op": "exists"}), output)
        self.assertFalse(output.exists())

    def test_no_output_overwrite(self):
        self.event()
        path, rules = self.seal(), self.rules({"op": "exists"})
        output = self.root / "report"
        analyzer.analyze(path, rules, output)
        before = (output / "report.md").read_bytes()
        with self.assertRaises(FileExistsError):
            analyzer.analyze(path, rules, output)
        self.assertEqual(before, (output / "report.md").read_bytes())

    def test_operationalization_is_preserved_and_shown_in_report(self):
        self.event()
        rules_path = self.rules({"op": "exists"})
        rules = json.loads(rules_path.read_text())
        definition = "Synthetic operational definition, not a paper-derived effectiveness claim"
        rules["conditions"][0]["operationalization"] = definition
        rules_path.write_text(json.dumps(rules))
        output = self.root / "operationalization-report"
        result = analyzer.analyze(self.seal(), rules_path, output)
        self.assertEqual(result["conditions"][0]["operationalization"], definition)
        self.assertIn(definition, (output / "report.md").read_text())

    def test_failed_and_blocked_runs_have_only_unknown_conditions(self):
        self.event(raw={"ok": False}, source=False)["context"] = {}
        rules = self.rules({"op": "compare", "field": "raw.ok", "cmp": "eq", "value": True})
        for status in ("blocked", "failed"):
            result = analyzer.analyze(self.seal(status), rules, self.root / status)
            self.assertIsNone(result["conditions"][0]["value"])
            self.assertEqual(result["run_status"], status)
            self.assertIn("Synthetic unavailable dependency", (self.root / status / "report.md").read_text())

    @unittest.skipIf(np is None, "NumPy required")
    def test_tensor_distance_and_exact_equality(self):
        self.tensor(self.event(), [1.0, 2.0])
        self.tensor(self.event(role="attack"), [2.0, 2.0])
        result = self.interpret(self.pair_rule())
        self.assertIs(result["value"], True)
        self.assertEqual(result["children"][0]["observations"][0]["actual"], 1.0)
        self.assertIs(self.interpret(self.pair_rule(op="tensor_equality"))["value"], False)

    @unittest.skipIf(np is None, "NumPy required")
    def test_similarity_is_labelled_similarity_not_distance_in_summary(self):
        self.tensor(self.event(), np.array([1.0, 2.0], dtype=np.float32))
        self.tensor(self.event(role="attack"), np.array([1.0, 3.0], dtype=np.float32))
        result = self.interpret(self.pair_rule(op="pairwise_tensor_cosine", cmp="ge", value=-1))
        self.assertEqual(result["children"][0]["observations"][0]["quantity"], "cosine_similarity")
        summary = analyzer._essential_reason(result)
        self.assertIn("cosine 유사도", summary)
        self.assertNotIn("거리", summary)

    def test_summary_does_not_merge_quantities_in_different_artifact_units(self):
        base = {"metric": "linf", "quantity": "linf_distance", "left_event_ids": ["l"], "right_event_ids": ["r"]}
        pixels = {**base, "actual": 32.0, "left_artifact": "input_pixels", "left_dtype": "uint8"}
        encoder = {**base, "actual": 0.25, "left_artifact": "encoder_input", "left_dtype": "float32"}
        result = analyzer._result(True, "Synthetic display test", observations=[pixels, copy.deepcopy(pixels), encoder])
        summary = analyzer._essential_reason(result)
        self.assertIn("input_pixels/uint8 L∞ 거리=32 (1쌍)", summary)
        self.assertIn("encoder_input/float32 L∞ 거리=0.25 (1쌍)", summary)
        self.assertNotIn("0.25–32", summary)

    @unittest.skipIf(np is None, "NumPy required")
    def test_exact_integer_equality_does_not_lose_precision(self):
        self.tensor(self.event(), np.array([2**60], dtype=np.uint64))
        self.tensor(self.event(role="attack"), np.array([2**60 + 1], dtype=np.uint64))
        self.assertIs(self.interpret(self.pair_rule(op="tensor_equality"))["value"], False)

    @unittest.skipIf(np is None, "NumPy required")
    def test_cosine_zero_norm_and_shape_mismatch_are_unknown(self):
        self.tensor(self.event(), [0.0, 0.0])
        attack = self.event(role="attack")
        self.tensor(attack, [1.0, 2.0])
        self.assertIsNone(self.interpret(self.pair_rule(metric="cosine"))["value"])
        self.tensor(attack, [1.0, 2.0, 3.0])
        self.assertIsNone(self.interpret(self.pair_rule())["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_missing_and_ambiguous_pairs_are_unknown(self):
        self.tensor(self.event(pair_id="left"), [1.0])
        self.tensor(self.event(role="attack", pair_id="right"), [2.0])
        self.assertIsNone(self.interpret(self.pair_rule())["value"])
        self.tensor(self.event(pair_id="left"), [3.0])
        self.assertIsNone(self.interpret(self.pair_rule())["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_selected_tensor_with_missing_join_is_not_silently_dropped(self):
        self.tensor(self.event(), [1.0])
        self.tensor(self.event(role="attack"), [2.0])
        self.tensor(self.event(pair_id=None), [1.0])
        self.assertIsNone(self.interpret(self.pair_rule())["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_artifact_hash_and_descriptor_mismatch_rejected(self):
        event = self.event()
        self.tensor(event, [1.0])
        path = self.seal()
        target = self.run / event["artifacts"]["embedding"]["path"]
        target.write_bytes(b"tampered")
        with self.assertRaisesRegex(analyzer.EvidenceError, "Artifact size mismatch"):
            analyzer.EvidencePackage(path)
        self.tensor(event, [1.0])
        event["artifacts"]["embedding"]["shape"] = [9]
        package = analyzer.EvidencePackage(self.seal())
        with self.assertRaisesRegex(analyzer.EvidenceError, "descriptor mismatch"):
            package.tensor(package.events[0], "embedding")

    def test_artifact_traversal_and_symlink_escape_rejected(self):
        outside = self.root / "outside.npy"
        outside.write_bytes(b"outside")
        descriptor = {"path": "../outside.npy", "sha256": analyzer.file_sha256(outside),
                      "shape": [1], "dtype": "float32", "bytes": outside.stat().st_size}
        self.event()["artifacts"]["bad"] = descriptor
        with self.assertRaisesRegex(analyzer.EvidenceError, "traversal"):
            analyzer.EvidencePackage(self.seal())
        (self.run / "escape.npy").symlink_to(outside)
        descriptor["path"] = "escape.npy"
        with self.assertRaisesRegex(analyzer.EvidenceError, "outside run directory"):
            analyzer.EvidencePackage(self.seal())

    @unittest.skipIf(np is None, "NumPy required")
    def test_nonfinite_tensor_is_unknown(self):
        self.tensor(self.event(), [1.0, float("nan")])
        self.tensor(self.event(role="attack"), [1.0, 2.0])
        self.assertIsNone(self.interpret(self.pair_rule())["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_explicit_concat_reconstructs_only_one_requests_ordered_tiles(self):
        left = self.event()
        right1 = self.event(role="attack")
        right2 = self.event(role="attack")
        self.tensor(left, [[1.0, 2.0], [3.0, 4.0]])
        self.tensor(right1, [[1.0, 2.0]])
        self.tensor(right2, [[3.0, 4.0]])
        rule = self.pair_rule(op="tensor_equality")
        self.assertIsNone(self.interpret(rule)["value"])
        rule["right"].update({"aggregate": "concat", "axis": 0, "order_by": "sequence"})
        result = self.interpret(rule)
        self.assertIs(result["value"], True)
        self.assertEqual(result["children"][0]["observations"][0]["right_event_ids"],
                         [right1["event_id"], right2["event_id"]])
        # Identical tensor bytes from another request are not a valid tile join.
        right2["context"]["request_id"] = "unrelated-request"
        self.assertIsNone(self.interpret(rule)["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_concat_rejects_incompatible_dtype_shape_and_axis(self):
        self.tensor(self.event(), np.array([[1, 2], [3, 4]], dtype=np.float32))
        first = self.event(role="attack")
        second = self.event(role="attack")
        self.tensor(first, np.array([[1, 2]], dtype=np.float32))
        self.tensor(second, np.array([[3, 4]], dtype=np.float64))
        rule = self.pair_rule(op="tensor_equality")
        rule["right"].update({"aggregate": "concat", "axis": 0})
        self.assertIsNone(self.interpret(rule)["value"])
        self.tensor(second, np.array([[3, 4, 5]], dtype=np.float32))
        self.assertIsNone(self.interpret(rule)["value"])
        rule["right"]["axis"] = 5
        self.assertIsNone(self.interpret(rule)["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_tensor_stat_checks_complete_raw_zeros_not_intervention_label(self):
        first = self.event(role="ablation", raw={"intervention": True})
        second = self.event(role="ablation", raw={"intervention": True})
        self.tensor(first, [[0.0, 0.0]])
        self.tensor(second, [[0.0, 0.0]])
        rule = {"op": "tensor_stat", "select": {"context": {"role": "ablation"}},
                "artifact": "embedding", "aggregate": "concat", "axis": 0,
                "join_by": ["context.request_id"], "stat": "max_abs", "cmp": "eq", "value": 0}
        self.assertIs(self.interpret(rule)["value"], True)
        self.tensor(second, [[0.0, 0.125]])
        self.assertIs(self.interpret(rule)["value"], False)
        second["context"]["request_id"] = None
        self.assertIsNone(self.interpret(rule)["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_tensor_stat_signed_minimum_does_not_overflow_absolute_value(self):
        self.tensor(self.event(), np.array([-(2**63)], dtype=np.int64))
        rule = {"op": "tensor_stat", "artifact": "embedding", "stat": "max_abs", "cmp": "gt", "value": 0}
        result = self.interpret(rule)
        self.assertIs(result["value"], True)
        self.assertEqual(result["children"][0]["observations"][0]["actual"], float(2**63))

    def test_actual_common_logger_contract(self):
        logger_path = ANALYZER_PATH.parents[1] / "LieMappBench" / "Logging-Dataset" / "logger.py"
        spec = importlib.util.spec_from_file_location("liemapp_logger_integration_fixture", logger_path)
        logger_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(logger_module)
        target = self.root / "real-logger-synthetic-evidence"
        logger = logger_module.Logger(target, {"attack_id": "synthetic-attack",
                                              "engine": {"id": "synthetic-engine-a"},
                                              "execution_scope": "native_runtime"}, durable=False)
        logger.emit("preflight", {"ok": True}, readable={"explanation": "Synthetic fixture"})
        logger.close()
        result = analyzer.analyze(target / "events.jsonl", self.rules({"op": "exists"}), self.root / "interop-report")
        self.assertIs(result["conditions"][0]["value"], True)

    @unittest.skipIf(np is None, "NumPy required")
    def test_calibration_threshold_and_availability_are_distinct_from_detection(self):
        for index, difference in enumerate([0.1, 0.2, 0.3]):
            self.tensor(self.event(role="base", pair_id=f"c{index}"), [1.0])
            self.tensor(self.event(role="calibration", pair_id=f"c{index}"), [1.0 + difference])
        self.tensor(self.event(role="base", pair_id="test"), [1.0])
        self.tensor(self.event(role="attack", pair_id="test"), [1.05])
        calibration = self.pair_rule()
        calibration["left"]["select"]["context"]["role"] = "base"
        calibration["right"]["select"]["context"]["role"] = "calibration"
        # Restrict shared references so unrelated test keys cannot enter calibration.
        calibration["left"]["select"]["context"]["transform"] = "cal"
        calibration["right"]["select"]["context"]["transform"] = "cal"
        for event in self.events[:6]:
            event["context"]["transform"] = "cal"
        test = self.pair_rule()
        test["left"]["select"]["context"] = {"role": "base", "transform": "identity"}
        rule = {"op": "calibrated_tensor_distance", "calibration": calibration, "test": test,
                "min_pairs": 3, "percentile": 95, "mode": "available", "cmp": "gt", "label": "synthetic/jpeg"}
        result = self.interpret(rule)
        self.assertIs(result["value"], True)
        self.assertAlmostEqual(result["observations"][0]["threshold"], 0.29)
        self.assertEqual(result["observations"][0]["test_threshold_flags"], [False])
        table = "\n".join(analyzer._calibration_table([{**result, "id": "synthetic-condition"}]))
        self.assertIn("synthetic/jpeg", table)
        self.assertIn("0.29", table)
        self.assertIn("0/1", table)
        rule["percentile_method"] = "higher"
        result = self.interpret(rule)
        self.assertAlmostEqual(result["observations"][0]["threshold"], 0.3)
        rule["mode"] = "exceeds"
        self.assertIs(self.interpret(rule)["value"], False)
        rule["min_pairs"] = 10
        self.assertIsNone(self.interpret(rule)["value"])

    @unittest.skipIf(np is None, "NumPy required")
    def test_calibration_test_pair_leakage_is_unknown(self):
        for index in range(3):
            self.tensor(self.event(pair_id=str(index)), [1.0])
            self.tensor(self.event(role="attack", pair_id=str(index)), [1.1])
        pair = self.pair_rule()
        rule = {"op": "calibrated_tensor_distance", "calibration": pair, "test": copy.deepcopy(pair),
                "min_pairs": 3, "mode": "available"}
        result = self.interpret(rule)
        self.assertIsNone(result["value"])
        self.assertIn("leakage", result["reason"])


if __name__ == "__main__":
    unittest.main()
