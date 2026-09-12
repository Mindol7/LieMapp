"""Synthetic-only protocol selection, rule and publication regressions."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_ama_framework as legacy

ROOT = legacy.ROOT
WORKFLOW = legacy.WORKFLOW
PUBLIC = ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1"
PROTOCOL_ID = "ama-public-http-v1"
AUDIT = legacy.load_module("ama_protocol_publication_audit_test", ROOT / "internal/verify_publication.py")


class ProtocolRegistryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="liemapp-protocol-registry-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.attack = {
            "label": "AMA", "rules": str(legacy.RULES_PATH),
            "presentation": str(legacy.PRESENTATION_PATH),
            "protocols": {PROTOCOL_ID: {
                "rules": str(PUBLIC / "conditions.json"),
                "presentation": str(PUBLIC / "presentation.json")}},
            "engines": {"synthetic-a": {"label": "synthetic-a", "source_log": "not-executed"}},
        }

    def select(self, metadata=None, attack=None):
        return WORKFLOW.selected_protocol(attack or self.attack, metadata or {
            "attack_id": "ama", "protocol_id": PROTOCOL_ID}, root=self.root)

    def test_absent_protocol_preserves_legacy_rules_and_presentation(self):
        selected = self.select({"attack_id": "ama", "engine": {"id": "anything"}})
        self.assertIsNone(selected["protocol_id"])
        self.assertEqual(selected["rules"], legacy.RULES_PATH)
        self.assertEqual(selected["presentation"], legacy.PRESENTATION_PATH)

    def test_registered_protocol_is_selected_independently_of_engine_name(self):
        first = self.select({"attack_id": "ama", "protocol_id": PROTOCOL_ID, "engine": {"id": "synthetic-a"}})
        second = self.select({"attack_id": "ama", "protocol_id": PROTOCOL_ID, "engine": {"id": "synthetic-b"}})
        self.assertEqual(first, second)
        self.assertEqual(first["rules"], PUBLIC / "conditions.json")

    def test_explicit_unknown_null_or_malformed_protocol_never_falls_back(self):
        for value in ("unregistered", None, "", False, 7, [], {}, "../escape", "has space"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.select({"attack_id": "ama", "protocol_id": value})

    def test_bad_registry_configuration_is_rejected_when_loading_config(self):
        values = (None, [], {"bad id": {"rules": "rules.json"}}, {PROTOCOL_ID: None},
                  {PROTOCOL_ID: {"rules": []}}, {PROTOCOL_ID: {"rules": ""}},
                  {PROTOCOL_ID: {"rules": "rules.json", "presentation": None}},
                  {PROTOCOL_ID: {"rules": "rules.json", "engine_override": "not allowed"}})
        path = self.root / "config.json"
        for value in values:
            with self.subTest(value=value):
                attack = {**self.attack, "protocols": value}
                path.write_text(json.dumps({"schema_version": "1.0.0", "attacks": {"ama": attack}}))
                with self.assertRaises(ValueError):
                    WORKFLOW.load_config(path)

    def test_rules_identity_must_match_sealed_protocol_and_attack(self):
        source = json.loads((PUBLIC / "conditions.json").read_text())
        path = self.root / "rules.json"
        attack = copy.deepcopy(self.attack)
        attack["protocols"][PROTOCOL_ID]["rules"] = str(path)
        for key, value in (("protocol_id", "other"), ("attack_id", "other")):
            path.write_text(json.dumps({**source, key: value}))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "rules do not match"):
                self.select(attack=attack)

    def test_presentation_cannot_silently_describe_another_protocol(self):
        path = self.root / "presentation.json"
        path.write_text(json.dumps({"attack_id": "ama", "protocol_id": "other"}))
        attack = copy.deepcopy(self.attack)
        attack["protocols"][PROTOCOL_ID]["presentation"] = str(path)
        with self.assertRaisesRegex(ValueError, "presentation does not match"):
            self.select(attack=attack)

    def test_protocol_without_presentation_uses_generic_display_not_legacy_claims(self):
        attack = copy.deepcopy(self.attack)
        attack["protocols"][PROTOCOL_ID].pop("presentation")
        self.assertIsNone(self.select(attack=attack)["presentation"])

    def test_new_rules_keep_exact_workbook_condition_wording(self):
        rules = legacy.ANALYZER.load_rules(PUBLIC / "conditions.json")
        original = legacy.ANALYZER.load_rules(legacy.RULES_PATH)
        self.assertEqual(rules["library"], original["library"])
        for actual, previous in zip(rules["conditions"], original["conditions"], strict=True):
            for key in ("id", "kind", "text", "source_cell"):
                self.assertEqual(actual[key], previous[key])
        self.assertEqual(rules["protocol_id"], PROTOCOL_ID)

    def records(self, *, origin=True, confirmed=True, no_call=False, execution=True):
        records = legacy.AMAEvidenceTests.request(no_call=no_call)
        selected = next(raw["selected_tools"] for stage, raw, _ in records if stage == "ama_tool_selected")
        context = copy.deepcopy(records[0][2])
        records.append(("ama_tool_provenance", {
            "all_selected_platform_origins_verified": False if no_call else origin,
            "all_selected_public_calls_confirmed": False if no_call else confirmed,
            "selected_tools": copy.deepcopy(selected),
            "evidence_notice": "Synthetic unit-test evidence; no HTTP request is sent."}, context))
        for stage, raw, _ in records:
            if stage == "ama_tool_execution":
                raw["execution_recorded"] = False if no_call else execution
        return records

    def log(self, records, *, engine="synthetic-a", protocol=PROTOCOL_ID):
        directory = self.root / (engine + "-raw")
        metadata = {"attack_id": "ama", "engine": {"id": engine}, "run_id": engine + "-synthetic",
                    "execution_scope": "native_runtime", "protocol_id": protocol}
        with legacy.LOGGER.Logger(directory, metadata, durable=False) as logger:
            for stage, raw, context in records:
                logger.emit(stage, raw, context=context, readable={"notice": "Synthetic test only"})
        return directory / "events.jsonl"

    def analyze(self, records, *, engine="synthetic-a"):
        log = self.log(records, engine=engine)
        result = legacy.ANALYZER.analyze(log, PUBLIC / "conditions.json", self.root / (engine + "-analysis"))
        return {row["id"]: row["value"] for row in result["conditions"]}

    def test_engine_review_is_not_established_by_a_harness_switch(self):
        """AC2 is answered by engine evidence only; an agent-layer review flag cannot set it."""
        records = self.records()
        for stage, raw, _ in records:
            if stage == "ama_metadata_review":
                raw["performed"] = True
        self.assertIs(self.analyze(records)["AC2"], False)

    def test_engine_review_is_true_only_when_the_engine_changed_what_it_rendered(self):
        records = self.records()
        for stage, raw, _ in records:
            if stage == "ama_native_prompt_rendered":
                raw["rendered_prompt"] = "Synthetic prompt after the engine removed the attacker description"
        self.assertIs(self.analyze(records)["AC2"], True)

    def test_missing_engine_rendering_keeps_review_unknown(self):
        records = [row for row in self.records() if row[0] != "ama_native_prompt_rendered"]
        self.assertIsNone(self.analyze(records)["AC2"])

    def test_no_call_request_stays_in_conditions_and_is_not_vacuously_true(self):
        result = self.analyze(self.records(no_call=True))
        for condition in ("DC1", "DC2"):
            self.assertIs(result[condition], False)

    def test_unknown_http_execution_is_not_converted_into_known_noninvocation(self):
        result = self.analyze(self.records(confirmed=None, execution=None))
        self.assertIsNone(result["DC2"])

    def test_same_public_rules_apply_to_two_engine_identifiers(self):
        first = self.analyze(self.records(), engine="synthetic-a")
        second = self.analyze(self.records(), engine="synthetic-b")
        self.assertEqual(first, second)
        self.assertEqual(first, {"AC1": True, "AC2": False, "DC1": True, "DC2": True})

    def test_saved_log_workflow_and_audit_share_protocol_selection(self):
        attack = copy.deepcopy(self.attack)
        attack["engines"] = {}
        for engine in ("synthetic-a", "synthetic-b"):
            log = self.log(self.records(), engine=engine)
            attack["engines"][engine] = {"label": engine, "source_log": str(log)}
        config = {"schema_version": "1.0.0", "attacks": {"ama": attack}}
        path = self.root / "config.json"
        path.write_text(json.dumps(config))
        with patch.object(WORKFLOW, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()):
            for engine in attack["engines"]:
                args = ["--config", str(path), "--attack", "ama", "--engine", engine]
                self.assertEqual(WORKFLOW.main(args, actor="developer"), 0)
                self.assertEqual(WORKFLOW.main(args + ["--replace"], actor="investigator"), 0)
        result = AUDIT.audit(config, root=self.root, recompute=True)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["outputs"]), 2)
        for output in result["outputs"]:
            self.assertEqual(output["condition_file_count"], 4)
            self.assertEqual(output["report_count"], 1)
            self.assertEqual(output["conditions"]["AC1"]["verdict"], "T")

    def test_existing_llama_and_vllm_publications_still_recompute_exactly(self):
        paths = [ROOT / ".evidence/current/ama" / (engine + ".json") for engine in ("llamacpp", "vllm")]
        if not all(path.is_file() for path in paths):
            self.skipTest("Historical canonical packages are not distributed with this checkout")
        config = WORKFLOW.load_config(ROOT / "internal/experiments.json")
        attack = config["attacks"]["ama"]
        attack["engines"] = {engine: attack["engines"][engine] for engine in ("llamacpp", "vllm")}
        config["attacks"] = {"ama": attack}
        result = AUDIT.audit(config, root=ROOT, recompute=True)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["outputs"]), 2)
        self.assertTrue(all(output["public_documents_reconstructed"] for output in result["outputs"]))

    def test_frozen_legacy_rule_presentation_and_protocol_bytes_are_unchanged(self):
        expected = {
            legacy.RULES_PATH: "96857012936d09c248b2b25deeb9c1bc43f46d3e21660a62922f24bf80797737",
            legacy.PRESENTATION_PATH: "5dcad2aeccb9d951df9af8fd140119c4d1d4b1f24ed06528eeb71a5846eb98b6",
            ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/shared/ama_protocol.py":
                "a61094c09e7be79d2fed9fa46f6d077309efb29a9e1e5d76b68b3ebaa0a30330",
        }
        for path, digest in expected.items():
            self.assertEqual(legacy.LIBRARY.sha256(path), digest)


if __name__ == "__main__":
    unittest.main()
