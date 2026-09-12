"""Check rule provenance and experimental joins; never evaluate an open run."""
from __future__ import annotations

from argparse import Namespace
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LOGGING = ROOT / "LieMappBench/Logging-Dataset"
SCRIPTS = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/siai"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_module("siai_rule_analyzer", ROOT / "LieMappAnalyzer/analyzer.py")
BUILDER = load_module("siai_rule_builder", SCRIPTS / "shared/build_rules.py")
LIBRARY = load_module("siai_rule_library", LOGGING / "library.py")
RUNNER = load_module("siai_rule_runner", SCRIPTS / "llamacpp/run.py")


def all_rules(rule):
    yield rule
    for child in rule.get("rules", []):
        yield from all_rules(child)
    for cohort in ("calibration", "test"):
        if cohort in rule:
            yield rule[cohort]


class SIAIRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = ANALYZER.load_rules(LOGGING / "siai/conditions.json")
        cls.conditions = {item["id"]: item for item in cls.rules["conditions"]}
        manifest_path = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/siai/shared/experiment-cpu128-v1/dataset.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        attack_id = next(case["input_id"] for case in manifest["cases"]
                         if case["role"] == "attack" and case["transform"] == "original")
        clean_id = next(case["input_id"] for case in manifest["cases"]
                        if case["role"] == "clean" and case["transform"] == "original")
        args = Namespace(case=[], limit=None, ablate_input=[attack_id], explicit_input=[clean_id],
                         explicit_prompt="Synthetic explicit-instruction context")
        prepared = RUNNER.prepare_cases(manifest, manifest_path, args)
        cls.contexts = []
        for index, case in enumerate(prepared):
            prompt = case.get("prompt", "Describe this image.")
            context = {key: value for key, value in case.items() if key not in ("resolved_path", "path")}
            context.update(request_id=f"synthetic-request-{index}", prompt=prompt,
                           prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                           seed=int(case.get("seed", 20260906)), temperature=0.0, max_tokens=48,
                           isolated_process=True, model_revision=RUNNER.MODEL_CACHE.name)
            context.setdefault("evaluation", "condition_audit")
            context.setdefault("question_id", "audit-default")
            cls.contexts.append(context)

    def test_frozen_rules_equal_deterministic_builder_output(self):
        before = LIBRARY.sha256(LIBRARY.WORKBOOK)
        self.assertEqual(self.rules, BUILDER.build())
        self.assertEqual(LIBRARY.sha256(LIBRARY.WORKBOOK), before)

    def test_workbook_hash_and_original_condition_wording_are_preserved(self):
        library = LIBRARY.load_library()
        siai = next(attack for attack in library["attacks"] if attack["attack_id"] == "siai")
        self.assertEqual(self.rules["library"]["sha256"], LIBRARY.sha256(LIBRARY.WORKBOOK))
        self.assertEqual(self.rules["library"]["sheet"], "AI 포렌식")
        self.assertEqual(self.rules["library"]["row"], siai["row"])
        self.assertEqual(list(self.conditions), ["AC1", "AC2", "AC3", "DC1", "DC2", "DC3"])
        for original in siai["conditions"]:
            exported = self.conditions[original["condition_id"]]
            self.assertEqual(exported["text"], original["text"])
            self.assertEqual(exported["kind"], original["type"])
            self.assertEqual(exported["source_cell"], original["source"]["cell"])
            self.assertTrue(exported["operationalization"])

    def test_all_six_conditions_require_runtime_and_valid_generic_dsl(self):
        for condition in self.conditions.values():
            self.assertEqual(condition["rule"]["scope"], "runtime")
            ANALYZER.RuleInterpreter.validate(condition["rule"])
            for rule in all_rules(condition["rule"]):
                for side in ("left", "right"):
                    if side in rule:
                        self.assertTrue(rule["join_by"])
                        selection = rule[side]["select"]
                        self.assertNotIn("readable", selection)
                        self.assertNotIn("metadata.engine.id", selection)

    def test_dataset_contexts_have_expected_roles_and_distinct_control_requests(self):
        self.assertEqual(len(self.contexts), 86)
        normal = [context for context in self.contexts if context["run_kind"] == "normal"]
        self.assertEqual(Counter(context["role"] for context in normal), {"calibration": 70, "clean": 7, "attack": 7})
        self.assertEqual(sum(context["role"] == "ablation" for context in self.contexts), 1)
        self.assertEqual(sum(context["role"] == "explicit_instruction" for context in self.contexts), 1)
        self.assertEqual(len({context["request_id"] for context in self.contexts}), 86)

    def selected_contexts(self, selector):
        stage = selector["stage"]
        rows = [{"stage": stage, "context": context} for context in self.contexts]
        return ANALYZER.RuleInterpreter._selected(rows, selector)

    def check_pair_contexts(self, pair):
        groups = []
        for side in ("left", "right"):
            selected = self.selected_contexts(pair[side]["select"])
            self.assertTrue(selected, pair)
            grouped = ANALYZER.RuleInterpreter._group(selected, pair["join_by"])
            self.assertEqual(sum(map(len, grouped.values())), len(selected), "Missing join field")
            self.assertTrue(all(len(rows) == 1 for rows in grouped.values()), "Ambiguous request pairing")
            groups.append(grouped)
        self.assertEqual(groups[0].keys(), groups[1].keys(), "Unmatched manifest pair contexts")
        return groups

    def test_every_pair_selector_matches_manifest_contexts_without_cross_role_leakage(self):
        for condition in self.conditions.values():
            for pair in all_rules(condition["rule"]):
                if "left" not in pair:
                    continue
                with self.subTest(condition=condition["id"], selector=pair["left"]["select"]):
                    self.check_pair_contexts(pair)

    def test_causal_keys_pin_input_prompt_seed_and_generation_configuration(self):
        self.assertTrue({"context.input_id", "context.prompt_sha256", "context.seed", "context.temperature",
                         "context.max_tokens", "context.model_revision"}.issubset(BUILDER.CAUSAL_KEYS))
        pairs = [rule for rule in all_rules(self.conditions["AC3"]["rule"])
                 if rule.get("left", {}).get("artifact") == "logits"]
        self.assertEqual(len(pairs), 1)
        pair = pairs[0]
        left, right = self.check_pair_contexts(pair)
        for key in left:
            self.assertNotEqual(left[key][0]["context"]["request_id"], right[key][0]["context"]["request_id"])
            self.assertEqual(left[key][0]["context"]["role"], "attack")
            self.assertEqual(right[key][0]["context"]["role"], "ablation")

    def test_ac1_successes_must_belong_to_each_same_attack_request(self):
        rule = self.conditions["AC1"]["rule"]
        self.assertEqual(rule["select"], {"context": BUILDER.ORIGINAL_ATTACK})
        self.assertEqual(rule["join_by"], ["context.request_id"])
        self.assertEqual(rule["reduce"], "all")

    def test_ac3_checks_real_zero_tensor_and_unmodified_normal_branch(self):
        rules = list(all_rules(self.conditions["AC3"]["rule"]))
        zero = [rule for rule in rules if rule["op"] == "tensor_stat"]
        self.assertEqual(len(zero), 1)
        self.assertEqual(zero[0]["stat"], "max_abs")
        self.assertEqual(zero[0]["value"], 0)
        self.assertEqual(zero[0]["cmp"], "eq")
        self.assertEqual(zero[0]["aggregate"], "concat")
        self.assertEqual(zero[0]["select"]["context"]["role"], "ablation")
        normal_flags = [rule for rule in rules if rule.get("field") == "raw.intervention" and rule.get("value") is False]
        self.assertEqual(len(normal_flags), 1)
        self.assertEqual(normal_flags[0]["select"]["context"]["role"], "attack")

    def test_dc2_is_cosine_availability_not_a_validated_detector(self):
        rules = self.conditions["DC2"]["rule"]["rules"]
        self.assertEqual(len(rules), 3 * 6)
        self.assertTrue(all(rule["op"] == "pairwise_tensor_cosine" and rule["value"] == -1 and rule["cmp"] == "ge"
                            for rule in rules))

    def test_calibration_is_normal_only_per_transform_and_held_out(self):
        rules = self.conditions["DC3"]["rule"]["rules"]
        self.assertEqual(len(rules), 2 * 6)
        for rule in rules:
            self.assertEqual(rule["mode"], "available")
            self.assertEqual(rule["min_pairs"], 10)
            self.assertEqual(rule["percentile"], 95)
            self.assertEqual(rule["percentile_method"], "higher")
            calibration, test = rule["calibration"], rule["test"]
            self.assertEqual(calibration["metric"], "cosine")
            self.assertEqual(test["metric"], "cosine")
            for side in ("left", "right"):
                self.assertEqual(calibration[side]["select"]["context"]["role"], "calibration")
                self.assertIn(test[side]["select"]["context"]["role"], {"clean", "attack"})
            self.assertEqual(calibration["right"]["select"]["context"]["transform"], test["right"]["select"]["context"]["transform"])
            cal_left, _ = self.check_pair_contexts(calibration)
            test_left, _ = self.check_pair_contexts(test)
            self.assertEqual(len(cal_left), 10)
            self.assertEqual(len(test_left), 1)
            self.assertFalse(cal_left.keys() & test_left.keys())


if __name__ == "__main__":
    unittest.main()
