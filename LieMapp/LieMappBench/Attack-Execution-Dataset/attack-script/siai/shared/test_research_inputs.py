"""Lightweight reproducibility and provenance checks, no model downloads."""
import importlib.util
import json
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from prepare_dataset import DEFAULT_SOURCE, TRANSFORMS, digest, stable_seed, transform_image

LIE = Path(__file__).resolve().parents[5]
spec = importlib.util.spec_from_file_location("lie_library", LIE / "LieMappBench/Logging-Dataset/library.py")
library = importlib.util.module_from_spec(spec)
spec.loader.exec_module(library)


class LibraryTests(unittest.TestCase):
    def test_actual_attack_count_and_cell_provenance(self):
        result = library.load_library()
        self.assertEqual(result["attack_count"], 5)
        siai = next(a for a in result["attacks"] if a["attack_id"] == "siai")
        self.assertEqual(siai["row"], 10)
        self.assertEqual([c["condition_id"] for c in siai["conditions"]], ["AC1", "AC2", "AC3", "DC1", "DC2", "DC3"])
        self.assertEqual({c["source"]["cell"] for c in siai["conditions"]}, {"G10", "H10"})

    def test_placeholder_is_not_condition(self):
        for placeholder in ["-", "TBA", "", "to be determined"]:
            self.assertEqual(library.split_conditions(placeholder), [])

    def test_all_static_source_anchors_remain_hash_valid(self):
        for engine in library.ENGINES:
            path = LIE / "LieMappBench/Logging-Dataset/siai" / engine / "source-review.json"
            review = json.loads(path.read_text())
            self.assertEqual(review["status"], "static_candidate_review_only")
            for entry in review["logging_points"]:
                self.assertFalse(entry["executed"])
                self.assertFalse(entry["instrumented"])
                source = LIE / review["source_root"] / entry["source"]["file"]
                self.assertEqual(digest(source), entry["source"]["sha256"])


class DatasetTests(unittest.TestCase):
    def test_heldout_manifest_controls_and_separation(self):
        path = DEFAULT_SOURCE / "behavior-heldout-v1/dataset.json"
        manifest = json.loads(path.read_text())
        provenance_path = path.parent / manifest["attack_provenance"]["path"]
        self.assertEqual(digest(provenance_path), manifest["attack_provenance"]["sha256"])
        provenance = json.loads(provenance_path.read_text())
        train = {qa["question"] for qa in provenance["train_qa"]}
        self.assertEqual(len(manifest["cases"]), 12)
        groups = {}
        for case in manifest["cases"]:
            self.assertEqual(case["evaluation"], "behavior_heldout")
            self.assertTrue(case["question_id"])
            self.assertNotIn(case["question"], train)
            self.assertNotEqual(case["role"], "calibration")
            self.assertEqual(digest(path.parent / case["path"]), case["input_sha256"])
            groups.setdefault(case["question_id"], {})[case["role"]] = case
        self.assertEqual(len(groups), 4)
        for group in groups.values():
            self.assertEqual(set(group), {"clean", "attack", "explicit_instruction"})
            self.assertEqual(group["clean"]["prompt"], group["attack"]["prompt"])
            self.assertEqual(group["clean"]["input_sha256"], group["explicit_instruction"]["input_sha256"])
            self.assertNotEqual(group["attack"]["input_sha256"], group["clean"]["input_sha256"])
            self.assertEqual(group["clean"]["prompt"], group["clean"]["question"])
            self.assertIn("begin your answer with Arrr", group["explicit_instruction"]["prompt"])

    def test_final_attack_dataset_integrity_and_bound(self):
        path = DEFAULT_SOURCE / "experiment-cpu128-v1/dataset.json"
        manifest = json.loads(path.read_text())
        self.assertEqual(manifest["case_count"], 84)
        self.assertTrue(manifest["attack"]["available"])
        for case in manifest["cases"]:
            self.assertEqual(digest(path.parent / case["path"]), case["input_sha256"])
        originals = {c["role"]: c for c in manifest["cases"] if c["role"] != "calibration" and c["transform"] == "original"}
        clean = np.asarray(Image.open(path.parent / originals["clean"]["path"])).astype(np.int16)
        attack = np.asarray(Image.open(path.parent / originals["attack"]["path"])).astype(np.int16)
        self.assertGreater(np.max(np.abs(clean - attack)), 0)
        self.assertLessEqual(np.max(np.abs(clean - attack)), 32)
        self.assertEqual(originals["clean"]["attack_pair_id"], originals["attack"]["attack_pair_id"])

    def test_seed_stable(self):
        self.assertEqual(stable_seed(5, "pair"), stable_seed(5, "pair"))
        self.assertNotEqual(stable_seed(5, "pair"), stable_seed(5, "other"))

    def test_six_transform_replay(self):
        array = np.arange(64 * 64 * 3, dtype=np.uint8).reshape(64, 64, 3)
        image = Image.fromarray(array)
        for name in TRANSFORMS:
            a, ap = transform_image(image, name, 20260906)
            b, bp = transform_image(image, name, 20260906)
            self.assertEqual(ap, bp)
            np.testing.assert_array_equal(np.asarray(a), np.asarray(b))
            self.assertEqual(a.size, image.size)

    def test_calibration_manifest_hashes_and_no_leak(self):
        path = DEFAULT_SOURCE / "calibration-v1/dataset.json"
        manifest = json.loads(path.read_text())
        self.assertEqual(manifest["case_count"], 77)
        self.assertFalse(manifest["attack"]["available"])
        ids = set()
        pairs = {}
        calibration, evaluation = set(), set()
        for case in manifest["cases"]:
            self.assertNotIn(case["input_id"], ids)
            ids.add(case["input_id"])
            self.assertEqual(case["input_sha256"], digest(path.parent / case["path"]))
            pairs.setdefault(case["pair_id"], []).append(case)
            (calibration if case["role"] == "calibration" else evaluation).add(case["input_sha256"])
        self.assertFalse(calibration & evaluation)
        self.assertEqual(len(pairs), 11)
        for group in pairs.values():
            self.assertEqual(len(group), 7)
            self.assertEqual({c["transform"] for c in group}, {"original", *TRANSFORMS})
            base = next(c for c in group if c["transform"] == "original")
            for case in group:
                if case["transform"] != "original":
                    self.assertEqual(case["parent_id"], base["input_id"])


if __name__ == "__main__":
    unittest.main()
