"""Verify emitted dataset bytes and training provenance without invoking a model."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image

from prepare_dataset import DEFAULT_SOURCE, TRANSFORMS, digest


def verify(manifest_path, provenance_path=None):
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest["cases"]
    assert manifest["case_count"] == len(cases), "incorrect case count"
    assert len({c["input_id"] for c in cases}) == len(cases), "duplicate input ID"
    pairs, calibration_hashes, evaluation_hashes = {}, set(), set()
    for case in cases:
        assert digest(manifest_path.parent / case["path"]) == case["input_sha256"], "input hash mismatch"
        assert Image.open(manifest_path.parent / case["path"]).size == (512, 512), "unexpected image size"
        assert case["role"] in {"calibration", "clean", "attack"}, "invalid role"
        assert case["transform"] in {"original", *TRANSFORMS}, "invalid transform"
        assert case["context"]["input_sha256"] == case["input_sha256"], "inconsistent context"
        pairs.setdefault(case["pair_id"], []).append(case)
        (calibration_hashes if case["role"] == "calibration" else evaluation_hashes).add(case["input_sha256"])
    assert not calibration_hashes & evaluation_hashes, "calibration/evaluation overlap"
    for group in pairs.values():
        assert {c["transform"] for c in group} == {"original", *TRANSFORMS}, "missing transform"
        assert len(group) == 7, "ambiguous join key"
        assert len({c["role"] for c in group}) == 1, "mixed roles within image pair"
        base = next(c for c in group if c["transform"] == "original")
        assert all(c["parent_id"] == base["input_id"] for c in group if c["transform"] != "original"), "incorrect parent"
    assert sum(c["role"] == "calibration" and c["transform"] == "original" for c in cases) == 10
    result = {"verified_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "passed": True, "manifest_sha256": digest(manifest_path), "verified_case_count": len(cases),
              "checks": ["all raw image hashes", "unique inputs", "canonical dimensions", "calibration/evaluation separation",
                         "original/augmentation relation", "unambiguous per-transform joins", "10 normal calibration bases"],
              "script_hashes": {p.name: digest(p) for p in Path(__file__).resolve().parent.glob("*.py")}}
    if provenance_path:
        provenance_path = Path(provenance_path)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        clean = provenance_path.parent / provenance["input"]["clean"]
        attack = provenance_path.parent / provenance["output"]["attack"]
        assert digest(clean) == provenance["input"]["clean_sha256"]
        assert digest(attack) == provenance["output"]["attack_sha256"]
        raw_pixels = provenance_path.parent / provenance["output"]["pixels"]
        assert digest(raw_pixels) == provenance["output"]["pixels_sha256"]
        trace_path = provenance_path.parent / "training-trace.jsonl"
        assert digest(trace_path) == provenance["output"]["training_trace_sha256"]
        trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        assert len(trace) == provenance["training"]["completed_steps"] == provenance["training"]["requested_steps"]
        for i, row in enumerate(trace, 1):
            assert row["step"] == i and math.isfinite(row["loss_before_update"])
            assert math.isfinite(row["gradient_abs_max"]) and row["gradient_abs_max"] > 0
            assert row["linf_after_update"] <= provenance["training"]["epsilon_linf"] + 1e-6
        delta = np.asarray(Image.open(attack)).astype(np.int16) - np.asarray(Image.open(clean)).astype(np.int16)
        assert np.max(np.abs(delta)) <= 32 and np.count_nonzero(delta) > 0
        train_questions = {qa["question"] for qa in provenance["train_qa"]}
        assert not train_questions & set(provenance["heldout_questions"]), "train/heldout question leak"
        result["training"] = {"provenance_sha256": digest(provenance_path), "actual_steps": len(trace),
                              "linf_in_integer_pixels": int(np.max(np.abs(delta))),
                              "nonzero_gradient_steps": len(trace), "train_heldout_exact_questions_disjoint": True,
                              "checks": ["clean/attack/rawpixels/trace hashes", "finite nonzero gradients", "PGD bound each step", "PNG bound after encoding"]}
    tracked = subprocess.check_output(["git", "-C", str(DEFAULT_SOURCE / "upstream"), "ls-files", "-z"])
    result["upstream"] = {"commit": subprocess.check_output(["git", "-C", str(DEFAULT_SOURCE / "upstream"), "rev-parse", "HEAD"], text=True).strip(),
                          "files": [{"path": name, "sha256": digest(DEFAULT_SOURCE / "upstream" / name)}
                                    for name in tracked.decode().split("\0") if name]}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--attack-provenance", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.manifest, args.attack_provenance)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
        print(json.dumps({"passed": True, "output": str(args.output), "verified_case_count": result["verified_case_count"]}))
    else:
        print(encoded)
