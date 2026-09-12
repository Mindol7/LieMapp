"""Seal real kernel, greedy-token and nondegenerate native-score evidence."""
from __future__ import annotations
import argparse
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mlc_cpu_validation_kernels", HERE / "verify_cpu_kernels.py")
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)
V = K.V


def score_evidence(score_registration, score_comparison, stock_library, candidate_library):
    registration = json.loads(Path(score_registration).read_text())
    comparison = json.loads(Path(score_comparison).read_text())
    policy = registration["specification"]
    if policy["policy_id"] != "ama-mlc-cpu-equivalence-native-scores-v1":
        raise ValueError("Missing explicit nondegenerate native-score preregistration")
    if policy["model_settings"]["temperature"] != 1.0 or policy["model_settings"]["max_tokens"] != 1:
        raise ValueError("Native score probe settings changed")
    if policy["model_available_logprobs"] != V.SPECIFICATION["model_available_logprobs"]:
        raise ValueError("Score tolerance changed")
    if comparison["registration"] != V.descriptor(score_registration):
        raise ValueError("Score comparison registration identity mismatch")
    implementations = [registration[key] for key in ("registration_implementation", "shared_probe_implementation")]
    for descriptor in implementations:
        V.assert_descriptor(descriptor)
    artifacts = {}
    probes = []
    for role, library in (("stock", stock_library), ("optimized", candidate_library)):
        V.assert_descriptor(comparison[role])
        path = Path(comparison[role]["path"])
        probe = json.loads(path.read_text())
        if probe["library"] != library or probe["registration"] != comparison["registration"]:
            raise ValueError("Score probe library or registration mismatch")
        for child in sorted(path.parent.rglob("*")):
            if child.is_file():
                artifacts[str(child.resolve())] = V.descriptor(child)
        probes.append(probe)
    expected = [case["case_id"] for case in policy["model_cases"]]
    if [case["case_id"] for case in comparison["cases"]] != expected:
        raise ValueError("Missing score comparison cases")
    if any([case["case_id"] for case in probe["cases"]] != expected for probe in probes):
        raise ValueError("Missing, extra, or reordered raw native score probe cases")
    nondegenerate = []
    recomputed = []
    for index, (left, right) in enumerate(zip(probes[0]["cases"], probes[1]["cases"])):
        if left["case_id"] != expected[index] or right["case_id"] != expected[index]:
            raise ValueError("Score probe case identity mismatch")
        for case in (left, right):
            for key in ("temperature", "top_p", "max_tokens", "seed", "n", "logprobs", "top_logprobs"):
                if case["native_generation_config"][key] != policy["model_settings"][key]:
                    raise ValueError("Actual C++ setting differs from score preregistration: " + key)
        a = left["response"]["choices"][0]["logprobs"]
        b = right["response"]["choices"][0]["logprobs"]
        scores = V.compare_scores(a, b, policy["model_available_logprobs"])
        recomputed.append(scores)
        # The selected token may legitimately be extremely likely; require at
        # least two distinct, strictly interior alternative probabilities for
        # each probe so a greedy one-hot/clamp vector cannot satisfy this check.
        for values in (a, b):
            top = values["content"][0]["top_logprobs"]
            interior = {row["logprob"] for row in top if math.log(1e-9) < row["logprob"] < -1e-7}
            nondegenerate.append(len(interior) >= 2)
    passed = (comparison["status"] == "passed" and all(case["passed"] for case in comparison["cases"])
              and all(score["passed"] for score in recomputed) and all(nondegenerate))
    return {"passed": passed, "registration": V.descriptor(score_registration),
            "comparison": V.descriptor(score_comparison), "nondegenerate_checks": nondegenerate,
            "implementations": implementations,
            "case_count": len(comparison["cases"]),
            "values_compared": sum(score["values_compared"] for score in recomputed),
            "maximum_absolute_error": max(score["maximum_absolute_error"] for score in recomputed),
            "evidence_files": list(artifacts.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("registration", "kernel-evidence", "greedy-model-evidence", "score-registration", "score-model-evidence", "output"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    base_path = output.with_name(output.stem + "-kernel-greedy.json")
    base = K.finalize_validation(args.registration, args.kernel_evidence, args.greedy_model_evidence, base_path)
    scores = score_evidence(args.score_registration, args.score_model_evidence,
                            base["stock_library"], base["candidate_library"])
    report = {**base, "status": "pass" if base["passed"] and scores["passed"] else "fail",
              "passed": base["passed"] and scores["passed"], "kernel_greedy_evidence": V.descriptor(base_path),
              "probabilistic_native_score_validation": scores,
              "greedy_score_interpretation": "temperature=0 returned one-hot/clamped probabilities; used only with exact token/text evidence, not raw-logit equivalence.",
              "scope": "All changed TIR kernels on finite registered shapes; exact greedy tokens/text; first-token chosen/top5 native log probabilities at temperature1. No full-vocabulary logits or universal equivalence claim.",
              "finalizer": V.descriptor(__file__)}
    V.write_new(output, report)
    print(json.dumps({"status": report["status"], "output": str(output)}), flush=True)
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
