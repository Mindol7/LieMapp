"""Additive preregistered non-greedy native score probe; never an AMA trial.

Greedy temperature=0 native probabilities can be one-hot. They are not logits
equivalence evidence. This separate immutable protocol uses temperature=1 and
one output token to compare native chosen/top-5 log probabilities before any
AMA evaluation. Original greedy evidence and acceptance thresholds stay intact.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mlc_cpu_supplemental_scores_base", HERE / "verify_cpu_equivalence.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
V.SPECIFICATION = copy.deepcopy(V.SPECIFICATION)
V.SPECIFICATION["policy_id"] = "ama-mlc-cpu-equivalence-native-scores-v1"
V.SPECIFICATION["model_settings"].update(temperature=1.0, max_tokens=1)
V.SPECIFICATION["scope_limit"] = (
    "Two non-AMA prompts, native first-token chosen/top-5 log probabilities at temperature=1; "
    "not full-vocabulary raw logits or mathematical equivalence. Original greedy cases remain separate."
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("--base-registration", required=True)
    register.add_argument("--output", required=True)
    for name in ("model-probe", "_model-worker"):
        probe = sub.add_parser(name)
        probe.add_argument("--registration", required=True)
        probe.add_argument("--variant", choices=("stock", "optimized"), required=True)
        probe.add_argument("--library", required=True)
        probe.add_argument("--output-dir", required=True)
        probe.add_argument("--threads", type=int, default=6)
    compare = sub.add_parser("compare-model")
    for key in ("registration", "stock-dir", "optimized-dir", "output"):
        compare.add_argument("--" + key, required=True)
    args = parser.parse_args()
    if args.command == "register":
        base = json.loads(Path(args.base_registration).read_text())
        if base["specification"]["policy_id"] != "ama-mlc-cpu-equivalence-v1":
            raise ValueError("A preserved original greedy registration is required")
        V.assert_descriptor(base["stock_library"])
        V.assert_descriptor(base["official_model_manifest"])
        V.write_new(args.output, {
            "registered_utc": datetime.now(timezone.utc).isoformat(),
            "specification": V.SPECIFICATION,
            "stock_library": base["stock_library"],
            "official_model_manifest": base["official_model_manifest"],
            "base_registration": V.descriptor(args.base_registration),
            "registration_implementation": V.descriptor(__file__),
            "shared_probe_implementation": V.descriptor(HERE / "verify_cpu_equivalence.py"),
            "temperature_one_outputs_examined_at_registration": False,
            "reason": "Greedy native probabilities were degenerate; add genuinely probabilistic score coverage before AMA, without altering prior tests.",
        })
        print(json.dumps(V.descriptor(args.output)), flush=True)
        return
    registration = V.validate_registration(args.registration)
    for key in ("registration_implementation", "shared_probe_implementation", "base_registration"):
        V.assert_descriptor(registration[key])
    if args.command == "_model-worker":
        V.model_worker(args)
    elif args.command == "compare-model":
        V.compare_model(args)
    else:
        output = Path(args.output_dir).resolve()
        output.mkdir(parents=True, exist_ok=False)
        native = V.load(HERE / "native_runtime.py", "mlc_cpu_native_score_runtime")
        command = [str(native.PYTHON), "-B", str(Path(__file__).resolve()), "_model-worker",
                   "--registration", str(Path(args.registration).resolve()), "--variant", args.variant,
                   "--library", str(Path(args.library).resolve()), "--output-dir", str(output)]
        V.write_new(output / "invocation.json", {"command": command, "threads": args.threads,
                    "supplemental_implementation": V.descriptor(__file__),
                    "shared_probe_implementation": V.descriptor(HERE / "verify_cpu_equivalence.py")})
        with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
            process = subprocess.run(command, cwd=V.ROOT, env=native.environment(output, threads=args.threads),
                                     stdout=stdout, stderr=stderr, check=False)
        V.write_new(output / "process.json", {"exit_code": process.returncode,
                    "stdout": V.descriptor(output / "stdout.log"), "stderr": V.descriptor(output / "stderr.log")})
        print(json.dumps({"variant": args.variant, "exit_code": process.returncode, "output": str(output)}), flush=True)
        if process.returncode:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
