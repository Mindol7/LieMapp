"""Finite synthetic-input throughput comparison, never an acceptance substitute.

Runs actual generated quantized matmul kernels from two captured IR modules on
identical deterministic arrays. v1/v2 are compared bitwise and at the unchanged
registered FP32 tolerance. No model, prompt, or network request is executed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

import verify_cpu_kernels as checker

V = checker.V
ROOT = V.ROOT
HERE = Path(__file__).resolve().parent
KERNELS = ("fused_dequantize1_fused_NT_matmul5_add2", "fused_dequantize3_NT_matmul7")
SIZES = (1, 7, 31, 128)


def worker(args):
    import tvm
    output = Path(args.output_dir).resolve(strict=True)
    arrays = output / "outputs"
    arrays.mkdir()
    left_dir, right_dir = Path(args.baseline_ir), Path(args.candidate_ir)
    left = tvm.ir.load_json((left_dir / "after_schedule.json").read_text())
    right = tvm.ir.load_json((right_dir / "after_schedule.json").read_text())
    results = []
    for name in KERNELS:
        a, b = checker.build_kernel(left[name]), checker.build_kernel(right[name])
        for size in SIZES:
            results.append(checker.run_case(name, left[name], right[name], a, b, size, arrays))
    summary = {"status": "passed" if all(row["passed"] for row in results) else "failed",
               "scope": "finite_synthetic_input_v1_vs_v2_kernel_performance_not_final_acceptance",
               "baseline_semantics": "preserved v1 schedule, not stock schedule",
               "baseline_ir": V.descriptor(left_dir / "after_schedule.json"),
               "candidate_ir": V.descriptor(right_dir / "after_schedule.json"),
               "worker": V.descriptor(__file__), "checker": V.descriptor(checker.__file__),
               "kernels": list(KERNELS), "sizes": list(SIZES), "cases": results,
               "speedups": [{"kernel": row["kernel"], "n": row["dynamic_n"],
                             "v1_seconds": row["stock_seconds"], "v2_seconds": row["optimized_seconds"],
                             "ratio": row["stock_seconds"] / row["optimized_seconds"]} for row in results],
               "model_inferences": 0, "external_api_calls": 0,
               "caveat": "Single timing per deterministic shape is diagnostic only; independent full numerical and native-model validation remains required."}
    V.write_new(output / "benchmark.json", summary)
    if summary["status"] != "passed":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ir", required=True)
    parser.add_argument("--candidate-ir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    if args.worker:
        worker(args)
        return
    output = Path(args.output_dir).resolve()
    if not output.is_relative_to(ROOT / ".evidence/setup/ama/mlc-llm"):
        parser.error("Benchmark evidence must stay in isolated AMA setup")
    output.mkdir(parents=True, exist_ok=False)
    from native_runtime import environment, PYTHON
    env = environment(output, threads=6)
    command = [str(PYTHON), "-B", str(Path(__file__).resolve()), "--worker",
               "--baseline-ir", str(Path(args.baseline_ir).resolve(strict=True)),
               "--candidate-ir", str(Path(args.candidate_ir).resolve(strict=True)),
               "--output-dir", str(output)]
    snapshot = output / "benchmark_cpu_schedules.py.snapshot"
    snapshot.write_bytes(Path(__file__).read_bytes())
    V.write_new(output / "invocation.json", {"command": command, "worker_snapshot": V.descriptor(snapshot),
                "baseline_ir": V.descriptor(Path(args.baseline_ir) / "after_schedule.json"),
                "candidate_ir": V.descriptor(Path(args.candidate_ir) / "after_schedule.json"),
                "input_seed": V.SPECIFICATION["input_seed"], "threads": 6,
                "kernels_predeclared": list(KERNELS), "dynamic_sizes_predeclared": list(SIZES),
                "model_inferences": 0, "evaluation_data_used": False})
    started = time.monotonic()
    with (output / "stdout.log").open("xb") as out, (output / "stderr.log").open("xb") as err:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, check=False)
    V.write_new(output / "process.json", {"exit_code": result.returncode, "elapsed_seconds": time.monotonic()-started,
                "stdout": V.descriptor(output / "stdout.log"), "stderr": V.descriptor(output / "stderr.log")})
    print((output / "stdout.log").read_text())
    if result.returncode:
        print((output / "stderr.log").read_text(), file=sys.stderr)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
