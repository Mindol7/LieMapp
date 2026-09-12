"""V2 kernel orchestration, reusing the unchanged v1 numerical checker.

Separate driver preserves hashes of completed v1 validation source/evidence.
All cases/tolerances stay in the original immutable preregistration.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mlc_v2_preserved_kernel_core", HERE / "verify_cpu_kernels.py")
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)
V, ROOT = K.V, K.ROOT
structural_check = K.structural_check
function_buffers = K.function_buffers
concrete_shape = K.concrete_shape
build_kernel = K.build_kernel
run_case = K.run_case
synthetic_function = K.synthetic_function

def worker(args):
    V.validate_registration(args.registration)
    import tvm
    from mlc_llm.cli.model_metadata import _extract_metadata
    output = Path(args.output_dir).resolve(strict=True)
    arrays = output / "outputs"
    arrays.mkdir()
    source = Path(args.schedule_ir).resolve(strict=True)
    before = tvm.ir.load_json((source / "before_schedule.json").read_text())
    after = tvm.ir.load_json((source / "after_schedule.json").read_text())
    report = json.loads((source / "schedule-report.json").read_text())
    structure = structural_check(before, after, report)
    stock_metadata = _extract_metadata(Path(args.stock_library).resolve(strict=True))
    optimized_metadata = _extract_metadata(Path(args.optimized_library).resolve(strict=True))
    if stock_metadata != optimized_metadata:
        raise ValueError("Compiled model parameter/KV/runtime metadata changed")
    V.write_new(output / "stock-model-metadata.json", stock_metadata)
    V.write_new(output / "optimized-model-metadata.json", optimized_metadata)
    V.write_new(output / "structural-equivalence.json", {**structure, "compiled_metadata_equal": True})
    results = []
    required_cases = []
    # All changed kernels are required, not a favorable subset. Dynamic n axes
    # are evaluated at every registered value; fully fixed kernels run once.
    for name in structure["changed_kernels"]:
        left, right = before[name], after[name]
        buffers, _ = function_buffers(left)
        dynamic = any(concrete_shape(buffer, 1)[1] for buffer in buffers)
        sizes = V.SPECIFICATION["kernel_dynamic_n"] if dynamic else [1]
        required_cases.extend({"kernel": name, "dynamic_n": n} for n in sizes)
        a, b = build_kernel(left), build_kernel(right)
        for n in sizes:
            results.append(run_case(name, left, right, a, b, n, arrays))
    optimizer = V.load(HERE / "cpu_schedule_v2.py", "mlc_cpu_schedule_independent_validation")
    for m, n, k in V.SPECIFICATION["synthetic_matmul_shapes"]:
        name = f"synthetic_matmul_m{m}_n{n}_k{k}"
        left = synthetic_function(m, n, k)
        right, decision = optimizer.apply_schedule(left, name)
        if right is None or not decision["applied"]:
            raise ValueError("Declared synthetic matmul schedule rejected: " + json.dumps(decision))
        required_cases.append({"kernel": name, "dynamic_n": 1})
        results.append(run_case(name, left, right, build_kernel(left), build_kernel(right), 1, arrays))
    artifact = {"status": "passed" if all(row["passed"] for row in results) else "failed",
                "registration": V.descriptor(args.registration), "worker": V.descriptor(__file__), "numerical_core": V.descriptor(HERE / "verify_cpu_kernels.py"),
                "optimizer": V.descriptor(HERE / "cpu_schedule_v2.py"),
                "schedule_inputs": [V.descriptor(source / name) for name in
                                     ("before_schedule.json", "after_schedule.json", "schedule-report.json")],
                "stock_library": V.descriptor(args.stock_library), "optimized_library": V.descriptor(args.optimized_library),
                "structural_comparison": structure, "required_cases": required_cases, "cases": results,
                "cases_count": len(results), "model_inferences": 0, "external_api_calls": 0,
                "scope": "Every changed model TIR kernel on deterministic input samples, all registered dynamic sizes and synthetic M/N/K tails; not a universal proof."}
    V.write_new(output / "kernel-equivalence.json", artifact)
    if artifact["status"] != "passed":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("registration", "schedule-ir", "stock-library", "optimized-library", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    if args.worker:
        worker(args)
        return
    V.validate_registration(args.registration)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    native = V.load(HERE / "native_runtime.py", "mlc_cpu_kernel_validation_native")
    command = [str(native.PYTHON), "-B", str(Path(__file__).resolve()), "--worker"]
    for key in ("registration", "schedule_ir", "stock_library", "optimized_library", "output_dir"):
        command += ["--" + key.replace("_", "-"), str(Path(getattr(args, key)).resolve())]
    V.write_new(output / "invocation.json", {"command": command, "threads": args.threads,
                 "worker": V.descriptor(__file__), "numerical_policy": V.SPECIFICATION})
    with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
        result = subprocess.run(command, cwd=ROOT, env=native.environment(output, threads=args.threads),
                                stdout=stdout, stderr=stderr, check=False)
    V.write_new(output / "process.json", {"exit_code": result.returncode,
                 "stdout": V.descriptor(output / "stdout.log"), "stderr": V.descriptor(output / "stderr.log")})
    print(json.dumps({"output": str(output), "exit_code": result.returncode}), flush=True)
    if result.returncode != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

