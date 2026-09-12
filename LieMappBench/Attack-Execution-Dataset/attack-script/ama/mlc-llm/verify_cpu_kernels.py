"""Execute stock/scheduled TIR kernels against immutable numerical preregistration.

Every changed model kernel and preregistered dynamic size is tested. Synthetic
matmuls exercise non-multiple output/reduction tails. This checker performs no
model inference, attack prompt, or external API call.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mlc_cpu_kernel_equivalence", HERE / "verify_cpu_equivalence.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
ROOT = V.ROOT


def numeric_comparison(stock, optimized, tolerance):
    import numpy as np
    if stock.shape != optimized.shape or stock.dtype != optimized.dtype:
        return {"passed": False, "reason": "shape_or_dtype_changed"}
    finite = bool(np.isfinite(stock).all() and np.isfinite(optimized).all())
    exact = bool(np.array_equal(stock.view(np.uint8), optimized.view(np.uint8)))
    if np.issubdtype(stock.dtype, np.integer):
        return {"passed": exact, "finite": finite, "bitwise_equal": exact, "comparison": "exact_integer"}
    difference = np.abs(stock.astype("float64") - optimized.astype("float64"))
    threshold = tolerance["atol"] + tolerance["rtol"] * np.abs(stock.astype("float64"))
    passed = finite and bool(np.all(difference <= threshold))
    return {"passed": passed, "finite": finite, "bitwise_equal": exact,
            "elements": int(stock.size), "shape": list(stock.shape), "dtype": str(stock.dtype),
            "max_absolute_error": float(difference.max()) if finite else None,
            "max_relative_error": float((difference / np.maximum(np.abs(stock), 1e-30)).max()) if finite else None,
            "failed_elements": int(np.count_nonzero(difference > threshold)) if finite else None,
            "atol": tolerance["atol"], "rtol": tolerance["rtol"]}


def structural_check(before, after, report):
    import tvm
    import tvm_ffi
    before_functions = {global_var.name_hint: function for global_var, function in before.functions_items()}
    after_functions = {global_var.name_hint: function for global_var, function in after.functions_items()}
    if set(before_functions) != set(after_functions):
        raise ValueError("Model function set changed")
    changed = sorted(name for name in before_functions if not tvm_ffi.structural_equal(
        before_functions[name], after_functions[name], map_free_vars=True))
    declared = sorted(record["name"] for record in report["decisions"] if record["applied"])
    if changed != declared or len(declared) != report["applied"]:
        raise ValueError("Changed functions differ from explicitly declared scheduled kernels")
    if any(not isinstance(before_functions[name], tvm.tirx.PrimFunc) for name in changed):
        raise ValueError("A non-kernel model graph function changed")
    return {"total_functions": len(before_functions), "changed_kernels": changed,
            "unchanged_functions": sorted(set(before_functions) - set(changed)),
            "relax_model_graph_functions_unchanged": True}


def function_buffers(function):
    import tvm
    buffers = []
    for parameter in function.params:
        if isinstance(parameter, tvm.tirx.Buffer):
            buffers.append(parameter)
        elif parameter in function.buffer_map:
            buffers.append(function.buffer_map[parameter])
        else:
            raise ValueError("Unrecognized scalar/native kernel argument: " + str(parameter))
    stores = []
    def visit(node):
        if isinstance(node, tvm.tirx.BufferStore):
            stores.append(node.buffer.data)
    tvm.tirx.stmt_functor.post_order_visit(function.body, visit)
    outputs = [index for index, buffer in enumerate(buffers)
               if any(buffer.data.same_as(data) for data in stores)]
    if not outputs:
        raise ValueError("No externally written output buffer identified")
    return buffers, outputs


def concrete_shape(buffer, dynamic_n):
    import tvm
    substitutions = {}
    for extent in buffer.shape:
        def collect(node):
            if isinstance(node, tvm.tirx.Var):
                if node.name not in {"n", "seq_len", "batch_size"}:
                    raise ValueError("Undeclared dynamic dimension: " + node.name)
                substitutions[node] = tvm.tirx.IntImm(node.ty, dynamic_n)
        tvm.tirx.stmt_functor.post_order_visit(extent, collect)
    result = []
    for extent in buffer.shape:
        value = tvm.arith.Analyzer().simplify(tvm.tirx.stmt_functor.substitute(extent, substitutions))
        if not isinstance(value, tvm.tirx.IntImm) or int(value) <= 0:
            raise ValueError("Unresolved/invalid kernel dimension: " + str(value))
        result.append(int(value))
    return tuple(result), bool(substitutions)


def build_kernel(function):
    import tvm
    return tvm.tirx.build(tvm.IRModule({"probe_kernel": function.with_attr("global_symbol", "probe_kernel")}),
                          target=tvm.target.Target({"kind": "llvm", "mcpu": "haswell"}))["probe_kernel"]


def run_case(name, stock_function, optimized_function, stock_kernel, optimized_kernel, dynamic_n, output):
    import numpy as np
    import tvm
    stock_buffers, output_indices = function_buffers(stock_function)
    optimized_buffers, optimized_outputs = function_buffers(optimized_function)
    signature = [(concrete_shape(buffer, dynamic_n)[0], str(buffer.dtype)) for buffer in stock_buffers]
    other_signature = [(concrete_shape(buffer, dynamic_n)[0], str(buffer.dtype)) for buffer in optimized_buffers]
    if signature != other_signature or output_indices != optimized_outputs:
        raise ValueError("Kernel argument/output shape/dtype contract changed")
    stock_arguments, optimized_arguments, input_records = [], [], []
    for index, (shape, dtype) in enumerate(signature):
        seed = V.SPECIFICATION["input_seed"] + index
        random = np.random.default_rng(seed)
        if index in output_indices:
            value = np.full(shape, np.nan if dtype.startswith("float") else 0xA5, dtype=dtype)
        elif dtype.startswith("uint"):
            value = random.integers(0, np.iinfo(dtype).max, size=shape, dtype=dtype)
        elif dtype.startswith("int"):
            value = random.integers(0, 7, size=shape, dtype=dtype)
        else:
            value = random.uniform(-0.125, 0.125, size=shape).astype(dtype)
        if index not in output_indices:
            input_records.append({"argument_index": index, "seed": seed, "shape": list(shape),
                                  "dtype": dtype, "sha256": hashlib.sha256(value.tobytes()).hexdigest(),
                                  "generator": "numpy.default_rng(seed), uniform(-0.125,0.125) or dtype-specific integers"})
        stock_arguments.append(tvm.runtime.tensor(value, tvm.cpu()))
        optimized_arguments.append(tvm.runtime.tensor(value, tvm.cpu()))
    started = time.monotonic()
    stock_kernel(*stock_arguments)
    stock_seconds = time.monotonic() - started
    started = time.monotonic()
    optimized_kernel(*optimized_arguments)
    optimized_seconds = time.monotonic() - started
    for record in input_records:
        for values in (stock_arguments, optimized_arguments):
            if hashlib.sha256(values[record["argument_index"]].numpy().tobytes()).hexdigest() != record["sha256"]:
                raise ValueError("Read-only kernel input was modified")
    comparisons = []
    for index in output_indices:
        baseline, candidate = stock_arguments[index].numpy(), optimized_arguments[index].numpy()
        result = numeric_comparison(baseline, candidate, V.SPECIFICATION["kernel_float32"])
        stem = f"{name}-n{dynamic_n}-arg{index}"
        for variant, value in (("stock", baseline), ("optimized", candidate)):
            path = output / (stem + "-" + variant + ".npy")
            with path.open("xb") as stream:
                np.save(stream, value, allow_pickle=False)
            result[variant + "_output"] = V.descriptor(path)
        result["argument_index"] = index
        comparisons.append(result)
    record = {"kernel": name, "dynamic_n": dynamic_n, "inputs": input_records,
              "output_comparisons": comparisons, "passed": all(row["passed"] for row in comparisons),
              "stock_seconds": stock_seconds, "optimized_seconds": optimized_seconds}
    V.write_new(output / f"{name}-n{dynamic_n}.json", record)
    print(json.dumps({"kernel": name, "dynamic_n": dynamic_n, "passed": record["passed"],
                      "max_absolute_error": max(row.get("max_absolute_error", 0) or 0 for row in comparisons),
                      "stock_seconds": stock_seconds, "optimized_seconds": optimized_seconds}), flush=True)
    return record


def synthetic_function(m, n, k):
    import tvm
    from tvm.script import tirx as T
    source = f'''@T.prim_func(s_tir=True)
def synthetic_matmul(A: T.Buffer(({m}, {k}), "float32"), B: T.Buffer(({n}, {k}), "float32"), C: T.Buffer(({m}, {n}), "float32")):
    for i, j, r in T.grid({m}, {n}, {k}):
        with T.sblock("matmul"):
            vi, vj, vr = T.axis.remap("SSR", [i, j, r])
            with T.init():
                C[vi, vj] = T.float32(0)
            C[vi, vj] = C[vi, vj] + A[vi, vr] * B[vj, vr]
'''
    return tvm.script.from_source(source, extra_vars={"T": T})


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
    optimizer = V.load(HERE / "cpu_schedule.py", "mlc_cpu_schedule_independent_validation")
    for m, n, k in V.SPECIFICATION["synthetic_matmul_shapes"]:
        name = f"synthetic_matmul_m{m}_n{n}_k{k}"
        left = synthetic_function(m, n, k)
        right, decision = optimizer.apply_schedule(left, name)
        if right is None or not decision["applied"]:
            raise ValueError("Declared synthetic matmul schedule rejected: " + json.dumps(decision))
        required_cases.append({"kernel": name, "dynamic_n": 1})
        results.append(run_case(name, left, right, build_kernel(left), build_kernel(right), 1, arrays))
    artifact = {"status": "passed" if all(row["passed"] for row in results) else "failed",
                "registration": V.descriptor(args.registration), "worker": V.descriptor(__file__),
                "optimizer": V.descriptor(HERE / "cpu_schedule.py"),
                "schedule_inputs": [V.descriptor(source / name) for name in
                                     ("before_schedule.json", "after_schedule.json", "schedule-report.json")],
                "stock_library": V.descriptor(args.stock_library), "optimized_library": V.descriptor(args.optimized_library),
                "structural_comparison": structure, "required_cases": required_cases, "cases": results,
                "cases_count": len(results), "model_inferences": 0, "external_api_calls": 0,
                "scope": "Every changed model TIR kernel on deterministic input samples, all registered dynamic sizes and synthetic M/N/K tails; not a universal proof."}
    V.write_new(output / "kernel-equivalence.json", artifact)
    if artifact["status"] != "passed":
        raise SystemExit(1)


def finalize_validation(registration_path, kernel_path, model_path, output_path):
    """Bind the finite numerical evidence to the exact deployable library."""
    V.validate_registration(registration_path)
    kernel_path, model_path = Path(kernel_path), Path(model_path)
    kernel = json.loads(kernel_path.read_text())
    model = json.loads(model_path.read_text())
    stock_probe = json.loads(Path(model["stock"]["path"]).read_text())
    candidate_probe = json.loads(Path(model["optimized"]["path"]).read_text())
    registration = V.descriptor(registration_path)
    for document in (kernel, model, stock_probe, candidate_probe):
        if document["registration"] != registration:
            raise ValueError("Validation runs do not share the same preregistration")
    if kernel["stock_library"] != stock_probe["library"] or kernel["optimized_library"] != candidate_probe["library"]:
        raise ValueError("Kernel and native model probes evaluated different binaries")
    required = [(row["kernel"], row["dynamic_n"]) for row in kernel["required_cases"]]
    actual = [(row["kernel"], row["dynamic_n"]) for row in kernel["cases"]]
    if not required or len(set(required)) != len(required) or actual != required:
        raise ValueError("Missing, duplicated, reordered, or undeclared kernel validation cases")
    expected_models = [case["case_id"] for case in V.SPECIFICATION["model_cases"]]
    if [case["case_id"] for case in model["cases"]] != expected_models:
        raise ValueError("Native model validation coverage differs from preregistration")
    kernels_passed = kernel["status"] == "passed" and all(row["passed"] for row in kernel["cases"])
    model_passed = model["status"] == "passed" and all(row["passed"] for row in model["cases"])
    # Pin the proof's transitive descriptors (arrays, compiler IR, worker source,
    # model evidence) rather than only trusting a top-level pass flag.
    artifacts = {}
    def collect(value):
        if isinstance(value, dict):
            if {"path", "sha256", "bytes"} <= value.keys():
                V.assert_descriptor(value)
                artifacts[value["path"]] = {key: value[key] for key in ("path", "sha256", "bytes")}
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    for document in (kernel, model, stock_probe, candidate_probe):
        collect(document)
    # Native observation logs and invocation/process evidence are part of the
    # comparison audit, although their run timestamps are not semantic targets.
    for probe in (model["stock"], model["optimized"]):
        for path in sorted(Path(probe["path"]).parent.rglob("*")):
            if path.is_file():
                artifacts[str(path.resolve())] = V.descriptor(path)
    report = {
        "status": "pass" if kernels_passed and model_passed else "fail",
        "passed": kernels_passed and model_passed,
        "preregistration": registration,
        "stock_library": kernel["stock_library"],
        "candidate_library": kernel["optimized_library"],
        "kernel_evidence": V.descriptor(kernel_path),
        "model_evidence": V.descriptor(model_path),
        "kernel_validation_passed": kernels_passed,
        "model_validation_passed": model_passed,
        "kernel_cases": len(actual), "changed_model_kernels": len(kernel["structural_comparison"]["changed_kernels"]),
        "model_cases": len(model["cases"]),
        "full_vocabulary_logits_collected": False,
        "thresholds": {"kernels": V.SPECIFICATION["kernel_float32"], "native_logprobs": V.SPECIFICATION["model_available_logprobs"]},
        "scope": V.SPECIFICATION["scope_limit"],
        "limitations": ["Finite deterministic tests are not a mathematical or universal equivalence proof.",
                        "Native scores cover generated tokens and their top-5 alternatives, not full-vocabulary logits.",
                        "This validates a disclosed custom CPU scheduling variant, not an unmodified upstream CPU build."],
        "external_api_calls": 0,
        "evidence_files": [artifacts[key] for key in sorted(artifacts)],
        "finalizer": V.descriptor(__file__),
    }
    V.write_new(output_path, report)
    return report


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
