"""Compile an explicitly approved CPU scheduling variant, preserving stock files."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
SOURCE_CONFIG = ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-instruct-q4f32_1-9fa644f/mlc-chat-config.json"
MODEL_DIR = ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-cpu-channel-v1"
MODEL_LIB = MODEL_DIR / "qwen2.5-3b-instruct-q4f32_1-cpu-channel-v1.so"
STOCK_LIB = ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-instruct-q4f32_1-9fa644f/qwen2.5-3b-instruct-q4f32_1-cpu.so"


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def descriptor(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def child(evidence, output):
    import tvm
    from mlc_llm.compiler_pass import pipeline
    from mlc_llm.__main__ import main as mlc_main
    from cpu_schedule import make_pass
    original = pipeline.LowBatchGemvSpecialize
    schedule_pass = make_pass(evidence / "schedule-ir")
    pipeline.LowBatchGemvSpecialize = lambda: tvm.transform.Sequential([original(), schedule_pass])
    debug = evidence / "compiler-ir"
    debug.mkdir()
    sys.argv = ["mlc_llm", "compile", str(SOURCE_CONFIG), "--device", '{"kind":"llvm","mcpu":"haswell"}',
                "--host", "x86_64-linux-gnu", "--overrides", "context_window_size=4096;prefill_chunk_size=512;max_batch_size=1",
                "--opt", "O0", "--debug-dump", str(debug), "-o", str(output)]
    mlc_main()


def identity_worker(evidence, candidate, compile_attempt):
    """Produce explicit compiler scope/unchanged-graph proof; not numeric proof."""
    import tvm
    import tvm_ffi
    from mlc_llm.cli.model_metadata import _extract_metadata
    source_dir = ROOT / ".evidence/setup/ama/mlc-llm" / compile_attempt
    ir_dir = source_dir / "schedule-ir"
    before = tvm.ir.load_json((ir_dir / "before_schedule.json").read_text())
    after = tvm.ir.load_json((ir_dir / "after_schedule.json").read_text())
    left = {g.name_hint: f for g, f in before.functions_items()}
    right = {g.name_hint: f for g, f in after.functions_items()}
    if left.keys() != right.keys():
        raise ValueError("Compiler pass added or removed model functions")
    changed = [name for name in left if not tvm_ffi.structural_equal(left[name], right[name], map_free_vars=True)]
    relax_names = [name for name in left if isinstance(left[name], tvm.relax.Function)]
    schedule_report = json.loads((ir_dir / "schedule-report.json").read_text())
    scheduled = [row["name"] for row in schedule_report["decisions"] if row["applied"]]
    if set(changed) != set(scheduled) or any(name in changed for name in relax_names):
        raise ValueError("Changes exceed declared TIR scheduling scope")
    stock_metadata = _extract_metadata(STOCK_LIB)
    candidate_metadata = _extract_metadata(candidate)
    if stock_metadata != candidate_metadata:
        raise ValueError("Compiled model metadata differs from stock")
    original, instrumented = ROOT / "LIE/mlc-llm", ROOT / "Instrumented-LIE/ama/mlc-llm/engine"
    original_commit = subprocess.check_output(["git", "-C", str(original), "rev-parse", "HEAD"], text=True).strip()
    original_status = subprocess.check_output(["git", "-C", str(original), "status", "--porcelain"], text=True)
    if original_commit != "9fa644f54b04983adea4d0168f49fc6af4a893ba" or original_status:
        raise ValueError("Original MLC source revision or clean status changed")
    math_sources = []
    for subtree in ("python/mlc_llm/model/qwen2", "python/mlc_llm/nn", "python/mlc_llm/op", "python/mlc_llm/compiler_pass"):
        for path in sorted((original / subtree).rglob("*.py")):
            relative = path.relative_to(original)
            copy = instrumented / relative
            if not copy.is_file() or sha(path) != sha(copy):
                raise ValueError(f"Model math/compiler source changed: {relative}")
            math_sources.append({"path": str(relative), "original_sha256": sha(path), "instrumented_sha256": sha(copy)})
    manifest = json.loads((source_dir / "manifest.json").read_text())
    if manifest["exit_code"] != 0 or manifest["output"]["sha256"] != sha(candidate):
        raise ValueError("Candidate does not match successful compiler attempt")
    report = {"schema_version": "1.0.0", "status": "pass", "scope": "compiler_identity_and_source_preservation_not_numerical_equivalence",
              "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "stock_library": descriptor(STOCK_LIB),
              "candidate_library": descriptor(candidate), "compiler_attempt": descriptor(source_dir / "manifest.json"),
              "compiler_source_snapshots": [descriptor(source_dir / (name + ".snapshot")) for name in ("compile_cpu.py", "cpu_schedule.py")],
              "ir_artifacts": {name: descriptor(ir_dir / name) for name in ("before_schedule.json", "after_schedule.json", "schedule-report.json")},
              "all_function_count": len(left), "relax_graph_function_count": len(relax_names),
              "all_relax_model_graph_functions_unchanged": True, "changed_tir_functions": changed,
              "changed_functions_exactly_match_declared_schedule": True,
              "all_other_functions_unchanged": True, "compiled_metadata_entirely_equal": True,
              "compiled_parameter_contracts_equal": True, "compiled_parameter_count": len(stock_metadata["params"]),
              "stock_compiled_metadata": stock_metadata,
              "original_repository": str(original.relative_to(ROOT)), "original_commit": original_commit,
              "original_worktree_status": original_status, "original_worktree_clean": True,
              "model_math_and_upstream_compiler_sources_unchanged": math_sources,
              "unchanged_source_file_count": len(math_sources),
              "remaining_validation": "Independent actual kernel numerics, native greedy outputs/scores and performance must pass separately before AMA execution."}
    (evidence / "compiler-identity.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
    print(json.dumps({"compiler_identity": "pass", "changed_tir_functions": len(changed),
                      "relax_functions_unchanged": len(relax_names), "source_files_unchanged": len(math_sources)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--verify-identity", action="store_true")
    parser.add_argument("--compile-attempt")
    parser.add_argument("--output", type=Path, default=MODEL_LIB)
    args = parser.parse_args()
    if not args.attempt.replace("-", "").replace("_", "").isalnum():
        parser.error("Invalid attempt name")
    if args.verify_identity and (not args.compile_attempt or not args.compile_attempt.replace("-", "").replace("_", "").isalnum()):
        parser.error("Identity verification requires a valid compile-attempt")
    evidence = ROOT / ".evidence/setup/ama/mlc-llm" / args.attempt
    if args.child:
        if args.verify_identity:
            identity_worker(evidence, args.output, args.compile_attempt)
        else:
            child(evidence, args.output)
        return 0
    if args.output.exists() and not args.verify_identity:
        raise FileExistsError(args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=False)
    from native_runtime import environment, PYTHON, DEPS, ENGINE
    env = environment(evidence)
    env["TMPDIR"] = str(evidence / "tmp")
    Path(env["TMPDIR"]).mkdir()
    env["TVM_CACHE_DIR"] = str(evidence / "tvm-cache")
    Path(env["TVM_CACHE_DIR"]).mkdir()
    commands = [str(PYTHON), "-B", str(Path(__file__).resolve()), "--child", "--attempt", args.attempt, "--output", str(args.output)]
    if args.verify_identity:
        commands += ["--verify-identity", "--compile-attempt", args.compile_attempt]
    dependencies = [Path(__file__), HERE / "cpu_schedule.py", HERE / "native_runtime.py", SOURCE_CONFIG,
                    DEPS / "copy-manifest.json", ENGINE / "python/mlc_llm/compiler_pass/pipeline.py",
                    ENGINE / "python/mlc_llm/model/qwen2/qwen2_model.py", DEPS / "lib/libtvm_compiler.so",
                    DEPS / "lib/libtvm_runtime.so", DEPS / "python/tvm_ffi/lib/libtvm_ffi.so"]
    record = {"schema_version": "1.0.0", "scope": "explicit_CPU_compiler_scheduling_variant_not_stock_upstream",
              "command": commands, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "dependencies_before": [descriptor(p) for p in dependencies],
              "stock_library_preserved": ".evidence/models/ama/mlc-qwen2.5-3b-instruct-q4f32_1-9fa644f/qwen2.5-3b-instruct-q4f32_1-cpu.so",
              "environment": {k: env[k] for k in ("PYTHONPATH", "TVM_LIBRARY_PATH", "MLC_LIBRARY_PATH", "LD_LIBRARY_PATH",
                                                    "TVM_NUM_THREADS", "TMPDIR", "TVM_CACHE_DIR")},
              "user_approved": True, "evaluation_data_used": False}
    for path in (Path(__file__), HERE / "cpu_schedule.py"):
        (evidence / (path.name + ".snapshot")).write_bytes(path.read_bytes())
    (evidence / "manifest-start.json").write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps({"evidence": str(evidence), "command": commands}), flush=True)
    started = time.monotonic()
    with (evidence / "stdout.log").open("wb") as out, (evidence / "stderr.log").open("wb") as err:
        result = subprocess.run(commands, cwd=ROOT, env=env, stdout=out, stderr=err, check=False)
    record.update({"exit_code": result.returncode, "elapsed_seconds": time.monotonic()-started,
                   "dependencies_after": [descriptor(p) for p in dependencies],
                   "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "output": descriptor(args.output) if args.output.is_file() else None,
                   "stdout": descriptor(evidence / "stdout.log"), "stderr": descriptor(evidence / "stderr.log")})
    record["dependencies_unchanged"] = record["dependencies_before"] == record["dependencies_after"]
    (evidence / "manifest.json").write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps({"exit_code": result.returncode, "elapsed_seconds": record["elapsed_seconds"],
                      "dependencies_unchanged": record["dependencies_unchanged"], "output": record["output"]}), flush=True)
    if result.returncode:
        print((evidence / "stderr.log").read_text(errors="replace")[-5000:], flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
