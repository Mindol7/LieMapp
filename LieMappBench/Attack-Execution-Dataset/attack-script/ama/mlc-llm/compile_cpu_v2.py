"""Compile independent M4xN8 CPU candidate without editing v1 or stock files."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import time

import compile_cpu as previous

ROOT, HERE = previous.ROOT, previous.HERE
SOURCE_CONFIG = previous.SOURCE_CONFIG
MODEL_LIB = ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-cpu-row4-channel8-v2/qwen2.5-3b-instruct-q4f32_1-cpu-row4-channel8-v2.so"
V1_LIB = previous.MODEL_LIB
SOURCES = [HERE / name for name in ("compile_cpu_v2.py", "cpu_schedule_v2.py", "compile_cpu.py", "cpu_schedule.py")]
descriptor, sha = previous.descriptor, previous.sha


def child(evidence, output):
    import tvm
    from mlc_llm.compiler_pass import pipeline
    from mlc_llm.__main__ import main as mlc_main
    from cpu_schedule_v2 import make_pass
    original = pipeline.LowBatchGemvSpecialize
    schedule_pass = make_pass(evidence / "schedule-ir")
    pipeline.LowBatchGemvSpecialize = lambda: tvm.transform.Sequential([original(), schedule_pass])
    debug = evidence / "compiler-ir"
    debug.mkdir()
    sys.argv = ["mlc_llm", "compile", str(SOURCE_CONFIG), "--device", '{"kind":"llvm","mcpu":"haswell"}',
                "--host", "x86_64-linux-gnu", "--overrides", "context_window_size=4096;prefill_chunk_size=512;max_batch_size=1",
                "--opt", "O0", "--debug-dump", str(debug), "-o", str(output)]
    mlc_main()


def identity_worker(evidence, output, compile_attempt):
    previous.identity_worker(evidence, output, compile_attempt)
    report_path = evidence / "compiler-identity.json"
    report = json.loads(report_path.read_text())
    attempt_dir = ROOT / ".evidence/setup/ama/mlc-llm" / compile_attempt
    report["compiler_source_snapshots"] = [descriptor(attempt_dir / (path.name + ".snapshot")) for path in SOURCES]
    report["variant"] = "llvm-cpu-row4-channel8-v2"
    report["previous_v1_library_preserved"] = descriptor(V1_LIB)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")


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
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-cpu-row4-channel8-v2"):
        parser.error("v2 output must remain in its isolated model directory")
    evidence = ROOT / ".evidence/setup/ama/mlc-llm" / args.attempt
    if args.child:
        if args.verify_identity:
            identity_worker(evidence, output, args.compile_attempt)
        else:
            child(evidence, output)
        return 0
    if output.exists() and not args.verify_identity:
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=False)
    from native_runtime import environment, PYTHON, DEPS, ENGINE
    env = environment(evidence)
    for variable, name in (("TMPDIR", "tmp"), ("TVM_CACHE_DIR", "tvm-cache")):
        env[variable] = str(evidence / name)
        Path(env[variable]).mkdir()
    command = [str(PYTHON), "-B", str(Path(__file__).resolve()), "--child", "--attempt", args.attempt, "--output", str(output)]
    if args.verify_identity:
        command += ["--verify-identity", "--compile-attempt", args.compile_attempt]
    dependencies = [*SOURCES, HERE / "native_runtime.py", SOURCE_CONFIG, previous.STOCK_LIB, V1_LIB,
                    DEPS / "copy-manifest.json", ENGINE / "python/mlc_llm/compiler_pass/pipeline.py",
                    ENGINE / "python/mlc_llm/model/qwen2/qwen2_model.py", DEPS / "lib/libtvm_compiler.so",
                    DEPS / "lib/libtvm_runtime.so", DEPS / "python/tvm_ffi/lib/libtvm_ffi.so"]
    record = {"schema_version": "1.0.0", "scope": "explicit_CPU_M4xN8_compiler_variant_not_stock_upstream",
              "variant": "llvm-cpu-row4-channel8-v2", "command": command,
              "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "dependencies_before": [descriptor(path) for path in dependencies],
              "environment": {key: env[key] for key in ("PYTHONPATH", "TVM_LIBRARY_PATH", "MLC_LIBRARY_PATH",
                  "LD_LIBRARY_PATH", "TVM_NUM_THREADS", "TMPDIR", "TVM_CACHE_DIR")},
              "user_approved": True, "evaluation_data_used": False,
              "preserved_prior_libraries": [descriptor(previous.STOCK_LIB), descriptor(V1_LIB)]}
    for path in SOURCES:
        (evidence / (path.name + ".snapshot")).write_bytes(path.read_bytes())
    (evidence / "manifest-start.json").write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps({"evidence": str(evidence), "command": command}), flush=True)
    started = time.monotonic()
    with (evidence / "stdout.log").open("wb") as out, (evidence / "stderr.log").open("wb") as err:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, check=False)
    record.update({"exit_code": result.returncode, "elapsed_seconds": time.monotonic()-started,
                   "dependencies_after": [descriptor(path) for path in dependencies],
                   "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "output": descriptor(output) if output.is_file() else None,
                   "stdout": descriptor(evidence / "stdout.log"), "stderr": descriptor(evidence / "stderr.log")})
    record["dependencies_unchanged"] = record["dependencies_before"] == record["dependencies_after"]
    (evidence / "manifest.json").write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps({key: record[key] for key in ("exit_code", "elapsed_seconds", "dependencies_unchanged", "output")}), flush=True)
    if result.returncode:
        print((evidence / "stderr.log").read_text(errors="replace")[-5000:], flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
