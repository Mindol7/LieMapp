"""Prepare a native CPU MLC model from the already pinned AMA HF source.

Every command has a new evidence directory; stdout, stderr, exit status and
input/output hashes are retained. No original or SIAI source is modified.
The pre-existing pinned compiler/runtime/Python environment are READ-ONLY
dependencies, not newly built artifacts. This is setup, not an AMA evaluation.
"""
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
ENGINE = ROOT / "Instrumented-LIE/ama/mlc-llm/engine"
LEGACY = ROOT / "Instrumented-LIE/siai/mlc-llm"
SOURCE = ROOT / ".evidence/models/ama/qwen2.5-3b-instruct-hf/aa8e72537993ba99e69dfaafa59ed015b17504d1"
MODEL = ROOT / ".evidence/models/ama/mlc-qwen2.5-3b-instruct-q4f32_1-9fa644f"
LIBRARY = MODEL / "qwen2.5-3b-instruct-q4f32_1-cpu.so"
PYTHON = LEGACY / ".venv/bin/python"
REVISION = "9fa644f54b04983adea4d0168f49fc6af4a893ba"


def convert_with_dtype_compat(torch_site: str, argv: list[str]) -> None:
    """Conversion-process-only adapter: typed TVM dtype -> identical NumPy string.

    No model/compiler/runtime source changes. Exact BF16 -> FP32 finite values
    are checked against PyTorch for every BF16 bit pattern before conversion.
    The pinned TVM API supplies DataType objects where the MLC loader passes
    them directly to NumPy; canonical str(dtype) is the NumPy-compatible
    representation, not a quantization or precision change.
    """
    import functools
    import runpy
    sys.path.append(torch_site)
    # Match stock CLI load order: MLC/TVM are initialized before the HF loader
    # imports PyTorch. This avoids silently changing native-library resolution.
    from mlc_llm.loader.mapping import ExternMapping
    from tvm.runtime import DataType
    import ml_dtypes
    import numpy as np
    import torch

    raw = np.arange(65536, dtype=np.uint16)
    source = raw.view(ml_dtypes.bfloat16)
    canonical = source.astype(str(DataType("float32")))
    expected = torch.from_numpy(raw.view(np.int16)).view(torch.bfloat16).float().numpy()
    finite = np.isfinite(expected)
    if canonical[finite].tobytes() != expected[finite].tobytes():
        raise RuntimeError("BF16->FP32 dtype representation equivalence failed")
    if not np.array_equal(canonical, expected, equal_nan=True):
        raise RuntimeError("Nonfinite BF16 conversion classification differs")
    print(json.dumps({"conversion_dtype_adapter": "TVM DataType -> canonical str(dtype), float32 only",
                      "bf16_patterns_checked": 65536, "finite_bit_exact_patterns": int(finite.sum()),
                      "all_values_equal_including_nonfinite_classification": True,
                      "torch_version": torch.__version__, "numpy_version": np.__version__}), flush=True)
    original = ExternMapping.add_mapping
    count = 0

    def normalized(self, map_from, map_to, func):
        nonlocal count
        if isinstance(func, functools.partial) and "dtype" in func.keywords:
            dtype = str(func.keywords["dtype"])
            if dtype != "float32":
                raise RuntimeError(f"Unexpected conversion dtype {dtype}; adapter accepts only float32")
            func = functools.partial(func.func, *func.args, **(func.keywords | {"dtype": dtype}))
            count += 1
        return original(self, map_from, map_to, func)

    ExternMapping.add_mapping = normalized
    sys.argv = ["mlc_llm", *argv]
    try:
        runpy.run_module("mlc_llm", run_name="__main__")
    finally:
        print(json.dumps({"dtype_argument_normalizations": count}), flush=True)


def verify_model_contract(model_dir: str, model_lib: str, output: str) -> None:
    """Verify official packed weights, compile metadata and source architecture.

    Physical cache order need not equal parameter order: the pinned native
    FunctionTable loads parameters by metadata name. Each shape/dtype and
    packed byte interval is checked, and every floating cache value is finite.
    This is not proof of the publisher's unspecified original HF base revision.
    """
    import math
    import numpy as np
    from mlc_llm.cli.model_metadata import _extract_metadata
    model = Path(model_dir)
    config = json.loads((model / "mlc-chat-config.json").read_text())
    cache = json.loads((model / "tensor-cache.json").read_text())
    metadata = _extract_metadata(Path(model_lib))
    expected = {p["name"]: {k: p[k] for k in ("name", "shape", "dtype")} for p in metadata["params"]}
    observed, checked_shards, floating_count = {}, [], 0
    for shard in cache["records"]:
        path = model / shard["dataPath"]
        if path.resolve().parent != model.resolve():
            raise ValueError("Unsafe tensor cache shard path")
        packed = path.read_bytes()
        if len(packed) != shard["nbytes"]:
            raise ValueError("Shard byte count mismatch")
        if "md5sum" in shard and hashlib.md5(packed).hexdigest() != shard["md5sum"]:
            raise ValueError("Shard publisher MD5 mismatch")
        intervals = []
        for param in shard["records"]:
            name = param["name"]
            if name in observed:
                raise ValueError("Duplicate tensor name")
            observed[name] = {k: param[k] for k in ("name", "shape", "dtype")}
            start, count = param["byteOffset"], math.prod(param["shape"])
            end = start + param["nbytes"]
            if not (0 <= start <= end <= len(packed)):
                raise ValueError("Invalid tensor byte range")
            intervals.append((start, end))
            dtype = param["dtype"]
            encoding = param["format"]
            if dtype == "float32" and encoding == "f32-to-bf16":
                if param["nbytes"] != count * 2:
                    raise ValueError("Packed BF16 size mismatch")
                words = np.frombuffer(packed, dtype="<u2", count=count, offset=start)
                values = np.left_shift(words.astype("uint32"), np.uint32(16)).view("float32")
                if not np.isfinite(values).all():
                    raise ValueError(f"Nonfinite floating weight: {name}")
                floating_count += count
            elif dtype in ("float32", "uint32"):
                if param["nbytes"] != count * 4:
                    raise ValueError("Raw 32-bit tensor size mismatch")
                if dtype == "float32":
                    values = np.frombuffer(packed, dtype="<f4", count=count, offset=start)
                    if not np.isfinite(values).all():
                        raise ValueError(f"Nonfinite floating weight: {name}")
                    floating_count += count
            else:
                raise ValueError(f"Unexpected dtype {dtype}")
        cursor = 0
        for start, end in sorted(intervals):
            if start != cursor:
                raise ValueError("Overlapping or uncovered tensor bytes")
            cursor = end
        if cursor != len(packed):
            raise ValueError("Trailing uncovered shard bytes")
        checked_shards.append(record(path))
    if expected != observed or len(expected) != len(metadata["params"]):
        raise ValueError("Official tensor contracts differ from compiled metadata")
    source_config = json.loads((SOURCE / "config.json").read_text())
    architecture_fields = ("hidden_act", "hidden_size", "intermediate_size", "num_attention_heads", "num_hidden_layers",
                           "num_key_value_heads", "rms_norm_eps", "rope_theta", "vocab_size", "tie_word_embeddings")
    architecture = {k: {"official": config["model_config"][k], "reference_hf": source_config[k],
                        "equal": config["model_config"][k] == source_config[k]} for k in architecture_fields}
    if not all(p["equal"] for p in architecture.values()):
        raise ValueError("Official architecture differs from compilation source")
    if metadata["quantization"] != config["quantization"] or metadata["quantization"] != "q4f32_1":
        raise ValueError("Quantization identity mismatch")
    result = {"schema_version": "1.0.0", "status": "verified_provisional_library_selection_not_frozen", "checked_at": timestamp(),
              "model_cache_path": str(model.relative_to(ROOT)), "compiled_library": record(Path(model_lib)),
              "official_repository": "mlc-ai/Qwen2.5-3B-Instruct-q4f32_1-MLC",
              "official_provenance": "LieMappBench/Attack-Execution-Dataset/attack-source/ama/mlc-llm/model-provenance/dfa91e8/manifest.json",
              "base_hf_revision_known": False,
              "base_hf_revision_caveat": "The official prequantized distribution does not identify its exact Qwen base revision; equality to the other engines' HF revision is not asserted.",
              "quantization": "q4f32_1", "model_compute_dtype": "float32", "packed_weights": "uint32 int4 group32",
              "floating_storage_note": "Publisher uses f32-to-bf16 encoding for float32-declared scales and unquantized tensors; native cache loader expands to float32.",
              "compiled_metadata": metadata, "parameter_count_in_cache": len(observed), "shard_count": len(checked_shards),
              "all_parameter_names_shapes_dtypes_match": True,
              "physical_order_equals_compiled_parameter_order": list(expected) == list(observed),
              "physical_order_explanation": "cpp/serve/function_table.cc:185-196 calls vm.builtin.param_array_from_cache_by_name with compiled metadata parameter names.",
              "floating_values_checked_finite": floating_count, "all_byte_ranges_covered_without_overlap": True,
              "all_publisher_shard_md5_matches": True, "architectural_comparison": architecture,
              "tokenizer_comparison_to_reference": {name: {"official_sha256": sha(model/name), "reference_sha256": sha(SOURCE/name),
                   "equal": sha(model/name) == sha(SOURCE/name)} for name in ("tokenizer.json", "tokenizer_config.json", "vocab.json", "merges.txt")},
              "official_files": [record(p) for p in sorted(model.iterdir()) if p.is_file()], "checked_shards": checked_shards}
    destination = Path(output)
    with destination.open("x") as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2)+"\n")
    print(json.dumps({k: result[k] for k in ("status", "parameter_count_in_cache", "shard_count", "floating_values_checked_finite",
                                           "all_parameter_names_shapes_dtypes_match")}), flush=True)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record(path: Path) -> dict:
    return {"path": str(path), "size_bytes": path.stat().st_size, "sha256": sha(path)}


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main() -> int:
    global MODEL, LIBRARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, choices=("gen-config", "compile", "convert", "smoke", "quant-probe", "verify-model"))
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--conversion-torch-site", type=Path,
                        help="Explicit read-only PyTorch site-packages fallback, used only by convert")
    parser.add_argument("--conversion-dtype-compat", action="store_true",
                        help="Normalize only stock weight-loader TVM dtype arguments to equivalent NumPy strings")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--smoke-model-dir", type=Path,
                        help="Explicit separately verified model directory, smoke stage only")
    parser.add_argument("--smoke-model-lib", type=Path,
                        help="Explicit compiled MLC library, smoke stage only")
    args = parser.parse_args()
    if args.conversion_torch_site and args.stage != "convert":
        parser.error("conversion-torch-site is only valid for weight conversion")
    if args.conversion_dtype_compat and not args.conversion_torch_site:
        parser.error("conversion-dtype-compat requires explicit conversion-torch-site")
    if args.threads < 1 or args.threads > 6:
        parser.error("threads must be between 1 and 6")
    if (args.smoke_model_dir or args.smoke_model_lib) and args.stage not in ("smoke", "verify-model"):
        parser.error("Model overrides are only valid for smoke or verify-model stage")
    if args.smoke_model_dir:
        MODEL = args.smoke_model_dir.resolve(strict=True)
    if args.smoke_model_lib:
        LIBRARY = args.smoke_model_lib.resolve(strict=True)
    if not args.attempt.replace("-", "").replace("_", "").isalnum():
        parser.error("attempt must contain only letters, numbers, hyphens or underscores")
    if subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip() != REVISION:
        raise RuntimeError("Unexpected AMA source revision")
    evidence = ROOT / ".evidence/setup/ama/mlc-llm" / args.attempt
    evidence.mkdir(parents=True, exist_ok=False)
    for name in ("tmp", "cache", "hf-cache", "tvm-cache", "mlc-cache"):
        (evidence / name).mkdir()
    env_delta = {
        "PYTHONPATH": ":".join(("/tmp/mlc-exact-python", str(LEGACY / "engine/3rdparty/tvm/python"), str(ENGINE / "python"))),
        "TVM_LIBRARY_PATH": "/tmp/mlc-tvm-837c-build/lib",
        "MLC_LIBRARY_PATH": str(LEGACY / "engine/build"),
        "PYTHONDONTWRITEBYTECODE": "1", "OMP_NUM_THREADS": str(args.threads), "OPENBLAS_NUM_THREADS": "1",
        "TVM_NUM_THREADS": str(args.threads), "TOKENIZERS_PARALLELISM": "false",
        "TMPDIR": str(evidence / "tmp"), "XDG_CACHE_HOME": str(evidence / "cache"),
        "HF_HOME": str(evidence / "hf-cache"), "HF_HUB_OFFLINE": "1",
        "TVM_CACHE_DIR": str(evidence / "tvm-cache"), "MLC_LLM_HOME": str(evidence / "mlc-cache"),
    }
    prefix = [str(PYTHON), "-B", "-m", "mlc_llm"]
    if args.stage == "gen-config":
        if MODEL.exists():
            raise FileExistsError(f"Refusing to overwrite existing model directory: {MODEL}")
        command = prefix + ["gen_config", str(SOURCE), "--quantization", "q4f32_1", "--conv-template", "qwen2",
                            "--context-window-size", "4096", "--prefill-chunk-size", "512", "--max-batch-size", "1", "-o", str(MODEL)]
    elif args.stage == "compile":
        if LIBRARY.exists():
            raise FileExistsError(f"Refusing to overwrite compiled library: {LIBRARY}")
        command = prefix + ["compile", str(MODEL), "--device", '{"kind":"llvm","mcpu":"haswell"}',
                            "--host", "x86_64-linux-gnu", "--overrides",
                            "context_window_size=4096;prefill_chunk_size=512;max_batch_size=1", "--opt", "O0", "-o", str(LIBRARY)]
    elif args.stage == "convert":
        if (MODEL / "ndarray-cache.json").exists() or list(MODEL.glob("params_shard_*.bin")):
            raise FileExistsError("Refusing to overwrite existing MLC converted weights")
        command = prefix + ["convert_weight", str(SOURCE), "--quantization", "q4f32_1", "--model-type", "qwen2",
                            "--device", "cpu", "--source-format", "huggingface-safetensor", "-o", str(MODEL)]
        if args.conversion_torch_site:
            torch_site = args.conversion_torch_site.resolve(strict=True)
            if not (torch_site / "torch/__init__.py").is_file():
                raise ValueError("Explicit fallback does not contain PyTorch")
            wrapper = ("import sys,runpy; " + f"sys.path.append({str(torch_site)!r}); "
                       "sys.argv=['mlc_llm']+sys.argv[1:]; runpy.run_module('mlc_llm',run_name='__main__')")
            if args.conversion_dtype_compat:
                wrapper = ("import sys,runpy; " + f"runpy.run_path({str(Path(__file__).resolve())!r})"
                           f"['convert_with_dtype_compat']({str(torch_site)!r},sys.argv[1:])")
            command = [str(PYTHON), "-B", "-c", wrapper] + command[4:]
    elif args.stage == "verify-model":
        command = [str(PYTHON), "-B", "-c", "import runpy; " +
                   f"runpy.run_path({str(Path(__file__).resolve())!r})['verify_model_contract']("
                   f"{str(MODEL)!r},{str(LIBRARY)!r},{str(evidence / 'model-contract.json')!r})"]
    elif args.stage == "quant-probe":
        command = [str(PYTHON), "-B", "-u", "-X", "faulthandler", "-c", (
            "import tvm,numpy as np,json; from mlc_llm.quantization import QUANTIZATION; "
            "print('allocate deterministic full embedding shape',flush=True); "
            "x=tvm.runtime.tensor(np.ones((151936,2048),dtype='float32'),tvm.cpu()); "
            "print('native quantize',flush=True); y=QUANTIZATION['q4f32_1'].quantize_weight(x); "
            "print(json.dumps([{'shape':list(a.shape),'dtype':str(a.dtype),'finite':bool(np.isfinite(a.numpy()).all())} for a in y]),flush=True)"
        )]
    else:
        command = [str(PYTHON), "-B", "-c", (
            "import json, time; from mlc_llm import MLCEngine; from mlc_llm.serve.config import EngineConfig; "
            f"engine = MLCEngine({str(MODEL)!r}, device='cpu', model_lib={str(LIBRARY)!r}, mode='interactive', "
            "engine_config=EngineConfig(max_num_sequence=1, max_total_sequence_length=4096, "
            "max_single_sequence_length=4096, prefill_chunk_size=512, prefix_cache_mode='disable')); "
            "t=time.monotonic(); response=engine.chat.completions.create(messages=[{'role':'user','content':'What is 2 plus 2? Answer briefly.'}], "
            "temperature=0, top_p=1, seed=20260912, max_tokens=16, stream=False); "
            "print(json.dumps({'setup_only':True,'network_calls':0,'response':response.model_dump(mode='json'),"
            "'elapsed_seconds':time.monotonic()-t},ensure_ascii=False)); engine.terminate()"
        )]
    dependencies = [Path(__file__), PYTHON.resolve(), Path("/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so"),
                    Path("/tmp/mlc-tvm-837c-build/lib/libtvm_runtime.so"), Path("/tmp/mlc-tvm-837c-build/lib/libtvm_ffi.so"),
                    LEGACY / "engine/build/libmlc_llm.so", ENGINE / "python/mlc_llm/compiler_pass/pipeline.py",
                    ENGINE / "python/mlc_llm/model/qwen2/qwen2_model.py"]
    if args.conversion_torch_site:
        dependencies += [args.conversion_torch_site / "torch/__init__.py", args.conversion_torch_site / "torch/version.py"]
        dependencies += sorted((args.conversion_torch_site / "torch/lib").glob("*.so"))
    manifest = {"schema_version": "1.0", "scope": "native_mlc_cpu_setup_not_attack_evaluation", "stage": args.stage,
                "started_at": timestamp(), "command": command, "cwd": str(ROOT), "environment_overrides": env_delta,
                "mlc_revision": REVISION, "hf_revision": SOURCE.name,
                "smoke_model_directory_override": str(args.smoke_model_dir) if args.smoke_model_dir else None,
                "source_revision_applies_to": "local attempted conversion input; NOT proof of official prequantized base revision",
                "dependency_policy": "Existing compiler/runtime/environment reused read-only; source clone is separate; no substitute inference.",
                "dependencies_before": [record(p) for p in dependencies],
                "source_model_files": [record(p) for p in sorted(SOURCE.iterdir()) if p.is_file()],
                "source_worktree_before": subprocess.check_output(["git", "-C", str(ENGINE), "status", "--porcelain"], text=True),
                "inputs_before": [record(p) for p in sorted(MODEL.iterdir()) if p.is_file()] if MODEL.exists() else []}
    (evidence / "manifest-start.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (evidence / "prepare_model.snapshot.py").write_bytes(Path(__file__).read_bytes())
    print(json.dumps({"stage": args.stage, "evidence": str(evidence), "command": command}), flush=True)
    started = time.monotonic()
    with (evidence / "stdout.log").open("wb") as stdout, (evidence / "stderr.log").open("wb") as stderr:
        result = subprocess.run(command, cwd=ROOT, env=os.environ | env_delta, stdout=stdout, stderr=stderr, check=False)
    manifest.update({"completed_at": timestamp(), "elapsed_seconds": time.monotonic()-started, "exit_code": result.returncode,
                     "dependencies_after": [record(p) for p in dependencies],
                     "output_files": [record(p) for p in sorted(MODEL.iterdir()) if p.is_file()] if MODEL.exists() else [],
                     "stdout": record(evidence / "stdout.log"), "stderr": record(evidence / "stderr.log")})
    manifest["dependencies_unchanged"] = manifest["dependencies_before"] == manifest["dependencies_after"]
    (evidence / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"stage": args.stage, "exit_code": result.returncode, "elapsed_seconds": manifest["elapsed_seconds"],
                      "dependencies_unchanged": manifest["dependencies_unchanged"]}), flush=True)
    if result.returncode:
        print((evidence / "stderr.log").read_text(errors="replace")[-10000:], flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
