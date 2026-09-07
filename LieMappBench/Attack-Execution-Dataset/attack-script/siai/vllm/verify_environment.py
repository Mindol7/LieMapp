"""Validate installed CPU libraries; this is not a model inference experiment."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LIE").is_dir() and (p / "LieMappBench").is_dir())
ENGINE = ROOT / "Instrumented-LIE/siai/vllm"


def source():
    frame = inspect.currentframe().f_back
    return {"path": str(Path(__file__).resolve()), "function": frame.f_code.co_name,
            "line": frame.f_lineno, "logging_point_id": "siai.vllm.cpu-environment-verification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--supersedes")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("common_logger", ROOT / "LieMappBench/Logging-Dataset/logger.py")
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    metadata = {"run_id": args.run_id, "attack_id": "siai", "engine": {"id": "vllm",
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ENGINE, text=True).strip()},
        "execution_scope": "kernel_readiness", "limitation": "A CPU-kernel test is not native model inference or an AC/DC verdict",
        "supersedes": args.supersedes,
        "environment": {k: os.environ.get(k) for k in ("LD_LIBRARY_PATH", "LD_PRELOAD", "VLLM_TARGET_DEVICE")}}
    with common.Logger(ROOT / ".evidence/raw/siai/vllm" / args.run_id, metadata, source_root=ROOT.parent) as logger:
        import torch
        import vllm
        from vllm.platforms import current_platform
        assert current_platform.is_cpu()
        assert not torch.cpu._is_avx512_supported()
        current_platform.import_kernels()
        values = torch.arange(16, dtype=torch.float32).reshape(1, 16) / 10
        output = torch.empty(1, 8, dtype=torch.float32)
        torch.ops._C.silu_and_mul(output, values)
        expected = torch.nn.functional.silu(values[:, :8]) * values[:, 8:]
        torch.testing.assert_close(output, expected, rtol=1e-6, atol=1e-6)
        maps = Path("/proc/self/maps").read_text()
        loaded = sorted({line.split()[-1] for line in maps.splitlines() if str(ENGINE / "vllm/_C") in line})
        assert any("_C_AVX2" in item for item in loaded)
        assert not any("_C_AVX512" in item or "/_C.abi3" in item for item in loaded)
        ldd_env = os.environ.copy()
        ldd_env["LD_LIBRARY_PATH"] = str(Path(torch.__file__).parent / "lib") + ":" + ldd_env.get("LD_LIBRARY_PATH", "")
        artifacts = [{"path": path, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                      "ldd": subprocess.run(["ldd", path], env=ldd_env, capture_output=True, text=True).stdout} for path in loaded]
        logger.emit("kernel_verified", {"status": "success", "returncode": 0,
            "vllm_version": str(vllm.__version__), "torch_version": str(torch.__version__),
            "ldd_library_search_path": ldd_env["LD_LIBRARY_PATH"],
            "platform": str(current_platform), "avx512_supported": False,
            "loaded_native_libraries": artifacts, "native_operator": "torch.ops._C.silu_and_mul",
            "max_absolute_error": float((output - expected).abs().max())},
            tensors={"input": values.numpy(), "output": output.numpy(), "expected": expected.numpy()}, source=source(),
            readable={"summary": "The actual AVX2 extension loaded and executed a numeric CPU kernel; no AMX/AVX512 runtime forced"})
        print({"loaded_native_libraries": loaded, "output": output.tolist(), "status": "success"})


if __name__ == "__main__":
    main()
