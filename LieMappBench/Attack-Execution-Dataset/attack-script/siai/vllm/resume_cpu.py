"""Resume an owned exact-source CMake cache after the initial audit timeout."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LIE").is_dir() and (p / "LieMappBench").is_dir())
ENGINE = ROOT / "Instrumented-LIE/siai/vllm"


def source():
    frame = inspect.currentframe().f_back
    return {"path": str(Path(__file__).resolve()), "function": frame.f_code.co_name,
            "line": frame.f_lineno, "logging_point_id": "siai.vllm.cached-build-resume"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--build-temp", type=Path, required=True)
    parser.add_argument("--cache-backup", type=Path)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    cache = args.build_temp.resolve()
    candidate = cache if cache.exists() else args.cache_backup
    if candidate is None:
        raise ValueError("Existing task-owned cache or its backup is required")
    cmake = (candidate / "CMakeCache.txt").read_text()
    if f"CMAKE_HOME_DIRECTORY:INTERNAL={ENGINE}" not in cmake:
        raise ValueError("CMake cache is not from this private engine source")
    if f"CMAKE_CACHEFILE_DIR:INTERNAL={cache}" not in cmake:
        raise ValueError("The exact original cache path must be reused")
    if cache.parent != Path("/tmp") or not cache.name.endswith(".build-temp"):
        raise ValueError("Refusing a non-task build directory")
    spec = importlib.util.spec_from_file_location("common_logger", ROOT / "LieMappBench/Logging-Dataset/logger.py")
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    native = ENGINE / ".native-deps/usr"
    env = os.environ.copy()
    env.update(VIRTUAL_ENV=str(ENGINE / ".venv"), VLLM_TARGET_DEVICE="cpu", MAX_JOBS="4",
               VLLM_REQUIRE_RUST_FRONTEND="0", CPATH=str(native / "include"),
               LIBRARY_PATH=str(native / "lib/x86_64-linux-gnu"),
               LD_LIBRARY_PATH=str(native / "lib/x86_64-linux-gnu"), CMAKE_PREFIX_PATH=str(native))
    env["PATH"] = str(ENGINE / ".venv/bin") + ":" + str(ROOT / ".tooling/bin") + ":" + env["PATH"]
    commands = []
    if not cache.exists():
        backup = args.cache_backup.resolve()
        if backup.parent != ENGINE or not backup.name.startswith(".build-recovery-"):
            raise ValueError("Backup must be the owned private recovery directory")
        commands.append(["cp", "-a", str(backup), str(cache)])
    commands.append([str(ENGINE / ".venv/bin/python"), "setup.py", "build", "--build-temp", str(cache), "develop", "--no-deps"])
    metadata = {"run_id": args.run_id, "attack_id": "siai", "engine": {"id": "vllm",
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ENGINE, text=True).strip()},
        "execution_scope": "environment_build", "phase": "resume_exact_cache",
        "cache_path": str(cache), "cmake_cache_sha256": hashlib.sha256(cmake.encode()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "reason": "Initial 20-minute audit checkpoint is not a hardware incompatibility; resume the same generated build cache",
        "supersedes_failed_build": "siai-vllm-cpu-source-build-20260906-001"}
    with common.Logger(ROOT / ".evidence/raw/siai/vllm" / args.run_id, metadata, source_root=ROOT.parent) as logger:
        for i, command in enumerate(commands):
            logger.emit("build_command_started", {"status": "started", "command": command}, source=source(), context={"request_id": f"resume-{i}"})
            print(json.dumps({"command": command}), flush=True)
            start = time.perf_counter()
            with subprocess.Popen(command, cwd=ENGINE, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
                timed_out = False
                try:
                    stdout, stderr = process.communicate(timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        stdout, stderr = process.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        stdout, stderr = process.communicate()
                raw = {"status": "success" if process.returncode == 0 and not timed_out else "error",
                       "returncode": process.returncode, "command": command, "stdout": stdout, "stderr": stderr,
                       "seconds": time.perf_counter() - start, "timeout": timed_out}
            logger.emit("build_command_result", raw, source=source(), context={"request_id": f"resume-{i}"})
            print(json.dumps({"status": raw["status"], "seconds": raw["seconds"], "stderr_tail": stderr[-2000:]}), flush=True)
            if raw["status"] != "success":
                raise RuntimeError("Actual cached build failed; see sealed stdout/stderr")


if __name__ == "__main__":
    main()
