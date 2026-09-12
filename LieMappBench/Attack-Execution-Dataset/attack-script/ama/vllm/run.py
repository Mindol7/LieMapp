"""Run the frozen AMA metadata protocol through a real, private vLLM CPU server.

The agent calls only allowlisted local fixture functions. Native vLLM events,
agent decisions and in-callee receipts all pass through the common Logger.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
ENGINE = ROOT / "Instrumented-LIE/ama/vllm"
SHARED = HERE.parent / "shared/ama_protocol.py"
FIXTURES = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/vllm/fixtures.json"
BUILD_MANIFEST = ROOT / "LieMappBench/Logging-Dataset/ama/vllm/native-build-manifest.json"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source(point):
    frame = inspect.currentframe().f_back
    return {"path": str(Path(__file__).resolve()), "function": frame.f_code.co_name,
            "line": frame.f_lineno, "logging_point_id": point}


def checked_model():
    spec = json.loads((HERE / "model.json").read_text(encoding="utf-8"))
    directory = (ROOT / spec["cache_path"]).resolve(strict=True)
    if not directory.is_relative_to(ROOT / ".evidence/models/ama"):
        raise ValueError("Model directory must remain inside the AMA model cache")
    names = [record["path"] for record in spec["files"]]
    if not names or len(names) != len(set(names)):
        raise ValueError("Empty or duplicate model filenames")
    for record in spec["files"]:
        name = record["path"]
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("Invalid model filename")
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
            raise ValueError("Pinned model file is absent or changed; run prepare_model.py: " + name)
    return {**spec, "name": spec["repository"], "path": str(directory), "dtype": "float32"}, directory


def build_metadata(args, dataset, jobs, model, runtime):
    tracked = [SHARED, HERE / "native_runtime.py", HERE / "model.json", BUILD_MANIFEST,
               ROOT / "LieMappBench/Logging-Dataset/logger.py", ROOT / "LieMappAnalyzer/analyzer.py",
               ROOT / "LieMappBench/Logging-Dataset/ama/conditions.json",
               ROOT / "LieMappBench/Logging-Dataset/ama/presentation.json"]
    revision = subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip()
    settings = {"temperature": args.temperature, "max_tokens": args.max_tokens,
                "stream": False, "n": 1, "parallel_tool_calls": False,
                "top_p": 1.0, "top_k": -1, "repetition_penalty": 1.0}
    return {
        "attack_id": "ama", "run_id": args.run_id, "execution_scope": "native_runtime",
        "engine": {"id": "vllm", "name": "vLLM", "revision": revision,
                   "source_commit": revision, "source_path": str(ENGINE)},
        "model": model,
        "dataset": {"id": dataset["dataset_id"], "path": str(args.dataset.resolve()),
                    "sha256": digest(args.dataset),
                    "reuse_scope": "Unchanged cross-engine inputs; held_out refers to the original fixture split, not newly unseen tasks."},
        "harness": {"path": str(Path(__file__).resolve()), "sha256": digest(__file__)},
        "environment": {"architecture": platform.machine(), "os": platform.platform(),
                        "python": platform.python_version(), "logical_cpus": os.cpu_count(),
                        "gpu_layers": 0, "threads": args.threads,
                        "memory_total_kib": int(next(line.split()[1] for line in
                            Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:")))},
        "protocol": {"split": args.split, "requested_count": len(jobs),
                     "temperature": args.temperature, "seeds": args.seeds, "orders": args.orders,
                     "schedule_seed": args.schedule_seed, "max_tokens": args.max_tokens,
                     "context_size": args.context_size, "request_settings": settings,
                     "cache_prompt": False, "prefix_cache_enabled": False,
                     "cache_control_location": "vLLM server configuration; no unsupported cache_prompt request field",
                     "slots": 1, "limited_run": args.limit is not None,
                     "conditions": [["neutral", "none"], ["attractive_targeted", "none"],
                                    ["attractive_targeted", "fixed"], ["attractive_targeted", "metadata_review"]],
                     "independent_request_messages": True, "original_qnt_reproduction": False,
                     "scope": "fixed_metadata_mechanism_replication_and_logging_validation",
                     "tool_parser": "hermes", "model_alias": "local-ama-model",
                     "cross_engine_precision_controlled": False},
        "code_dependencies": [{"path": str(p.relative_to(ROOT)), "sha256": digest(p)} for p in tracked],
        "native_build": runtime,
        "limitations": ["Official BF16 safetensors loaded as FP32; not the llama.cpp Q4_K_M representation.",
                        "Model, template, parser and sampler differences prevent attributing outcome differences solely to the engine.",
                        "Local synthetic tools, no external service invocation or real private data.",
                        "Single tool-selection and dispatch step; final answer quality and full QNT optimization are not evaluated."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id")
    parser.add_argument("--dataset", type=Path, default=FIXTURES)
    parser.add_argument("--split", choices=["development", "held_out"], default="held_out")
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--seeds", nargs="+", type=int, default=[20260911, 20260912])
    parser.add_argument("--orders", nargs="+", choices=["normal_first", "sink_first"], default=["normal_first", "sink_first"])
    parser.add_argument("--schedule-seed", type=int, default=20260911)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--max-tokens", type=int, default=192)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--startup-timeout", type=float, default=600)
    args = parser.parse_args(argv)
    if not all(math.isfinite(value) for value in (args.timeout, args.startup_timeout, args.temperature)):
        parser.error("Timeouts and temperature must be finite")
    if min(args.threads, args.max_tokens, args.context_size, args.timeout, args.startup_timeout) <= 0 or (args.limit is not None and args.limit <= 0):
        parser.error("Limits must be positive")
    if not 0 <= args.temperature <= 2 or len(set(args.seeds)) != len(args.seeds) or len(set(args.orders)) != len(args.orders):
        parser.error("Invalid sampling configuration")
    args.run_id = args.run_id or "ama-vllm-" + args.split + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    if not args.run_id or args.run_id in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in args.run_id):
        parser.error("Unsafe run ID")
    protocol = load(SHARED, "liemapp_ama_protocol")
    native = load(HERE / "native_runtime.py", "liemapp_ama_vllm_native_runtime")
    dataset = protocol.strict_json(args.dataset.read_text(encoding="utf-8"))
    model_spec, model_path = checked_model()
    runtime = native.validate_runtime()
    jobs = protocol.schedule(dataset, args)
    metadata = build_metadata(args, dataset, jobs, model_spec, runtime)
    run_dir = ROOT / ".evidence/raw/ama/vllm" / args.run_id
    common = load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "liemapp_ama_vllm_logger")
    with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
        protocol.write_new(run_dir / "dataset.snapshot.json", dataset)
        logger.emit("ama_run_started", {"dataset_snapshot": dataset, "planned_requests": len(jobs),
                    "request_plan": [{"sequence": i, "task_id": job[1]["id"], "family": job[0]["id"],
                                      "order": job[2], "seed": job[3], "variant": job[4], "control": job[5]}
                                     for i, job in enumerate(jobs, 1)]},
                    readable={"summary": "입력·대조군·요청 순서를 먼저 고정하고 실제 vLLM CPU 추론을 시작합니다."},
                    source=source("AMA-RUN-LP01"))
        try:
            with common.Collector(logger) as collector:
                with native.server(args, model_path, run_dir, collector.socket_path) as (base, command):
                    logger.emit("ama_server_started", {"command": command, "endpoint": base},
                                readable={"summary": "별도 AMA 계측 vLLM 서버가 실제 모델을 로드하고 준비되었습니다."},
                                source=source("AMA-RUN-LP02"))
                    for index, spec in enumerate(jobs, 1):
                        print(f"Request {index}/{len(jobs)}", flush=True)
                        protocol.run_request(dataset, spec, args, logger, base,
                                             request_settings=metadata["protocol"]["request_settings"],
                                             model_alias="local-ama-model")
            logger.emit("ama_run_finished", {"completed_requests": len(jobs), "status": "completed"},
                        readable={"summary": "계획된 vLLM 요청과 로컬 함수 호출의 증거 수집을 완료했습니다."},
                        source=source("AMA-RUN-LP03"))
        except Exception as error:
            logger.emit("ama_run_failed", {"error_type": type(error).__name__, "error": str(error)},
                        readable={"summary": "실행 오류입니다. 공격 방어 또는 엔진 안전을 의미하지 않습니다."},
                        source=source("AMA-RUN-LP04"))
            raise
        finally:
            for name in ("server.stdout.log", "server.stderr.log", "native-network-audit.json"):
                path = run_dir / name
                if path.exists():
                    logger.emit("ama_process_output", {"filename": name, "sha256": digest(path),
                                "text": path.read_text(encoding="utf-8", errors="replace")},
                                readable={"summary": "실제 vLLM 서버의 출력·오류 또는 로컬 수신 소켓 점검 원문입니다."},
                                source=source("AMA-RUN-LP05"))
    protocol.make_observations(run_dir, engine_id="vllm", engine_label="vLLM", harness_path=Path(__file__).resolve())
    print(protocol.canonical({"run_dir": str(run_dir), "status": "completed", "requests": len(jobs)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
