"""Actual MLC-LLM CPU + common AMA public HTTP protocol; synthetic values only."""
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
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHARED = HERE / "mlc_protocol.py"
# These exact frozen inputs are shared with SGLang; never tune per engine.
SOURCE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/SGLang/public-http-v1"
BUILD = ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/native-build-manifest.json"


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
    metadata = json.loads((HERE / "model.json").read_text())
    directory = (ROOT / metadata["cache_path"]).resolve(strict=True)
    if not directory.is_relative_to(ROOT / ".evidence/models/ama"):
        raise ValueError("Unexpected model cache")
    names = [r["path"] for r in metadata["files"]]
    if not names or len(names) != len(set(names)):
        raise ValueError("Empty or duplicate model files")
    for record in metadata["files"]:
        name = record["path"]
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("Invalid model filename")
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
            raise ValueError("Pinned model changed: " + name)
    return {**metadata, "name": metadata["repository"], "dtype": "q4f32_1", "path": str(directory)}, directory


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id")
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
    parser.add_argument("--model-lib")
    args = parser.parse_args(argv)
    if not all(math.isfinite(v) for v in (args.temperature, args.timeout, args.startup_timeout)) or not 0 <= args.temperature <= 2:
        parser.error("Invalid finite settings")
    if not 1 <= args.threads <= 6 or min(args.max_tokens, args.context_size, args.timeout, args.startup_timeout) <= 0:
        parser.error("Invalid positive bounds")
    if args.limit is not None and args.limit <= 0:
        parser.error("limit must be positive")
    if len(args.seeds) != len(set(args.seeds)) or len(args.orders) != len(set(args.orders)):
        parser.error("Duplicate seeds/orders")
    if any(not 0 <= seed < 2**32 for seed in [*args.seeds, args.schedule_seed]) or len(args.task) != len(set(args.task)):
        parser.error("Invalid seed range or duplicate task filter")
    args.run_id = args.run_id or "ama-mlc-llm-public-" + args.split + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    if not args.run_id or args.run_id in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in args.run_id):
        parser.error("Unsafe run identifier")
    return args


def main(argv=None):
    args = parse_args(argv)
    protocol = load(SHARED, "ama_public_protocol_runner")
    native = load(HERE / "native_runtime.py", "ama_mlc-llm_native_runner")
    common = load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "ama_mlc-llm_common_logger")
    dataset_path = SOURCE / "fixtures.json"
    dataset = protocol.strict_json(dataset_path.read_text())
    protocol.validate_dataset(dataset)
    provenance = protocol.verify_provenance(SOURCE / "provenance.json")
    if digest(SOURCE / "provenance.json") != dataset["source_binding"]["provenance_sha256"]:
        raise ValueError("Dataset provenance binding mismatch")
    jobs = protocol.schedule(dataset, args)
    if len(jobs) > 128:
        raise ValueError("This version permits at most 128 sequential model requests per run")
    model, model_path = checked_model()
    model["manifest"] = {"path": str((HERE / "model.json").relative_to(ROOT)), "sha256": digest(HERE / "model.json")}
    runtime = native.validate_runtime()
    plan_path = HERE / "evaluation-plan.json"
    plan = protocol.strict_json(plan_path.read_text())
    if plan["protocol_id"] != protocol.PROTOCOL_ID or plan["dataset"]["sha256"] != digest(dataset_path):
        raise ValueError("Predeclared evaluation plan identity mismatch")
    if args.split == "held_out":
        expected = plan["evaluation"]
        if (args.task or args.limit is not None or len(jobs) != expected["planned_model_requests"]
                or args.seeds != expected["seeds"] or args.orders != expected["orders"]
                or args.schedule_seed != expected["schedule_seed"]
                or args.temperature != expected["temperature"] or args.max_tokens != expected["max_tokens"]):
            raise ValueError("Evaluation must match the predeclared full plan; use development for preparation")
        protocol.verify_readiness(HERE / "evaluation-readiness.json")
    settings = {"temperature": args.temperature, "max_tokens": args.max_tokens, "stream": False, "n": 1,
                "parallel_tool_calls": False, "top_p": 1.0}
    tracked = [SHARED, HERE.parent / "shared/public_http_protocol.py", HERE.parent / "shared/ama_protocol.py", HERE / "service.py", HERE / "native_runtime.py", HERE / "model.json", plan_path, BUILD,
               ROOT / "LieMappBench/Logging-Dataset/logger.py", ROOT / "LieMappAnalyzer/analyzer.py",
               ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json",
               ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/presentation.json",
               ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/public-http-native-v1/conditions.json",
               ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/public-http-native-v1/presentation.json", Path(__file__).resolve()]
    if args.split == "held_out":
        tracked.append(HERE / "evaluation-readiness.json")
    # Snapshot encoding is deterministic and identical to write_new.
    snapshot = (json.dumps(dataset, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
    metadata = {"attack_id": "ama", "protocol_id": protocol.PROTOCOL_ID, "run_id": args.run_id,
                "execution_scope": "native_runtime",
                "engine": {"id": "mlc-llm", "name": "MLC-LLM", "revision": runtime["upstream_commit"],
                           "source_commit": runtime["upstream_commit"], "source_path": str(native.ENGINE)},
                "model": model, "dataset": {"id": dataset["dataset_id"], "path": str(dataset_path), "sha256": digest(dataset_path),
                    "snapshot_sha256": hashlib.sha256(snapshot).hexdigest()},
                "harness": {"path": str(Path(__file__).resolve()), "sha256": digest(__file__)},
                "environment": {"os": platform.platform(), "architecture": platform.machine(), "python": platform.python_version(),
                                "logical_cpus": os.cpu_count(), "threads": args.threads, "gpu_used": False,
                                "cross_engine_precision_controlled": False},
                "native_build": runtime, "native_build_manifest": {"path": str(BUILD.relative_to(ROOT)), "sha256": digest(BUILD)},
                "evaluation_plan": {"path": str(plan_path.relative_to(ROOT)), "sha256": digest(plan_path)},
                "protocol": {"split": args.split, "requested_count": len(jobs), "request_settings": settings,
                    "task": args.task, "limit": args.limit,
                    "seeds": args.seeds, "orders": args.orders, "schedule_seed": args.schedule_seed, "limited_run": args.limit is not None,
                    "context_size": args.context_size, "prefix_cache_enabled": False, "slots": 1,
                    "native_argument_representation": "python_call_text_and_native_dictionary",
                    "repetition_penalty": 1.0,
                    "repetition_penalty_source": "Actual C++ generation config resolves API default 1.0; official model file contains 1.05 but does not determine this effective value",
                    "native_tool_choice_control": "required_single_candidate_translated_to_named_choice_without_grammar",
                    "native_template": "Configured qwen2 Conversation exposes function_string and native Python-call syntax. Auto does not force a tool call.", "model_alias": "local-ama-model",
                    "original_qnt_reproduction": False, "public_api_operations": 1, "tool_dispatch": "actual_allowlisted_public_https_get",
                    "provider_is_attacker_owned": False, "real_private_data": False, "http_max_attempts_per_call": 1,
                    "input_reuse_scope": "Exact unchanged SGLang public-http-v1 fixture bytes; held_out is the original split, not newly unseen data.",
                    "cpu_compilation_scope": "Separately approved CPU scheduling variant, independently numerically validated before evaluation; exact compiler and library identities in native_build",
                    "cross_engine_limit": "MLC uses the official mlc-ai Qwen2.5-3B q4f32_1 distribution; its exact upstream HF base revision is not disclosed. Local conversion of the other engines' pinned HF revision failed and is not used. CPU scheduling, configured Python-call template, native parser and named control differ; no engine-only ranking. Actual repetition is 1.0."},
                "code_dependencies": [{"path": str(p.relative_to(ROOT)), "sha256": digest(p)} for p in tracked]}
    if args.split == "held_out":
        metadata["evaluation_readiness"] = {"path": str((HERE / "evaluation-readiness.json").relative_to(ROOT)),
                                           "sha256": digest(HERE / "evaluation-readiness.json")}
    run_dir = ROOT / ".evidence/raw/ama/mlc-llm" / args.run_id
    with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
        protocol.write_new(run_dir / "dataset.snapshot.json", dataset)
        logger.emit("ama_run_started", {"dataset_snapshot": dataset, "source_provenance_snapshot": provenance,
                    "planned_requests": len(jobs), "request_plan": [{"sequence": i, "family": j[0]["id"], "task_id": j[1]["id"],
                    "order": j[2], "seed": j[3], "variant": j[4], "control": j[5]} for i, j in enumerate(jobs, 1)]},
                    readable={"summary": "공개 API 출처·합성 입력·메타데이터 개입·대조군·실행 순서를 추론 전에 고정합니다."},
                    source=source("AMA-MLC-RUN01"))
        try:
            with common.Collector(logger) as collector:
                with native.server(args, model_path, run_dir, collector.socket_path) as (base, command):
                    logger.emit("ama_server_started", {"command": command, "endpoint": base},
                                readable={"summary": "독립 계측 MLC-LLM CPU 서버에서 실제 모델을 로드했습니다."}, source=source("AMA-MLC-RUN02"))
                    for index, job in enumerate(jobs, 1):
                        print(f"Request {index}/{len(jobs)}", flush=True)
                        protocol.run_request(dataset, job, args, logger, base, request_settings=settings)
            logger.emit("ama_run_finished", {"completed_requests": len(jobs), "status": "completed"},
                        readable={"summary": "계획한 네이티브 추론과 실제 공개 API 호출 관측을 완료했습니다."}, source=source("AMA-MLC-RUN03"))
        except Exception as error:
            logger.emit("ama_run_failed", {"error_type": type(error).__name__, "error": str(error)},
                        readable={"summary": "실행 오류이며 공격 방어 또는 안전 판정으로 해석하지 않습니다."}, source=source("AMA-MLC-RUN04"))
            raise
        finally:
            for name in ("server.stdout.log", "server.stderr.log", "native-network-audit.json", "native-service-identity.json"):
                path = run_dir / name
                if path.exists():
                    logger.emit("ama_process_output", {"filename": name, "sha256": digest(path), "text": path.read_text(errors="replace")},
                                readable={"summary": "실제 서버 실행 출력과 네트워크 수신 범위 점검 기록입니다."}, source=source("AMA-MLC-RUN05"))
    protocol.make_observations(run_dir, engine_id="mlc-llm", engine_label="MLC-LLM", harness_path=Path(__file__).resolve())
    print(protocol.canonical({"run_dir": str(run_dir), "status": "completed", "requests": len(jobs)}), flush=True)


if __name__ == "__main__":
    main()
