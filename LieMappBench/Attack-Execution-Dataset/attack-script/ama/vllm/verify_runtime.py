"""Compare logging-on/off native vLLM semantics on two development inputs.

Both modes use the same instrumented vLLM sources, CPU kernels and model.
This does not compare unmodified upstream code or dispatch any local tools.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import math
from pathlib import Path
import uuid


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ama_vllm_parity_runner", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
ROOT = RUN.ROOT
PROTOCOL = RUN.load(RUN.SHARED, "ama_vllm_parity_protocol")


def semantics(response):
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError("Expected exactly one native response choice")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("Expected a native response message")
    raw_calls = message.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise ValueError("tool_calls must be a list or null")
    calls = []
    for call in raw_calls:
        if not isinstance(call, dict) or call.get("type") != "function":
            raise ValueError("Expected a native function tool call")
        function = call.get("function")
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise ValueError("Expected the native function name")
        text = function.get("arguments")
        if not isinstance(text, str):
            raise ValueError("Native arguments must remain the original JSON string")
        arguments = PROTOCOL.strict_json(text)
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must decode to an object")
        calls.append({"type": call["type"], "name": function["name"],
                      "arguments_text": text, "arguments": arguments})
    return {"finish_reason": choices[0].get("finish_reason"), "role": message.get("role"),
            "content": message.get("content"), "reasoning_content": message.get("reasoning_content"),
            "reasoning": message.get("reasoning"), "tool_calls": calls}


def payloads(dataset, seed, max_tokens):
    family = next(f for f in dataset["families"] if f["id"] == "research")
    task = next(t for t in family["tasks"] if t["id"] == "research-dev-01" and t["split"] == "development")
    result = []
    for variant in ("neutral", "attractive_targeted"):
        request_id = "vllm-runtime-parity-" + task["id"] + "-" + variant
        records = PROTOCOL.tools_for(dataset, family, variant)
        result.append({"model": "local-ama-model", "messages": [
            {"role": "system", "content": dataset["system_prompt"]},
            {"role": "user", "content": task["user_prompt"]}],
            "tools": [{"type": "function", "function": r["function"]} for r in records],
            "tool_choice": "auto", "parallel_tool_calls": False, "stream": False, "n": 1,
            "temperature": 0.0, "top_p": 1.0, "top_k": -1, "repetition_penalty": 1.0,
            "seed": seed, "max_tokens": max_tokens,
            "liemapp_request_id": request_id,
            "liemapp_context": {"request_id": request_id, "task_id": task["id"], "variant": variant,
                                 "cohort": "development", "purpose": "logging_semantic_parity",
                                 "layer": "inference_engine"}})
    return result


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": RUN.digest(path)}


def changed_files(records):
    changed = []
    for record in records:
        path = Path(record["path"])
        if not path.is_file() or path.stat().st_size != record["bytes"] or RUN.digest(path) != record["sha256"]:
            changed.append(str(path))
    return changed


def verify_native_events(records, payload, response, response_text, enabled):
    request_id = payload["liemapp_request_id"]
    all_events = [event for event in records if event["context"].get("request_id") == request_id]
    native = [event for event in all_events if event["stage"] in PROTOCOL.NATIVE_STAGES]
    if not enabled:
        if records:
            raise ValueError("Disabled mode unexpectedly emitted native evidence")
        return native, all_events
    if len(native) != 3 or {e["stage"] for e in native} != set(PROTOCOL.NATIVE_STAGES):
        raise ValueError("Expected exactly three standard native events per enabled request")
    by_stage = {event["stage"]: event for event in native}
    if by_stage[PROTOCOL.NATIVE_STAGES[0]]["raw"]["tools"] != payload["tools"]:
        raise ValueError("Native received metadata differs from the request")
    returned = by_stage[PROTOCOL.NATIVE_STAGES[2]]["raw"]
    if returned["response"] != response or returned["response_text"] != response_text:
        raise ValueError("Native returned response differs from the observed HTTP response")
    rendered = by_stage[PROTOCOL.NATIVE_STAGES[1]]["raw"].get("rendered_prompt")
    if not isinstance(rendered, str) or request_id in rendered:
        raise ValueError("Native rendered prompt unavailable or contaminated by a diagnostic request ID")
    for tool in payload["tools"]:
        function = tool["function"]
        if function["name"] not in rendered or function["description"] not in rendered:
            raise ValueError("Provided metadata was not observed in the native rendered prompt")
    return native, all_events


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".evidence/audits/ama-vllm-runtime-validation.json")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--max-tokens", type=int, default=192)
    parser.add_argument("--seed", type=int, default=20260911)
    parser.add_argument("--startup-timeout", type=float, default=600)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args(argv)
    if (not 1 <= args.threads <= 6 or min(args.context_size, args.max_tokens) <= 0
            or any(not math.isfinite(value) or value <= 0 for value in (args.startup_timeout, args.timeout))):
        parser.error("Positive finite limits and between one and six CPU threads are required")
    if args.output.is_symlink() or args.output.exists():
        raise FileExistsError("Validation output already exists; use a new --output path")
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    native_runtime = RUN.load(HERE / "native_runtime.py", "ama_vllm_parity_native_runtime")
    runtime = native_runtime.validate_runtime()
    model_spec, model_path = RUN.checked_model()
    model_files = [{"path": str((model_path / record["path"]).resolve(strict=True)),
                    "bytes": record["bytes"], "sha256": record["sha256"]} for record in model_spec["files"]]
    dataset = PROTOCOL.strict_json(RUN.FIXTURES.read_text(encoding="utf-8"))
    requests = payloads(dataset, args.seed, args.max_tokens)
    source_paths = [HERE / "run.py", Path(__file__), HERE / "native_runtime.py", RUN.SHARED,
                    RUN.FIXTURES, HERE / "model.json", RUN.BUILD_MANIFEST,
                    ROOT / "LieMappBench/Logging-Dataset/logger.py"]
    sources = [identity(path) for path in source_paths]
    runtime_files = [identity(ROOT / record["path"]) for record in runtime["validated_files"]]
    validation_id = "ama-vllm-runtime-parity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    evidence_dir = args.output.parent / validation_id
    evidence_dir.mkdir(exist_ok=False)
    common = RUN.load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "ama_vllm_parity_common_logger")
    modes, errors = {}, []
    for enabled in (True, False):
        mode = "logging_enabled" if enabled else "logging_disabled"
        run_dir = evidence_dir / mode
        metadata = {"attack_id": "ama", "engine": {"id": "vllm", "name": "vLLM"},
                    "run_id": validation_id + "-" + mode, "execution_scope": "native_runtime",
                    "purpose": "instrumented_runtime_logging_on_off_parity_not_attack_evaluation",
                    "logging_enabled": enabled, "model": model_spec,
                    "source_identities": sources, "runtime_identities": runtime_files}
        responses, command = [], None
        try:
            with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
                with common.Collector(logger) as collector:
                    with native_runtime.server(args, model_path, run_dir, collector.socket_path if enabled else None) as (base, command):
                        for payload in requests:
                            response, text = PROTOCOL.request_json(base, "/v1/chat/completions", payload, timeout=args.timeout)
                            record = {"request": payload, "response": response, "response_text": text}
                            responses.append(record)
                            native, all_events = verify_native_events(logger._records, payload, response, text, enabled)
                            record.update(semantics=semantics(response), native_event_count=len(native),
                                          all_native_event_count=len(all_events),
                                          native_event_ids=[e["event_id"] for e in native],
                                          additional_native_event_ids=[e["event_id"] for e in all_events if e["stage"] not in PROTOCOL.NATIVE_STAGES])
                            print(PROTOCOL.canonical({"mode": mode, "variant": payload["liemapp_context"]["variant"],
                                                      "standard_events": len(native), "all_events": len(all_events),
                                                      "semantics": record["semantics"]}), flush=True)
        except Exception as error:
            errors.append({"mode": mode, "error_type": type(error).__name__, "error": str(error)})
        mode_result = {"responses": responses, "command": command, "evidence_dir": str(run_dir)}
        seal = run_dir / "seal.json"
        if seal.is_file():
            mode_result["seal"] = PROTOCOL.strict_json(seal.read_text(encoding="utf-8"))
        mode_result["process_artifacts"] = [identity(run_dir / name) for name in
            ("server.stdout.log", "server.stderr.log", "native-network-audit.json") if (run_dir / name).is_file()]
        modes[mode] = mode_result
        if errors:
            break
    changed_sources = changed_files(sources)
    changed_runtime = changed_files(runtime_files)
    changed_model = changed_files(model_files)
    comparisons = []
    enabled_results = modes.get("logging_enabled", {}).get("responses", [])
    disabled_results = modes.get("logging_disabled", {}).get("responses", [])
    for index, payload in enumerate(requests):
        on = enabled_results[index] if index < len(enabled_results) else {}
        off = disabled_results[index] if index < len(disabled_results) else {}
        comparisons.append({"variant": payload["liemapp_context"]["variant"],
                            "identical_request": bool(on and off) and on["request"] == off["request"],
                            "semantic_response_equal": "semantics" in on and "semantics" in off and on["semantics"] == off["semantics"],
                            "native_event_counts": {"enabled": on.get("native_event_count"), "disabled": off.get("native_event_count")}})
    passed = not any((errors, changed_sources, changed_runtime, changed_model)) and all(
        item["identical_request"] and item["semantic_response_equal"] for item in comparisons)
    artifact = {"schema_version": "1.0.0", "validation_id": validation_id,
                "created_utc": datetime.now(timezone.utc).isoformat(), "status": "passed" if passed else "failed",
                "comparison_scope": "Same instrumented vLLM source, native CPU kernels and FP32 model with logging enabled versus disabled; NOT an uninstrumented upstream comparison",
                "task_count": 1, "metadata_variants": 2, "planned_native_inference_requests": 4,
                "native_responses_received": sum(len(mode["responses"]) for mode in modes.values()),
                "dataset_split": "development", "tool_dispatch_performed": False,
                "model": {"manifest": model_spec, "artifacts": model_files}, "runtime_manifest": runtime,
                "source_identities": sources, "runtime_identities": runtime_files,
                "changed_sources_during_validation": changed_sources,
                "changed_runtime_artifacts_during_validation": changed_runtime,
                "changed_model_files_during_validation": changed_model,
                "comparisons": comparisons, "modes": modes, "errors": errors,
                "normalization": "Compare finish_reason, role, content, reasoning_content, reasoning and tool type/name/literal argument string/parsed arguments. Normalize null tool_calls to [] only in comparison; retain full raw responses. Ignore response IDs, call IDs, timestamps, usage and timing fields.",
                "limitations": ["Two development metadata variants do not prove parity for all requests, concurrent requests or streaming.",
                                "No tool is dispatched and no attack-success rate is measured by this validation.",
                                "Additional native events are preserved but the standard three-stage evidence contract is counted separately."]}
    PROTOCOL.write_new(args.output, artifact)
    print(PROTOCOL.canonical({"output": str(args.output), "status": artifact["status"], "comparisons": comparisons,
                              "errors": errors}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
