"""Development-only llamacpp logging ON/OFF observation parity; no tool dispatch.

Uses the public AMA protocol's real request constructor. Both modes execute the
same instrumented source, CPU runtime and model. This is not an upstream versus
instrumented comparison and does not measure attack effectiveness.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import math
from pathlib import Path
import shutil
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ama_llamacpp_parity_runner", HERE / "run_public.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
ROOT = RUN.ROOT
PROTOCOL = RUN.load(RUN.SHARED, "ama_llamacpp_public_parity_protocol")


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": RUN.digest(path)}


def changed_files(records):
    return [r["path"] for r in records if not Path(r["path"]).is_file()
            or Path(r["path"]).stat().st_size != r["bytes"]
            or RUN.digest(r["path"]) != r["sha256"]]


def archive_sources(records, evidence_dir):
    """Preserve source bytes before execution; never silently use a later edit."""
    snapshots = []
    for record in records:
        original = Path(record["path"])
        if not original.is_relative_to(ROOT):
            raise ValueError("Source archive input lies outside the project")
        target = evidence_dir / "source-snapshots" / original.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output, original.open("rb") as source:
            shutil.copyfileobj(source, output)
        if target.stat().st_size != record["bytes"] or RUN.digest(target) != record["sha256"]:
            raise ValueError("Source changed while creating its pre-execution snapshot")
        snapshots.append({**record, "snapshot_path": str(target)})
    return snapshots


def semantics(response):
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("Exactly one response choice required")
    choice = choices[0]
    message = choice["message"]
    calls = message.get("tool_calls")
    if calls is None:
        calls = []
    if not isinstance(calls, list):
        raise ValueError("tool_calls must be a list or null")
    normalized = []
    for call in calls:
        function = call["function"]
        text = function["arguments"]
        if call["type"] != "function" or not isinstance(text, str):
            raise ValueError("Expected literal function argument JSON")
        arguments = PROTOCOL.strict_json(text)
        if not isinstance(arguments, dict):
            raise ValueError("Function arguments must be a JSON object")
        normalized.append({"type": call["type"], "name": function["name"],
                           "arguments_text": text, "arguments": arguments})
    verbose = response.get("__verbose", {})
    tokens = verbose.get("tokens")
    if not isinstance(tokens, list) or not tokens or any(type(t) is not int for t in tokens):
        raise ValueError("Missing exact generated token IDs from __verbose.tokens")
    if not isinstance(verbose.get("content"), str) or not isinstance(verbose.get("prompt"), str):
        raise ValueError("Missing pre-parser generated content or rendered prompt")
    token_fields = {"response_token_ids": tokens, "pre_parser_generated_text": verbose["content"],
                    "rendered_prompt": verbose["prompt"]}
    return {"finish_reason": choice.get("finish_reason"), "role": message.get("role"),
            "content": message.get("content"), "reasoning_content": message.get("reasoning_content"),
            "reasoning": message.get("reasoning"), "tool_calls": normalized, **token_fields}


def payloads(dataset, seed, max_tokens):
    family = next(f for f in dataset["families"] if f["id"] == "public_echo")
    task = next(t for t in family["tasks"] if t["id"] == "echo-dev-02" and t["split"] == "development")
    settings = {"temperature": 0.0, "max_tokens": max_tokens, "stream": False, "n": 1,
                "parallel_tool_calls": False, "top_p": 1.0, "top_k": 0, "min_p": 0.0, "cache_prompt": False}
    result = []
    for variant in ("neutral", "attractive_targeted"):
        job = (family, task, "normal_first", seed, variant, "none")
        request_id = "llamacpp-public-runtime-parity-" + task["id"] + "-" + variant
        context = {"request_id": request_id, "task_id": task["id"], "variant": variant,
                   "family": family["id"], "order": "normal_first", "seed": seed, "control": "none",
                   "cohort": "development", "purpose": "logging_semantic_parity"}
        payload = PROTOCOL.request_payload(dataset, job, settings, context)
        # Native response-only observability option; identical in both modes.
        payload["return_tokens"] = True
        result.append((payload, PROTOCOL.prepared_tools(dataset, job)[1]))
    return result


def verify_native(events, payload, response, response_text, tools, enabled):
    if not enabled:
        if events:
            raise ValueError("Disabled runtime emitted an event")
        return []
    request_id = payload["liemapp_request_id"]
    native = [e for e in events if e["context"].get("request_id") == request_id]
    PROTOCOL.check_native(native, payload, response, tools)
    if len(native) != 3:
        raise ValueError("Exactly three native events required")
    by_stage = {e["stage"]: e["raw"] for e in native}
    returned = by_stage["ama_native_tool_calls_returned"]
    if returned["response_text"] != response_text:
        raise ValueError("Native response text differs from actual HTTP bytes")
    rendered = by_stage["ama_native_prompt_rendered"]
    if request_id in rendered["rendered_prompt"]:
        raise ValueError("Diagnostic correlation ID was included in model prompt")
    semantic = semantics(response)
    if rendered["rendered_prompt"] != semantic["rendered_prompt"]:
        raise ValueError("Native template differs from actual generation prompt")
    return native


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".evidence/audits/ama-llamacpp-public-runtime-validation.json")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--max-tokens", type=int, default=192)
    parser.add_argument("--seed", type=int, default=20260911)
    parser.add_argument("--startup-timeout", type=float, default=600)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args(argv)
    if (not 1 <= args.threads <= 6 or min(args.context_size, args.max_tokens) <= 0
            or any(not math.isfinite(v) or v <= 0 for v in (args.startup_timeout, args.timeout))):
        parser.error("Positive finite limits and one to six threads required")
    if args.output.is_symlink() or args.output.exists():
        raise FileExistsError("Audit exists; select a new output path")
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runtime_module = RUN.load(HERE / "native_public_runtime.py", "ama_llamacpp_parity_runtime")
    runtime = runtime_module.validate_runtime()
    model, model_path = RUN.checked_model()
    model_files = [{"path": str(Path(model["path"]) / r["path"]), "bytes": r["bytes"], "sha256": r["sha256"]}
                   for r in model["files"]]
    dataset_path = RUN.SOURCE / "fixtures.json"
    provenance_path = RUN.SOURCE / "provenance.json"
    dataset = PROTOCOL.strict_json(dataset_path.read_text())
    PROTOCOL.validate_dataset(dataset)
    provenance = PROTOCOL.verify_provenance(provenance_path)
    if RUN.digest(provenance_path) != dataset["source_binding"]["provenance_sha256"]:
        raise ValueError("Provenance binding mismatch")
    requests = payloads(dataset, args.seed, args.max_tokens)
    source_paths = [Path(__file__), HERE / "run_public.py", HERE / "native_public_runtime.py", RUN.SHARED,
                    HERE.parent / "shared/ama_protocol.py", HERE / "model-public.json", RUN.BUILD,
                    dataset_path, provenance_path, ROOT / "LieMappBench/Logging-Dataset/logger.py"]
    source_paths += [provenance_path.parent / r["path"] for r in provenance["files"]]
    sources = [identity(path) for path in source_paths]
    runtime_files = [identity(ROOT / r["path"]) for r in runtime["validated_files"]]
    validation_id = "ama-llamacpp-public-parity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    evidence_dir = args.output.parent / validation_id
    evidence_dir.mkdir(exist_ok=False)
    source_snapshots = archive_sources(sources, evidence_dir)
    common = RUN.load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "ama_llamacpp_parity_logger")
    modes, errors = {}, []
    for enabled in (True, False):
        mode = "logging_enabled" if enabled else "logging_disabled"
        run_dir = evidence_dir / mode
        metadata = {"attack_id": "ama", "protocol_id": PROTOCOL.PROTOCOL_ID,
                    "engine": {"id": "llamacpp", "name": "llama.cpp"}, "run_id": validation_id + "-" + mode,
                    "execution_scope": "native_runtime", "purpose": "logging_on_off_parity_not_attack_evaluation",
                    "logging_enabled": enabled, "model": model, "source_identities": sources,
                    "runtime_identities": runtime_files}
        responses, command = [], None
        try:
            with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
                with common.Collector(logger) as collector:
                    with runtime_module.server(args, model_path, run_dir, collector.socket_path if enabled else None) as (base, command):
                        for payload, tools in requests:
                            response, response_text = PROTOCOL.request_json(base, "/v1/chat/completions", payload, timeout=args.timeout)
                            record = {"request": payload, "response": response, "response_text": response_text}
                            responses.append(record)
                            runtime_module.checked_generation(response, payload)
                            native = verify_native(logger._records, payload, response, response_text, tools, enabled)
                            record.update(semantics=semantics(response), native_event_count=len(native),
                                          native_event_ids=[e["event_id"] for e in native])
                            if enabled:
                                returned = next(e["raw"] for e in native if e["stage"] == "ama_native_tool_calls_returned")
                                record["pre_parser_generated_text"] = returned["response"]["__verbose"]["content"]
                            print(PROTOCOL.canonical({"mode": mode, "variant": payload["liemapp_context"]["variant"],
                                  "native_events": len(native), "response_tokens": len(record["semantics"]["response_token_ids"]),
                                  "calls": record["semantics"]["tool_calls"]}), flush=True)
        except Exception as error:
            errors.append({"mode": mode, "error_type": type(error).__name__, "error": str(error)})
        modes[mode] = {"responses": responses, "command": command, "evidence_dir": str(run_dir),
                       "artifacts": [identity(run_dir / name) for name in
                                     ("seal.json", "events.jsonl", "run.json", "server.stdout.log", "server.stderr.log", "native-network-audit.json")
                                     if (run_dir / name).is_file()]}
        if errors:
            break
    changes = {"source": changed_files(sources), "runtime": changed_files(runtime_files), "model": changed_files(model_files)}
    comparisons = []
    on_results = modes.get("logging_enabled", {}).get("responses", [])
    off_results = modes.get("logging_disabled", {}).get("responses", [])
    for index, (payload, _) in enumerate(requests):
        on = on_results[index] if index < len(on_results) else {}
        off = off_results[index] if index < len(off_results) else {}
        comparisons.append({"variant": payload["liemapp_context"]["variant"],
            "identical_request": bool(on and off) and on["request"] == off["request"],
            "semantic_response_and_token_ids_equal": "semantics" in on and "semantics" in off and on["semantics"] == off["semantics"],
            "native_event_counts": {"enabled": on.get("native_event_count"), "disabled": off.get("native_event_count")}})
    passed = not errors and not any(changes.values()) and all(
        c["identical_request"] and c["semantic_response_and_token_ids_equal"]
        and c["native_event_counts"] == {"enabled": 3, "disabled": 0} for c in comparisons)
    audit = {"schema_version": "1.0.0", "validation_id": validation_id,
        "created_utc": datetime.now(timezone.utc).isoformat(), "status": "passed" if passed else "failed",
        "protocol_id": PROTOCOL.PROTOCOL_ID, "dataset_split": "development", "task_id": "echo-dev-02",
        "comparison_scope": "Same instrumented llamacpp source, read-only CPU native binary and Q4_K_M model, logging ON versus OFF; not an unmodified upstream comparison",
        "request_settings": {"temperature": 0.0, "seed": args.seed, "max_tokens": args.max_tokens,
                             "response_only_extra": {"return_tokens": True}},
        "planned_native_inference_requests": 4, "native_responses_received": sum(len(m["responses"]) for m in modes.values()),
        "tool_dispatch_performed": False, "external_api_calls_performed": 0,
        "model": model, "model_identities": model_files, "runtime_manifest": runtime,
        "source_identities": sources, "runtime_identities": runtime_files, "changed_artifacts": changes,
        "source_snapshots": source_snapshots,
        "comparisons": comparisons, "modes": modes, "errors": errors,
        "normalization": "Compare exact output token IDs, rendered prompt string, pre-parser generated text, finish reason, role, content, reasoning and tool type/name/literal arguments/parsed arguments. Only absent/null tool_calls normalize to []; omit random response/call IDs, timestamps and timing from equality while preserving complete raw responses.",
        "limitations": ["Two development variants do not establish universal, concurrent or streaming parity.",
                       "Both modes expose actual generated token IDs and pre-parser text through native __verbose response. Exact input token IDs are unavailable; input comparison covers literal messages/tools and actual rendered prompt string, not an independent tokenizer-level measurement.",
                       "No external tool executes and no attack-success rate is measured."]}
    PROTOCOL.write_new(args.output, audit)
    print(PROTOCOL.canonical({"output": str(args.output), "status": audit["status"], "comparisons": comparisons,
                              "changed_artifacts": changes, "errors": errors}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
