"""Validate logging-on/off semantic parity on two fixed development inputs.

Both modes use the SAME instrumented native binary. This is not a comparison
against an unmodified upstream binary and is not an attack-success evaluation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ama_runtime_validation_harness", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
ROOT = RUN.ROOT


def semantics(response):
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("Expected exactly one response choice")
    message = choices[0].get("message", {})
    calls = []
    for call in message.get("tool_calls", []):
        function = call["function"]
        calls.append({"type": call["type"], "name": function["name"],
                      "arguments": RUN.strict_json(function["arguments"]),
                      "arguments_text": function["arguments"]})
    return {"finish_reason": choices[0].get("finish_reason"), "role": message.get("role"),
            "content": message.get("content"), "reasoning_content": message.get("reasoning_content"),
            "tool_calls": calls}


def payloads(dataset, seed, max_tokens):
    family = next(f for f in dataset["families"] if f["id"] == "research")
    task = next(t for t in family["tasks"] if t["id"] == "research-dev-01" and t["split"] == "development")
    result = []
    for variant in ("neutral", "attractive_targeted"):
        request_id = "runtime-parity-" + task["id"] + "-" + variant
        records = RUN.tools_for(dataset, family, variant)
        result.append({"model": "local-ama-model", "messages": [
            {"role": "system", "content": dataset["system_prompt"]},
            {"role": "user", "content": task["user_prompt"]}],
            "tools": [{"type": "function", "function": r["function"]} for r in records],
            "tool_choice": "auto", "parallel_tool_calls": False, "stream": False, "n": 1,
            "temperature": 0.0, "top_p": 1.0, "top_k": 0, "seed": seed,
            "max_tokens": max_tokens, "cache_prompt": False,
            "liemapp_request_id": request_id,
            "liemapp_context": {"request_id": request_id, "task_id": task["id"], "variant": variant,
                                 "cohort": "development", "purpose": "logging_semantic_parity",
                                 "layer": "inference_engine"}})
    return result


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": RUN.digest(path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".evidence/audits/ama-llamacpp-runtime-validation.json")
    parser.add_argument("--binary", type=Path, default=RUN.ENGINE / "build-liemapp/bin/llama-server")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--max-tokens", type=int, default=192)
    parser.add_argument("--seed", type=int, default=20260911)
    parser.add_argument("--startup-timeout", type=float, default=180)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args(argv)
    if min(args.threads, args.context_size, args.max_tokens, args.startup_timeout, args.timeout) <= 0:
        parser.error("Resource and time limits must be positive")
    args.output = args.output.resolve()
    if args.output.exists():
        raise FileExistsError("Validation output already exists; use a new --output path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.binary = args.binary.resolve(strict=True)
    binary_identity = identity(args.binary)
    library_identities = [identity(p) for p in sorted(args.binary.parent.glob("*.so"))]
    model_spec = RUN.strict_json((HERE / "model.json").read_text(encoding="utf-8"))
    model = ROOT / model_spec["cache_path"]
    model_identity = identity(model)
    if model_identity["bytes"] != model_spec["bytes"] or model_identity["sha256"] != model_spec["sha256"]:
        raise ValueError("Model does not match the frozen model manifest")
    dataset = RUN.strict_json(RUN.FIXTURES.read_text(encoding="utf-8"))
    requests = payloads(dataset, args.seed, args.max_tokens)
    source_paths = [HERE / "run.py", Path(__file__), RUN.FIXTURES, HERE / "model.json",
                    ROOT / "LieMappBench/Logging-Dataset/logger.py",
                    ROOT / "LieMappBench/Logging-Dataset/native/bridge.h",
                    RUN.ENGINE / "tools/server/server-context.cpp",
                    RUN.ENGINE / "tools/server/server-common.cpp"]
    sources = [identity(path) for path in source_paths]
    transport_manifest_path = ROOT / "LieMappBench/Logging-Dataset/ama/llamacpp/native-build-manifest.json"
    transport_manifest = RUN.strict_json(transport_manifest_path.read_text(encoding="utf-8"))
    transport_validation = {"manifest": identity(transport_manifest_path),
                            "reported_validation": transport_manifest["validation"]["native_transport_smoke"],
                            "scope": "Prior direct C++ to common Collector concurrency test; not rerun by this parity script"}
    validation_id = "ama-runtime-parity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    evidence_dir = args.output.parent / validation_id
    evidence_dir.mkdir(exist_ok=False)
    common = RUN.load_logger()
    modes = {}
    for enabled in (True, False):
        mode = "logging_enabled" if enabled else "logging_disabled"
        run_dir = evidence_dir / mode
        metadata = {"attack_id": "ama", "engine": {"id": "llamacpp"},
                    "run_id": validation_id + "-" + mode, "execution_scope": "native_runtime",
                    "purpose": "instrumented_binary_logging_on_off_parity_not_attack_evaluation",
                    "logging_enabled": enabled, "model_sha256": model_identity["sha256"]}
        responses = []
        with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
            with common.Collector(logger) as collector:
                with RUN.server(args, model, run_dir, collector.socket_path if enabled else None) as (base, command):
                    for payload in requests:
                        response, text = RUN.request_json(base, "/v1/chat/completions", payload, timeout=args.timeout)
                        request_id = payload["liemapp_request_id"]
                        events = [e for e in logger._records if e["context"].get("request_id") == request_id]
                        if enabled:
                            if len(events) != 3 or {e["stage"] for e in events} != set(RUN.NATIVE_STAGES):
                                raise ValueError("Expected exactly three native events per enabled request")
                            by_stage = {e["stage"]: e for e in events}
                            if by_stage[RUN.NATIVE_STAGES[0]]["raw"]["tools"] != payload["tools"]:
                                raise ValueError("Native received metadata mismatch")
                            if by_stage[RUN.NATIVE_STAGES[2]]["raw"]["response"] != response:
                                raise ValueError("Native response mismatch")
                            if by_stage[RUN.NATIVE_STAGES[2]]["raw"]["response_text"] != text:
                                raise ValueError("Native raw response text mismatch")
                            if request_id in by_stage[RUN.NATIVE_STAGES[1]]["raw"]["rendered_prompt"]:
                                raise ValueError("Diagnostic request ID entered the model prompt")
                        elif events or logger._records:
                            raise ValueError("Disabled mode unexpectedly emitted native evidence")
                        responses.append({"request": payload, "response": response, "response_text": text,
                                          "semantics": semantics(response), "native_event_count": len(events),
                                          "native_event_ids": [e["event_id"] for e in events]})
                        print(RUN.canonical({"mode": mode, "variant": payload["liemapp_context"]["variant"],
                                             "native_events": len(events), "semantics": semantics(response)}), flush=True)
        modes[mode] = {"responses": responses, "command": command, "evidence_dir": str(run_dir),
                       "seal": RUN.strict_json((run_dir / "seal.json").read_text()),
                       "server_stdout": identity(run_dir / "server.stdout.log"),
                       "server_stderr": identity(run_dir / "server.stderr.log")}
    changed_sources = [s["path"] for s in sources if RUN.digest(s["path"]) != s["sha256"]]
    changed_runtime_artifacts = [s["path"] for s in [binary_identity, *library_identities]
                                 if RUN.digest(s["path"]) != s["sha256"]]
    comparisons = []
    for index, payload in enumerate(requests):
        on = modes["logging_enabled"]["responses"][index]
        off = modes["logging_disabled"]["responses"][index]
        comparisons.append({"variant": payload["liemapp_context"]["variant"],
                            "identical_request": on["request"] == off["request"],
                            "semantic_response_equal": on["semantics"] == off["semantics"],
                            "native_event_counts": {"enabled": on["native_event_count"], "disabled": off["native_event_count"]}})
    passed = not changed_sources and not changed_runtime_artifacts and all(
        c["identical_request"] and c["semantic_response_equal"] for c in comparisons)
    artifact = {"schema_version": "1.0.0", "validation_id": validation_id,
                "created_utc": datetime.now(timezone.utc).isoformat(), "status": "passed" if passed else "failed",
                "comparison_scope": "Same instrumented native binary with logging enabled versus disabled; NOT an uninstrumented upstream comparison",
                "task_count": 1, "metadata_variants": 2, "native_inference_requests": 4,
                "dataset_split": "development", "model": {"manifest": model_spec, "artifact": model_identity},
                "binary": binary_identity, "native_libraries": library_identities,
                "source_identities": sources, "changed_sources_during_validation": changed_sources,
                "changed_runtime_artifacts_during_validation": changed_runtime_artifacts,
                "prior_concurrent_transport_validation": transport_validation,
                "comparisons": comparisons, "modes": modes,
                "normalization": "Compare role/content/reasoning/finish_reason plus tool type, name, exact argument string and parsed arguments. Ignore response IDs, tool-call IDs, timestamps, timing and token-usage metadata.",
                "limitations": ["Two development metadata variants do not prove parity for all requests or streaming.",
                                "No tool is dispatched by this validation; it checks native inference and logging only.",
                                "Separate native-transport-smoke.cpp test verifies concurrent context isolation; this inference validation uses one server slot."]}
    RUN.write_new(args.output, artifact)
    print(RUN.canonical({"output": str(args.output), "status": artifact["status"], "comparisons": comparisons}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
