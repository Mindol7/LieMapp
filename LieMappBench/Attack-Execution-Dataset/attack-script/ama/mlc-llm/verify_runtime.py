"""Four real native development inferences: logger ON/OFF, no external API calls."""
import argparse
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import shutil
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ama_mlc_parity_runner", HERE / "run_public.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
P = RUN.load(HERE / "mlc_protocol.py", "ama_mlc_parity_protocol")
ROOT = RUN.ROOT


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": RUN.digest(path)}


def get_diagnostics(base):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base + "/diagnostics/last", timeout=10) as response:
        return P.strict_json(response.read(4 * 1024 * 1024).decode())


def semantic(response, diagnostic):
    observed = {record["stage"]: record["raw"] for record in diagnostic["observations"]}
    if len(diagnostic["observations"]) != 3 or set(observed) != set(P.NATIVE_STAGES):
        raise ValueError("Missing native parity diagnostics")
    output = observed["ama_native_tool_calls_returned"]
    rendered = observed["ama_native_prompt_rendered"]
    choice = response["choices"][0]
    calls = P.legacy.normalized_tool_calls(choice["message"])
    parse_issue = P.audit_python_calls(output["generated_texts_before_parser"], calls, allow_loss=True)
    for field, tokens in (("input", rendered["input_token_ids"]), ("output", output["output_token_ids"])):
        if not isinstance(tokens, list) or any(type(t) is not int for t in tokens):
            raise ValueError("Missing actual native " + field + " tokens")
        if not tokens and (field == "input" or not output.get("native_finish_reasons")
                           or output["generated_texts_before_parser"] != [""] or calls):
            raise ValueError("Empty tokens lack an observed native termination")
    return {"rendered_prompt": rendered["rendered_prompt"],
            "input_token_ids": rendered["input_token_ids"], "output_token_ids": output["output_token_ids"],
            "generated_texts_before_parser": output["generated_texts_before_parser"],
            "finish_reasons_before_parser": output["finish_reasons_before_parser"],
            "generation_config": rendered["generation_config"],
            "native_generation_config": output["native_generation_config"],
            "native_parse_issue": parse_issue,
            "content": choice["message"].get("content"), "finish_reason": choice.get("finish_reason"),
            "function_calls": [c["function"] for c in calls]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--startup-timeout", type=float, default=600)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--model-lib")
    args = parser.parse_args()
    args.diagnostics = True
    if args.output.is_symlink() or args.output.exists():
        raise FileExistsError("Select a new parity audit output")
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    native = RUN.load(HERE / "native_runtime.py", "ama_mlc_parity_native")
    common = RUN.load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "ama_mlc_parity_common")
    runtime = native.validate_runtime()
    model, model_path = RUN.checked_model()
    dataset = P.strict_json((RUN.SOURCE / "fixtures.json").read_text())
    P.validate_dataset(dataset)
    P.verify_provenance(RUN.SOURCE / "provenance.json")
    family = dataset["families"][0]
    task = next(t for t in family["tasks"] if t["id"] == "echo-dev-02" and t["split"] == "development")
    requests = []
    for variant in ("neutral", "attractive_targeted"):
        job = (family, task, "normal_first", 20260911, variant, "none")
        context = {"request_id": "mlc-parity-" + variant, "task_id": task["id"], "family": family["id"],
                   "variant": variant, "control": "none", "order": "normal_first", "seed": 20260911,
                   "cohort": "development", "pair_id": task["id"] + "-normal_first-20260911",
                   "purpose": "logging_semantic_parity"}
        request = P.request_payload(dataset, job, {"temperature": 0.0, "top_p": 1.0, "max_tokens": 192,
                    "stream": False, "n": 1, "parallel_tool_calls": False}, context)
        requests.append((request, P.prepared_tools(dataset, job)[1]))
    run_id = "ama-mlc-parity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    directory = args.output.parent / run_id
    directory.mkdir(exist_ok=False)
    dependencies = [identity(ROOT / row["path"]) for row in runtime["validated_files"]]
    sources = [identity(path) for path in (HERE / "verify_runtime.py", HERE / "run_public.py", HERE / "mlc_protocol.py",
        HERE / "service.py", HERE / "native_runtime.py", HERE / "model.json", RUN.BUILD,
        RUN.SOURCE / "fixtures.json", ROOT / "LieMappBench/Logging-Dataset/logger.py")]
    for record in sources:
        original = Path(record["path"])
        destination = directory / "source-snapshots" / original.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with original.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target)
    models = [identity(model_path / row["path"]) for row in model["files"]]
    modes, errors = {}, []
    for enabled in (True, False):
        mode = "logging_enabled" if enabled else "logging_disabled"
        run_dir = directory / mode
        records = []
        metadata = {"attack_id": "ama", "engine": {"id": "mlc-llm", "name": "MLC-LLM"},
                    "run_id": run_id + "-" + mode, "execution_scope": "native_runtime",
                    "purpose": "development_logging_parity_no_external_api", "logging_enabled": enabled,
                    "runtime_identities": dependencies, "source_identities": sources, "model": model}
        try:
            with common.Logger(run_dir, metadata, source_root=ROOT) as logger:
                with common.Collector(logger) as collector:
                    with native.server(args, model_path, run_dir, collector.socket_path if enabled else None) as (base, command):
                        for payload, tools in requests:
                            response, text = P.request_json(base, "/v1/chat/completions", payload, timeout=args.timeout)
                            diagnostic = get_diagnostics(base)
                            P.check_native(diagnostic["observations"], payload, response, tools)
                            observations = [e for e in logger._records if e["context"].get("request_id") == payload["liemapp_request_id"]]
                            if enabled:
                                P.check_native(observations, payload, response, tools)
                            elif observations:
                                raise ValueError("Logger OFF emitted native evidence")
                            comparison = semantic(response, diagnostic)
                            if payload["liemapp_request_id"] in comparison["rendered_prompt"]:
                                raise ValueError("Diagnostic request ID leaked into model input")
                            record = {"request": payload, "response": response, "response_text": text,
                                      "diagnostic": diagnostic, "semantics": comparison,
                                      "native_event_count": len(observations), "native_event_ids": [e["event_id"] for e in observations]}
                            records.append(record)
                            print(P.canonical({"mode": mode, "variant": payload["liemapp_context"]["variant"],
                                  "native_events": len(observations), "output_tokens": len(comparison["output_token_ids"])}), flush=True)
        except Exception as error:
            errors.append({"mode": mode, "type": type(error).__name__, "error": str(error)})
        modes[mode] = {"responses": records, "evidence_dir": str(run_dir),
                       "artifacts": [identity(run_dir / name) for name in
                        ("events.jsonl", "seal.json", "run.json", "server.stdout.log", "server.stderr.log",
                         "native-network-audit.json", "native-service-identity.json") if (run_dir / name).is_file()]}
        if errors:
            break
    changed = [r["path"] for r in [*sources, *dependencies, *models] if
               not Path(r["path"]).is_file() or RUN.digest(r["path"]) != r["sha256"]]
    on = modes.get("logging_enabled", {}).get("responses", [])
    off = modes.get("logging_disabled", {}).get("responses", [])
    compared = []
    for index, (payload, _) in enumerate(requests):
        a, b = (on[index] if index < len(on) else {}), (off[index] if index < len(off) else {})
        compared.append({"variant": payload["liemapp_context"]["variant"],
                         "exact_input_output_tokens_and_semantics_equal": bool(a and b) and a["semantics"] == b["semantics"],
                         "identical_request": bool(a and b) and a["request"] == b["request"],
                         "native_event_counts": {"enabled": a.get("native_event_count"), "disabled": b.get("native_event_count")}})
    passed = not errors and not changed and all(c["exact_input_output_tokens_and_semantics_equal"] and
              c["identical_request"] and c["native_event_counts"] == {"enabled": 3, "disabled": 0} for c in compared)
    audit = {"status": "passed" if passed else "failed", "protocol_id": P.PROTOCOL_ID, "run_id": run_id,
             "scope": "Same instrumented MLC source + native CPU model, logger emission ON/OFF; both modes retain explicit local diagnostic capture. Not stock-versus-instrumented parity or an attack evaluation.",
             "native_responses_received": len(on) + len(off), "external_api_calls": 0,
             "comparisons": compared, "modes": modes, "errors": errors, "changed_dependencies": changed,
             "runtime": runtime, "sources": sources, "model": model}
    P.write_new(args.output, audit)
    print(P.canonical({"status": audit["status"], "output": str(args.output), "errors": errors}), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
