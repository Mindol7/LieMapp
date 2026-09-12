"""Preregistered numerical/semantic checks of a CPU compiler schedule variant.

This is not an AMA attack evaluation. No tool is proposed or invoked and no
external API is contacted. Actual native model/kernel outputs are compared;
passing finite cases is not a mathematical equivalence proof.
"""

from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = next(path for path in HERE.parents if (path / "LieMappBench").is_dir())
SPECIFICATION = {
    "policy_id": "ama-mlc-cpu-equivalence-v1",
    "input_seed": 2026091201,
    "kernel_float32": {"atol": 1e-4, "rtol": 1e-4, "finite_only": True,
                       "also_report_bitwise_equality": True},
    "integer_and_copy": {"exact_equality_required": True},
    "model_available_logprobs": {"atol": 1e-3, "rtol": 1e-3, "finite_only": True},
    "model_input_and_output_tokens": {"exact_equality_required": True},
    "model_settings": {"temperature": 0.0, "top_p": 1.0, "seed": 20260911,
                       "max_tokens": 8, "n": 1, "stream": False,
                       "logprobs": True, "top_logprobs": 5},
    "model_cases": [
        {"case_id": "arithmetic", "messages": [{"role": "user", "content": "What is 2 + 2? Reply with only the number."}]},
        {"case_id": "literal_repeat", "messages": [{"role": "user", "content": "Repeat exactly: blue sky"}]},
    ],
    "kernel_dynamic_n": [1, 2, 7, 16, 31],
    "synthetic_matmul_shapes": [[1, 7, 31], [2, 9, 33], [7, 17, 65], [16, 32, 64], [31, 33, 63]],
    "comparison_rule": "Every required case must pass; no tolerance widening, cherry-picking, or failed-case removal after seeing results.",
    "scope_limit": "Representative finite kernel cases plus exact greedy tokens and available native top-logprob scores; no claim of full-vocabulary logits unless explicitly collected.",
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def descriptor(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}


def write_new(path, value):
    path = Path(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")


def validate_registration(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document["specification"] != SPECIFICATION:
        raise ValueError("Preregistered inputs/tolerances differ; never reinterpret an existing registration")
    return document


def register(args):
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    write_new(output, {"registered_utc": datetime.now(timezone.utc).isoformat(),
                       "specification": SPECIFICATION,
                       "stock_library": descriptor(args.stock_library),
                       "official_model_manifest": descriptor(HERE / "model.json"),
                       "optimized_numerical_outputs_examined_at_registration": False,
                       "registration_implementation": descriptor(__file__),
                       "implementation_note": "Implementation identities are also pinned per execution; this immutable document fixes test inputs and acceptance thresholds."})
    print(json.dumps({"registered": str(output), "sha256": digest(output)}), flush=True)


def assert_descriptor(record):
    path = Path(record["path"])
    if not path.is_file() or path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
        raise ValueError("Pinned file changed: " + str(path))


def model_worker(args):
    registration = validate_registration(args.registration)
    assert_descriptor(registration["stock_library"])
    assert_descriptor(registration["official_model_manifest"])
    output = Path(args.output_dir).resolve(strict=True)
    library = Path(args.library).resolve(strict=True)
    if args.variant == "stock" and str(library) != registration["stock_library"]["path"]:
        raise ValueError("Stock probe must use the preregistered library")
    runner = load(HERE / "run_public.py", "mlc_cpu_equivalence_runner")
    model, model_path = runner.checked_model()
    common = load(ROOT / "LieMappBench/Logging-Dataset/logger.py", "mlc_cpu_equivalence_logger")
    from mlc_llm import MLCEngine, liemapp_ama
    from mlc_llm.serve.config import EngineConfig

    config = EngineConfig(max_num_sequence=1, max_total_sequence_length=4096,
                          max_single_sequence_length=4096, prefill_chunk_size=512,
                          prefix_cache_mode="disable", speculative_mode="disable", prefill_mode="chunked")
    started = time.monotonic()
    engine = MLCEngine(str(model_path), device="cpu", model_lib=str(library),
                       mode="server", engine_config=config)
    metadata = {"attack_id": "ama", "engine": {"id": "mlc-llm", "name": "MLC-LLM"},
                "run_id": output.name + "-model-evidence", "execution_scope": "native_runtime",
                "purpose": "non_AMA_CPU_compiler_numerical_semantic_validation",
                "variant": args.variant, "registration": descriptor(args.registration),
                "worker": descriptor(__file__), "library": descriptor(library),
                "model": model, "native_engine_config": json.loads(engine.engine_config.asjson()),
                "conversation": engine.conv_template.model_dump(), "startup_seconds": time.monotonic() - started,
                "native_shared_objects": sorted({str(Path(line.split()[-1]).resolve())
                    for line in Path("/proc/self/maps").read_text().splitlines()
                    if len(line.split()) >= 6 and line.split()[-1].startswith("/")
                    and ".so" in Path(line.split()[-1]).name and Path(line.split()[-1]).is_file()})}
    results = []
    prior_socket = os.environ.get("LIEMAPP_SOCKET")
    try:
        with common.Logger(output / "model-evidence", metadata, source_root=ROOT) as logger:
            with common.Collector(logger) as collector:
                os.environ["LIEMAPP_SOCKET"] = collector.socket_path
                for case in SPECIFICATION["model_cases"]:
                    request_id = "cpu-equivalence-" + case["case_id"]
                    effective = {"messages": case["messages"], "model": "local-ama-model",
                                 **SPECIFICATION["model_settings"], "request_id": request_id}
                    submitted = {key: value for key, value in effective.items() if key != "request_id"}
                    submitted.update(liemapp_request_id=request_id,
                                     liemapp_context={"case_id": case["case_id"], "purpose": metadata["purpose"]})
                    begin = time.monotonic()
                    print(json.dumps({"variant": args.variant, "case_id": case["case_id"], "status": "started"}), flush=True)
                    with liemapp_ama.request_scope(submitted, effective, []):
                        response = engine.chat.completions.create(**effective).model_dump()
                    events = [event for event in logger._records if event["context"].get("request_id") == request_id]
                    by_stage = {event["stage"]: event for event in events}
                    if len(events) != 3:
                        raise ValueError("Native numerical probe must preserve exactly three observation stages")
                    rendered = by_stage["ama_native_prompt_rendered"]["raw"]
                    generated = by_stage["ama_native_tool_calls_returned"]["raw"]
                    if generated["response"] != response:
                        raise ValueError("Native observed response does not match returned response")
                    result = {"case_id": case["case_id"], "effective_request": effective,
                              "rendered_prompt": rendered["rendered_prompt"],
                              "input_token_ids": rendered["input_token_ids"],
                              "output_token_ids": generated["output_token_ids"],
                              "generated_texts": generated["generated_texts_before_parser"],
                              "native_generation_config": generated["native_generation_config"],
                              "response": response, "elapsed_seconds": time.monotonic() - begin,
                              "event_ids": [event["event_id"] for event in events]}
                    results.append(result)
                    write_new(output / (case["case_id"] + ".json"), result)
                    print(json.dumps({"variant": args.variant, "case_id": case["case_id"], "status": "completed",
                                      "elapsed_seconds": result["elapsed_seconds"],
                                      "input_tokens": len(result["input_token_ids"]),
                                      "output_tokens": len(result["output_token_ids"])}), flush=True)
        write_new(output / "model-results.json", {"variant": args.variant, "registration": descriptor(args.registration),
                  "library": descriptor(library), "model_manifest": descriptor(HERE / "model.json"),
                  "cases": results, "external_api_calls": 0, "full_vocabulary_logits_collected": False,
                  "score_coverage": "native logprobs for each generated token and top_logprobs=5 only"})
    finally:
        if prior_socket is None:
            os.environ.pop("LIEMAPP_SOCKET", None)
        else:
            os.environ["LIEMAPP_SOCKET"] = prior_socket
        engine.terminate()


def probe_model(args):
    validate_registration(args.registration)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    native = load(HERE / "native_runtime.py", "mlc_cpu_equivalence_native")
    command = [str(native.PYTHON), "-B", str(Path(__file__).resolve()), "_model-worker",
               "--registration", str(Path(args.registration).resolve()), "--variant", args.variant,
               "--library", str(Path(args.library).resolve()), "--output-dir", str(output)]
    write_new(output / "invocation.json", {"command": command, "threads": args.threads,
              "created_utc": datetime.now(timezone.utc).isoformat(), "verification_implementation": descriptor(__file__)})
    with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
        result = subprocess.run(command, cwd=ROOT, env=native.environment(output, threads=args.threads),
                                stdout=stdout, stderr=stderr, check=False)
    write_new(output / "process.json", {"exit_code": result.returncode,
              "stdout": descriptor(output / "stdout.log"), "stderr": descriptor(output / "stderr.log")})
    print(json.dumps({"variant": args.variant, "exit_code": result.returncode, "output": str(output)}), flush=True)
    if result.returncode != 0:
        raise SystemExit(1)


def compare_scores(left, right, tolerance):
    """Compare corresponding native token-score structures without sorting away changes."""
    scores = []
    def walk(a, b, path):
        if path.endswith(".logprob"):
            if isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
                raise ValueError("Invalid native logprob at " + path)
            if not math.isfinite(a) or not math.isfinite(b):
                raise ValueError("Non-finite native logprob at " + path)
            scores.append({"path": path, "stock": a, "optimized": b,
                           "absolute_error": abs(a - b),
                           "passed": abs(a - b) <= tolerance["atol"] + tolerance["rtol"] * abs(a)})
        elif isinstance(a, dict) and isinstance(b, dict):
            if set(a) != set(b):
                raise ValueError("Native score structure keys differ at " + path)
            for key in a:
                walk(a[key], b[key], path + "." + key)
        elif isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                raise ValueError("Native score list lengths differ at " + path)
            for index, (value_a, value_b) in enumerate(zip(a, b)):
                walk(value_a, value_b, path + f"[{index}]")
        elif a != b:
            raise ValueError("Native score token identity/order differs at " + path)
    walk(left, right, "logprobs")
    if not scores:
        raise ValueError("No actual native logprob values were captured")
    return {"passed": all(row["passed"] for row in scores), "values_compared": len(scores),
            "maximum_absolute_error": max(row["absolute_error"] for row in scores), "values": scores}


def compare_model(args):
    validate_registration(args.registration)
    stock = json.loads((Path(args.stock_dir) / "model-results.json").read_text())
    optimized = json.loads((Path(args.optimized_dir) / "model-results.json").read_text())
    if stock["variant"] != "stock" or optimized["variant"] != "optimized":
        raise ValueError("Comparison roles differ")
    if stock["registration"] != optimized["registration"] or stock["registration"]["sha256"] != digest(args.registration):
        raise ValueError("Model probes use different preregistration")
    if stock["model_manifest"] != optimized["model_manifest"]:
        raise ValueError("Model weights/configuration identity differs")
    expected = [case["case_id"] for case in SPECIFICATION["model_cases"]]
    if [case["case_id"] for case in stock["cases"]] != expected or [case["case_id"] for case in optimized["cases"]] != expected:
        raise ValueError("Missing/reordered model validation case")
    cases = []
    for left, right in zip(stock["cases"], optimized["cases"]):
        fields = ("effective_request", "rendered_prompt", "input_token_ids", "output_token_ids", "generated_texts", "native_generation_config")
        equal_fields = {key: left[key] == right[key] for key in fields}
        choices = (left["response"]["choices"][0], right["response"]["choices"][0])
        equal_fields["response_message"] = choices[0]["message"] == choices[1]["message"]
        equal_fields["finish_reason"] = choices[0]["finish_reason"] == choices[1]["finish_reason"]
        score_error = None
        try:
            scores = compare_scores(choices[0]["logprobs"], choices[1]["logprobs"], SPECIFICATION["model_available_logprobs"])
        except ValueError as error:
            scores = {"passed": False};score_error = str(error)
        cases.append({"case_id": left["case_id"], "exact_fields": equal_fields, "scores": scores,
                      "score_error": score_error, "passed": all(equal_fields.values()) and scores["passed"],
                      "stock_seconds": left["elapsed_seconds"], "optimized_seconds": right["elapsed_seconds"]})
    result = {"status": "passed" if all(case["passed"] for case in cases) else "failed",
              "registration": descriptor(args.registration), "stock": descriptor(Path(args.stock_dir) / "model-results.json"),
              "optimized": descriptor(Path(args.optimized_dir) / "model-results.json"), "cases": cases,
              "scope": SPECIFICATION["scope_limit"], "external_api_calls": 0}
    write_new(args.output, result)
    print(json.dumps({"status": result["status"], "output": str(args.output)}), flush=True)
    if result["status"] != "passed":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register")
    registration.add_argument("--stock-library", required=True)
    registration.add_argument("--output", required=True)
    for command in ("model-probe", "_model-worker"):
        probe = commands.add_parser(command)
        probe.add_argument("--registration", required=True)
        probe.add_argument("--variant", choices=("stock", "optimized"), required=True)
        probe.add_argument("--library", required=True)
        probe.add_argument("--output-dir", required=True)
        probe.add_argument("--threads", type=int, default=6)
    comparison = commands.add_parser("compare-model")
    for key in ("registration", "stock-dir", "optimized-dir", "output"):
        comparison.add_argument("--" + key, required=True)
    args = parser.parse_args()
    {"register": register, "model-probe": probe_model,
     "_model-worker": model_worker, "compare-model": compare_model}[args.command](args)


if __name__ == "__main__":
    main()
