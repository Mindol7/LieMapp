"""Create-only AMA MLC evaluation -> mapping -> context -> publication -> audit.

Requires an already passed native parity, four-cohort development run and
evaluation-readiness.json. Never prepares/changes a model, runtime, proof,
common Analyzer, logger or experiment configuration. A failure stops the chain.
Only a successful final independent audit permits pipeline status 'completed'.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
PYTHON = ROOT / ".venv/bin/python"
PROTOCOL_ID = "ama-public-http-mlc-native-v1"
MAPPING_BASE = ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm"
MAPPING = MAPPING_BASE / "public-http-native-v1"
SUPPLEMENT = ROOT / ".evidence/supplements/ama-mlc-public-context-20260912.json"
READY = HERE / "evaluation-readiness.json"
CONFIG = ROOT / "internal/experiments.json"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))


def write_new(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def descriptor(path):
    path = Path(path).resolve(strict=True)
    require(path.is_relative_to(ROOT), "Evidence/source outside this project: " + str(path))
    return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": digest(path)}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def safe_output(path):
    path = Path(path).absolute()
    require(path.is_relative_to(ROOT), "Output outside this project")
    for candidate in (path, *path.parents):
        if candidate == ROOT:
            break
        require(not candidate.is_symlink(), "Symlinked output is not allowed: " + str(candidate))
    require(path.resolve().is_relative_to(ROOT), "Output escaped this project")
    return path


def paths_for(run_id):
    require(isinstance(run_id, str) and SAFE_ID.fullmatch(run_id), "Unsafe run identifier")
    return {"pipeline": safe_output(ROOT / ".evidence/pipelines" / run_id),
            "run": safe_output(ROOT / ".evidence/raw/ama/mlc-llm" / run_id),
            "mapping_json": safe_output(MAPPING / "logging-points.json"),
            "mapping_md": safe_output(MAPPING / "logging-points.md"),
            "supplement": safe_output(SUPPLEMENT),
            "audit": safe_output(ROOT / ".evidence/audits" / (run_id + "-publication"))}


def unused_outputs(paths):
    for key, path in paths.items():
        if path.exists() or path.is_symlink():
            raise FileExistsError("Refusing existing " + key + ": " + str(path))


def config_check(paths):
    sys.path.insert(0, str(ROOT))
    from internal.workflow import load_config, resolve, selected_protocol
    config = load_config(CONFIG)
    attack = config["attacks"]["ama"]
    engine = attack["engines"]["mlc-llm"]
    require(attack["label"] == "AMA" and engine["label"] == "MLC-LLM", "Unexpected publication filenames/labels")
    require(resolve(engine["source_log"]) == paths["run"] / "events.jsonl", "Config source_log must name this NEW run explicitly")
    require(resolve(engine["mapping"]) == paths["mapping_json"], "Config mapping must name the NEW public MLC mapping")
    require([resolve(path) for path in engine.get("supplements", [])] == [paths["supplement"]]
            and engine.get("run_supplements") == ["observations.json"], "Config must select the verified MLC context plus run observations")
    selected = selected_protocol(attack, {"attack_id": "ama", "protocol_id": PROTOCOL_ID})
    require(selected["rules"] == MAPPING / "conditions.json"
            and selected["presentation"] == MAPPING / "presentation.json", "Wrong registered MLC protocol rules/presentation")
    return {"config": descriptor(CONFIG), "protocol_id": PROTOCOL_ID,
            "source_log": str(paths["run"] / "events.jsonl"), "mapping": str(paths["mapping_json"])}


def verify_ready(args):
    """Read-only child stage; no inference or HTTPS request is made here."""
    paths = paths_for(args.run_id)
    parity = args.parity.resolve(strict=True)
    development = args.development_run.resolve(strict=True)
    require(parity.is_relative_to(ROOT / ".evidence"), "Parity must be preserved within .evidence")
    require(development.is_relative_to(ROOT / ".evidence/raw/ama/mlc-llm"), "Wrong development evidence directory")
    document = read(READY)
    require((ROOT / document["parity"]["path"]).resolve() == parity
            and document["parity"]["sha256"] == digest(parity), "--parity differs from frozen readiness")
    require((ROOT / document["development_run"]["directory"]).resolve() == development,
            "--development-run differs from frozen readiness")
    selected = config_check(paths)
    protocol = load(HERE / "mlc_protocol.py", "mlc_complete_readiness_protocol")
    protocol.verify_readiness(READY)
    package, finished = protocol.verify_run(development)
    groups = Counter((e["context"]["variant"], e["context"]["control"]) for e in finished)
    require(len(finished) == 4 and groups == Counter({g: 1 for g in protocol.CONDITIONS}),
            "Expected exactly four development requests, one per cohort")
    require(package.metadata["protocol"]["split"] == "development"
            and any(e["raw"]["public_calls_confirmed"] for e in finished), "Development gates not met")
    audit = load(HERE / "audit_run.py", "mlc_complete_readonly_parity_audit")
    parity_result = audit.check_parity(parity, package, protocol)
    result = {"status": "passed", "readiness": descriptor(READY), "configuration": selected,
              "development_run": str(development), "development_requests": len(finished),
              "independent_parity": parity_result, "model_requests_executed_here": 0,
              "external_api_calls_executed_here": 0}
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return result


def commands(args, paths):
    python = str(PYTHON)
    base = [python, "-B"]
    common_args = ["--run-id", args.run_id, "--parity", str(args.parity.resolve()),
                   "--development-run", str(args.development_run.resolve())]
    return [
        ("00-readiness", [*base, str(HERE / "complete_run.py"), *common_args, "--verify-readiness"]),
        ("01-native-evaluation", [*base, str(HERE / "run_public.py"), "--run-id", args.run_id, "--timeout", "1800"]),
        ("02-source-mapping", [*base, str(MAPPING_BASE / "freeze_mapping.py"), "--run-dir", str(paths["run"]),
                               "--output-dir", str(MAPPING)]),
        ("03-readable-context", [*base, str(HERE / "context_report.py"), "--run", str(paths["run"]),
                                 "--output", str(paths["supplement"])]),
        ("04-common-publication", [*base, str(ROOT / "developer.py"), "--log", str(paths["run"] / "events.jsonl"),
                                   "--attack", "ama", "--engine", "mlc-llm", "--replace"]),
        ("05-independent-audit", [*base, str(HERE / "audit_run.py"), "--run", str(paths["run"]),
                                  "--publication", "--parity", str(args.parity.resolve()),
                                  "--output-dir", str(paths["audit"])]),
    ]


def snapshot_dependencies(args, pipeline):
    files = {HERE / name for name in ("complete_run.py", "run_public.py", "mlc_protocol.py", "native_runtime.py",
        "service.py", "prepare_evaluation.py", "verify_runtime.py", "audit_run.py", "context_report.py",
        "model.json", "evaluation-plan.json", "evaluation-readiness.json")}
    files.update({CONFIG, MAPPING_BASE / "freeze_mapping.py", MAPPING_BASE / "native-build-manifest.json",
        MAPPING / "conditions.json", MAPPING / "presentation.json", ROOT / "developer.py",
        ROOT / "internal/workflow.py", ROOT / "internal/publication.py", ROOT / "internal/verify_publication.py",
        ROOT / "LieMappAnalyzer/analyzer.py", ROOT / "LieMappBench/Logging-Dataset/logger.py",
        args.parity.resolve(strict=True), args.development_run.resolve(strict=True) / "run.json",
        args.development_run.resolve(strict=True) / "seal.json"})
    records = []
    for path in sorted(files):
        record = descriptor(path)
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == record["sha256"], "Source changed while snapshotting")
        target = pipeline / "source-snapshots" / record["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        records.append({**record, "snapshot": str(target.relative_to(pipeline))})
    write_new(pipeline / "dependencies.json", records)
    return records


def unchanged(records):
    for record in records:
        path = ROOT / record["path"]
        require(path.is_file() and path.stat().st_size == record["bytes"] and digest(path) == record["sha256"],
                "Pipeline dependency changed; preserving partial results: " + record["path"])


class StageFailure(RuntimeError):
    pass


def stop_child(process):
    if process.poll() is not None:
        return
    # SIGINT lets run_public unwind its native-server context and preserve logs.
    for sig, timeout in ((signal.SIGINT, 45), (signal.SIGTERM, 20), (signal.SIGKILL, 10)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            continue


def run_stage(name, command, pipeline, dependencies):
    directory = pipeline / name
    directory.mkdir(exist_ok=False)
    started, monotonic = utc(), time.monotonic()
    write_new(directory / "command.json", {"stage": name, "command": command, "cwd": str(ROOT),
        "started_at_utc": started, "shell": False, "environment_overrides": {
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}})
    print(json.dumps({"stage": name, "status": "starting", "log_dir": str(directory)}), flush=True)
    process, error, code = None, None, None
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        try:
            unchanged(dependencies)
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
                start_new_session=True)
            code = process.wait()
        except BaseException as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
            stderr.write(traceback.format_exc().encode("utf-8"))
            stderr.flush()
            if process is not None:
                stop_child(process)
                code = process.poll()
    result = {"stage": name, "status": "passed" if code == 0 and error is None else "failed",
              "started_at_utc": started, "ended_at_utc": utc(), "elapsed_seconds": time.monotonic() - monotonic,
              "process_started": process is not None, "pid": process.pid if process is not None else None,
              "exit_code": code, "error": error, "stdout": descriptor(directory / "stdout.log"),
              "stderr": descriptor(directory / "stderr.log")}
    write_new(directory / "result.json", result)
    print(json.dumps({"stage": name, "status": result["status"], "exit_code": code}), flush=True)
    if result["status"] != "passed":
        raise StageFailure("Stage failed; no later stage was started: " + name)
    return result


def check_run(paths, run_id):
    metadata, seal = read(paths["run"] / "run.json"), read(paths["run"] / "seal.json")
    require(metadata["run_id"] == run_id and metadata["engine"]["id"] == "mlc-llm"
            and metadata["protocol_id"] == PROTOCOL_ID and metadata["protocol"]["split"] == "held_out"
            and metadata["protocol"]["requested_count"] == 128 and seal["status"] == "completed",
            "Evaluation returned without a completed canonical 128-request run")
    require(digest(paths["run"] / "events.jsonl") == seal["events_sha256"]
            and (paths["run"] / "observations.json").is_file(), "Incomplete or changed raw evidence")
    return seal["events_sha256"]


def completion_artifacts(paths, run_id):
    sha = check_run(paths, run_id)
    audit = read(paths["audit"] / "audit.json")
    require(audit["audit_status"] == "pass" and audit["run_id"] == run_id and audit["engine_id"] == "mlc-llm"
            and audit["protocol_id"] == PROTOCOL_ID and audit["request_count"] == 128
            and audit["hashes"]["raw_log"] == sha and audit["publication"] is not None
            and audit["mapping"] is not None and audit["logging_parity"]["status"] == "pass",
            "No passing independent audit for this canonical publication")
    mapping = read(paths["mapping_json"])
    require(mapping["source_run"]["run_id"] == run_id and mapping["source_run"]["events_sha256"] == sha,
            "Mapping does not belong to this run")
    log_directory = ROOT / "LieMappAnalyzer/LogFile/ama/mlc-llm"
    report_directory = ROOT / "report/ama/mlc-llm"
    expected_json = {f"AMA-{condition}-MLC-LLM-LogFile.json" for condition in ("AC1", "AC2", "AC3", "DC1", "DC2")}
    require({p.name for p in log_directory.glob("*.json")} == expected_json, "Expected exactly five condition JSON files")
    require({p.name for p in report_directory.glob("*.md")} == {"AMA-MLC-LLM-Report.md"}, "Expected exactly one final report")
    artifacts = [paths["run"] / name for name in ("run.json", "seal.json", "events.jsonl", "observations.json")]
    artifacts += [paths["mapping_json"], paths["mapping_md"], paths["supplement"], paths["audit"] / "audit.json",
                  report_directory / "AMA-MLC-LLM-Report.md", *sorted(log_directory.glob("*.json"))]
    return [descriptor(path) for path in artifacts]


def execute(args):
    paths = paths_for(args.run_id)
    unused_outputs(paths)
    require(PYTHON.is_file(), "Project .venv/bin/python is required")
    directory = paths["pipeline"]
    directory.mkdir(parents=True, exist_ok=False)
    started = utc()
    steps = commands(args, paths)
    write_new(directory / "pipeline-start.json", {"run_id": args.run_id, "status": "started", "started_at_utc": started,
        "parity": str(args.parity.resolve()), "development_run": str(args.development_run.resolve()),
        "steps": [{"stage": name, "command": command} for name, command in steps],
        "scope": "One new native 128-request MLC run; create-only mapping/context/audit, common recoverable publication replacement"})
    passed, active = [], "snapshot-inputs"
    try:
        dependencies = snapshot_dependencies(args, directory)
        for name, command in steps:
            active = name
            result = run_stage(name, command, directory, dependencies)
            passed.append(result["stage"])
            if name == "01-native-evaluation":
                check_run(paths, args.run_id)
        active = "final-artifact-validation"
        unchanged(dependencies)
        artifacts = completion_artifacts(paths, args.run_id)
        result = {"run_id": args.run_id, "status": "completed", "started_at_utc": started, "ended_at_utc": utc(),
                  "passed_stages": passed, "artifacts": artifacts,
                  "completion_basis": "All stage exit codes zero, native run completed, common publication reconstructed and independent parity/publication audit passed"}
        write_new(directory / "pipeline-result.json", result)
        print(json.dumps({"status": "completed", "run_id": args.run_id, "pipeline_result": str(directory / "pipeline-result.json")}), flush=True)
        return 0
    except BaseException as exc:
        write_new(directory / "pipeline-result.json", {"run_id": args.run_id, "status": "failed",
            "started_at_utc": started, "ended_at_utc": utc(), "failed_stage": active, "passed_stages": passed,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "notice": "Partial raw/mapping/publication artifacts are preserved, not deleted or represented as a completed pipeline. No automatic retry or resume."})
        print(json.dumps({"status": "failed", "stage": active, "pipeline_result": str(directory / "pipeline-result.json"),
                          "error": str(exc)}), file=sys.stderr, flush=True)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--parity", type=Path, required=True)
    parser.add_argument("--development-run", type=Path, required=True)
    parser.add_argument("--verify-readiness", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.verify_readiness:
        verify_ready(args)
        return 0
    def interrupted(signum, _frame):
        raise KeyboardInterrupt("Pipeline interrupted by signal " + str(signum))
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return execute(args)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
