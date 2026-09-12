"""Create an observation-only receipt for an interrupted, preserved run.

No run file, seal, pipeline result, evaluation setting, or source snapshot is
created or repaired. File hashes describe bytes observed now; frozen dependency
snapshots describe the recorded execution, not today's mutable configuration.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def safe_path(value, root, *, exists=True):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("Symlink paths are not accepted: " + str(current))
    path = path.resolve(strict=exists)
    if not path.is_relative_to(root) or path == root:
        raise ValueError("Path must be strictly inside the project: " + str(path))
    return path


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError("Non-JSON numeric constant: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def fingerprint(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def descriptor(path):
    before = fingerprint(path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if fingerprint(path) != before:
        raise ValueError("Input changed while being read: " + str(path))
    return {"path": str(path), "bytes": before[2], "sha256": digest}


def option(command, name):
    if not isinstance(command, list) or any(not isinstance(value, str) for value in command):
        raise ValueError("Pipeline commands must be explicit argument lists")
    positions = [index for index, value in enumerate(command) if value == name]
    if len(positions) != 1 or positions[0] + 1 >= len(command):
        raise ValueError("Expected one pipeline argument: " + name)
    return command[positions[0] + 1]


def bind_pipeline(run, start, run_dir, pipeline_dir, root):
    run_id, attack, engine = run["run_id"], run["attack_id"], run["engine"]["id"]
    if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
           for value in (run_id, attack, engine)):
        raise ValueError("Invalid run, attack, or engine identifier")
    if run_dir != root / ".evidence/raw" / attack / engine / run_id:
        raise ValueError("Raw path does not match its recorded attack/engine/run identity")
    if pipeline_dir != root / ".evidence/pipelines" / run_id or start["run_id"] != run_id:
        raise ValueError("Pipeline and raw run identities differ")
    steps = start["steps"]
    evaluation = [step for step in steps if step["stage"] == "01-native-evaluation"]
    if len(evaluation) != 1:
        raise ValueError("Expected one recorded native evaluation stage")
    command = evaluation[0]["command"]
    if option(command, "--run-id") != run_id:
        raise ValueError("Native evaluation command targets a different run")
    scripts = [value for value in command if Path(value).name == "run_public.py"]
    expected_script = root / "LieMappBench/Attack-Execution-Dataset/attack-script" / attack / engine / "run_public.py"
    # This is a path binding only. Do not open/hash the mutable current script.
    if len(scripts) != 1 or Path(scripts[0]) != expected_script:
        raise ValueError("Pipeline native command targets another attack or engine")
    pointers = []
    for step in steps:
        command = step["command"]
        for key in ("--run-dir", "--run", "--log"):
            if key in command:
                expected = run_dir / "events.jsonl" if key == "--log" else run_dir
                if Path(option(command, key)) != expected:
                    raise ValueError("Pipeline raw-evidence pointer differs: " + key)
                pointers.append({"stage": step["stage"], "argument": key, "path": str(expected)})
        if "--engine" in command and option(command, "--engine") != engine:
            raise ValueError("Pipeline publication engine differs")
        if "--attack" in command and option(command, "--attack") != attack:
            raise ValueError("Pipeline publication attack differs")
    if not pointers:
        raise ValueError("Pipeline does not explicitly point to the raw run")
    recorded_command = strict_json((pipeline_dir / "01-native-evaluation/command.json").read_bytes())
    if recorded_command["command"] != evaluation[0]["command"] or Path(recorded_command["cwd"]) != root:
        raise ValueError("Executed command record differs from pipeline start")
    return {"run_id": run_id, "attack_id": attack, "engine_id": engine,
            "native_command": evaluation[0]["command"], "raw_evidence_pointers": pointers}


def scan_events(path, identity):
    before = fingerprint(path)
    digest = hashlib.sha256()
    offset, parsed = 0, 0
    stages, starts, finishes = Counter(), [], []
    malformed, last, nonsequential = [], None, []
    final_newline = None
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            digest.update(line)
            at = offset
            offset += len(line)
            final_newline = line.endswith(b"\n")
            try:
                event = strict_json(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as error:
                malformed.append({"line": number, "byte_offset": at, "bytes": len(line),
                                  "sha256": hashlib.sha256(line).hexdigest(),
                                  "trailing_partial": not final_newline,
                                  "reason": type(error).__name__})
                continue
            if not isinstance(event, dict):
                raise ValueError("A parsed event is not a JSON object")
            if (event.get("run_id") != identity["run_id"]
                or event.get("metadata", {}).get("engine", {}).get("id") != identity["engine_id"]
                or event.get("metadata", {}).get("attack_id") != identity["attack_id"]):
                raise ValueError("Event stream contains a different run/engine/attack")
            sequence, stage = event.get("sequence"), event.get("stage")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or not isinstance(stage, str):
                raise ValueError("Event lacks a valid sequence/stage")
            if sequence != (last["sequence"] + 1 if last else 1):
                nonsequential.append({"line": number, "sequence": sequence})
            parsed += 1
            stages[stage] += 1
            request_id = event.get("context", {}).get("request_id")
            if stage.endswith("_request_started") or stage.endswith("_request_finished"):
                if not isinstance(request_id, str) or not request_id:
                    raise ValueError("Request boundary lacks its request ID")
                (starts if stage.endswith("_request_started") else finishes).append(request_id)
            last = {"sequence": sequence, "stage": stage, "event_id": event.get("event_id"),
                    "timestamp_utc": event.get("timestamp_utc"), "request_id": request_id,
                    "line": number, "terminated_by_newline": final_newline}
    if fingerprint(path) != before or offset != before[2]:
        raise ValueError("Event stream changed during receipt collection")
    return {"file": {"path": str(path), "bytes": offset, "sha256": digest.hexdigest()},
            "parsed_event_count": parsed, "stage_counts": dict(stages), "last_complete_event": last,
            "request_started_count": len(starts), "request_finished_count": len(finishes),
            "started_request_ids": starts, "finished_request_ids": finishes,
            "incomplete_request_ids": list(dict.fromkeys(value for value in starts if value not in set(finishes))),
            "finished_without_start_ids": list(dict.fromkeys(value for value in finishes if value not in set(starts))),
            "duplicate_started_ids": [key for key, count in Counter(starts).items() if count > 1],
            "duplicate_finished_ids": [key for key, count in Counter(finishes).items() if count > 1],
            "malformed_lines": malformed, "has_trailing_partial_line": any(row["trailing_partial"] for row in malformed),
            "file_ends_with_newline": final_newline, "nonsequential_events": nonsequential,
            "interpretation": "Counts describe parseable recorded events, not successful attacks, completed evaluation, or a reconstructed seal."}


def observe_linux_host():
    """Current Linux instance only; no inference about the interruption cause."""
    observation = {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
                   "scope": "Current Linux instance boot/uptime; not proof of physical reboot, sender identity, or interruption cause."}
    try:
        boot_line = next(line for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
        epoch = int(boot_line.split()[1])
        observation.update(boot_epoch_seconds=epoch, boot_time_utc=datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
                           boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                           uptime_seconds=float(Path("/proc/uptime").read_text().split()[0]),
                           sources=["/proc/stat:btime", "/proc/sys/kernel/random/boot_id", "/proc/uptime"])
    except (OSError, ValueError, StopIteration, IndexError) as error:
        observation["unavailable_reason"] = type(error).__name__
    return observation


def build_receipt(run_dir, pipeline_dir, output, *, root=ROOT, observe_host=False):
    root = Path(root).resolve(strict=True)
    run_dir, pipeline_dir = (safe_path(value, root) for value in (run_dir, pipeline_dir))
    output = safe_path(output, root, exists=False)
    if output.exists() or not output.parent.is_dir() or output.suffix != ".json":
        raise ValueError("Output must be a new JSON file in an existing directory")
    if output.is_relative_to(run_dir) or output.is_relative_to(pipeline_dir):
        raise ValueError("Receipt must not be written inside the preserved run or pipeline")
    paths = []
    for directory in (run_dir, pipeline_dir):
        for path in sorted(directory.rglob("*")):
            safe_path(path, root)
            if path.is_file():
                paths.append(path)
    before = {path: fingerprint(path) for path in paths}
    run = strict_json((run_dir / "run.json").read_bytes())
    start = strict_json((pipeline_dir / "pipeline-start.json").read_bytes())
    identity = bind_pipeline(run, start, run_dir, pipeline_dir, root)
    events = scan_events(run_dir / "events.jsonl", identity)
    inventory = {str(path): events["file"] if path == run_dir / "events.jsonl" else descriptor(path) for path in paths}
    dependencies = strict_json((pipeline_dir / "dependencies.json").read_bytes())
    frozen = []
    for record in dependencies:
        snapshot = safe_path(pipeline_dir / record["snapshot"], root)
        if not snapshot.is_relative_to(pipeline_dir / "source-snapshots"):
            raise ValueError("Dependency snapshot is outside the frozen snapshot directory")
        observed = inventory[str(snapshot)]
        frozen.append({"original_path_at_run": record["path"], "snapshot": observed,
                       "recorded_sha256": record["sha256"], "recorded_bytes": record["bytes"],
                       "matches_recorded_dependency": observed["sha256"] == record["sha256"] and observed["bytes"] == record["bytes"]})
    signals = []
    for path in paths:
        if path.is_relative_to(pipeline_dir) and path.name == "stderr.log":
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for number, line in enumerate(stream, 1):
                    match = re.fullmatch(r"KeyboardInterrupt: Pipeline interrupted by signal ([0-9]+)\s*", line)
                    if match:
                        value = int(match.group(1))
                        signals.append({"signal_number": value, "signal_name": "SIGTERM" if value == 15 else None,
                                        "path": str(path), "line": number, "text": line.rstrip("\r\n"),
                                        "evidence_file": inventory[str(path)]})
    for path, stamp in before.items():
        if fingerprint(path) != stamp:
            raise ValueError("Input changed before receipt was finalized: " + str(path))
    current_paths = {path for directory in (run_dir, pipeline_dir) for path in directory.rglob("*") if path.is_file()}
    if current_paths != set(paths):
        raise ValueError("Input file inventory changed during receipt collection")
    expected_optional = [run_dir / name for name in ("seal.json", "events.pretty.json", "observations.json")]
    expected_optional += [pipeline_dir / "pipeline-result.json", pipeline_dir / "01-native-evaluation/result.json"]
    receipt = {"schema_version": "1.0.0", "record_kind": "interruption_evidence_receipt",
               "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "identity_binding": identity,
               "run_directory": str(run_dir), "pipeline_directory": str(pipeline_dir),
               "pipeline_start_status_observed": start.get("status"),
               "events": events, "signal_observations": signals,
               "termination_sender": None, "termination_sender_status": "unknown; not identified by the recorded traceback",
               "artifact_presence": [{"path": str(path), "present": path.is_file()} for path in expected_optional],
               "raw_files": [inventory[str(path)] for path in paths if path.is_relative_to(run_dir)],
               "pipeline_files": [inventory[str(path)] for path in paths if path.is_relative_to(pipeline_dir)],
               "frozen_dependency_snapshots": frozen, "current_configuration_compared_to_old_run": False,
               "limitations": ["No old file, seal, pipeline result, or completion/failure judgment was created or repaired.",
                               "Signal observations reproduce stderr messages; they do not identify the sender or prove an operating-system cause.",
                               "Only existing snapshot bytes are bound to recorded dependencies; mutable current source/configuration is not assumed identical.",
                               "File hashes and event counts are a preservation receipt, not full Logger chain validation or AC/DC analysis."],
               "receipt_utility": descriptor(Path(__file__).resolve())}
    if observe_host:
        receipt["current_linux_host_observation"] = observe_linux_host()
    payload = (json.dumps(receipt, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    descriptor_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor_fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("run-dir", "pipeline-dir", "output"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--observe-host", action="store_true", help="Record current Linux boot/uptime without attributing the interruption cause")
    args = parser.parse_args()
    receipt = build_receipt(args.run_dir, args.pipeline_dir, args.output, observe_host=args.observe_host)
    print(json.dumps({"output": str(Path(args.output).resolve()),
                      "request_started_count": receipt["events"]["request_started_count"],
                      "request_finished_count": receipt["events"]["request_finished_count"],
                      "signals_observed": [row["signal_number"] for row in receipt["signal_observations"]]}))


if __name__ == "__main__":
    main()
