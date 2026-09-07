"""Export actual sealed event-source locations from the historical hook mapping.

This is a schema adapter for the SGLang mapping, not a rule evaluator. Original
mapping, code and raw evidence remain read-only; output must be a new file.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "LieMappAnalyzer/analyzer.py").is_file())
SPEC = importlib.util.spec_from_file_location("mapping_export_analyzer", ROOT / "LieMappAnalyzer/analyzer.py")
analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analyzer)


class MappingError(ValueError):
    pass


def read(path):
    return analyzer._json(Path(path).read_text(encoding="utf-8"), str(path))


def verified_file(source, snapshots):
    """Find exact source bytes without substituting current changed source."""
    original = Path(source["path"])
    matches = [path for path in snapshots if path.is_file() and analyzer.file_sha256(path) == source["sha256"]]
    if matches:
        return sorted(matches)[0], True
    if original.is_file() and analyzer.file_sha256(original) == source["sha256"]:
        return original.resolve(), False
    raise MappingError("No source file or snapshot matches the recorded hash: " + source["path"])


def functions_at(path, name, line):
    return [node for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
            and node.lineno <= line <= node.end_lineno]


def convert_point(point, events, snapshots, destination):
    if not events:
        raise MappingError("The mapped stage was not observed: " + point["stage"])
    hook = point["actual_hook"]
    if not isinstance(point.get("reason_ko"), str) or not isinstance(point.get("conditions"), list):
        raise MappingError("Historical point lacks reason_ko/conditions")
    sources = {analyzer.canonical_json(event["source"]): event["source"] for event in events}
    if len(sources) != 1:
        raise MappingError("A historical hook cannot ambiguously represent multiple actual sources")
    source = next(iter(sources.values()))
    if not isinstance(source, dict) or any(source[key] != hook[key] for key in ("path", "function", "sha256")):
        raise MappingError("Observed source path/function/hash does not match the original hook")
    path, snapshot = verified_file(source, snapshots)
    definitions = functions_at(path, source["function"], source["line"])
    if len(definitions) != 1 or definitions[0].lineno != hook["line"]:
        raise MappingError("Observed emission line is not inside the documented hook definition")
    calls = [node for node in ast.walk(definitions[0])
             if isinstance(node, ast.Call) and node.lineno == source["line"]
             and isinstance(node.func, ast.Name) and node.func.id in {"emit", "source"}
             and any(isinstance(argument, ast.Constant) and argument.value == source["logging_point_id"]
                     for argument in node.args)]
    if len(calls) != 1:
        raise MappingError("Observed source line is not the matching emit/source capture call")
    emission = calls[0].func.id
    if emission == "emit" and (not isinstance(calls[0].args[0], ast.Constant) or calls[0].args[0].value != point["stage"]):
        raise MappingError("Actual emit call has a different stage")
    site = point["native_engine_site"]
    native_path, native_snapshot = verified_file(site, snapshots)
    if not functions_at(native_path, site["function"], site["line"]):
        raise MappingError("Native engine connection line is outside its documented function")
    row = {"logging_point_id": source["logging_point_id"], "stage": point["stage"],
           "condition_ids": point["conditions"], "reason": point["reason_ko"],
           "source": source, "original_hook_definition": hook,
           "native_engine_site": site,
           "line_semantics": "source.line은 실제 emit 또는 source 기록 호출 행, original_hook_definition.line은 함수 정의 행입니다.",
           "recording_boundary": "direct_emit" if emission == "emit" else "first_logits_source_capture_before_runner_composition",
           "raw_values": point.get("raw_values"), "request_identity": point.get("request_identity"),
           "observed_event_count": len(events), "event_ids": [event["event_id"] for event in events],
           "verified_source": {"path": os.path.relpath(path, destination.parent), "sha256": source["sha256"],
                               "kind": "existing_hash_verified_snapshot" if snapshot else "current_hash_verified_source"},
           "verified_native_site_source": {"path": os.path.relpath(native_path, destination.parent),
                                           "sha256": site["sha256"], "is_snapshot": native_snapshot}}
    if snapshot:
        row["source_snapshot"] = os.path.relpath(path, destination.parent)
    return row


def export(log_path, mapping_path, output, snapshot_dirs=()):
    log_path, mapping_path = Path(log_path).resolve(strict=True), Path(mapping_path).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Refusing to replace an existing mapping: " + str(output))
    if output.resolve().is_relative_to(log_path.parent):
        raise MappingError("New mapping must be outside the immutable raw archive")
    mapping = read(mapping_path)
    package = analyzer.EvidencePackage(log_path)
    if mapping["attack_id"] != package.metadata["attack_id"] or mapping["engine_id"] != package.metadata["engine"]["id"]:
        raise MappingError("Mapping attack/engine identity does not match the sealed evidence")
    if package.seal["status"] != "completed" or mapping.get("canonical_run") != package.run_id:
        raise MappingError("This exporter requires the mapping's completed canonical run")
    snapshots = [path for directory in snapshot_dirs for path in Path(directory).resolve(strict=True).rglob("*.py")]
    grouped = defaultdict(list)
    for event in package.events:
        grouped[event["stage"]].append(event)
    points = [convert_point(point, grouped[point["stage"]], snapshots, output) for point in mapping["logging_points"]]
    data = {"schema_version": "1.0.0", "attack_id": mapping["attack_id"], "engine_id": mapping["engine_id"],
            "description": "기존 함수 정의 기준 매핑과 봉인된 실제 이벤트의 호출 행을 대조한 공개용 매핑입니다. 원본 문서는 변경하지 않았습니다.",
            "source_commit": mapping.get("source_commit"), "scope": mapping.get("scope"),
            "logging_points": points, "unmapped_stages": sorted(set(grouped) - {point["stage"] for point in points}),
            "limitations": mapping.get("limitations", []),
            "provenance": {"canonical_run": package.run_id,
                           "raw_log": {"path": os.path.relpath(log_path, output.parent), "sha256": analyzer.file_sha256(log_path)},
                           "original_mapping": {"path": os.path.relpath(mapping_path, output.parent), "sha256": analyzer.file_sha256(mapping_path)},
                           "exporter_sha256": analyzer.file_sha256(Path(__file__)),
                           "observed_lines_not_inferred": True, "rules_or_raw_modified": False}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return {"path": str(output), "sha256": analyzer.file_sha256(output), "logging_points": len(points),
            "observed_event_counts": {point["stage"]: point["observed_event_count"] for point in points}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--mapping", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot-dir", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        result = export(args.log, args.mapping, args.output, args.snapshot_dir)
    except (MappingError, analyzer.EvidenceError, OSError) as error:
        print("Mapping export rejected: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
