#!/usr/bin/env python3
"""Engine-independent, evidence-first analysis of sealed LieMapp event streams.

Rules are data, never executable Python.  See README.md for the small rule DSL.
An absent observation is unknown, not false; an invalid evidence package is an
error, not a security verdict.  ``readable`` fields never participate in rules.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
import numbers
from pathlib import Path
import sys
from typing import Any


SCHEMA_VERSION = "1.0.0"
MISSING = object()
COMPARISONS = {"eq", "ne", "gt", "ge", "lt", "le", "contains", "not_contains", "in"}
OPS = {"exists", "compare", "count", "all", "any", "pairwise_tensor_distance",
       "pairwise_tensor_cosine", "tensor_equality", "calibrated_tensor_distance", "tensor_stat"}


class EvidenceError(ValueError):
    """The supplied package cannot be trusted as a valid evidence stream."""


class RuleError(ValueError):
    """A rule is malformed or requests an unsupported operation."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"Non-finite JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _json(text: str, label: str) -> Any:
    try:
        result = json.loads(text, parse_constant=_reject_constant,
                            object_pairs_hook=_unique_object)
        # JSON's 1e999 is syntactically numeric but Python decodes it to infinity.
        canonical_json(result)
        return result
    except (ValueError, TypeError) as error:
        raise EvidenceError(f"Invalid JSON in {label}: {error}") from error


def _path_value(value: Any, field: str) -> Any:
    for key in field.split("."):
        if not isinstance(value, dict) or key not in value:
            return MISSING
        value = value[key]
    return value


def _equal(left: Any, right: Any) -> bool:
    # Python's True == 1 is not appropriate for a typed evidence comparison.
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_equal(left[key], right[key]) for key in left)
    return left == right


def _subset(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        return actual is not MISSING and _equal(actual, expected)
    if not isinstance(actual, dict):
        return False
    return all(_subset(_path_value(actual, key), value)
               for key, value in expected.items())


def _compare(actual: Any, cmp: str, expected: Any) -> bool | None:
    if cmp not in COMPARISONS:
        raise RuleError(f"Unsupported comparison: {cmp!r}")
    if actual is MISSING or actual is None or expected is None:
        return None
    if cmp == "eq":
        return _equal(actual, expected)
    if cmp == "ne":
        return not _equal(actual, expected)
    if cmp in {"gt", "ge", "lt", "le"}:
        if (isinstance(actual, bool) or isinstance(expected, bool)
                or not isinstance(actual, numbers.Real)
                or not isinstance(expected, numbers.Real)
                or not math.isfinite(actual) or not math.isfinite(expected)):
            return None
        return {"gt": lambda: actual > expected, "ge": lambda: actual >= expected,
                "lt": lambda: actual < expected, "le": lambda: actual <= expected}[cmp]()
    try:
        if cmp in {"contains", "not_contains"}:
            if isinstance(actual, list):
                present = any(_equal(item, expected) for item in actual)
            elif isinstance(actual, (str, dict)):
                present = expected in actual
            else:
                return None
            return present if cmp == "contains" else not present
        if isinstance(expected, list):
            return any(_equal(actual, item) for item in expected)
        return actual in expected if isinstance(expected, (str, list, dict)) else None
    except TypeError:
        return None


def _reduce(values: list[bool | None], mode: str) -> bool | None:
    if mode not in {"all", "any"}:
        raise RuleError(f"reduce must be 'all' or 'any', got {mode!r}")
    if not values:
        return None
    if mode == "all":
        if False in values:
            return False
        return None if None in values else True
    if True in values:
        return True
    return None if None in values else False


def _result(value: bool | None, reason: str, events: list[dict] | None = None,
            observations: list[dict] | None = None, children: list[dict] | None = None) -> dict:
    return {
        "value": value,
        "status": {True: "satisfied", False: "not_satisfied", None: "insufficient_evidence"}[value],
        "reason": reason,
        "evidence_ids": list(dict.fromkeys(event["event_id"] for event in (events or []))),
        "observations": observations or [],
        "children": children or [],
    }


class EvidencePackage:
    """Validate the complete event chain and all locally referenced artifacts."""

    def __init__(self, log_path: str | Path):
        self.path = Path(log_path).resolve(strict=True)
        self.root = self.path.parent
        self.events: list[dict] = []
        self.artifact_paths: dict[tuple[str, str], Path] = {}
        self._load()

    def _load(self) -> None:
        previous = None
        ids: set[str] = set()
        identity = None
        with self.path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    raise EvidenceError(f"Blank JSONL record at line {line_number}")
                event = _json(line, f"{self.path.name}:{line_number}")
                self._validate_event(event, line_number)
                if event["event_id"] in ids:
                    raise EvidenceError(f"Duplicate event_id at line {line_number}")
                ids.add(event["event_id"])
                current_identity = (event["run_id"], canonical_json(event["metadata"]))
                if identity is not None and current_identity != identity:
                    raise EvidenceError("Mixed run_id or metadata within one event stream")
                identity = current_identity
                expected_previous = event["previous_event_hash"]
                if line_number == 1:
                    if expected_previous not in (None, "0" * 64):
                        raise EvidenceError("First previous_event_hash must be null or 64 zeroes")
                elif expected_previous != previous:
                    raise EvidenceError(f"Broken hash chain at line {line_number}")
                unsigned = {key: value for key, value in event.items() if key != "event_hash"}
                actual_hash = hashlib.sha256(canonical_json(unsigned)).hexdigest()
                if event["event_hash"] != actual_hash:
                    raise EvidenceError(f"Event hash mismatch at line {line_number}")
                previous = actual_hash
                for name, descriptor in event["artifacts"].items():
                    self.artifact_paths[(event["event_id"], name)] = self._artifact(descriptor)
                self.events.append(event)
        if not self.events:
            raise EvidenceError("An empty event stream cannot be analyzed")
        seal_path = self.root / "seal.json"
        if not seal_path.is_file():
            raise EvidenceError("Missing seal.json: completeness is not established")
        self.seal = _json(seal_path.read_text(encoding="utf-8"), "seal.json")
        if not isinstance(self.seal, dict):
            raise EvidenceError("seal.json must contain an object")
        if (type(self.seal.get("event_count")) is not int
                or self.seal["event_count"] != len(self.events)
                or self.seal.get("last_event_hash") != previous):
            raise EvidenceError("Seal does not match event count or terminal hash")
        if self.seal.get("status") not in {"completed", "failed", "blocked"}:
            raise EvidenceError("Unsupported seal status; expected completed, failed, or blocked")
        if "run_id" in self.seal and self.seal["run_id"] != self.events[0]["run_id"]:
            raise EvidenceError("Seal run_id does not match event stream")
        if "events_sha256" in self.seal and self.seal["events_sha256"] != file_sha256(self.path):
            raise EvidenceError("Seal events_sha256 does not match JSONL file")
        if "schema_version" in self.seal and self.seal["schema_version"] != SCHEMA_VERSION:
            raise EvidenceError("Unsupported seal schema_version")
        self.metadata = self.events[0]["metadata"]
        self.run_id = self.events[0]["run_id"]

    @staticmethod
    def _validate_event(event: Any, sequence: int) -> None:
        if not isinstance(event, dict):
            raise EvidenceError(f"Event {sequence} must be an object")
        required = {"schema_version", "event_id", "run_id", "sequence", "timestamp_utc",
                    "metadata", "stage", "context", "source", "raw", "readable", "artifacts",
                    "previous_event_hash", "event_hash"}
        missing = required - event.keys()
        if missing:
            raise EvidenceError(f"Event {sequence} missing fields: {sorted(missing)}")
        if event["schema_version"] != SCHEMA_VERSION:
            raise EvidenceError(f"Unsupported schema_version: {event['schema_version']!r}")
        if type(event["sequence"]) is not int or event["sequence"] != sequence:
            raise EvidenceError(f"Invalid sequence at event {sequence}")
        for field in ("event_id", "run_id", "stage", "timestamp_utc", "event_hash"):
            if not isinstance(event[field], str) or not event[field]:
                raise EvidenceError(f"Invalid {field} at event {sequence}")
        try:
            stamp = datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00"))
            if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
                raise ValueError("UTC offset required")
        except ValueError as error:
            raise EvidenceError(f"Invalid UTC timestamp at event {sequence}") from error
        for field in ("metadata", "context", "raw", "readable", "artifacts"):
            if not isinstance(event[field], dict):
                raise EvidenceError(f"{field} must be an object at event {sequence}")
        metadata = event["metadata"]
        if not isinstance(metadata.get("attack_id"), str) or not metadata["attack_id"]:
            raise EvidenceError("metadata.attack_id is required")
        if (not isinstance(metadata.get("engine"), dict)
                or not isinstance(metadata["engine"].get("id"), str) or not metadata["engine"]["id"]):
            raise EvidenceError("metadata.engine.id is required")
        if "run_id" in metadata and metadata["run_id"] != event["run_id"]:
            raise EvidenceError("metadata.run_id does not match event.run_id")
        if not isinstance(metadata.get("execution_scope"), str):
            raise EvidenceError("metadata.execution_scope must be a string")
        source = event["source"]
        if source is not None:
            if not isinstance(source, dict):
                raise EvidenceError("source must be an object or null")
            for field in ("path", "function", "logging_point_id", "sha256"):
                if not isinstance(source.get(field), str) or not source[field]:
                    raise EvidenceError(f"source.{field} must be a nonempty string")
            if len(source["sha256"]) != 64 or any(character not in "0123456789abcdef" for character in source["sha256"]):
                raise EvidenceError("source.sha256 must be a lowercase SHA-256 hex digest")
            if type(source.get("line")) is not int or source["line"] < 1:
                raise EvidenceError("source.line must be a positive integer")

    def _artifact(self, descriptor: Any) -> Path:
        if not isinstance(descriptor, dict):
            raise EvidenceError("Artifact descriptor must be an object")
        for field in ("path", "sha256", "dtype", "shape", "bytes"):
            if field not in descriptor:
                raise EvidenceError(f"Artifact descriptor missing {field}")
        raw_path = descriptor["path"]
        if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute():
            raise EvidenceError("Artifact path must be relative to its run directory")
        if ".." in Path(raw_path).parts:
            raise EvidenceError("Artifact traversal is forbidden")
        try:
            path = (self.root / raw_path).resolve(strict=True)
            path.relative_to(self.root)
        except (OSError, ValueError) as error:
            raise EvidenceError(f"Missing artifact or path outside run directory: {raw_path}") from error
        if not path.is_file():
            raise EvidenceError(f"Artifact is not a regular file: {raw_path}")
        if type(descriptor["bytes"]) is not int or path.stat().st_size != descriptor["bytes"]:
            raise EvidenceError(f"Artifact size mismatch: {raw_path}")
        if file_sha256(path) != descriptor["sha256"]:
            raise EvidenceError(f"Artifact SHA-256 mismatch: {raw_path}")
        return path

    def tensor(self, event: dict, name: str):
        """Return (array, error); invalid numeric data is not contrary evidence."""
        try:
            import numpy as np
        except ImportError:
            return None, "NumPy is unavailable; tensor evidence cannot be evaluated"
        descriptor = event["artifacts"].get(name)
        if descriptor is None:
            return None, f"Missing artifact {name!r}"
        path = self.artifact_paths[(event["event_id"], name)]
        try:
            array = np.load(path, allow_pickle=False, mmap_mode="r")
            if not isinstance(array, np.ndarray):
                if hasattr(array, "close"):
                    array.close()
                return None, "Expected one numeric .npy array, not a container"
        except (ValueError, OSError, EOFError) as error:
            return None, f"Artifact is not a safe .npy array: {error}"
        if list(array.shape) != descriptor["shape"] or str(array.dtype) != descriptor["dtype"]:
            raise EvidenceError(f"Tensor descriptor mismatch: {descriptor['path']}")
        if array.dtype.kind not in "biuf" or array.size == 0:
            return None, "Tensor must be a nonempty real numeric array"
        if not np.isfinite(array).all():
            return None, "Tensor contains non-finite values"
        return array, None


class RuleInterpreter:
    """No engine or attack dispatch: the same operators handle every package."""

    def __init__(self, package: EvidencePackage):
        self.package = package

    @staticmethod
    def validate(rule: Any) -> None:
        if not isinstance(rule, dict) or rule.get("op") not in OPS:
            raise RuleError(f"Unsupported or absent rule op: {rule!r}")
        if rule.get("reduce", "all") not in {"all", "any"}:
            raise RuleError("reduce must be all or any")
        selectors = [rule.get("select", {})]
        for side in ("left", "right"):
            specification = rule.get(side, {})
            if not isinstance(specification, dict):
                raise RuleError(f"{side} must be an object")
            selectors.append(specification.get("select", {}))
        for selector in selectors:
            if not isinstance(selector, dict):
                raise RuleError("select must be an object")
            for field in selector:
                if field.split(".")[0] not in {"stage", "context", "raw", "metadata", "source"}:
                    raise RuleError(f"Selector cannot use {field!r}; readable is display-only")
        if rule["op"] in {"all", "any"}:
            children = rule.get("rules")
            if not isinstance(children, list) or not children:
                raise RuleError("all/any require a nonempty rules list")
            for child in children:
                RuleInterpreter.validate(child)
        if rule["op"] == "calibrated_tensor_distance":
            if rule.get("mode", "exceeds") not in {"available", "exceeds"}:
                raise RuleError("calibration mode must be available or exceeds")
            if rule.get("cmp", "gt") not in {"gt", "ge", "lt", "le"}:
                raise RuleError("calibration cmp must be gt/ge/lt/le")
            if type(rule.get("min_pairs", 10)) is not int or rule.get("min_pairs", 10) < 2:
                raise RuleError("calibration min_pairs must be an integer >= 2")
            percentile = rule.get("percentile", 95)
            if isinstance(percentile, bool) or not isinstance(percentile, (int, float)) or not 0 <= percentile <= 100:
                raise RuleError("calibration percentile must be a number between 0 and 100")
            if rule.get("percentile_method", "linear") not in {"linear", "higher", "lower", "nearest", "midpoint"}:
                raise RuleError("Unsupported percentile_method")
            for cohort in ("calibration", "test"):
                if not isinstance(rule.get(cohort), dict):
                    raise RuleError(f"calibration rule requires {cohort} pair specification")
                child = {**rule[cohort], "op": "pairwise_tensor_distance", "cmp": "ge", "value": 0}
                RuleInterpreter.validate(child)
            if rule["calibration"].get("metric", "l2") != rule["test"].get("metric", "l2"):
                raise RuleError("Calibration and test must use the same distance metric")
        if rule["op"] in {"compare", "count", "pairwise_tensor_distance", "pairwise_tensor_cosine", "tensor_stat"}:
            if rule.get("cmp") not in COMPARISONS or "value" not in rule:
                raise RuleError("Comparison rules require a supported cmp and value")
        if rule["op"] == "compare":
            field = rule.get("field", "")
            if not isinstance(field, str) or field.split(".")[0] not in {"raw", "context", "metadata", "source", "stage"}:
                raise RuleError("compare field must reference raw evidence, never readable")
        if "join_by" in rule:
            if (not isinstance(rule["join_by"], list) or not rule["join_by"]
                    or any(not isinstance(field, str) or not field.startswith("context.")
                           for field in rule["join_by"])):
                raise RuleError("join_by must be a nonempty list of context.* fields")
        if rule["op"] == "tensor_stat":
            if not isinstance(rule.get("artifact"), str) or not rule["artifact"]:
                raise RuleError("tensor_stat requires an artifact name")
            if rule.get("stat") not in {"max_abs", "l2", "mean", "min", "max", "count_nonzero", "size"}:
                raise RuleError("Unsupported tensor_stat statistic")
            RuleInterpreter._validate_aggregation(rule)
            if rule.get("aggregate") == "concat" and not rule.get("join_by"):
                raise RuleError("tensor_stat concat requires explicit context join_by")
        if rule["op"].startswith("pairwise_tensor") or rule["op"] == "tensor_equality":
            if not rule.get("join_by"):
                raise RuleError("Tensor comparisons require explicit join_by to prevent unrelated pairs")
            for side in ("left", "right"):
                if not isinstance(rule.get(side), dict) or not isinstance(rule[side].get("artifact"), str):
                    raise RuleError(f"{side} must specify select and artifact")
                specification = rule[side]
                RuleInterpreter._validate_aggregation(specification)
            if rule["op"] == "pairwise_tensor_distance" and rule.get("metric", "l2") not in {"l2", "linf", "cosine"}:
                raise RuleError("distance metric must be l2, linf, or cosine")

    @staticmethod
    def _validate_aggregation(specification: dict) -> None:
        if specification.get("aggregate", "single") not in {"single", "concat"}:
            raise RuleError("Tensor aggregate must be single or concat")
        if specification.get("aggregate") == "concat":
            if type(specification.get("axis", 0)) is not int or specification.get("axis", 0) < 0:
                raise RuleError("concat axis must be a nonnegative integer")
            if specification.get("order_by", "sequence") != "sequence":
                raise RuleError("concat order_by must be sequence (the recorded event order)")

    @staticmethod
    def _selected(events: list[dict], selector: dict) -> list[dict]:
        return [event for event in events if _subset(event, selector)]

    @staticmethod
    def _group(events: list[dict], keys: list[str]) -> dict:
        grouped = defaultdict(list)
        for event in events:
            values = [_path_value(event, key) for key in keys]
            if any(value is MISSING or value is None or value == "" for value in values):
                continue
            grouped[canonical_json(values).decode("utf-8")].append(event)
        return grouped

    def evaluate(self, rule: dict, events: list[dict] | None = None) -> dict:
        self.validate(rule)
        events = self.package.events if events is None else events
        scope = rule.get("scope")
        if scope is not None:
            allowed = scope if isinstance(scope, list) else [scope]
            if scope == "runtime":
                allowed = ["runtime", "native_runtime", "engine_runtime", "end_to_end"]
            events = [event for event in events if event["metadata"]["execution_scope"] in allowed]
            if not events:
                return _result(None, f"No evidence in required execution scope: {scope}")
        op = rule["op"]
        if op in {"all", "any"}:
            if "select" in rule:
                events = self._selected(events, rule["select"])
            if not events:
                return _result(None, "No matching evidence for the composite rule")
            if "join_by" in rule:
                groups = self._group(events, rule["join_by"])
                children = []
                for key, grouped_events in groups.items():
                    child_rule = {key: value for key, value in rule.items() if key != "join_by"}
                    child = self.evaluate(child_rule, grouped_events)
                    child["group"] = key
                    children.append(child)
                grouped_ids = {event["event_id"] for group in groups.values() for event in group}
                missing = [event for event in events if event["event_id"] not in grouped_ids]
                if missing:
                    children.append(_result(None, "Selected evidence is missing required context join fields", missing))
                value = _reduce([child["value"] for child in children], rule.get("reduce", "all"))
                return self._combined(value, f"{op} evaluated independently in {len(groups)} joined contexts", children)
            children = [self.evaluate(child, events) for child in rule["rules"]]
            value = _reduce([child["value"] for child in children], op)
            return self._combined(value, f"{op} of {len(children)} subconditions", children)
        if op == "calibrated_tensor_distance":
            return self._calibration(rule, events)
        if op == "tensor_stat":
            return self._tensor_stat(rule, events)
        if op.startswith("pairwise_tensor") or op == "tensor_equality":
            return self._tensor_rule(rule, events)
        selected = self._selected(events, rule.get("select", {}))
        if op == "exists":
            if not selected:
                return _result(None, "No matching observation; absence alone is not contrary evidence")
            return _result(True, f"Observed {len(selected)} matching event(s)", selected)
        if op == "count":
            # Even a sealed log does not prove a logger covered unobserved behavior.
            if not selected:
                return _result(None, "No matching observations; zero does not establish coverage")
            count = len(selected)
            value = _compare(count, rule["cmp"], rule["value"])
            return _result(value, f"Observed event count {count} {rule['cmp']} {rule['value']}",
                           selected, [{"count": count, "cmp": rule["cmp"], "expected": rule["value"]}])
        if not selected:
            return _result(None, "No matching raw observation for comparison")
        observations = []
        values = []
        for event in selected:
            actual = _path_value(event, rule["field"])
            value = _compare(actual, rule["cmp"], rule["value"])
            values.append(value)
            observations.append({"event_id": event["event_id"], "field": rule["field"],
                                 "actual": None if actual is MISSING else actual,
                                 "field_present": actual is not MISSING,
                                 "cmp": rule["cmp"], "expected": rule["value"], "value": value})
        value = _reduce(values, rule.get("reduce", "all"))
        return _result(value, f"Raw comparison {rule['field']} {rule['cmp']} {rule['value']!r}",
                       selected, observations)

    @staticmethod
    def _combined(value: bool | None, reason: str, children: list[dict]) -> dict:
        result = _result(value, reason, children=children)
        result["evidence_ids"] = list(dict.fromkeys(
            evidence_id for child in children for evidence_id in child["evidence_ids"]))
        return result

    def _tensor_rule(self, rule: dict, events: list[dict]) -> dict:
        left_selected = self._selected(events, rule["left"].get("select", {}))
        right_selected = self._selected(events, rule["right"].get("select", {}))
        left = self._group(left_selected, rule["join_by"])
        right = self._group(right_selected, rule["join_by"])
        grouped_ids = {event["event_id"] for group in [*left.values(), *right.values()] for event in group}
        missing = [event for event in left_selected + right_selected if event["event_id"] not in grouped_ids]
        keys = sorted(set(left) | set(right))
        if not keys:
            return _result(None, "No tensor pairs with all required context join keys")
        children = []
        for key in keys:
            left_events, right_events = left.get(key, []), right.get(key, [])
            left_events = sorted(left_events, key=lambda event: event["sequence"])
            right_events = sorted(right_events, key=lambda event: event["sequence"])
            pair_events = left_events + right_events
            if not left_events or not right_events:
                child = _result(None, "Missing pair; both sides must contain evidence", pair_events)
            elif (set(event["event_id"] for event in left_events) & set(event["event_id"] for event in right_events)
                  and rule["left"]["artifact"] == rule["right"]["artifact"]):
                child = _result(None, "A paired comparison cannot compare an artifact with itself", pair_events)
            else:
                left_tensor, left_error = self._aggregate(left_events, rule["left"])
                right_tensor, right_error = self._aggregate(right_events, rule["right"])
                if left_error or right_error:
                    child = _result(None, "; ".join(error for error in (left_error, right_error) if error), pair_events)
                elif left_tensor.shape != right_tensor.shape:
                    child = _result(None, "Incompatible tensor shapes; no distance was computed", pair_events,
                                    [{"left_shape": list(left_tensor.shape), "right_shape": list(right_tensor.shape)}])
                else:
                    child = self._numeric_pair(rule, left_tensor, right_tensor, pair_events)
                    for observation in child["observations"]:
                        observation.update({
                            "left_event_ids": [event["event_id"] for event in left_events],
                            "right_event_ids": [event["event_id"] for event in right_events],
                            "left_artifact": rule["left"]["artifact"], "right_artifact": rule["right"]["artifact"],
                            "left_aggregation": rule["left"].get("aggregate", "single"),
                            "right_aggregation": rule["right"].get("aggregate", "single"),
                            "aggregation_order": "sequence",
                        })
            child["group"] = key
            children.append(child)
        if missing:
            children.append(_result(None, "Selected tensor evidence is missing required context join fields", missing))
        value = _reduce([child["value"] for child in children], rule.get("reduce", "all"))
        return self._combined(value, f"Paired tensor comparison across {len(keys)} context(s)", children)

    def _aggregate(self, events: list[dict], specification: dict):
        aggregate = specification.get("aggregate", "single")
        if aggregate == "single" and len(events) != 1:
            return None, "Ambiguous pair; exactly one event per side required unless concat is explicit"
        if aggregate == "concat":
            request_ids = [event["context"].get("request_id") for event in events]
            if any(not isinstance(value, str) or not value for value in request_ids) or len(set(request_ids)) != 1:
                return None, "concat requires a single nonempty request_id; unrelated requests cannot be joined"
        arrays = []
        for event in events:
            array, error = self.package.tensor(event, specification["artifact"])
            if error:
                return None, error
            arrays.append(array)
        if aggregate == "single":
            return arrays[0], None
        import numpy as np
        axis = specification.get("axis", 0)
        if any(array.ndim <= axis for array in arrays):
            return None, "concat axis exceeds tensor dimensionality"
        if len({str(array.dtype) for array in arrays}) != 1:
            return None, "concat requires identical numeric dtypes"
        other_shapes = {array.shape[:axis] + array.shape[axis + 1:] for array in arrays}
        if len(other_shapes) != 1 or len({array.ndim for array in arrays}) != 1:
            return None, "concat requires compatible shapes outside the concatenation axis"
        return np.concatenate(arrays, axis=axis), None

    def _tensor_stat(self, rule: dict, events: list[dict]) -> dict:
        selected = self._selected(events, rule.get("select", {}))
        if not selected:
            return _result(None, "No matching tensor evidence for statistic")
        if "join_by" in rule:
            groups = self._group(selected, rule["join_by"])
        else:
            groups = {event["event_id"]: [event] for event in selected}
        children = []
        grouped_ids = {event["event_id"] for group in groups.values() for event in group}
        for key, group in groups.items():
            group = sorted(group, key=lambda event: event["sequence"])
            array, error = self._aggregate(group, rule)
            if error:
                child = _result(None, error, group)
            else:
                import numpy as np
                stat = rule["stat"]
                numeric = array.astype(np.float64)
                with np.errstate(over="ignore", invalid="ignore"):
                    actual = {"max_abs": lambda: float(np.max(np.abs(numeric))),
                              "l2": lambda: float(np.linalg.norm(numeric.ravel())),
                              "mean": lambda: float(np.mean(numeric)),
                              "min": lambda: float(np.min(numeric)),
                              "max": lambda: float(np.max(numeric)),
                              "count_nonzero": lambda: int(np.count_nonzero(array)),
                              "size": lambda: int(array.size)}[stat]()
                if not math.isfinite(actual):
                    child = _result(None, "Computed tensor statistic is non-finite", group)
                else:
                    value = _compare(actual, rule["cmp"], rule["value"])
                    child = _result(value, f"Tensor {stat} {actual:.9g} {rule['cmp']} {rule['value']}", group,
                                    [{"stat": stat, "actual": actual, "cmp": rule["cmp"], "expected": rule["value"],
                                      "shape": list(array.shape), "artifact": rule["artifact"],
                                      "event_ids": [event["event_id"] for event in group],
                                      "aggregation": rule.get("aggregate", "single"), "aggregation_order": "sequence"}])
            child["group"] = key
            children.append(child)
        missing = [event for event in selected if event["event_id"] not in grouped_ids]
        if missing:
            children.append(_result(None, "Selected tensor evidence is missing required context join fields", missing))
        value = _reduce([child["value"] for child in children], rule.get("reduce", "all"))
        return self._combined(value, f"{rule['stat']} computed from verified raw tensors", children)

    def _calibration(self, rule: dict, events: list[dict]) -> dict:
        cohorts = {}
        for name in ("calibration", "test"):
            child_rule = {**rule[name], "op": "pairwise_tensor_distance", "cmp": "ge", "value": 0}
            cohorts[name] = self._tensor_rule(child_rule, events)
        calibration = cohorts["calibration"]
        test = cohorts["test"]
        children = [calibration, test]
        if calibration["value"] is None or test["value"] is None:
            return self._combined(None, "Calibration or test cohort has missing, ambiguous, or invalid tensor pairs", children)
        calibration_pairs = calibration["children"]
        test_pairs = test["children"]
        if (any(child["value"] is None for child in calibration_pairs + test_pairs)
                or len(calibration_pairs) < rule.get("min_pairs", 10)):
            return self._combined(None, f"Need at least {rule.get('min_pairs', 10)} complete calibration pairs; "
                                  f"observed {len(calibration_pairs)}", children)
        calibration_ids = {frozenset(child["evidence_ids"]) for child in calibration_pairs}
        test_ids = {frozenset(child["evidence_ids"]) for child in test_pairs}
        if calibration_ids & test_ids:
            return self._combined(None, "Calibration/test leakage: the same event pair appears in both cohorts", children)
        import numpy as np
        values = [child["observations"][0]["actual"] for child in calibration_pairs]
        percentile = rule.get("percentile", 95)
        percentile_method = rule.get("percentile_method", "linear")
        threshold = float(np.percentile(values, percentile, method=percentile_method))
        flags = []
        for child in test_pairs:
            observation = child["observations"][0]
            actual = observation["actual"]
            flag = _compare(actual, rule.get("cmp", "gt"), threshold)
            observation.update({"threshold": threshold, "cmp": rule.get("cmp", "gt"),
                                "expected": threshold, "exceeds_threshold": flag})
            child["threshold_comparison"] = flag
            if rule.get("mode", "exceeds") == "exceeds":
                child["value"] = flag
                child["status"] = {True: "satisfied", False: "not_satisfied", None: "insufficient_evidence"}[flag]
                child["reason"] = f"Test distance {actual:.9g} {rule.get('cmp', 'gt')} calibration threshold {threshold:.9g}"
            flags.append(flag)
        mode = rule.get("mode", "exceeds")
        value = True if mode == "available" else _reduce(flags, rule.get("reduce", "all"))
        result = self._combined(value, "Calibrated comparison is available (not detector effectiveness)"
                                if mode == "available" else "Test distances compared with the calibration-only threshold", children)
        result["observations"] = [{"mode": mode, "metric": rule["calibration"].get("metric", "l2"),
                                   "label": rule.get("label"),
                                   "calibration_n": len(values), "calibration_distances": values,
                                   "percentile": percentile, "percentile_method": percentile_method, "threshold": threshold,
                                   "test_n": len(flags), "test_threshold_flags": flags,
                                   "threshold_fit_from_test": False}]
        return result

    @staticmethod
    def _numeric_pair(rule: dict, left, right, events: list[dict]) -> dict:
        import numpy as np
        left_dtype, right_dtype = str(left.dtype), str(right.dtype)
        if rule["op"] == "tensor_equality":
            value = bool(np.array_equal(left, right))
            return _result(value, "Exact numeric tensor equality", events, [{"equal": value, "shape": list(left.shape)}])
        left = left.astype(np.float64)
        right = right.astype(np.float64)
        metric = "cosine" if rule["op"] == "pairwise_tensor_cosine" else rule.get("metric", "l2")
        with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
            if metric == "cosine":
                left_norm = float(np.linalg.norm(left.ravel()))
                right_norm = float(np.linalg.norm(right.ravel()))
                if left_norm == 0 or right_norm == 0 or not math.isfinite(left_norm * right_norm):
                    return _result(None, "Cosine is undefined for zero-norm or numerically overflowing tensors", events)
                cosine = float(np.clip(np.dot(left.ravel(), right.ravel()) / (left_norm * right_norm), -1, 1))
                actual = cosine if rule["op"] == "pairwise_tensor_cosine" else 1 - cosine
            elif metric == "linf":
                actual = float(np.max(np.abs(left - right)))
            else:
                actual = float(np.linalg.norm((left - right).ravel()))
        if not math.isfinite(actual):
            return _result(None, "Computed tensor metric is non-finite", events)
        value = _compare(actual, rule["cmp"], rule["value"])
        return _result(value, f"Paired {metric} value {actual:.9g} {rule['cmp']} {rule['value']}", events,
                       [{"metric": metric, "actual": actual, "cmp": rule["cmp"],
                         "quantity": "cosine_similarity" if rule["op"] == "pairwise_tensor_cosine" else metric + "_distance",
                         "left_dtype": left_dtype, "right_dtype": right_dtype,
                         "expected": rule["value"], "shape": list(left.shape)}])


def load_rules(path: str | Path) -> dict:
    rules_path = Path(path)
    rules = _json(rules_path.read_text(encoding="utf-8"), str(rules_path))
    if not isinstance(rules, dict) or not isinstance(rules.get("attack_id"), str):
        raise RuleError("Rules require attack_id")
    if not isinstance(rules.get("attack_name"), str) or not rules["attack_name"]:
        raise RuleError("Rules require attack_name")
    if not isinstance(rules.get("library"), dict):
        raise RuleError("Rules must preserve Attack-Library provenance in library")
    conditions = rules.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise RuleError("Rules require a nonempty conditions list")
    ids = set()
    for condition in conditions:
        if (not isinstance(condition, dict) or not isinstance(condition.get("id"), str)
                or not condition["id"] or condition["id"] in ids):
            raise RuleError("Condition ids must be unique nonempty strings")
        ids.add(condition["id"])
        if condition.get("kind") not in {"AC", "DC"} or not isinstance(condition.get("text"), str):
            raise RuleError("Each condition needs kind AC/DC and text")
        if "source_cell" not in condition:
            raise RuleError("Each condition requires its originating workbook source_cell")
        RuleInterpreter.validate(condition.get("rule"))
    return rules


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _verdict(value: bool | None) -> str:
    return {True: "T", False: "F", None: "판정불가"}[value]


def _leaf_results(result: dict):
    if result.get("children"):
        for child in result["children"]:
            yield from _leaf_results(child)
    else:
        yield result


def _all_results(result: dict):
    yield result
    for child in result.get("children", []):
        yield from _all_results(child)


def _essential_reason(condition: dict) -> str:
    """A compact numeric explanation; all unabridged observations remain below."""
    observations = [observation for node in _all_results(condition) for observation in node.get("observations", [])]
    calibrated = [observation for observation in observations if "calibration_n" in observation]
    if calibrated:
        thresholds = [observation["threshold"] for observation in calibrated]
        counts = sorted({observation["calibration_n"] for observation in calibrated})
        cohorts = defaultdict(list)
        for observation in calibrated:
            label = observation.get("label") or "시험"
            cohorts[label.split("/", 1)[0]].extend(observation["test_threshold_flags"])
        flags_text = ", ".join(f"{label} {sum(flag is True for flag in flags)}/{len(flags)}"
                               for label, flags in cohorts.items())
        return (f"보정 비교 {len(calibrated)}개, 정상 n={','.join(map(str, counts))}; "
                f"τ={min(thresholds):.5g}–{max(thresholds):.5g}; 초과 {flags_text} "
                "(비교가능성과 탐지성능 별개)")
    equal = [observation["equal"] for observation in observations if "equal" in observation]
    measurements = defaultdict(dict)
    for observation in observations:
        if "metric" not in observation or not isinstance(observation.get("actual"), (int, float)):
            continue
        quantity = observation.get("quantity", observation["metric"] + "_distance")
        artifact = observation.get("left_artifact", "tensor")
        dtype = observation.get("left_dtype", "")
        pair_identity = (tuple(observation.get("left_event_ids", [])), tuple(observation.get("right_event_ids", [])))
        measurements[(quantity, artifact, dtype)][pair_identity] = observation["actual"]
    pieces = []
    if equal:
        pieces.append(f"텐서 동일 {sum(value is True for value in equal)}/{len(equal)}쌍")
    labels = {"cosine_similarity": "cosine 유사도", "cosine_distance": "cosine 거리",
              "l2_distance": "L2 거리", "linf_distance": "L∞ 거리"}
    for (quantity, artifact, dtype), measured in measurements.items():
        values = list(measured.values())
        value_text = f"{min(values):.5g}" if min(values) == max(values) else f"{min(values):.5g}–{max(values):.5g}"
        dtype_text = f"/{dtype}" if dtype else ""
        pieces.append(f"{artifact}{dtype_text} {labels.get(quantity, quantity)}={value_text} ({len(values)}쌍)")
    statistics = [observation for observation in observations if "stat" in observation]
    for stat in sorted({observation["stat"] for observation in statistics}):
        values = [observation["actual"] for observation in statistics if observation["stat"] == stat]
        pieces.append(f"{stat}={min(values):.5g}–{max(values):.5g}")
    comparisons = [observation for observation in observations if "field" in observation]
    if comparisons:
        pieces.append(f"raw 조건 충족 {sum(observation['value'] is True for observation in comparisons)}/{len(comparisons)}건")
    if pieces:
        if condition["value"] is None:
            pieces.append("일부 필수 증거 부족")
        return "; ".join(pieces)
    return condition["reason"]


def _calibration_table(conditions: list[dict]) -> list[str]:
    rows = []
    for condition in conditions:
        for node in _all_results(condition):
            for observation in node.get("observations", []):
                if "calibration_n" not in observation:
                    continue
                test_observations = [item for leaf in _leaf_results(node["children"][1])
                                     for item in leaf.get("observations", []) if "metric" in item]
                values = ", ".join(f"{item['actual']:.7g}" for item in test_observations[:5])
                if len(test_observations) > 5:
                    values += f" … (총 {len(test_observations)}개; 전체 수치는 상세 근거)"
                flags = observation["test_threshold_flags"]
                rows.append(f"| {_md(observation.get('label') or condition['id'])} | "
                            f"{_md(observation['metric'])} 거리 | {observation['calibration_n']} | "
                            f"{observation['percentile']:g}p / {_md(observation['percentile_method'])} | "
                            f"{observation['threshold']:.7g} | {values} | "
                            f"{sum(flag is True for flag in flags)}/{len(flags)} |")
    if not rows:
        return []
    return ["", "## 정상 기준선과 시험 측정값", "",
            "아래의 임계값 초과는 조건의 T/F와 별도 측정값입니다. 비교가 가능하다는 사실만으로 탐지 성능을 주장하지 않습니다. "
            "표는 반올림한 표시값이며 판정에는 전체 정밀도의 값이 사용되었습니다.", "",
            "| 비교 구분 | 지표 | 정상 n | 보정 방법 | 정상 임계값 τ | 시험 측정값 | τ 초과 |",
            "|---|---|---:|---|---:|---:|---:|", *rows]


def _model_label(model: Any) -> str:
    if isinstance(model, dict):
        label = model.get("name") or model.get("id") or model.get("model_id") or "상세 모델 정보는 실행 메타데이터 참조"
        precision = model.get("quantization") or model.get("dtype")
        return str(label) + (f" / {precision}" if precision else "")
    return str(model) if model is not None else "미기록"


def render_report(analysis: dict) -> str:
    metadata = analysis["metadata"]
    engine = metadata["engine"]
    lines = [f"# LieMapp 분석 보고서: {analysis['attack_name']}", "",
             f"- 공격 종류: **{analysis['attack_name']}** (`{analysis['attack_id']}`)",
             f"- 추론 엔진: `{engine['id']}` / revision: `{engine.get('revision')}`",
             f"- 실행 범위: `{metadata.get('execution_scope')}`",
             f"- 실행 상태: `{analysis['run_status']}` / 사유: {analysis.get('run_reason') or '—'}",
             f"- 모델: `{_model_label(metadata.get('model'))}` · "
             f"[전체 실행 메타데이터](<{Path(analysis['provenance']['log_path']).with_name('run.json')}>)",
             f"- 실행 ID: `{analysis['run_id']}` / 이벤트: {analysis['integrity']['event_count']}개",
             f"- 로그: [원본 JSONL](<{analysis['provenance']['log_path']}>) · "
             f"[가독성 JSON](<{Path(analysis['provenance']['log_path']).with_name('events.pretty.json')}>)",
             "- 증거 검증: 이벤트 해시 체인·종료 seal·참조 아티팩트 SHA-256 확인",
             "", "## 조건별 판정", "",
             "T = 조건 관측, F = 명시적 반대 증거 관측, 판정불가 = 필요한 증거 부족. "
             "F 또는 미관측은 엔진의 안전성을 의미하지 않습니다.", "",
             "| 조건 | 구분 | 판정 | 조건 내용 | 핵심 근거 |",
             "|---|---|---|---|---|"]
    for condition in analysis["conditions"]:
        lines.append(f"| {_md(condition['id'])} | {condition['kind']} | {_verdict(condition['value'])} "
                     f"| {_md(condition['text'])} | {_md(_essential_reason(condition))} |")
    lines += _calibration_table(analysis["conditions"])
    lines += ["", "## 결론", "", analysis["conclusion"], "",
              "해시 검증은 이 패키지 내부의 일관성 검증이며, 수집 주체의 진정성이나 "
              "외부 보관 이력(Chain of Custody)을 독립적으로 증명하지 않습니다.",
              "", "## 판정 근거와 원본 값", ""]
    evidence = analysis["evidence"]
    for condition in analysis["conditions"]:
        lines += [f"### {condition['id']} — {_verdict(condition['value'])}", "",
                  condition["text"], "", f"- 원본 조건 셀: `{condition['source_cell']}`",
                  f"- 판정 설명: {condition['reason']}", ""]
        if condition.get("operationalization"):
            lines += [f"**이번 실험의 관측 정의:** {condition['operationalization']}", ""]
        lines += ["<details>", f"<summary>세부 측정과 판정 과정 ({len(condition['evidence_ids'])}개 이벤트)</summary>", ""]
        for node in _all_results(condition):
            if node.get("children"):
                for observation in node.get("observations", []):
                    lines.append("- 요약 측정값: `" + _md(json.dumps(observation, ensure_ascii=False, allow_nan=False)) + "`")
        for leaf in _leaf_results(condition):
            lines.append(f"- {_verdict(leaf['value'])}: {leaf['reason']}")
            for observation in leaf.get("observations", []):
                lines.append("  - 측정값: `" + _md(json.dumps(observation, ensure_ascii=False, allow_nan=False)) + "`")
        if condition["evidence_ids"]:
            lines += ["", "근거 이벤트: " + ", ".join(
                f"[{evidence[event_id]['sequence']}](#event-{event_id})" for event_id in condition["evidence_ids"])]
        lines += ["", "</details>", ""]
    lines += ["## 원본 증거 상세", "", "이벤트를 펼치면 소스 지점·요청 연결·원본 raw 값·텐서 파일을 볼 수 있습니다.", ""]
    for event_id, event in evidence.items():
        source = event["source"]
        lines += [f'<a id="event-{event_id}"></a>', "<details>",
                  f"<summary>#{event['sequence']} · {event['stage']} · {event_id}</summary>", ""]
        if source:
            lines += [f"- 코드 지점: `{source['path']}:{source['line']}` / `{source['function']}` / LP `{source['logging_point_id']}`",
                      f"- 수집 당시 소스 SHA-256: `{source['sha256']}`"]
        else:
            lines.append("- 소스 계측 지점 없음: 실행 제어·사전 점검 등 계측 외 이벤트입니다.")
        lines += [f"- 요청·입력 연결: `{json.dumps(event['context'], ensure_ascii=False)}`", "",
                  "```json", json.dumps(event["raw"], ensure_ascii=False, indent=2, allow_nan=False), "```", ""]
        for name, artifact in event["artifacts"].items():
            artifact_path = Path(analysis["provenance"]["log_path"]).parent / artifact["path"]
            lines.append(f"- 아티팩트 `{name}`: [원본 텐서](<{artifact_path}>), `{artifact['path']}`, "
                         f"shape=`{artifact['shape']}`, dtype=`{artifact['dtype']}`, SHA-256=`{artifact['sha256']}`")
        lines += ["", "</details>", ""]
    lines += ["## 규칙 출처와 재현 정보", "", "```json",
              json.dumps(analysis["provenance"], ensure_ascii=False, indent=2), "```", "",
              "판정은 raw와 검증된 아티팩트에서만 계산합니다. readable 값은 해석 편의를 위한 "
              "표시값이며 판정 입력이 아닙니다. 이 보고서는 제공된 실행 및 규칙에 한정되며, "
              "공격 성공률·범용 탐지 성능·모든 엔진 경로의 안전성을 입증하지 않습니다.", ""]
    return "\n".join(lines)


def analyze(log_path: str | Path, rules_path: str | Path, output_dir: str | Path) -> dict:
    """Validate, evaluate, and write analysis.json/report.md without overwriting.

    A fresh directory or an empty existing directory is accepted. Invalid evidence
    raises EvidenceError before any report file is created.
    """
    package = EvidencePackage(log_path)
    rules_path = Path(rules_path).resolve(strict=True)
    rules = load_rules(rules_path)
    if rules["attack_id"] != package.metadata["attack_id"]:
        raise RuleError("Rules attack_id does not match evidence metadata.attack_id")
    output = Path(output_dir).absolute()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"Refusing to overwrite nonempty report directory: {output}")
    interpreter = RuleInterpreter(package)
    conditions = []
    for condition in rules["conditions"]:
        if package.seal["status"] != "completed":
            result = _result(None, f"Run status is {package.seal['status']}: "
                             + str(package.seal.get("reason") or "execution did not complete"), package.events)
        else:
            result = interpreter.evaluate(condition["rule"])
        result.update({key: condition[key] for key in ("id", "kind", "text", "source_cell")})
        for key in ("operationalization", "source_condition_id", "observation_layer"):
            if key in condition:
                result[key] = condition[key]
        conditions.append(result)
    summary = {}
    for kind in ("AC", "DC"):
        selected = [condition for condition in conditions if condition["kind"] == kind]
        summary[kind] = {"true": sum(condition["value"] is True for condition in selected),
                         "false": sum(condition["value"] is False for condition in selected),
                         "unknown": sum(condition["value"] is None for condition in selected),
                         "total": len(selected)}
    has_unknown = any(condition["value"] is None for condition in conditions)
    conclusion = (
        f"이 실행에서 AC는 T {summary['AC']['true']}개 / F {summary['AC']['false']}개 / "
        f"판정불가 {summary['AC']['unknown']}개, DC는 T {summary['DC']['true']}개 / "
        f"F {summary['DC']['false']}개 / 판정불가 {summary['DC']['unknown']}개입니다. "
        + ("증거가 부족한 조건은 추가 계측·실험이 필요합니다. " if has_unknown else "")
        + "AC 충족은 해당 공격의 사전 조건 관측, DC 충족은 정의된 사후 관측 조건의 충족을 뜻합니다. "
          "이 결과만으로 실제 공격 성공, 침해 발생, 공격자 신원 또는 엔진의 안전성을 단정하지 않습니다."
    )
    evidence_ids = {event_id for condition in conditions for event_id in condition["evidence_ids"]}
    analysis = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attack_id": rules["attack_id"], "attack_name": rules["attack_name"],
        "run_id": package.run_id, "metadata": package.metadata,
        "run_status": package.seal["status"], "run_reason": package.seal.get("reason"),
        "status": "insufficient_evidence" if has_unknown else "evaluated",
        "summary": summary, "conditions": conditions, "conclusion": conclusion,
        "rule_snapshot": rules,
        "integrity": {"status": "verified", "event_count": len(package.events),
                      "last_event_hash": package.seal["last_event_hash"],
                      "artifact_references": len(package.artifact_paths)},
        "provenance": {"log_path": str(package.path), "log_sha256": file_sha256(package.path),
                       "seal_sha256": file_sha256(package.root / "seal.json"),
                       "rules_path": str(rules_path), "rules_sha256": file_sha256(rules_path),
                       "library": rules["library"], "analyzer_sha256": file_sha256(Path(__file__))},
        "evidence": {event["event_id"]: {key: event[key] for key in
                     ("event_id", "sequence", "stage", "timestamp_utc", "context", "source", "raw", "artifacts")}
                     for event in package.events if event["event_id"] in evidence_ids},
    }
    json_text = json.dumps(analysis, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    report_text = render_report(analysis)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "analysis.json").open("x", encoding="utf-8") as stream:
        stream.write(json_text)
    with (output / "report.md").open("x", encoding="utf-8") as stream:
        stream.write(report_text)
    return analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="Sealed events.jsonl")
    parser.add_argument("--rules", required=True, type=Path, help="Attack-Library-derived rule JSON")
    parser.add_argument("--output-dir", required=True, type=Path, help="New or empty report directory")
    args = parser.parse_args(argv)
    try:
        result = analyze(args.log, args.rules, args.output_dir)
    except (EvidenceError, RuleError, OSError) as error:
        print(f"Analysis rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "summary": result["summary"],
                      "report": str(args.output_dir / "report.md")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
