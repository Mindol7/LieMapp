#!/usr/bin/env python3
"""Publish readable condition evidence and one report without changing verdicts.

The existing Analyzer remains the only rule evaluator. Public T/F is a display
policy: null evidence is displayed as F, explicitly marked not_evaluated. This
module never converts an invalid evidence package into a security verdict.
All paths are supplied by the caller; raw archives are read-only inputs.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unicodedata
from urllib.parse import quote


SPEC = importlib.util.spec_from_file_location("liemapp_publication_analyzer", Path(__file__).resolve().parents[1] / "LieMappAnalyzer/analyzer.py")
analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analyzer)
SCHEMA_VERSION = "1.0.0"
RUNTIME_SCOPES = {"runtime", "native_runtime", "engine_runtime", "end_to_end"}
NOTICE = "조건별 JSON은 원시 로그를 대체하지 않는 검증 가능한 증거 묶음입니다. 전체 원본 값은 연결된 raw archive에 보존됩니다."
VERDICT_NOTICE = "T는 조건 충족을 확인했다는 뜻입니다. F는 관측상 불충족 또는 미평가를 구분해 표시합니다. 미평가 F는 공격 불가능·엔진 안전의 증명이 아닙니다."


class PublicationError(ValueError):
    """The requested public output would be ambiguous or unsafe."""


def _read(path):
    return analyzer._json(Path(path).read_text(encoding="utf-8"), str(path))


def _dump(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def _hash(path):
    return analyzer.file_sha256(Path(path))


def _label(value, field):
    if not isinstance(value, str) or not re.fullmatch(r"[^\W_][\w.-]{0,79}", value, re.UNICODE) or ".." in value:
        raise PublicationError(f"{field} must be one safe filename component (letters/numbers, dot, underscore, hyphen)")
    if value.endswith(".") or value.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise PublicationError(f"Unsafe or reserved filename component: {field}")
    return value


def _slug(value):
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,65}", normalized) and ".." not in normalized and not normalized.endswith("."):
        try:
            return _label(normalized, "identifier")
        except PublicationError:
            pass
    stem = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")[:45] or "identifier"
    return stem + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _relative(path, document):
    return os.path.relpath(Path(path).absolute(), Path(document).absolute().parent)


def _ref(path, document):
    path = Path(path).resolve(strict=True)
    return {"path": _relative(path, document), "sha256": _hash(path)}


def _text(value):
    escaped = html.escape(str(value), quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "#", "|", "!"):
        escaped = escaped.replace(character, "\\" + character)
    return escaped.replace("\r", "").replace("\n", "<br>")


def _link(label, path):
    return f"[{_text(label)}](<{quote(str(path), safe='/.:_-')}>)"


def _nodes(value):
    yield value
    for child in value.get("children", []):
        yield from _nodes(child)


def _scope_missing(rule, scope):
    required = rule.get("scope")
    if required is not None:
        allowed = RUNTIME_SCOPES if required == "runtime" else required if isinstance(required, list) else [required]
        if scope not in allowed:
            return True
    return any(_scope_missing(child, scope) for child in rule.get("rules", []))


def _verdict(condition, rule, analysis):
    value = condition["value"]
    if value is True:
        status, reason, explanation = "observed_satisfied", "condition_observed", "수집한 원시 증거에서 이 조건의 충족을 확인했습니다."
    elif value is False:
        status, reason, explanation = "observed_not_satisfied", "contrary_evidence", "수집한 원시 증거에서 이 조건을 충족하지 않는 관측 결과가 확인되었습니다."
    else:
        status = "not_evaluated"
        if _scope_missing(rule, analysis["metadata"]["execution_scope"]):
            reason, explanation = "scope_unavailable", "요구한 실행 범위의 증거가 확보되지 않아 조건 충족을 확인하지 못했습니다."
        elif analysis["run_status"] != "completed":
            reason, explanation = "run_incomplete", "실행이 완료되지 않아 조건을 평가하지 않았습니다."
        else:
            reason, explanation = "missing_required_evidence", "필요한 관측 값이 없거나 비교할 수 없어 조건을 평가하지 못했습니다."
        explanation += " 표시 F는 미평가를 뜻하며 공격 불가능이나 엔진 안전을 뜻하지 않습니다."
    return {"verdict": "T" if value is True else "F", "evidence_value": value,
            "evidence_status": status, "evaluation_reason": reason, "explanation": explanation}


def _checked_data(path, analysis, *, engine=False):
    if path is None:
        return {}, None
    path = Path(path).resolve(strict=True)
    value = _read(path)
    if not isinstance(value, dict) or value.get("attack_id") != analysis["attack_id"]:
        raise PublicationError(f"Display data attack_id does not match evidence: {path}")
    if engine and value.get("engine_id") != analysis["metadata"]["engine"]["id"]:
        raise PublicationError(f"Display data engine_id does not match evidence: {path}")
    return value, path


def _description(presentation, category, key, fallback, unit="별도 단위 없음"):
    configured = presentation.get(category, {}).get(key, {})
    if isinstance(configured, str):
        return {"label": configured, "unit": unit}
    if not isinstance(configured, dict):
        raise PublicationError(f"Invalid presentation entry: {category}.{key}")
    return {"label": configured.get("label", fallback), "unit": configured.get("unit", unit)}


def _validate_display(presentation, mapping, condition_ids):
    if "purpose" in presentation and not isinstance(presentation["purpose"], str):
        raise PublicationError("presentation.purpose must be text")
    for category in ("conditions", "field_labels", "artifact_labels"):
        if not isinstance(presentation.get(category, {}), dict):
            raise PublicationError(f"presentation.{category} must be an object")
    for identifier, value in presentation.get("conditions", {}).items():
        if identifier not in condition_ids or not isinstance(value, dict):
            raise PublicationError("Presentation conditions must name actual rule IDs")
        for key in ("question", "explanation"):
            if key in value and not isinstance(value[key], str):
                raise PublicationError(f"Condition {key} must be text")
        if "measurement_plan" in value and (not isinstance(value["measurement_plan"], list) or any(not isinstance(item, str) for item in value["measurement_plan"])):
            raise PublicationError("measurement_plan must be a list of text items")
    for category in ("field_labels", "artifact_labels"):
        for value in presentation.get(category, {}).values():
            if not isinstance(value, (str, dict)) or isinstance(value, dict) and any(key in value and not isinstance(value[key], str) for key in ("label", "unit")):
                raise PublicationError("Field/artifact display labels and units must be text")
    if not isinstance(mapping.get("logging_points", []), list):
        raise PublicationError("mapping.logging_points must be a list")
    for point in mapping.get("logging_points", []):
        if not isinstance(point, dict) or not isinstance(point.get("reason"), str):
            raise PublicationError("Each mapping point requires a logging reason")
        if point.get("source") is not None and not isinstance(point["source"], dict):
            raise PublicationError("A mapped source must be an object or null")


def _artifact_description(presentation, stage, name):
    key = f"{stage}.{name}"
    if key not in presentation.get("artifact_labels", {}):
        key = name
    return _description(presentation, "artifact_labels", key, name, "원본 텐서의 수치 단위(별도 단위 미기록)")


def _plan(rule, presentation):
    operation = rule["op"]
    stages = [side.get("select", {}).get("stage") for side in (rule.get("left", {}), rule.get("right", {}))]
    stages = " ↔ ".join(str(stage) for stage in stages if stage) or "선택한 동일 조건의 관측 값"
    descriptions = {
        "exists": "필요한 처리 경로가 실제 로그에 관측되었는지 확인합니다.",
        "count": "조건에 맞는 실제 관측 건수를 셉니다. 미관측을 자동으로 성공으로 보지 않습니다.",
        "tensor_equality": f"{stages}의 전체 수치 배열이 같은 형태와 값으로 전달되었는지 비교합니다.",
        "pairwise_tensor_distance": f"{stages}의 전체 수치 배열 사이의 차이를 계산합니다.",
        "pairwise_tensor_cosine": f"{stages}의 수치 배열이 얼마나 비슷한 방향을 갖는지 계산합니다.",
        "tensor_stat": "전체 원본 배열에서 지정한 통계량을 계산합니다. 일부 preview로 판정하지 않습니다.",
        "calibrated_tensor_distance": "정상 예시로 미리 정한 기준값을 계산하고 별도 시험 입력과 비교합니다. 비교 가능성과 탐지 성공은 다릅니다.",
    }
    if operation in {"all", "any"}:
        prefix = "다음 확인 항목 모두를 충족해야 합니다." if operation == "all" else "다음 확인 항목 중 하나 이상을 충족해야 합니다."
        return [prefix, *[item for child in rule["rules"] for item in _plan(child, presentation)]]
    if operation == "compare":
        field = rule["field"]
        label = _description(presentation, "field_labels", field, field)["label"]
        operators = {"eq": "같은지", "ne": "다른지", "gt": "큰지", "ge": "이상인지", "lt": "작은지", "le": "이하인지", "contains": "포함하는지", "in": "포함되는지"}
        return [f"{label}가 기준값 {json.dumps(rule.get('value'), ensure_ascii=False)}와 비교하여 {operators[rule['cmp']]} 확인합니다."]
    return [descriptions[operation]]


def _measurements(condition, evidence, presentation):
    rows, seen = [], set()
    for node in _nodes(condition):
        for observation in node.get("observations", []):
            key = analyzer.canonical_json(observation)
            if key in seen:
                continue
            seen.add(key)
            row = {"label": "원본 규칙의 측정 결과", "actual_value": observation.get("actual"),
                   "unit": "별도 단위 없음", "raw_observation": observation}
            if "calibration_n" in observation:
                row.update(label="정상 기준선과 시험 비교 / " + str(observation.get("label", "")),
                           actual_value={"normal_example_count": observation["calibration_n"],
                                         "threshold": observation["threshold"],
                                         "test_threshold_flags": observation["test_threshold_flags"]},
                           unit="유사도 기반 거리(단위 없음)",
                           explanation="기준값은 정상 예시만으로 계산했습니다. 기준 초과 여부는 이 조건의 T/F와 별도입니다.")
            elif "metric" in observation:
                metric = observation.get("quantity", observation["metric"] + "_distance")
                descriptions = {
                    "linf_distance": "대응하는 숫자 중 가장 큰 차이(L∞)",
                    "l2_distance": "전체 숫자의 차이를 합친 거리(L2)",
                    "cosine_distance": "표현 차이(cosine 거리, 작을수록 유사)",
                    "cosine_similarity": "표현 유사도(cosine 유사도, 클수록 유사)",
                }
                ids = observation.get("left_event_ids", [])
                stage = evidence.get(ids[0], {}).get("stage", "") if ids else ""
                artifact = _artifact_description(presentation, stage, observation.get("left_artifact", "tensor"))
                row.update(label=f"{artifact['label']} / {descriptions.get(metric, metric)}",
                           unit="단위 없음" if observation["metric"] == "cosine" else artifact["unit"],
                           comparison=observation.get("cmp"), reference_value=observation.get("expected"))
            elif "equal" in observation:
                row.update(label="전체 수치 배열의 전달 일치", actual_value=observation["equal"],
                           unit="일치 여부", explanation="배열 형태와 전체 숫자의 정확한 일치입니다. 일부 예시만 비교한 결과가 아닙니다.")
            elif "stat" in observation:
                labels = {"max_abs": "전체 배열에서 가장 큰 절댓값", "l2": "전체 배열의 L2 크기", "count_nonzero": "0이 아닌 원소 수", "size": "전체 원소 수", "mean": "평균", "min": "최솟값", "max": "최댓값"}
                row.update(label=labels.get(observation["stat"], observation["stat"]), unit="원본 배열 단위" if observation["stat"] not in {"size", "count_nonzero"} else "개")
            elif "field" in observation:
                row.update(_description(presentation, "field_labels", observation["field"], observation["field"]))
                row.update(comparison=observation.get("cmp"), reference_value=observation.get("expected"))
            elif "count" in observation:
                row.update(label="실제로 관측한 건수", actual_value=observation["count"], unit="건")
            rows.append(row)
    return rows


def _preview(descriptor, raw_root, destination):
    import numpy as np

    path = (raw_root / descriptor["path"]).resolve(strict=True)
    if not path.is_relative_to(raw_root) or _hash(path) != descriptor["sha256"]:
        raise analyzer.EvidenceError("Artifact changed or escaped the validated raw archive during publication")
    result = {"full_value": {"path": _relative(path, destination), "sha256": descriptor["sha256"],
                             "dtype": descriptor["dtype"], "shape": descriptor["shape"], "bytes": descriptor["bytes"]},
              "preview_notice": "아래 값은 실제 원본의 앞부분 preview입니다. 전체 배열은 full_value.path의 파일입니다."}
    try:
        array = np.load(path, allow_pickle=False, mmap_mode="r")
        if not isinstance(array, np.ndarray) or array.dtype.kind not in "biuf" or array.size == 0:
            raise ValueError("Not a nonempty real numeric array")
        if list(array.shape) != descriptor["shape"] or str(array.dtype) != descriptor["dtype"]:
            raise analyzer.EvidenceError("Artifact dtype/shape mismatch during publication")
        values = array.reshape(-1)[:8]
        if not np.isfinite(values).all():
            raise ValueError("Non-finite preview values cannot be rendered as JSON numbers")
        result.update(preview=values.tolist(), preview_element_count=int(values.size),
                      total_element_count=int(array.size), preview_is_complete=bool(array.size <= 8))
    except (ValueError, OSError, EOFError) as error:
        if isinstance(error, analyzer.EvidenceError):
            raise
        result.update(preview=None, preview_is_complete=False, preview_unavailable=str(error))
    return result


def _point_matches(point, source):
    if not isinstance(source, dict) or not source.get("logging_point_id") or point.get("logging_point_id") != source["logging_point_id"]:
        return False
    expected = point.get("source") or {}
    return all(expected.get(key) == source[key] for key in ("path", "function", "line", "sha256"))


def _condition_document(condition, rule, analysis, destination, presentation, mapping, mapping_path, internal_file, preview_cache):
    friendly = presentation.get("conditions", {}).get(condition["id"], {})
    if not isinstance(friendly, dict):
        raise PublicationError("Condition presentation must be an object")
    verdict = _verdict(condition, rule["rule"], analysis)
    observations = _measurements(condition, analysis["evidence"], presentation)
    raw_root = Path(analysis["provenance"]["log_path"]).parent
    events, points = [], {}
    for event_id in condition["evidence_ids"]:
        event = analysis["evidence"][event_id]
        artifacts = {}
        for name, descriptor in event["artifacts"].items():
            # All condition files share one destination directory. The source
            # bytes, not a potentially inaccurate stored descriptor preview,
            # determine the displayed exact prefix.
            key = (event_id, name, destination.parent)
            if key not in preview_cache:
                preview_cache[key] = _preview(descriptor, raw_root, destination)
            artifacts[name] = {**_artifact_description(presentation, event["stage"], name), **preview_cache[key]}
        events.append({"event_id": event_id, "sequence": event["sequence"],
                       "timestamp_utc": event["timestamp_utc"], "stage": event["stage"],
                       "context": event["context"], "source": event["source"],
                       "raw": event["raw"], "artifacts": artifacts})
        source = event["source"]
        if source is None:
            continue
        point_key = analyzer.canonical_json(source)
        if point_key not in points:
            matched = next((point for point in mapping.get("logging_points", []) if _point_matches(point, source)), None)
            points[point_key] = {"logging_point_id": source["logging_point_id"], "source": source,
                "observed": True, "reason": matched["reason"] if matched else "이 조건 평가에 사용된 실제 원시 값을 해당 소스 경계에서 수집한 관측입니다. 별도 로깅 의도 문서는 일치하는 매핑이 제공된 경우에만 연결됩니다.",
                "reason_origin": "matching_source_mapping" if matched else "generic_observation_description", "event_ids": []}
            if matched and matched.get("source_snapshot"):
                snapshot = (mapping_path.parent / matched["source_snapshot"]).resolve(strict=True)
                if _hash(snapshot) != source["sha256"]:
                    raise analyzer.EvidenceError("Mapped source snapshot does not match recorded source hash")
                points[point_key]["source_snapshot"] = _ref(snapshot, destination)
        points[point_key]["event_ids"].append(event_id)
    for point in mapping.get("logging_points", []):
        if condition["id"] in point.get("condition_ids", []) and not any(_point_matches(point, p["source"]) for p in points.values()):
            identity = point.get("logging_point_id", point.get("mapping_id", "unobserved-candidate"))
            points[identity.encode()] = {"logging_point_id": identity, "source": point.get("source"),
                "observed": False, "reason": point.get("reason", "제공된 소스 매핑의 후보 지점"),
                "reason_origin": "declared_mapping_not_observed_in_this_condition", "event_ids": []}
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {"attack_id": analysis["attack_id"], "attack_name": analysis["attack_name"],
                    "engine_id": analysis["metadata"]["engine"]["id"], "condition_id": condition["id"],
                    "kind": condition["kind"], **verdict, "document_notice": NOTICE},
        "question": {"plain": friendly.get("question", condition["text"]), "original": condition["text"],
                     "explanation": friendly.get("explanation", condition.get("operationalization", "Attack Library에서 정의한 조건을 아래 관측 항목으로 확인합니다."))},
        "measurement_plan": friendly.get("measurement_plan", list(dict.fromkeys(_plan(rule["rule"], presentation)))),
        "measurements": {"summary": analyzer._essential_reason(condition) if observations else verdict["explanation"],
                         "actual_measurement_count": len(observations), "items": observations},
        "judgment_basis": {"explanation": verdict["explanation"], "source_condition_cell": condition["source_cell"],
                           "original_evaluation_reason": condition["reason"],
                           "checks": [{"evidence_value": node["value"], "reason": node["reason"], "evidence_ids": node["evidence_ids"]} for node in _nodes(condition)],
                           "interpretation_limit": VERDICT_NOTICE},
        "logging_points": list(points.values()), "events": events,
        "provenance": {"run_id": analysis["run_id"], "execution_scope": analysis["metadata"]["execution_scope"],
                       "run_status": analysis["run_status"], "run_reason": analysis["run_reason"],
                       "raw_log": _ref(analysis["provenance"]["log_path"], destination),
                       "seal": _ref(raw_root / "seal.json", destination),
                       "rules": _ref(analysis["provenance"]["rules_path"], destination),
                       "library": analysis["provenance"]["library"],
                       "internal_analysis": {"path": _relative(internal_file, destination)},
                       "analyzer_sha256": analysis["provenance"]["analyzer_sha256"],
                       "mapping": _ref(mapping_path, destination) if mapping_path else None,
                       "raw_values_preserved": True, "readable_used_for_verdict": False},
    }


def _supplements(paths, analysis):
    result = []
    for path in paths:
        data, path = _checked_data(path, analysis, engine=True)
        if not isinstance(data.get("title"), str) or not isinstance(data.get("source_runs"), list) or not data["source_runs"]:
            raise PublicationError("Supplement requires title and nonempty source_runs")
        sources = []
        for source in data["source_runs"]:
            package = analyzer.EvidencePackage(path.parent / source["log_path"])
            if package.metadata["attack_id"] != analysis["attack_id"] or package.metadata["engine"]["id"] != analysis["metadata"]["engine"]["id"]:
                raise PublicationError("Supplement source run belongs to a different attack or engine")
            if _hash(package.path) != source["events_sha256"]:
                raise analyzer.EvidenceError("Supplement source events hash mismatch")
            sources.append({"path": package.path, "sha256": source["events_sha256"], "run_status": package.seal["status"]})
        for table in data.get("tables", []):
            if not table.get("columns") or any(not isinstance(column, dict) or not isinstance(column.get("key"), str) or not isinstance(column.get("label"), str) for column in table["columns"]):
                raise PublicationError("Supplement table needs explicit key/label columns")
            if not isinstance(table.get("rows"), list) or any(not isinstance(row, dict) for row in table["rows"]):
                raise PublicationError("Supplement table rows must be objects")
        for key in ("summary", "limitations"):
            if not isinstance(data.get(key, []), list) or any(not isinstance(item, str) for item in data.get(key, [])):
                raise PublicationError(f"Supplement {key} must contain text strings")
        result.append({"data": data, "path": path, "sources": sources})
    return result


def _supplement_table(table):
    """Keep compact comparisons tabular and expose long original text by row."""
    columns = table["columns"]
    lines = ["", "### " + _text(table.get("title", "관찰 결과")), ""]
    expanded = len(columns) > 5 or any(
        len(str(row.get(column["key"], ""))) > 120 or "\n" in str(row.get(column["key"], ""))
        for row in table["rows"] for column in columns
    )
    if not expanded:
        lines += ["| " + " | ".join(_text(column["label"]) for column in columns) + " |",
                  "|" + "---|" * len(columns)]
        lines += ["| " + " | ".join(_text(row.get(column["key"], "미기록")) for column in columns) + " |"
                  for row in table["rows"]]
        return lines
    lines += ["질문·응답 원문은 가로로 긴 표 대신 관찰별 상세에 보존했습니다.", ""]
    for index, row in enumerate(table["rows"], 1):
        heading = str(row.get(columns[0]["key"], ""))
        heading = heading[:80] + ("…" if len(heading) > 80 else "")
        lines += [f"<details><summary>관찰 {index} — {_text(heading)}</summary>", ""]
        for column in columns:
            value = row.get(column["key"], "미기록")
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False)
            # A longer fence prevents literal model output from terminating the block.
            fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
            lines += [_text(column["label"]), "", fence + "text", text, fence, ""]
        lines += ["</details>", ""]
    return lines


def _render(analysis, documents, targets, report_path, presentation, supplements, attack_label, engine_label):
    engine = analysis["metadata"]["engine"]
    statuses = {"observed_satisfied": "충족 확인", "observed_not_satisfied": "관측상 불충족", "not_evaluated": "미평가"}
    lines = [f"# {_text(attack_label)} / {_text(engine_label)} 분석 보고서", "", "## 무엇을 확인했나요?", "",
             _text(presentation.get("purpose", "공격 조건을 엔진 내부에서 관측할 수 있는지, 사후 분석에 필요한 증거를 수집했는지 확인합니다.")), "",
             "이 보고서는 원시 로그를 공통 Analyzer로 평가한 결과입니다. 공격 성공이나 엔진 전체의 안전성을 판정하는 인증서가 아닙니다.", "",
             "## 결과 한눈에 보기", "", "| 조건 | 쉬운 질문 | 표시 판정 | 증거 상태 | 실제 측정 요약 |", "|---|---|---|---|---|"]
    for document in documents:
        summary = document["summary"]
        identifier = summary["condition_id"]
        lines.append(f"| {_link(identifier, _relative(targets[identifier], report_path))} | {_text(document['question']['plain'])} | {summary['verdict']} | {statuses[summary['evidence_status']]} | {_text(document['measurements']['summary'])} |")
    lines += ["", VERDICT_NOTICE, "", "미평가의 원인은 조건별 JSON의 `summary.evaluation_reason`에 구분해 보존합니다. 내부 증거 값 true/false/null은 표시 정책으로 바꾸지 않습니다.", "",
              "## 실험 환경과 범위", "",
              f"- 공격: {_text(analysis['attack_name'])} / ID `{_text(analysis['attack_id'])}`",
              f"- 엔진: {_text(engine_label)} / ID `{_text(engine['id'])}` / revision `{_text(engine.get('revision', '미기록'))}`",
              f"- 모델: {_text(analyzer._model_label(analysis['metadata'].get('model')))}",
              f"- 실행 범위: `{_text(analysis['metadata']['execution_scope'])}` / 종료 상태: `{analysis['run_status']}`",
              f"- 실행 ID: `{_text(analysis['run_id'])}` / 이벤트 {analysis['integrity']['event_count']}개",
              f"- 미완료 사유: {_text(analysis['run_reason'] or '없음')}"]
    if analysis["metadata"].get("requested_model") is not None:
        lines += ["- 실행 전 검토 모델(로드 성공 의미 아님): "
                  + _text(analyzer._model_label(analysis["metadata"]["requested_model"]))]
    metadata_text = json.dumps(analysis["metadata"], ensure_ascii=False, indent=2, allow_nan=False)
    metadata_fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", metadata_text)), default=0))
    lines += ["", "<details><summary>모델·실행 설정의 원본 metadata 전체 보기</summary>", "",
              metadata_fence + "json", metadata_text, metadata_fence, "", "</details>", "",
              "## 결론", ""]
    for kind in ("AC", "DC"):
        selected = [d["summary"] for d in documents if d["summary"]["kind"] == kind]
        counts = {status: sum(d["evidence_status"] == status for d in selected) for status in statuses}
        lines.append(f"- {kind}: 충족 확인(T) {counts['observed_satisfied']}개, 관측상 불충족(F) {counts['observed_not_satisfied']}개, 미평가 표시(F) {counts['not_evaluated']}개입니다.")
    lines += ["", "충족한 조건은 이번 실행에서 확인한 범위에 한정됩니다. 미평가 F는 필요한 실행·계측 증거를 추가로 확보해야 한다는 뜻입니다.", "",
              "## 각 조건에서 무엇을 측정했나요?", ""]
    for document in documents:
        summary = document["summary"]
        lines += [f"### {_text(summary['condition_id'])} — {summary['verdict']} / {statuses[summary['evidence_status']]}", "",
                  _text(document["question"]["explanation"]), "", _text(summary["explanation"]), "",
                  _link("실제 측정값·단위·로깅 이유·원시 증거 보기", _relative(targets[summary["condition_id"]], report_path)), ""]
    for supplement in supplements:
        data = supplement["data"]
        lines += ["## 별도 보조 관찰 — " + _text(data["title"]), "",
                  "아래 보조 자료는 AC/DC 규칙의 입력이 아니며 조건별 T/F를 변경하지 않습니다.", ""]
        lines += ["- " + _text(item) for item in data.get("summary", [])]
        for table in data.get("tables", []):
            lines += _supplement_table(table)
        lines += ["", *["- 한계: " + _text(item) for item in data.get("limitations", [])], "",
                  _link("보조 관찰 데이터와 출처", _relative(supplement["path"], report_path)), ""]
        for source in supplement["sources"]:
            lines += [f"- {_link('검증한 보조 원시 로그', _relative(source['path'], report_path))} / `{source['sha256']}` / 상태 `{source['run_status']}`"]
    lines += ["", "## 해석 한계와 원본 근거", "", NOTICE, "",
              "- 해시·seal 검증은 증거 묶음 내부의 일관성을 확인합니다. 수집 주체의 진정성이나 외부 증거 보관 이력을 독립적으로 증명하지 않습니다.",
              "- 로깅 지점의 관측, 조건의 충족, 실제 공격 성공, 탐지 정확도는 서로 다른 주장입니다.",
              "- 읽기 쉬운 설명이나 preview가 아닌 원본 raw와 검증한 전체 아티팩트로 규칙을 평가했습니다.",
              f"- {_link('원본 JSONL', _relative(analysis['provenance']['log_path'], report_path))}",
              f"- {_link('동일하게 적용한 규칙', _relative(analysis['provenance']['rules_path'], report_path))} / SHA-256 `{analysis['provenance']['rules_sha256']}`", ""]
    return "\n".join(lines)


def render_documents(analysis, *, targets, report_path, presentation, presentation_path,
                     mapping, mapping_path, internal_file, internal_sha256, supplements,
                     attack_label, engine_label):
    """Render complete public documents from already validated inputs, read-only.

The same renderer is used for publication and independent full-content replay.
It reads raw artifacts and source/reference hashes, but creates no files and does
not mutate analysis or display inputs. Paths describe the final destinations.
"""
    documents, preview_cache = [], {}
    for condition, rule in zip(analysis["conditions"], analysis["rule_snapshot"]["conditions"], strict=True):
        target = Path(targets[condition["id"]])
        document = _condition_document(condition, rule, analysis, target, presentation,
                                       mapping, mapping_path, internal_file, preview_cache)
        document["summary"].update(attack_label=attack_label, engine_label=engine_label)
        if document["summary"]["evidence_status"] == "not_evaluated" and supplements:
            context = [{"title": item["data"]["title"], "summary": item["data"].get("summary", []),
                        "source": _ref(item["path"], target), "used_for_verdict": False,
                        "notice": "검증한 별도 로그에 연결된 보조 설명입니다. 이 조건의 실제 측정값이나 충족 증거를 대체하지 않습니다.",
                        "source_runs": [{"path": _relative(source["path"], target), "sha256": source["sha256"],
                                         "run_status": source["run_status"]} for source in item["sources"]]}
                       for item in supplements]
            document = {"schema_version": document["schema_version"], "summary": document["summary"],
                        "supplementary_context": context,
                        **{key: value for key, value in document.items() if key not in {"schema_version", "summary"}}}
        document["provenance"]["internal_analysis"]["sha256"] = internal_sha256
        document["provenance"]["presentation"] = _ref(presentation_path, target) if presentation_path else None
        documents.append(document)
    report_text = _render(analysis, documents, targets, report_path, presentation, supplements,
                          attack_label, engine_label)
    return documents, report_text


def _overlap(left, right):
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _atomic_copy(source, target, *, new_only=False):
    temporary = tempfile.NamedTemporaryFile(prefix=".publication-install-", dir=target.parent, delete=False)
    temporary.close()
    temporary_path = Path(temporary.name)
    try:
        shutil.copyfile(source, temporary_path)
        if new_only:
            os.link(temporary_path, target)
        else:
            os.replace(temporary_path, target)
    finally:
        temporary_path.unlink(missing_ok=True)


def _check_existing_names(files, analysis):
    """An engine directory must not retain stale publication names or ownership."""
    expected = set(files)
    for parent in {target.parent for target in expected}:
        if not parent.exists():
            continue
        stale = {path for pattern in ("*-Report.md", "*-LogFile.json") for path in parent.glob(pattern)} - expected
        if stale:
            raise PublicationError("Existing publication names differ; use an explicit migration or a new engine-specific output directory: "
                                   + ", ".join(sorted(path.name for path in stale)))
    for path in expected:
        if path.name.endswith("-LogFile.json") and path.is_file() and not path.is_symlink():
            document = _read(path)
            summary = document.get("summary", {}) if isinstance(document, dict) else {}
            if not isinstance(summary, dict):
                summary = {}
            if summary.get("attack_id") != analysis["attack_id"] or summary.get("engine_id") != analysis["metadata"]["engine"]["id"]:
                raise PublicationError("Existing condition publication belongs to a different attack/engine or lacks ownership metadata")


def _commit(staging, files, analysis_dir, analysis, replace, backup_dir):
    _check_existing_names(files, analysis)
    old_analysis = analysis_dir.exists() and any(analysis_dir.iterdir())
    if old_analysis:
        manifest_path = analysis_dir / "publication.json"
        if not manifest_path.is_file():
            raise PublicationError("Refusing to replace an internal directory not created by this publisher")
        previous = _read(manifest_path)
        if previous.get("attack_id") != analysis["attack_id"] or previous.get("engine_id") != analysis["metadata"]["engine"]["id"]:
            raise PublicationError("Existing internal analysis belongs to a different attack/engine")
        if {path.name for path in analysis_dir.iterdir()} != {"analysis.json", "report.md", "publication.json"} or any(path.is_symlink() or not path.is_file() for path in analysis_dir.iterdir()):
            raise PublicationError("Internal publication directory contains unrelated or non-regular files")
    existing = {}
    for target in files:
        if target.is_symlink() or target.exists() and not target.is_file():
            raise PublicationError(f"Output target is not a regular file: {target}")
        if target.exists():
            existing[target] = _hash(target)
    if (existing or old_analysis) and not replace:
        raise FileExistsError("Existing publication requires explicit --replace and a new --backup-dir")
    if replace and (backup_dir is None or backup_dir.exists()):
        raise PublicationError("--replace requires a new, nonexistent backup directory")
    report_target = next(path for path in files if path.suffix == ".md")
    for target in files:
        target.parent.mkdir(parents=True, exist_ok=True)
    lock = report_target.parent / ".liemapp-publication.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    installed, backups = [], {}
    saved_analysis = staging / "previous-analysis"
    new_analysis_installed = False
    try:
        _check_existing_names(files, analysis)
        for target in files:
            if target.is_symlink() or target.exists() != (target in existing) or target in existing and _hash(target) != existing[target]:
                raise PublicationError("Output changed while publication was being prepared")
        if replace:
            backup_dir.mkdir(parents=True, exist_ok=False)
            for index, (target, digest) in enumerate(existing.items()):
                backup = backup_dir / f"{index:03d}-{target.name}"
                shutil.copy2(target, backup)
                if _hash(backup) != digest:
                    raise OSError("Backup hash verification failed")
                backups[target] = backup
            if old_analysis:
                shutil.copytree(analysis_dir, backup_dir / "internal-analysis")
            _dump(backup_dir / "backup.json", {"schema_version": SCHEMA_VERSION,
                "attack_id": analysis["attack_id"], "engine_id": analysis["metadata"]["engine"]["id"],
                "files": [{"original": str(path), "backup": str(backups[path]), "sha256": digest} for path, digest in existing.items()],
                "internal_analysis": str(analysis_dir) if old_analysis else None})
        if old_analysis:
            os.replace(analysis_dir, saved_analysis)
        os.replace(staging / "analysis", analysis_dir)
        new_analysis_installed = True
        for target, source in files.items():
            _atomic_copy(source, target, new_only=target not in existing)
            installed.append(target)
    except BaseException:
        for target in reversed(installed):
            if target in backups:
                _atomic_copy(backups[target], target)
            else:
                target.unlink(missing_ok=True)
        if new_analysis_installed:
            os.replace(analysis_dir, staging / "failed-new-analysis")
        if saved_analysis.exists():
            os.replace(saved_analysis, analysis_dir)
        raise
    finally:
        lock.unlink(missing_ok=True)


def publish(log_path, rules_path, *, log_output_dir, report_output_dir, analysis_dir,
            mapping_path=None, presentation_path=None, supplement_paths=(),
            attack_label=None, engine_label=None, replace=False, backup_dir=None):
    """Create condition JSONs + one public MD, keeping internal analysis private.

Publication is staged before installation. Existing exact output names require
replace=True and a new backup_dir; unrelated files are never moved or removed.
The old Analyzer and its three-valued evidence decisions are unchanged.
"""
    log_path, rules_path = Path(log_path).resolve(strict=True), Path(rules_path).resolve(strict=True)
    log_dir, report_dir, internal = (Path(path).resolve() for path in (log_output_dir, report_output_dir, analysis_dir))
    directories = [log_dir, report_dir, internal]
    if any(_overlap(a, b) for index, a in enumerate(directories) for b in directories[index + 1:]):
        raise PublicationError("Public JSON, public report and internal-analysis directories must be separate")
    if any(_overlap(path, log_path.parent) for path in directories):
        raise PublicationError("Publication output must be separate from the immutable raw archive")
    if any(rules_path.is_relative_to(path) for path in directories):
        raise PublicationError("Publication must not overwrite its rule source")
    if internal.exists() and not internal.is_dir():
        raise PublicationError("analysis_dir must be a directory")
    backup = Path(backup_dir).resolve() if backup_dir is not None else None
    if replace and backup is None or not replace and backup is not None:
        raise PublicationError("--replace and --backup-dir must be supplied together")
    if backup is not None and any(_overlap(backup, path) for path in [*directories, log_path.parent]):
        raise PublicationError("Backup must be separate from all outputs and raw input")
    internal.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".publication-staging-", dir=internal.parent) as temporary:
        staging = Path(temporary)
        result = analyzer.analyze(log_path, rules_path, staging / "analysis")
        rules = result["rule_snapshot"]
        attack = _label(attack_label, "attack_label") if attack_label is not None else _slug(result["attack_id"])
        engine = _label(engine_label, "engine_label") if engine_label is not None else _slug(result["metadata"]["engine"]["id"])
        presentation, presentation_path = _checked_data(presentation_path, result)
        mapping, mapping_path = _checked_data(mapping_path, result, engine=True)
        _validate_display(presentation, mapping, {condition["id"] for condition in rules["conditions"]})
        supplements = _supplements(supplement_paths, result)
        protected = [path for path in [presentation_path, mapping_path, *[item["path"] for item in supplements]] if path]
        protected += [source["path"] for item in supplements for source in item["sources"]]
        if any(path.is_relative_to(directory) for path in protected for directory in directories):
            raise PublicationError("Publication output cannot contain its display/supplement source files")
        if any(_overlap(directory, source["path"].parent) for item in supplements for source in item["sources"] for directory in directories):
            raise PublicationError("Publication output must be separate from supplementary raw archives")
        if backup is not None and any(_overlap(backup, source["path"].parent) for item in supplements for source in item["sources"]):
            raise PublicationError("Backup must be separate from supplementary raw archives")
        targets = {condition["id"]: log_dir / f"{attack}-{_label(condition['id'], 'condition_id')}-{engine}-LogFile.json" for condition in rules["conditions"]}
        report_path = report_dir / f"{attack}-{engine}-Report.md"
        documents, report = render_documents(result, targets=targets, report_path=report_path,
            presentation=presentation, presentation_path=presentation_path, mapping=mapping, mapping_path=mapping_path,
            internal_file=internal / "analysis.json", internal_sha256=_hash(staging / "analysis/analysis.json"),
            supplements=supplements, attack_label=attack, engine_label=engine)
        files = {}
        for document in documents:
            target = targets[document["summary"]["condition_id"]]
            _dump(staging / target.name, document)
            files[target] = staging / target.name
        (staging / report_path.name).write_text(report, encoding="utf-8")
        files[report_path] = staging / report_path.name
        manifest = {"schema_version": SCHEMA_VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "attack_id": result["attack_id"], "engine_id": result["metadata"]["engine"]["id"],
            "run_id": result["run_id"], "report": str(report_path),
            "condition_files": {key: str(path) for key, path in targets.items()},
            "internal_analysis": str(internal / "analysis.json"),
            "raw_log": str(log_path), "raw_log_sha256": result["provenance"]["log_sha256"],
            "rules_sha256": result["provenance"]["rules_sha256"],
            "publisher_sha256": _hash(Path(__file__)),
            "display_policy": "T iff evidence_value is true; F otherwise, retaining observed_not_satisfied vs not_evaluated",
            "summary": {"T": sum(document["summary"]["verdict"] == "T" for document in documents),
                        "F": sum(document["summary"]["verdict"] == "F" for document in documents),
                        "observed_not_satisfied": sum(document["summary"]["evidence_status"] == "observed_not_satisfied" for document in documents),
                        "not_evaluated": sum(document["summary"]["evidence_status"] == "not_evaluated" for document in documents)},
            "files": [{"path": str(path), "sha256": _hash(source)} for path, source in files.items()],
            "backup_dir": str(backup) if backup else None}
        _dump(staging / "analysis/publication.json", manifest)
        _commit(staging, files, internal, result, replace, backup)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--log-output-dir", required=True, type=Path)
    parser.add_argument("--report-output-dir", required=True, type=Path)
    parser.add_argument("--analysis-dir", required=True, type=Path)
    parser.add_argument("--mapping", type=Path)
    parser.add_argument("--presentation", type=Path)
    parser.add_argument("--supplement", action="append", type=Path, default=[])
    parser.add_argument("--attack-label")
    parser.add_argument("--engine-label")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = publish(args.log, args.rules, log_output_dir=args.log_output_dir,
                         report_output_dir=args.report_output_dir, analysis_dir=args.analysis_dir,
                         mapping_path=args.mapping, presentation_path=args.presentation,
                         supplement_paths=args.supplement, attack_label=args.attack_label,
                         engine_label=args.engine_label, replace=args.replace, backup_dir=args.backup_dir)
    except (analyzer.EvidenceError, analyzer.RuleError, PublicationError, OSError) as error:
        print(f"Publication rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
