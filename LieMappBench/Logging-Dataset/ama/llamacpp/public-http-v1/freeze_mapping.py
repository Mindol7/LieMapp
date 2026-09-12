"""Bind llamacpp AMA source mapping to a sealed, real public-API run.

No inference, network requests, rule changes or report generation are performed.
Use --output-dir for a development preview. The existing canonical mapping is
only replaced when --replace is explicitly supplied.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
SCRIPT = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama"
EXPECTED_SOURCES = [SCRIPT / "shared/public_http_protocol.py", SCRIPT / "llamacpp/run_public.py"]
PROTOCOL = "ama-public-http-v1"
SPEC = {
    "AMA-PUBLIC-LP01": (["DC1"], "ama_tool_registry", "agent_harness",
        "공식 공개 API 계보와 로컬 메타데이터 어댑터를 분리하여 후보 목록을 기록한다. 후보의 출처 표시는 참고 기록이며, 추론 엔진은 도구의 출처 정보를 전달받지 않으므로 엔진 조건의 판정 근거가 아니다."),
    "AMA-PUBLIC-LP02": ([], "ama_metadata_review", "agent_harness",
        "메타데이터 검토 수행 여부·대상·제외 결과를 기록한다. 알려진 합성 비밀 필드 검사라는 제한적 대조군이며 범용 방어로 해석하지 않는다."),
    "AMA-PUBLIC-LP03": (["AC1"], "ama_selection_policy", "agent_harness",
        "실제 후보 이름과 auto/required 모드를 기록하여 자율 선택과 정상 도구 하나만 허용한 고정 선택을 구분한다."),
    "AMA-PUBLIC-LP04": (["AC1", "DC1"], "ama_request_started", "agent_harness",
        "HTTP 전송 전 메시지·도구 메타데이터·샘플링 설정과 요청 해시를 보존하여 엔진의 실제 수신·템플릿 결과와 대조한다."),
    "AMA-PUBLIC-LP05": (["DC1"], "ama_tool_selected", "agent_harness",
        "실제 모델이 선택한 함수 이름을 후보의 정확한 설명·매개변수 스키마·공개 API 계보에 연결한다. 선택과 실행은 구분한다."),
    "AMA-PUBLIC-LP06": (["DC2"], "ama_tool_execution", "agent_harness",
        "도구별 실제 외부 호출 확인·인자·응답 또는 호출 전 차단을 집계한다. 전송 후 확인되지 않은 호출은 원시 null로 보존한다."),
    "AMA-PUBLIC-LP07": (["DC2"], "ama_tool_provenance", "agent_harness",
        "실제 선택된 도구의 공개 플랫폼 계보와 확인된 HTTPS 호출 증거를 함께 연결한다. 공개 출처 표시는 에이전트 계층 기록이며 엔진 조건 판정에 사용하지 않는다."),
    "AMA-PUBLIC-LP08": (["DC1", "DC2"], "ama_request_finished", "agent_harness",
        "공격 역할 도구 선택·실행·합성 canary 전달을 분리 집계하고 원시 응답을 보존한다. 단일 성공 사례를 메타데이터의 인과적 효과로 단정하지 않는다."),
    "AMA-HTTP-LP01": (["DC2"], "ama_http_request", "http_client",
        "허용된 공식 공개 API로 전송할 실제 GET 경로·query·헤더·nonce를 기록하여 모델 인자와 외부 요청을 연결한다. 전송 의도 자체는 수신 증거가 아니다."),
    "AMA-HTTP-LP02": (["DC2"], "ama_http_response", "http_client",
        "제공자가 반환한 실제 HTTPS 응답 원문·TLS 정보·echo 및 nonce를 보존한다. 이는 클라이언트가 수집한 영수증이며 제공자 내부 함수의 계측 로그가 아니다."),
    "AMA-HTTP-LP03": (["DC2"], "ama_tool_call_outcome", "http_client",
        "개별 호출의 원문 인자·검증·전송·확인 결과를 request_id/tool_call_id/http_attempt_id로 연결한다. 부정확한 인자를 임의 보정하지 않는다."),
    "AMA-LLAMACPP-RUN01": ([], "ama_run_started", "experiment_runner",
        "데이터셋·공개 출처 스냅샷·전체 요청 순서를 실행 전에 고정한다."),
    "AMA-LLAMACPP-RUN02": ([], "ama_server_started", "experiment_runner",
        "실제로 준비된 로컬 CPU llamacpp 서버의 실행 명령과 주소를 기록한다."),
    "AMA-LLAMACPP-RUN03": ([], "ama_run_finished", "experiment_runner",
        "계획한 요청의 완료 수와 정상 종료 상태를 기록한다."),
    "AMA-LLAMACPP-RUN04": ([], "ama_run_failed", "experiment_runner",
        "실행 오류를 공격 방어 또는 엔진 안전 판정과 구분하여 보존한다."),
    "AMA-LLAMACPP-RUN05": ([], "ama_process_output", "experiment_runner",
        "서버 출력 원문·해시·자체 프로세스 트리의 TCP 수신 주소 점검을 보존한다."),
}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def locate_source(path, expected_sha, archive):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    path = path.absolute()
    if not path.is_relative_to(ROOT):
        raise ValueError("Source outside project: " + str(path))
    candidates = [path]
    if archive:
        candidates.append(archive / path.relative_to(ROOT))
    candidates.append(HERE / "source-snapshots" / expected_sha[:16] / path.name)
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink() and digest(candidate) == expected_sha:
            return candidate
    raise ValueError("Exact source bytes unavailable: " + str(path) + " SHA256=" + expected_sha)


def snapshot(path, output):
    sha = digest(path)
    relative = Path("source-snapshots") / sha[:16] / path.name
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_symlink() or digest(target) != sha:
            raise ValueError("Snapshot collision: " + str(target))
    else:
        with target.open("xb") as stream, path.open("rb") as original:
            shutil.copyfileobj(original, stream)
    return relative.as_posix()


def static_points(actual_path, logical_path):
    found = {}
    for function in (n for n in ast.parse(actual_path.read_text()).body
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        for node in ast.walk(function):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "source"
                    and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in SPEC):
                point = node.args[0].value
                if point in found:
                    raise ValueError("Duplicate source ID: " + point)
                found[point] = {"path": str(logical_path), "function": function.name, "line": node.lineno,
                                "logging_point_id": point, "sha256": digest(actual_path)}
    return found


def preserved_supporting_sources(mapping, output, archive=None):
    """Normalize legacy static reviews into exact, self-contained snapshots."""
    supporting = []
    # llama.cpp's legacy map names these static review sites explicitly; unlike
    # SGLang it does not have a supporting_sources field. Never mutate it.
    for original in mapping.get("supporting_sources", mapping.get("reviewed_uninstrumented_supporting_sites", [])):
        entry = deepcopy(original)
        entry["source_snapshot"] = snapshot(locate_source(entry["path"], entry["sha256"], archive), output)
        entry["evidence_kind"] = "static_review_of_uninstrumented_supporting_source_not_an_observed_logging_point"
        supporting.append(entry)
    if not supporting:
        raise ValueError("Preserved native supporting-source reviews are missing")
    return supporting


def make_markdown(mapping):
    binding = mapping["source_run"]
    counts = mapping["observed_counts"]
    lines = ["# AMA · llamacpp 로깅 지점", "",
        "공개 API 실험의 실제 원시 로그와 소스 스냅샷을 연결한 지도입니다. 조건 판정이나 공격 성공률 자체를 대신하지 않습니다.", "",
        "## 실행 및 증거 범위", "",
        f'- 프로토콜: `{PROTOCOL}`',
        f'- 실행: `{binding["run_id"]}` · 구분: `{binding["dataset_split"]}` · seal 상태: `{binding["status"]}`',
        f'- 완료 요청: {counts["completed_requests"]}개 · 전체 이벤트: {counts["events"]}개 · 네이티브 이벤트: {counts["native_events"]}개',
        f'- 관측 지점: {counts["observed_points"]}/{counts["mapped_points"]}개 · 원시 로그 SHA-256: `{binding["events_sha256"]}`', "",
        "공개 API 출처 → 실제 모델 입력·생성 → 선택한 도구 메타데이터 → 실제 HTTPS 요청·응답 → 조건별 근거 연결", "",
        "## 엔진 내부 지점", "",
        "| 지점 | 실제 함수·행 | 조건 | 관측 수 | 기록 이유 |", "|---|---|---|---:|---|"]
    for native in (True, False):
        if not native:
            lines += ["", "## 공통 에이전트·HTTP 클라이언트·실행부", "",
                "아래 지점은 llamacpp 고유 기능이 아니라 공통 실험 에이전트와 HTTP 클라이언트의 관측입니다.", "",
                "| 지점 | 실제 함수·행 | 조건 | 관측 수 | 기록 이유 |", "|---|---|---|---:|---|"]
        for point in mapping["logging_points"]:
            if (point["layer"] == "native_inference_engine") != native:
                continue
            src = point["source"]
            lines.append(f'| `{point["logging_point_id"]}` | `{Path(src["path"]).name}:{src["function"]}:{src["line"]}` | {", ".join(point["condition_ids"]) or "실행 무결성"} | {point["observed_event_count"]} | {point["reason"]} |')
    lines += ["", "## 해석 시 주의사항", "",
        "- **AC1:** 실제 선택된 API의 공개 플랫폼 원문·해시·엔드포인트 계보와 확인된 HTTPS 호출을 함께 확인합니다. 후보 목록의 출처 bool만으로 판정하지 않습니다.",
        "- 도구 이름·설명·인자 스키마는 로컬 메타데이터 어댑터입니다. 이를 공개 플랫폼에 게시된 악성 도구 원문 또는 공격자 소유 API라고 주장하지 않습니다.",
        "- **AC3의 T는 검토 수행**을 뜻합니다. 모든 AC를 단순 AND하여 공격 성공으로 해석하지 않습니다.",
        "- **DC2:** 요청 인자와 제공자 응답·echo/nonce로 클라이언트 측 실제 호출 확인을 뒷받침합니다. 제공자 내부 실행 경로·저장 여부를 직접 계측한 것은 아닙니다.",
        "- 네이티브 tool_calls는 호출 제안입니다. 외부 호출 여부는 별도 HTTP 증거와 연결해야 합니다.",
        "- 관측 수 0인 오류 지점은 이번 실행에서 활성화되지 않았다는 뜻이지, 로깅 지점이 없다는 뜻이 아닙니다.",
        "- 각 지점의 원시 필드 목록·예시 이벤트 ID·정확한 소스 해시·스냅샷은 logging-points.json에 있습니다.",
        "- 해시·seal은 보존된 파일 간 일관성 검증 자료이며, 독립적 전자서명이나 외부 증거 보관 이력을 대체하지 않습니다.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=HERE)
    parser.add_argument("--source-archive", type=Path, help="Optional exact archived source tree, project-relative layout")
    parser.add_argument("--replace", action="store_true", help="Replace only the two generated mapping documents")
    args = parser.parse_args(argv)
    run_dir = args.run_dir.resolve(strict=True)
    output = args.output_dir.resolve()
    archive = args.source_archive.resolve(strict=True) if args.source_archive else None
    if not run_dir.is_relative_to(ROOT / ".evidence"):
        raise ValueError("Run must be preserved under project .evidence")
    if not output.is_relative_to(ROOT):
        raise ValueError("Output must remain inside project")
    targets = [output / "logging-points.json", output / "logging-points.md"]
    if any(p.is_symlink() or (p.exists() and not args.replace) for p in targets):
        raise FileExistsError("Mapping exists or is a symlink; use a new preview directory or explicit --replace")
    sys.path.insert(0, str(ROOT))
    from LieMappAnalyzer.analyzer import EvidencePackage
    package = EvidencePackage(run_dir / "events.jsonl")
    metadata = package.metadata
    if metadata["attack_id"] != "ama" or metadata["engine"]["id"] != "llamacpp" or metadata.get("protocol_id") != PROTOCOL:
        raise ValueError("Wrong attack/engine/protocol identity")
    if package.seal["status"] != "completed":
        raise ValueError("Only completed sealed runs can bind this published mapping")
    disk_run = read_json(run_dir / "run.json")
    if disk_run != metadata:
        raise ValueError("run.json and sealed event metadata differ")
    mapping = read_json(HERE.parent / "logging-points.json")
    mapping["legacy_mapping"] = {"path": str((HERE.parent / "logging-points.json").relative_to(ROOT)), "sha256": digest(HERE.parent / "logging-points.json"), "preserved": True}
    native = [deepcopy(p) for p in mapping["logging_points"] if p["layer"] == "native_inference_engine"]
    if {p["logging_point_id"] for p in native} != {"AMA-LLAMACPP-LP01", "AMA-LLAMACPP-LP02", "AMA-LLAMACPP-LP03"}:
        raise ValueError("Expected three preserved native source points")
    dependencies = {str((ROOT / r["path"]).absolute()): r["sha256"] for r in metadata["code_dependencies"]}
    resolved = {}
    found = {}
    for path in EXPECTED_SOURCES:
        actual = locate_source(path, dependencies[str(path)], archive)
        resolved[str(path)] = actual
        found.update(static_points(actual, path))
    if set(found) != set(SPEC):
        raise ValueError("Source points missing: " + str(set(SPEC) - set(found)))
    points = native + [{"logging_point_id": point, "condition_ids": conditions, "layer": layer,
                        "stage": stage, "reason": reason, "source": found[point],
                        "evidence_limit": "공통 에이전트/클라이언트/실행부의 증거이다. 제공자 내부 실행의 직접 계측 또는 llamacpp 자체 보안 기능으로 간주하지 않는다."}
                       for point, (conditions, stage, layer, reason) in SPEC.items()]
    grouped = {}
    for event in package.events:
        source = event["source"]
        if source is None:
            raise ValueError("Unmapped event without a source")
        grouped.setdefault(source["logging_point_id"], []).append(event)
    unknown = set(grouped) - {p["logging_point_id"] for p in points}
    if unknown:
        raise ValueError("Observed source IDs not mapped: " + str(unknown))
    output.mkdir(parents=True, exist_ok=True)
    for point in points:
        src = point["source"]
        actual = locate_source(src["path"], src["sha256"], archive)
        point["source_snapshot"] = snapshot(actual, output)
        if point.get("original_source"):
            original = point["original_source"]
            original["source_snapshot"] = snapshot(
                locate_source(original["path"], original["sha256"], archive), output)
        events = grouped.get(point["logging_point_id"], [])
        if any(e["source"] != src or e["stage"] != point["stage"] for e in events):
            raise ValueError("Observed source/stage differs: " + point["logging_point_id"])
        point.update(observed=bool(events), observed_event_count=len(events),
                     observed_request_count=len({e["context"]["request_id"] for e in events if e["context"].get("request_id")}),
                     raw_fields=sorted({key for e in events for key in e["raw"]}),
                     raw_field_scope="Actual top-level raw keys observed in the bound run; empty for an unactivated point",
                     example_event_ids=[e["event_id"] for e in events[:3]])
    # Bind exactly the conditions version recorded by this run, not today's file.
    rules_path = ROOT / "LieMappBench/Logging-Dataset/ama/public-http-v1/conditions.json"
    rules_source = locate_source(rules_path, dependencies[str(rules_path)], archive)
    rules = read_json(rules_source)
    authority = dict(rules["library"])
    for condition in mapping["conditions"]:
        if condition["condition_id"] == "AC1":
            condition["native_evidence_limit"] = "Native tools JSON alone cannot verify platform origin or actual external invocation. Official archived platform provenance and observed HTTPS request/response nonce matching are both required."
        elif condition["condition_id"] == "DC2":
            condition["native_evidence_limit"] = "Native response contains a generated call proposal. Public HTTP client request/response evidence or an explicit pre-send rejection is required to record actual invocation status; post-send uncertainty remains raw null."
    authority["snapshot"] = snapshot(locate_source(ROOT / authority["path"], authority["sha256"], archive), output)
    supporting = preserved_supporting_sources(mapping, output, archive)
    mapping.pop("reviewed_uninstrumented_supporting_sites", None)
    mapping["request_contract"].update(
        protocol_id=PROTOCOL,
        scope="Native loopback inference request. Actual external API requests are made separately by the common agent HTTP client.",
        request_settings=deepcopy(metadata["protocol"]["request_settings"]),
        actual_tool_dispatch="Allowlisted public HTTPS GET with client-observed response, argument and nonce verification",
        native_generation_observations="Existing upstream response.__verbose diagnostics preserve pre-parser content and effective generation_settings; native tool_calls alone do not prove external invocation")
    mapping["interpretation_limits"] = [
        "This source mapping is bound to the exact completed sealed run in source_run; it is not itself an attack-success report.",
        "AC1 requires both the selected API's verified public platform provenance and confirmed external HTTPS invocation; the three native points alone cannot establish either condition.",
        "AC3 means an explicit metadata review was performed; tool JSON parsing or native grammar enforcement is not that review.",
        "The fixed-tool control provides only the designated normal tool with tool_choice=required; it is not unrestricted automatic choice.",
        "DC1/DC2 describe acquired evidence, not attack-detection accuracy. Provider-internal execution or data retention is not instrumented.",
        "Only nonstreaming n=1 requests are included. The shared public fixture is reused across engines, not newly held-out for each engine.",
        "The Q4_K_M model, native chat template and tool grammar differ from SGLang/vLLM FP32; observed differences cannot be attributed solely to inference-engine choice.",
        "Postman is a benign public test API. Tool names/descriptions and the private meaning of foo2 are local experimental overlays, not a malicious platform-published tool."]
    dependency_snapshots = []
    for path, sha in sorted(dependencies.items()):
        actual = locate_source(path, sha, archive)
        dependency_snapshots.append({"path": str(Path(path).relative_to(ROOT)), "sha256": sha,
                                     "source_snapshot": snapshot(actual, output)})
    stages = Counter(e["stage"] for e in package.events)
    finished = [e for e in package.events if e["stage"] == "ama_run_finished"]
    if len(finished) != 1 or finished[0]["raw"].get("completed_requests") != stages["ama_request_finished"]:
        raise ValueError("Completion count mismatch")
    mapping.update(protocol_id=PROTOCOL,
        scope="Actual llamacpp native inference + common public-API agent + client-side HTTPS evidence; local metadata overlays, no provider-internal instrumentation",
        condition_authority=authority, logging_points=points, supporting_sources=supporting,
        code_dependency_snapshots=dependency_snapshots,
        source_run={"run_id": package.run_id, "run_dir": str(run_dir.relative_to(ROOT)),
            "events_path": str((run_dir / "events.jsonl").relative_to(ROOT)),
            "events_sha256": package.seal["events_sha256"], "seal_sha256": digest(run_dir / "seal.json"),
            "run_metadata_sha256": digest(run_dir / "run.json"), "status": package.seal["status"],
            "dataset_split": metadata["protocol"]["split"],
            "observations_sha256": digest(run_dir / "observations.json") if (run_dir / "observations.json").is_file() else None},
        observed_counts={"events": len(package.events), "completed_requests": stages["ama_request_finished"],
            "native_events": sum(stages[s] for s in ("ama_native_tools_received", "ama_native_prompt_rendered", "ama_native_tool_calls_returned")),
            "mapped_points": len(points), "observed_points": sum(p["observed"] for p in points), "by_stage": dict(sorted(stages.items()))},
        observed_status="실제 완료된 원시 실행에 연결됨. source_run 및 지점별 관측 수를 확인하십시오.",
        operational_boundaries=rules["definitions"],
        native_patch_sha256=digest(HERE.parent / "native-instrumentation.patch"),
        native_patch_snapshot=snapshot(HERE.parent / "native-instrumentation.patch", output),
        freeze={"created_utc": datetime.now(timezone.utc).isoformat(), "utility_sha256": digest(__file__),
                "utility_snapshot": snapshot(Path(__file__), output),
                "seal_validation": "EvidencePackage complete event chain/artifact/seal verification",
                "claim_limit": "Source mapping binds recorded evidence; it does not independently recompute attack outcomes or replace protocol verification."})
    # Remove obsolete generic binding if inherited from an earlier preview.
    mapping.pop("runtime_evidence", None)
    for path, content in zip(targets, [json.dumps(mapping, ensure_ascii=False, indent=2, allow_nan=False) + "\n", make_markdown(mapping)]):
        with path.open("w" if args.replace else "x", encoding="utf-8") as stream:
            stream.write(content)
    print(json.dumps({"run_id": package.run_id, "output": str(output), "points": len(points),
                      "observed": mapping["observed_counts"]["observed_points"]}))


if __name__ == "__main__":
    main()
