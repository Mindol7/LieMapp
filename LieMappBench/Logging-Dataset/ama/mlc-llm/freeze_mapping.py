"""Map actual MLC source hooks, and optionally bind a completed sealed AMA run.

Static review is not runtime evidence. Uses the unchanged common logger and
Analyzer schema. Creates new artifacts; no original engine/source is modified.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
SCRIPT = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm"
ENGINE = ROOT / "Instrumented-LIE/ama/mlc-llm/engine"
PROTOCOL = "ama-public-http-mlc-native-v1"
SPEC = {
    "AMA-MLC-PUBLIC-LP01": (["DC1"], "ama_tool_registry", "agent_harness",
        "공식 공개 API 계보와 로컬 메타데이터 어댑터를 분리하여 후보 목록을 기록한다. 후보의 출처 표시는 참고 기록이며, 추론 엔진은 도구의 출처 정보를 전달받지 않으므로 엔진 조건의 판정 근거가 아니다."),
    "AMA-MLC-PUBLIC-LP02": ([], "ama_metadata_review", "agent_harness",
        "메타데이터 검토 수행 여부·대상·제외 결과를 기록한다. 알려진 합성 비밀 필드 검사라는 제한적 대조군이며 범용 방어로 해석하지 않는다."),
    "AMA-MLC-PUBLIC-LP03": (["AC1"], "ama_selection_policy", "agent_harness",
        "실제 후보 이름과 auto/required 모드를 기록하여 자율 선택과 정상 도구 하나만 허용한 고정 선택을 구분한다."),
    "AMA-MLC-PUBLIC-LP04": (["AC1", "DC1"], "ama_request_started", "agent_harness",
        "HTTP 전송 전 메시지·도구 메타데이터·샘플링 설정과 요청 해시를 보존하여 엔진의 실제 수신·템플릿 결과와 대조한다."),
    "AMA-MLC-PUBLIC-LP05": (["DC1"], "ama_tool_selected", "agent_harness",
        "실제 모델이 선택한 함수 이름을 후보의 정확한 설명·매개변수 스키마·공개 API 계보에 연결한다. 선택과 실행은 구분한다."),
    "AMA-MLC-PUBLIC-LP06": (["DC2"], "ama_tool_execution", "agent_harness",
        "도구별 실제 외부 호출 확인·인자·응답 또는 호출 전 차단을 집계한다. 전송 후 확인되지 않은 호출은 원시 null로 보존한다."),
    "AMA-MLC-PUBLIC-LP07": (["DC2"], "ama_tool_provenance", "agent_harness",
        "실제 선택된 도구의 공개 플랫폼 계보와 확인된 HTTPS 호출 증거를 함께 연결한다. 공개 출처 표시는 에이전트 계층 기록이며 엔진 조건 판정에 사용하지 않는다."),
    "AMA-MLC-PUBLIC-LP08": (["DC1", "DC2"], "ama_request_finished", "agent_harness",
        "공격 역할 도구 선택·실행·합성 canary 전달을 분리 집계하고 원시 응답을 보존한다. 단일 성공 사례를 메타데이터의 인과적 효과로 단정하지 않는다."),
    "AMA-MLC-HTTP-LP01": (["DC2"], "ama_http_request", "http_client",
        "허용된 공식 공개 API로 전송할 실제 GET 경로·query·헤더·nonce를 기록하여 모델 인자와 외부 요청을 연결한다. 전송 의도 자체는 수신 증거가 아니다."),
    "AMA-MLC-HTTP-LP02": (["DC2"], "ama_http_response", "http_client",
        "제공자가 반환한 실제 HTTPS 응답 원문·TLS 정보·echo 및 nonce를 보존한다. 이는 클라이언트가 수집한 영수증이며 제공자 내부 함수의 계측 로그가 아니다."),
    "AMA-MLC-HTTP-LP03": (["DC2"], "ama_tool_call_outcome", "http_client",
        "개별 호출의 원문 인자·검증·전송·확인 결과를 request_id/tool_call_id/http_attempt_id로 연결한다. 부정확한 인자를 임의 보정하지 않는다."),
    "AMA-MLC-RUN01": ([], "ama_run_started", "experiment_runner",
        "데이터셋·공개 출처 스냅샷·전체 요청 순서를 실행 전에 고정한다."),
    "AMA-MLC-RUN02": ([], "ama_server_started", "experiment_runner",
        "실제로 준비된 로컬 CPU MLC-LLM 서버의 실행 명령과 주소를 기록한다."),
    "AMA-MLC-RUN03": ([], "ama_run_finished", "experiment_runner",
        "계획한 요청의 완료 수와 정상 종료 상태를 기록한다."),
    "AMA-MLC-RUN04": ([], "ama_run_failed", "experiment_runner",
        "실행 오류를 공격 방어 또는 엔진 안전 판정과 구분하여 보존한다."),
    "AMA-MLC-RUN05": ([], "ama_process_output", "experiment_runner",
        "서버 출력 원문·해시·자체 프로세스 트리의 TCP 수신 주소 점검을 보존한다."),
}

SPEC.update({
    "AMA-MLC-LP01": (["AC1", "DC1"], "ama_native_tools_received", "native_inference_engine",
        "실제 MLC 요청 수신부에서 도구 이름·설명·스키마, 자율/고정 선택 설정 및 API 호환 변환 전후를 기록한다. 공개 API 출처와 실제 호출은 이 지점만으로 증명하지 않는다."),
    "AMA-MLC-LP02": (["AC1", "AC2", "DC1"], "ama_native_prompt_rendered", "native_inference_engine",
        "도구 메타데이터가 포함된 실제 템플릿 결과와 인코딩된 입력 토큰을 보존한다. 기본 Qwen2 템플릿이 아닌 명시적 Python 호출 형식 설정을 사용했음을 확인한다."),
    "AMA-MLC-LP03": (["DC1", "DC2"], "ama_native_tool_calls_returned", "native_inference_engine",
        "네이티브 생성 Python 원문·출력 토큰·파싱된 인자 사전·실제 C++ 생성 설정·최종 응답을 함께 기록한다. 파싱된 사전을 모델이 생성한 원본 JSON 문자열로 표현하지 않으며, 외부 실행 증거와 별도로 연결한다."),
})


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(path, output):
    path = Path(path).resolve(strict=True)
    sha = digest(path)
    relative = Path("source-snapshots") / sha[:16] / path.name
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_symlink() or digest(target) != sha:
            raise ValueError("Snapshot collision")
    else:
        with path.open("rb") as source, target.open("xb") as destination:
            shutil.copyfileobj(source, destination)
    return relative.as_posix()


def locate_points(path):
    tree = ast.parse(path.read_text())
    found = {}
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            point = None
            if isinstance(node.func, ast.Name) and node.func.id == "source" and node.args:
                point = node.args[0].value if isinstance(node.args[0], ast.Constant) else None
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "emit"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "liemapp_ama"
                    and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)):
                point = node.args[1].value
            if point in SPEC:
                if point in found:
                    raise ValueError("Duplicate source point")
                found[point] = {"path": str(path.resolve()), "function": function.name,
                               "line": node.lineno, "logging_point_id": point, "sha256": digest(path)}
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=HERE)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not output.is_relative_to(ROOT):
        raise ValueError("Mapping must stay within project")
    output.mkdir(parents=True, exist_ok=True)
    stem = "logging-points" if args.run_dir else "source-review"
    targets = [output / (stem + ".json"), output / (stem + ".md")]
    if any(p.exists() or p.is_symlink() for p in targets):
        raise FileExistsError("Use a fresh mapping output directory")
    rules_path = HERE / "public-http-native-v1/conditions.json"
    rules = json.loads(rules_path.read_text())
    authority = dict(rules["library"])
    if digest(ROOT / authority["path"]) != authority["sha256"]:
        raise ValueError("Workbook changed")
    authority["snapshot"] = snapshot(ROOT / authority["path"], output)
    sources = [SCRIPT / "mlc_protocol.py", SCRIPT / "run_public.py",
               ENGINE / "python/mlc_llm/serve/engine_base.py"]
    found = {}
    for path in sources:
        found.update(locate_points(path))
    if set(found) != set(SPEC):
        raise ValueError("Missing source hooks: " + str(set(SPEC) - set(found)))
    package = None
    if args.run_dir:
        module_spec = importlib.util.spec_from_file_location("mlc_mapping_protocol", SCRIPT / "mlc_protocol.py")
        protocol = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(protocol)
        package, finished = protocol.verify_run(args.run_dir.resolve(strict=True))
        if package.metadata["engine"]["id"] != "mlc-llm":
            raise ValueError("Wrong engine")
    grouped = {}
    if package:
        for event in package.events:
            grouped.setdefault(event["source"]["logging_point_id"], []).append(event)
        if set(grouped) - set(SPEC):
            raise ValueError("Unmapped raw source point")
    points = []
    for identifier, (conditions, stage, layer, reason) in SPEC.items():
        source = found[identifier]
        events = grouped.get(identifier, [])
        if any(e["source"] != source or e["stage"] != stage for e in events):
            raise ValueError("Raw source/function/line/hash mismatch: " + identifier)
        point = {"logging_point_id": identifier, "condition_ids": conditions, "stage": stage,
                 "layer": layer, "reason": reason, "source": source,
                 "source_snapshot": snapshot(source["path"], output),
                 "observed": bool(events), "observed_event_count": len(events),
                 "raw_fields": sorted({key for e in events for key in e["raw"]}),
                 "example_event_ids": [e["event_id"] for e in events[:3]],
                 "evidence_limit": "모델의 도구 호출 제안과 클라이언트 측 실제 HTTPS 호출 증거를 구분한다. 관측 전 정적 매핑은 조건 충족 증거가 아니다."}
        if layer == "native_inference_engine":
            original = ROOT / "LIE/mlc-llm/python/mlc_llm/serve/engine_base.py"
            point["original_source"] = {"path": str(original.relative_to(ROOT)),
                "function": source["function"], "sha256": digest(original),
                "source_snapshot": snapshot(original, output)}
        points.append(point)
    support_paths = [ENGINE / "python/mlc_llm/liemapp_ama.py", ENGINE / "python/mlc_llm/serve/engine.py",
        ENGINE / "python/mlc_llm/protocol/openai_api_protocol.py",
        ENGINE / "python/mlc_llm/protocol/conversation_protocol.py",
        ENGINE / "python/mlc_llm/conversation_template/qwen2.py",
        SCRIPT / "service.py", SCRIPT / "native_runtime.py", SCRIPT / "mlc_protocol.py",
        SCRIPT.parent / "shared/public_http_protocol.py",
        ROOT / "LieMappBench/Logging-Dataset/logger.py", ROOT / "LieMappAnalyzer/analyzer.py", rules_path]
    supporting = [{"path": str(p.relative_to(ROOT)), "sha256": digest(p),
                   "source_snapshot": snapshot(p, output)} for p in support_paths]
    dependencies = []
    if package:
        for row in package.metadata["code_dependencies"]:
            path = ROOT / row["path"]
            if digest(path) != row["sha256"]:
                raise ValueError("Frozen code dependency changed")
            dependencies.append({**row, "source_snapshot": snapshot(path, output)})
    binding = None
    counts = {}
    if package:
        run_dir = args.run_dir.resolve()
        binding = {"run_id": package.run_id, "run_dir": str(run_dir.relative_to(ROOT)),
                   "events_path": str((run_dir / "events.jsonl").relative_to(ROOT)),
                   "events_sha256": package.seal["events_sha256"], "status": package.seal["status"],
                   "seal_sha256": digest(run_dir / "seal.json"), "run_metadata_sha256": digest(run_dir / "run.json"),
                   "dataset_split": package.metadata["protocol"]["split"],
                   "observations_sha256": digest(run_dir / "observations.json")}
        stages = Counter(e["stage"] for e in package.events)
        counts = {"events": len(package.events), "completed_requests": stages["ama_request_finished"],
                  "native_events": sum(stages[s] for s in ("ama_native_tools_received", "ama_native_prompt_rendered", "ama_native_tool_calls_returned")),
                  "mapped_points": len(points), "observed_points": sum(p["observed"] for p in points),
                  "by_stage": dict(stages)}
    result = {"schema_version": "1.0.0", "attack_id": "ama", "engine_id": "mlc-llm", "protocol_id": PROTOCOL,
              "source_commit": subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip(),
              "scope": "Configured native MLC Python-call inference; unchanged common AC/DC and actual allowlisted HTTPS evidence",
              "condition_authority": authority, "conditions": [{"condition_id": c["id"], "type": c["kind"], "text": c["text"]} for c in rules["conditions"]],
              "logging_points": points, "supporting_sources": supporting, "code_dependency_snapshots": dependencies,
              "source_run": binding, "observed_counts": counts,
              "status": "bound_to_completed_native_run" if package else "static_source_review_only_not_runtime_evidence",
              "limitations": ["기본 Qwen2 템플릿에는 도구 정보가 포함되지 않아 별도 Conversation 설정을 사용한다.",
                  "MLC named 고정 선택은 다른 엔진의 required 문법 강제와 같지 않다.",
                  "Python 호출 원문·네이티브 인자 사전·HTTPS 전송 인자를 구분하며 보정하지 않는다.",
                  "AC3 T는 검토 수행, DC T는 증거 확보이며 공격 성공률 또는 안전 인증이 아니다."],
              "freeze": {"created_utc": datetime.now(timezone.utc).isoformat(), "utility_sha256": digest(__file__),
                         "utility_snapshot": snapshot(Path(__file__), output)}}
    lines = ["# AMA · MLC-LLM 로깅 지점", "",
             "실제 소스 코드의 어느 지점에서 무엇을 기록하며, 그 기록이 어떤 조건의 근거가 되는지 정리합니다.", "",
             "**자료 상태:** " + ("완료된 네이티브 실행 및 봉인 원시 로그와 대조 완료" if package else "정적 소스 분석 — 실행 성공이나 조건 충족을 의미하지 않음"), ""]
    if binding:
        lines += ["- 실행 ID: `" + binding["run_id"] + "`",
                  f'- 완료 요청 {counts["completed_requests"]}개 / 네이티브 이벤트 {counts["native_events"]}개',
                  "- 원시 로그 SHA-256: `" + binding["events_sha256"] + "`", ""]
    for native in (True, False):
        lines += ["## " + ("엔진 내부" if native else "실험 에이전트·HTTPS 클라이언트"), "",
                  "| 지점 | 함수·행 | 관련 조건 | 관측 수 | 기록 이유 |",
                  "|---|---|---|---:|---|"]
        for point in points:
            if (point["layer"] == "native_inference_engine") != native:
                continue
            source = point["source"]
            lines.append(f'| `{point["logging_point_id"]}` | `{Path(source["path"]).name}:{source["function"]}:{source["line"]}` | {", ".join(point["condition_ids"]) or "실행 무결성"} | {point["observed_event_count"] if package else "미실행"} | {point["reason"]} |')
        lines += [""]
    lines += ["## 해석 시 주의사항", ""] + ["- " + note for note in result["limitations"]]
    lines += ["", "정확한 경로·소스 해시·원문 스냅샷·원시 필드·예시 이벤트 ID는 같은 이름의 JSON에 있습니다.", ""]
    for path, text in zip(targets, [json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n", "\n".join(lines)]):
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text)
    print(json.dumps({"status": result["status"], "points": len(points), "output": str(output)}))


if __name__ == "__main__":
    main()
