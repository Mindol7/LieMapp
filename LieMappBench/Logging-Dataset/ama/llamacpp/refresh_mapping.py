"""Bind documented AMA logging reasons to exact source snapshots and observations."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
RUNNER = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/llamacpp/run.py"
SPEC = {
    "AMA-AGENT-LP01": (["DC1"], "ama_tool_registry", "도구 등록부의 실제 출처와 후보 정의를 보존한다. 로컬 작성 자료를 공개 플랫폼에서 수집한 도구로 가장하지 않기 위한 에이전트 계층 기록이다."),
    "AMA-AGENT-LP02": (["AC1"], "ama_selection_policy", "추론 요청을 만들기 전에 적용한 자동 선택 또는 고정 도구 정책을 기록한다. 엔진에 실제 전달한 선택 모드와 교차 확인한다."),
    "AMA-AGENT-LP03": ([], "ama_metadata_review", "명시적 메타데이터 검토가 실제 수행됐는지와 제외한 도구·근거를 기록한다. JSON 형식 검사 또는 시스템 지시문을 별도 보안 검토로 오인하지 않는다."),
    "AMA-AGENT-LP04": (["DC1"], "ama_tool_selected", "엔진이 실제 반환한 함수명을 제공한 도구의 유일한 정의와 연결하여 선택된 도구의 전체 메타데이터를 기록한다."),
    "AMA-AGENT-LP05": (["DC2"], "ama_tool_execution", "호출 제안과 실제 실행 결과를 구분하고 원본 인자 문자열·파싱 인자·실행 영수증 또는 차단 이유를 함께 보존한다."),
    "AMA-AGENT-LP06": (["DC2"], "ama_tool_call_outcome", "개별 호출의 검증·실행 결과를 요청 ID와 호출 ID로 연결한다. 형식 오류 또는 허용되지 않은 도구를 임의로 보정해 실행하지 않는다."),
    "AMA-AGENT-LP07": (["AC1", "DC1"], "ama_request_started", "완전한 HTTP 요청, 도구 후보, 메시지, 샘플링 설정을 전송 전에 보존하여 엔진 입력과 비교한다."),
    "AMA-AGENT-LP08": (["DC1", "DC2"], "ama_request_finished", "도구 선택·실제 실행·합성 비밀 전달을 별도 항목으로 기록한다. 결과 집계기는 원시 응답과 함수 수신 기록으로 이 값들을 다시 검증한다."),
    "AMA-TOOL-LP01": (["DC2"], "ama_tool_receiver", "실제로 진입한 로컬 도구 함수 내부에서 받은 인자와 영수증을 기록한다. 호출자가 실행했다고 기록한 사실과 수신자가 받은 값을 교차 확인하기 위한 핵심 지점이다."),
    "AMA-RUN-LP01": ([], "ama_run_started", "데이터셋 전체와 요청 순서를 결과 관찰 전에 고정하여 사후 사례 선택 및 입력 변경을 확인할 수 있게 한다."),
    "AMA-RUN-LP02": ([], "ama_server_started", "실제 서버 명령·로컬 주소를 보존한다. 설치 또는 import 성공만으로 모델 실행을 주장하지 않는다."),
    "AMA-RUN-LP03": ([], "ama_run_finished", "계획한 요청의 완료 수를 기록하고 평가 집계 시 실제 요청 기록과 대조한다."),
    "AMA-RUN-LP04": ([], "ama_run_failed", "실행 오류를 공격 방어 또는 엔진 안전과 구분하여 기록한다."),
    "AMA-RUN-LP05": ([], "ama_process_output", "실제 서버 표준 출력·오류의 원문과 파일 해시를 보존하여 모델 및 실행 설정을 점검한다."),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(path):
    sha = digest(path)
    destination = HERE / "source-snapshots" / sha[:16] / path.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if digest(destination) != sha:
            raise ValueError("Snapshot collision; refusing to overwrite")
    else:
        with destination.open("xb") as output, path.open("rb") as original:
            for chunk in iter(lambda: original.read(1024 * 1024), b""):
                output.write(chunk)
    return destination.relative_to(HERE).as_posix()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    path = HERE / "logging-points.json"
    mapping = json.loads(path.read_text(encoding="utf-8"))
    mapping["logging_points"] = [p for p in mapping["logging_points"] if p["logging_point_id"].startswith("AMA-LLAMACPP-")]
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    found = {}
    for function in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(function):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "source"
                    and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in SPEC):
                identifier = node.args[0].value
                if identifier in found:
                    raise ValueError("Duplicate logging point: " + identifier)
                found[identifier] = {"path": str(RUNNER), "function": function.name, "line": node.lineno,
                                     "logging_point_id": identifier, "sha256": digest(RUNNER)}
    if set(found) != set(SPEC):
        raise ValueError("Documented logging points differ from runner source")
    for identifier, (conditions, stage, reason) in SPEC.items():
        mapping["logging_points"].append({"logging_point_id": identifier, "condition_ids": conditions,
            "layer": "tool_receiver" if identifier.startswith("AMA-TOOL") else "agent_harness",
            "stage": stage, "reason": reason, "source": found[identifier],
            "source_snapshot": snapshot(RUNNER), "observed": False,
            "evidence_limit": "연구용 로컬 에이전트/도구에서 수집한 증거이며 llama.cpp 고유 기능으로 간주하지 않는다."})
    for point in mapping["logging_points"]:
        source = point["source"]
        source_path = Path(source["path"])
        if digest(source_path) != source["sha256"]:
            raise ValueError("Source changed since mapping: " + source["path"])
        point["source_snapshot"] = snapshot(source_path)
    workbook = ROOT / "LieMappBench/Attack-Library/attack_library.xlsx"
    if digest(workbook) != mapping["condition_authority"]["sha256"]:
        raise ValueError("Workbook changed since condition definition")
    mapping["condition_authority"]["snapshot"] = snapshot(workbook)
    mapping["scope"] = "Native inference, agent policy and local tool receiver mapped separately; shared logger and shared analyzer."
    if args.log:
        sys.path.insert(0, str(ROOT))
        from LieMappAnalyzer.analyzer import EvidencePackage
        package = EvidencePackage(args.log)
        if package.metadata["attack_id"] != "ama" or package.metadata["engine"]["id"] != "llamacpp":
            raise ValueError("Wrong run identity")
        for point in mapping["logging_points"]:
            events = [e for e in package.events if e["source"] and e["source"]["logging_point_id"] == point["logging_point_id"]]
            if any(e["source"] != point["source"] for e in events):
                raise ValueError("Observed source differs from mapped bytes: " + point["logging_point_id"])
            point["observed"] = bool(events)
            point["observed_event_count"] = len(events)
        mapping["runtime_evidence"] = {"run_id": package.run_id, "events_path": str(package.path),
                                       "sha256": package.seal["events_sha256"], "status": package.seal["status"]}
    path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path = HERE / "logging-points.md"
    text = md_path.read_text(encoding="utf-8").split("\n## 에이전트·도구 수신부의 실제 로깅 지점")[0]
    lines = ["", "## 에이전트·도구 수신부의 실제 로깅 지점", "",
             "아래 지점은 원본 엔진이 아닌 연구용 실행부에 속합니다. `run.py`는 Attack Script 디렉터리의 실행 스크립트이며, 정확한 경로·소스 스냅샷·해시는 JSON 지도에 있습니다.", "",
             "| 지점 | 소스 함수·행 | 조건 | 로깅 이유 |", "|---|---|---|---|"]
    for identifier, (conditions, stage, reason) in SPEC.items():
        src = found[identifier]
        lines.append(f'| {identifier} | `{src["function"]}:{src["line"]}` | {", ".join(conditions) or "실행 무결성"} | {reason} |')
    lines += ["", "소스 스냅샷과 엑셀 스냅샷은 수집 시점의 내용을 보존합니다. 파일 해시는 변경 확인용이며 외부 서명·신뢰 타임스탬프를 대체하지 않습니다.", ""]
    md_path.write_text(text.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    print(json.dumps({"mapping": str(path), "points": len(mapping["logging_points"]), "runtime_bound": bool(args.log)}))


if __name__ == "__main__":
    main()
