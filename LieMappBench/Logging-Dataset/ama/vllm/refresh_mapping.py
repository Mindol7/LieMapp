"""Bind native, shared-agent and tool logging reasons to exact AMA vLLM sources."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())
SCRIPT = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama"
SOURCES = [SCRIPT / "shared/ama_protocol.py", SCRIPT / "vllm/run.py"]
SPEC = {
    "AMA-AGENT-LP01": (["DC1"], "ama_tool_registry", "실제 후보와 로컬 합성 출처를 기록한다. 에이전트 계층 기록이며 엔진 조건 판정에 사용하지 않는다."),
    "AMA-AGENT-LP02": (["AC1"], "ama_selection_policy", "자동 선택과 정상 도구 고정 정책을 실제 제공한 후보 목록과 함께 기록한다."),
    "AMA-AGENT-LP03": ([], "ama_metadata_review", "별도 메타데이터 검토 수행 여부·검사 대상·제외 결정과 근거를 기록한다. 구문 검사와 구분한다."),
    "AMA-AGENT-LP04": (["DC1"], "ama_tool_selected", "모델이 반환한 함수명을 정확한 후보 메타데이터와 연결한다. 선택하지 않은 도구를 선택한 것으로 만들지 않는다."),
    "AMA-AGENT-LP05": (["DC2"], "ama_tool_execution", "호출 제안과 실제 함수 호출을 구분하고 인자 원문·파싱 값·수신 영수증 또는 차단 이유를 기록한다."),
    "AMA-AGENT-LP06": (["DC2"], "ama_tool_call_outcome", "개별 호출의 검증·실행 결과를 요청 ID와 호출 ID로 연결한다. 잘못된 인자를 임의 보정하지 않는다."),
    "AMA-AGENT-LP07": (["AC1", "DC1"], "ama_request_started", "전체 요청 메시지·후보·선택 정책·샘플링 설정을 전송 전에 보존해 엔진 입력과 대조한다."),
    "AMA-AGENT-LP08": (["DC1", "DC2"], "ama_request_finished", "선택·호출·합성 비밀 전달을 따로 기록하고 수신 측 원시 증거로 다시 검증한다."),
    "AMA-TOOL-LP01": (["DC2"], "ama_tool_receiver", "실제로 진입한 로컬 함수 내부에서 수신 인자와 영수증을 기록해 모델 출력 및 호출자 기록과 대조한다."),
    "AMA-RUN-LP01": ([], "ama_run_started", "데이터셋과 전체 요청 순서를 결과 관찰 전에 고정한다."),
    "AMA-RUN-LP02": ([], "ama_server_started", "실제로 준비된 vLLM 서버의 실행 명령과 로컬 주소를 보존한다."),
    "AMA-RUN-LP03": ([], "ama_run_finished", "계획한 요청의 완료 수와 종료 상태를 기록한다."),
    "AMA-RUN-LP04": ([], "ama_run_failed", "실행 오류를 공격 방어 또는 엔진 안전과 구분하여 기록한다."),
    "AMA-RUN-LP05": ([], "ama_process_output", "모델 로드·CPU 실행·설정을 확인할 실제 서버 출력 원문과 해시를 보존한다."),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(path):
    sha = digest(path)
    target = HERE / "source-snapshots" / sha[:16] / path.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if digest(target) != sha:
            raise ValueError("Snapshot collision; refusing overwrite")
    else:
        with target.open("xb") as output, path.open("rb") as original:
            for chunk in iter(lambda: original.read(1024 * 1024), b""):
                output.write(chunk)
    return target.relative_to(HERE).as_posix()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    target = HERE / "logging-points.json"
    mapping = json.loads(target.read_text(encoding="utf-8"))
    mapping["logging_points"] = [p for p in mapping["logging_points"] if p["logging_point_id"] not in SPEC]
    found = {}
    for path in SOURCES:
        for function in (n for n in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(n, ast.FunctionDef)):
            for node in ast.walk(function):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "source"
                        and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in SPEC):
                    point = node.args[0].value
                    if point in found:
                        raise ValueError("Duplicate source point: " + point)
                    found[point] = {"path": str(path), "function": function.name, "line": node.lineno,
                                    "logging_point_id": point, "sha256": digest(path)}
    if set(found) != set(SPEC):
        raise ValueError("Missing logging points: " + str(set(SPEC) - set(found)))
    for point, (conditions, stage, reason) in SPEC.items():
        mapping["logging_points"].append({"logging_point_id": point, "condition_ids": conditions,
            "layer": "tool_receiver" if point.startswith("AMA-TOOL") else "agent_harness",
            "stage": stage, "reason": reason, "source": found[point], "observed": False,
            "evidence_limit": "공통 연구용 에이전트의 증거이며 vLLM 고유 기능으로 간주하지 않는다."})
    for point in mapping["logging_points"]:
        path = Path(point["source"]["path"])
        if digest(path) != point["source"]["sha256"]:
            raise ValueError("Source changed since mapping: " + str(path))
        point["source_snapshot"] = snapshot(path)
    rules = json.loads((HERE.parent / "conditions.json").read_text(encoding="utf-8"))
    authority = dict(rules["library"])
    workbook = ROOT / authority["path"]
    if digest(workbook) != authority["sha256"]:
        raise ValueError("Workbook changed since condition definition")
    authority["snapshot"] = snapshot(workbook)
    mapping["condition_authority"] = authority
    if args.log:
        sys.path.insert(0, str(ROOT))
        from LieMappAnalyzer.analyzer import EvidencePackage
        package = EvidencePackage(args.log)
        if package.metadata["attack_id"] != "ama" or package.metadata["engine"]["id"] != "vllm":
            raise ValueError("Wrong run identity")
        for point in mapping["logging_points"]:
            events = [e for e in package.events if e["source"] and e["source"]["logging_point_id"] == point["logging_point_id"]]
            if any(e["source"] != point["source"] for e in events):
                raise ValueError("Observed source differs from mapped source: " + point["logging_point_id"])
            point.update(observed=bool(events), observed_event_count=len(events))
        mapping["runtime_evidence"] = {"run_id": package.run_id, "events_path": str(package.path),
            "sha256": package.seal["events_sha256"], "status": package.seal["status"]}
        observed = sum(point["observed"] for point in mapping["logging_points"])
        mapping["observed_status"] = (
            f"실제 원시 실행에 연결됨: 상태 {package.seal['status']}, "
            f"로깅 지점 {observed}/{len(mapping['logging_points'])}개 관측. "
            "실행 ID와 원시 증거 해시는 runtime_evidence를 확인하십시오.")
    else:
        mapping.pop("runtime_evidence", None)
        for point in mapping["logging_points"]:
            point.update(observed=False, observed_event_count=0)
        mapping["observed_status"] = "소스 매핑 준비 완료. 실제 관측 여부는 --log로 원시 실행을 연결한 뒤 확인합니다."
    target.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = HERE / "logging-points.md"
    text = md.read_text(encoding="utf-8").split("\n## 공통 에이전트·도구의 실제 로깅 지점")[0]
    lines = ["", "## 공통 에이전트·도구의 실제 로깅 지점", "",
             "원본 엔진이 아닌 공통 실험 모듈과 vLLM 실행부의 지점입니다. 정확한 파일·스냅샷·해시는 JSON 지도에 보존합니다.", "",
             "| 지점 | 소스 함수·행 | 조건 | 로깅 근거 |", "|---|---|---|---|"]
    for point, (conditions, stage, reason) in SPEC.items():
        src = found[point]
        lines.append(f'| {point} | `{Path(src["path"]).name}:{src["function"]}:{src["line"]}` | {", ".join(conditions) or "실행 무결성"} | {reason} |')
    lines += ["", "해시와 스냅샷은 변경 확인·재현을 위한 자료이며 외부 서명이나 독립적인 증거 보관 이력을 대체하지 않습니다.", ""]
    md.write_text(text.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    print(json.dumps({"points": len(mapping["logging_points"]), "runtime_bound": bool(args.log)}))


if __name__ == "__main__":
    main()
