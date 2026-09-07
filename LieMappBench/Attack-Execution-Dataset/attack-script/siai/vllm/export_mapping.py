"""Freeze observed vLLM source mappings from validated, sealed native evidence.

This exporter documents logging reasons; all AC/DC decisions remain exclusively
in the unchanged, engine-independent Analyzer and frozen condition rules.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "LieMappBench").is_dir())
OUT = ROOT / "LieMappBench/Logging-Dataset/siai/vllm"
REASONS = {
    "source_snapshot": ([], "실행 당시 모델 hook·observer·runner 소스 전체 바이트를 SHA-256과 함께 보존하여 행번호의 버전 종속성을 해결한다."),
    "input_received": (["AC2"], "공격 입력 파일 전체 바이트와 RGB 원본 값을 보존하고 clean/attack·증강 계보를 request/input/pair ID로 연결한다."),
    "request_started": ([], "실제 native 프로세스 명령과 요청 목록을 기록하여 단일 프로세스 재사용 및 격리 범위를 확인한다."),
    "engine_initialized": ([], "각 요청이 실제로 사용한 기존 LLMEngine·PID·로드된 CPU extension·버전·chat template을 기록한다. 요청별 출처 관측이며 이벤트 수는 엔진 생성 횟수가 아니다."),
    "processor_output": (["AC2", "DC1"], "실제 vLLM processor가 만든 5개 NCHW 이미지 타일 전체를 기록한다. 다음 encoder 입력과 byte-equivalent 수치 일치를 검증하는 출발점이다."),
    "encoder_dispatch": (["AC2", "DC1"], "native model이 전달받은 padding 필터 이전 픽셀을 보존한다. 전처리 patch-count 및 전달 경계 문제를 별도 진단한다."),
    "encoder_input": (["AC1", "AC2", "DC1"], "dtype·padding 처리가 끝난 뒤 실제 vision encoder가 받을 모든 픽셀을 보존한다. clean/attack 차이가 남는지 원본 텐서로 비교한다."),
    "projected_embedding": (["AC1", "AC3", "DC2", "DC3"], "성공한 vision encoder와 connector 이후 실제 320×576 visual embedding을 보존한다. 동일 계층의 clean/attack·증강 cosine 비교에 사용한다."),
    "decoder_input": (["AC1", "AC3", "DC2"], "기존 native merge가 실제 text decoder에 전달하는 visual rows를 진입 직전에 snapshot하고 forward 성공 후 기록한다. zero 개입에서 실제 소비한 값이 0인지 확인한다."),
    "generation_output": (["AC3"], "동일 활성 요청의 첫 native logits 전체와 공개 LLM.generate의 생성 텍스트·토큰을 연결한다. 두 수집 위치를 raw에서 분리하며 로그 차이를 공격 성공과 동일시하지 않는다."),
    "runtime_output": ([], "실제 자식 프로세스의 종료코드·시간·stdout/stderr 전체 바이트를 남겨 계측 오류와 엔진 실패도 숨기지 않는다."),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def preserve(directory, name, data, expected):
    if sha(data) != expected:
        raise ValueError(f"Snapshot bytes disagree with recorded hash: {name}")
    path = directory / f"{expected}-{Path(name).name}"
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"Conflicting immutable snapshot: {path}")
    else:
        with path.open("xb") as stream:
            stream.write(data)
    return path.relative_to(OUT).as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", action="append", type=Path, required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    if Path(args.name).name != args.name:
        raise ValueError("Output name must be one filename component")
    targets = [OUT / (args.name + suffix) for suffix in (".json", ".md")]
    if any(path.exists() for path in targets):
        raise FileExistsError("Existing mapping is immutable; choose a new name")
    spec = importlib.util.spec_from_file_location("mapping_common_analyzer", ROOT / "LieMappAnalyzer/analyzer.py")
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    review = json.loads((OUT / "source-review.json").read_text())
    snapshots = OUT / "source-snapshots"
    snapshots.mkdir(exist_ok=True)
    points, runs, files = {}, [], []
    for directory in args.run_dir:
        package = analyzer.EvidencePackage(directory / "events.jsonl")
        if package.seal["status"] != "completed":
            raise ValueError("Only completed native runs are eligible for final observed mapping")
        source_index = {}
        for event in package.events:
            if event["stage"] != "source_snapshot":
                continue
            artifact = event["artifacts"]["file_bytes"]
            data = np.load(package.root / artifact["path"], allow_pickle=False).tobytes()
            expected = event["raw"]["sha256"]
            saved = preserve(snapshots, event["raw"]["path"], data, expected)
            source_index[expected] = saved
            files.append({"run_id": package.run_id, "source_path": event["raw"]["path"],
                          "sha256": expected, "snapshot": saved,
                          "raw_event_id": event["event_id"], "raw_artifact": artifact})
        logger_path = ROOT / "LieMappBench/Logging-Dataset/logger.py"
        logger_hash = package.metadata["logger_sha256"]
        saved = preserve(snapshots, logger_path.name, logger_path.read_bytes(), logger_hash)
        files.append({"run_id": package.run_id, "source_path": str(logger_path),
                      "sha256": logger_hash, "snapshot": saved})
        native = package.metadata["engine"]["native_binary_sha256"]
        for path, expected in native.items():
            if sha(Path(path).read_bytes()) != expected:
                raise ValueError(f"Native CPU binary changed after collection: {path}")
        runs.append({"path": str(package.root), "seal": package.seal,
                     "runtime": package.metadata["runtime"],
                     "model": package.metadata["model"],
                     "native_binaries": native,
                     "build_run_id": package.metadata["engine"]["build_run_id"],
                     "kernel_verification_run_id": package.metadata["engine"]["kernel_verification_run_id"]})
        for event in package.events:
            source = event["source"]
            if source is None:
                continue
            stage = event["stage"]
            if stage not in REASONS:
                raise ValueError(f"Every observed logging stage needs an explicit reason: {stage}")
            key = (source["logging_point_id"], source["sha256"], source["line"])
            if source["sha256"] not in source_index:
                raise ValueError("Observed source has no matching run-time byte snapshot")
            if key not in points:
                conditions, reason = REASONS[stage]
                points[key] = {"logging_point_id": source["logging_point_id"],
                    "stage": stage, "condition_ids": conditions, "reason": reason,
                    "source": source, "source_snapshot": source_index[source["sha256"]],
                    "observed": True, "observed_events": 0,
                    "example": {"run_dir": str(package.root), "event_id": event["event_id"],
                                "sequence": event["sequence"], "context": event["context"],
                                "raw": event["raw"], "artifacts": event["artifacts"]}}
            points[key]["observed_events"] += 1
    output = {"schema_version": "1.0.0", "attack_id": "siai", "engine_id": "vllm",
              "source_commit": review["source_commit"], "condition_authority": review["library_source"],
              "conditions": review["conditions"], "runs": runs,
              "logging_points": list(points.values()), "reproducibility_files": files,
              "interpretation_limits": [
                  "1024px native preprocessing produces 5 parts / 320 visual tokens and differs from llama.cpp preprocessing.",
                  "512px smoke failed because the upstream patch-count API returned zero for one global image; failed runs are preserved.",
                  "Only original attack and zero ablation are fresh-process isolated when reuse-engine is enabled.",
                  "engine_initialized is per-request observation of the engine actually used, not a constructor invocation count.",
                  "Source mapping and AC/DC readiness do not establish attack success or validated detector accuracy.",
                  "Any same-input nonintervention repeat is separate validation; one repeat does not prove general determinism or alter frozen AC/DC rules.",
              ]}
    with targets[0].open("x", encoding="utf-8") as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    engine_observations = sum(point["observed_events"] for point in points.values()
                              if point["stage"] == "engine_initialized")
    lines = ["# SIAI / vLLM 실제 로깅 지점", "",
             "실제 `LLM.generate`의 CPU native 경로에서 관측한 지점이다. 조건 정의는 Attack Library 원문을 따른다.", "",
             "전처리는 longest_edge=1024이며 5개 타일·320개 visual token을 생성한다. llama.cpp와 동일 전처리를 주장하지 않는다.",
             "AC/DC T/F는 이 문서가 아니라 공통 Analyzer가 동일 frozen rules로 판정한다.", "",
             f"`engine_initialized`는 각 요청이 실제로 사용한 기존 엔진의 출처 관측이다. {engine_observations}개 관측을 엔진 {engine_observations}회 생성으로 해석하지 않는다.", "",
             "| 단계 / 실제 소스 | 조건 | 관측 수 | 로깅 이유 |", "|---|---|---:|---|"]
    for point in points.values():
        source = point["source"]
        label = f"{Path(source['path']).name}:{source['line']} / {source['function']}"
        lines.append(f"| `{point['stage']}`<br>[{label}]({point['source_snapshot']}) | {', '.join(point['condition_ids']) or '출처·실행 검증'} | {point['observed_events']} | {point['reason']} |")
    lines.extend(["", "## 원시 값과 수집 위치", "", "아래 preview는 전체 raw가 아니다. .npy 링크에는 손실 없이 보존한 모든 값이 있다.", ""])
    for point in points.values():
        example = point["example"]
        lines.extend([f"### {point['stage']}", "", f"이벤트 `{example['event_id']}` / sequence {example['sequence']}",
                      f"[전체 원본 로그]({example['run_dir']}/events.pretty.json)", ""])
        for name, artifact in example["artifacts"].items():
            lines.append(f"- `{name}`: `{artifact['dtype']}` / shape `{artifact['shape']}` / [전체 원본]({example['run_dir']}/{artifact['path']}) / preview `{artifact.get('preview', [])}`")
        if example["raw"]:
            lines.extend(["", "<details><summary>해당 지점의 실제 raw 필드</summary>", "", "```json",
                          json.dumps(example["raw"], ensure_ascii=False, indent=2), "```", "", "</details>", ""])
    lines.extend(["## 해석 한계", "", *[f"- {value}" for value in output["interpretation_limits"]], ""])
    with targets[1].open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
    print(json.dumps({"mapping": str(targets[0]), "observed_source_sites": len(points), "runs": len(runs)}))


if __name__ == "__main__":
    main()
