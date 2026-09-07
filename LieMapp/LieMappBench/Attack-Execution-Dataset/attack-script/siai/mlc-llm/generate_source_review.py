"""Generate a clearly static PhiV LP candidate review linked to CPU retry evidence."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from finalize_readiness import ENGINE, RAW, REVIEW, REVISION, new_json
from record_command import ROOT, common


def main():
    writer = common()
    readiness = RAW / 'siai-mlc-phi35-readiness-20260907-001'
    events = [json.loads(line) for line in (readiness / 'events.jsonl').read_text().splitlines()]
    prior = json.loads((REVIEW / 'source-review.json').read_text())
    snapshot = {event['raw']['relative_path']: event for event in events if event['stage'] == 'static_source_snapshot'}
    candidates = [
        ('python/mlc_llm/model/phi3v/phi3v_model.py', 'Phi3VForCausalLM', 'image_preprocess', 'processor_output', ['AC2', 'DC1'],
         '입력 uint8와 정규화·분할 후 실제 pixel tensor를 같은 request/input ID에 연결해야 함'),
        ('python/mlc_llm/model/phi3v/phi3v_model.py', 'Phi3VForCausalLM', 'image_embed', 'encoder_input', ['AC1', 'AC2', 'DC1'],
         '실제 vision encoder에 전달된 전체 tensor와 성공 반환을 확인해야 함'),
        ('python/mlc_llm/model/phi3v/phi3v_image.py', 'Phi3ImageEmbedding', 'get_img_features', 'encoder_output', ['AC1', 'DC2'],
         '동일 계층의 native visual feature를 증강 원본/변형에 대해 수집해야 함'),
        ('python/mlc_llm/model/phi3v/phi3v_image.py', 'Phi3ImageEmbedding', 'forward', 'projected_embedding', ['AC1', 'AC3', 'DC2', 'DC3'],
         '실제 projector 반환 embedding 전체 원시값과 stable layer identity가 필요함'),
        ('python/mlc_llm/model/phi3v/phi3v_model.py', 'Phi3VForCausalLM', 'prefill', 'decoder_input', ['AC1', 'AC3'],
         '언어 decoder의 실제 입력과 full first logits를 수집하고 동일 입력 정상/zero 개입·비개입 반복을 비교해야 함'),
    ]
    points = []
    for number, (relative, cls, symbol, stage, conditions, reason) in enumerate(candidates, 1):
        path = ENGINE / relative
        tree = ast.parse(path.read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == cls)
        function = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == symbol)
        event = snapshot[relative]
        points.append({'mapping_id': f'siai-mlc-phi35-static-{number:02d}', 'status': 'static_candidate_not_instrumented',
            'condition_ids': conditions, 'canonical_stage': stage,
            'source': {'path': str(path), 'relative_path': relative, 'class': cls, 'function': symbol,
                       'line': function.lineno, 'end_line': function.end_lineno,
                       'sha256': writer.sha256_file(path), 'base_revision': REVISION},
            'reason': reason, 'instrumented': False, 'native_request_executed': False,
            'raw_runtime_values': None, 'raw_runtime_values_status': 'not_collected_model_compilation_failed',
            'source_snapshot_event_id': event['event_id'], 'source_snapshot_sequence': event['sequence'],
            'source_snapshot_artifacts': event['artifacts'],
            'important': 'Python model methods construct compiled IR; function entry logging at compile time is not native request evidence'})
    result = {'schema_version': '1.0.0', 'attack_id': 'siai', 'engine_id': 'mlc-llm',
        'model_id': 'mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC', 'status': 'readiness_blocked_static_mapping_only',
        'conditions': prior['conditions'], 'library_source': prior['library_source'],
        'logging_points': points, 'native_request_count': 0,
        'readiness_run': str(readiness / 'events.jsonl'),
        'readiness_events_sha256': writer.sha256_file(readiness / 'events.jsonl'),
        'native_boundaries_to_pair': [
            {'file': 'cpp/serve/model.cc', 'function': 'ModelImpl::ImageEmbed', 'line': 128,
             'purpose': 'native runtime image_embed dispatch and returned visual embeddings'},
            {'file': 'cpp/serve/model.cc', 'function': 'ModelImpl::BatchPrefill', 'line': 245,
             'purpose': 'native decoder/prefill dispatch and returned full logits'}],
        'evidence_limit': 'No preprocessor, encoder, projected embedding, decoder input, logits or generated text was observed for a native model request.'}
    new_json(REVIEW / 'source-review-phi35-cpu-retry.json', result)
    lines = ['# Phi-3.5 Vision / MLC-LLM: 로깅 후보와 재시도 결과', '',
             '**실제 native 요청 0회. 아래는 계측 지점의 정적 후보이며, 계측 완료나 실행 결과가 아니다.**', '',
             '모델: `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC` · MLC source `' + REVISION + '`.', '',
             'AC/DC 원문은 `attack_library.xlsx`의 `AI 포렌식!G10/H10`에서 그대로 가져왔다. 과거 행 번호를 현재 소스의 행 번호로 재확인했다.', '',
             '| 후보 stage | 함수/지점 | 조건 | 필요한 로깅 근거 | 실제 raw 값 |',
             '|---|---|---|---|---|']
    for point in points:
        src = point['source']
        lines.append(f"| `{point['canonical_stage']}` | `{src['relative_path']}:{src['line']}` / `{src['class']}.{src['function']}` | {', '.join(point['condition_ids'])} | {point['reason']} | 미수집 — 모델 컴파일 실패 |")
    lines.extend(['', '## 컴파일과 요청 계측의 구분', '',
        '위 Python 함수는 TVM IR을 구성한다. 컴파일 중 함수가 호출되었다는 기록은 이미지가 실제 native 추론에 사용되었다는 증거가 아니다. 향후 계측은 compiled tensor의 실제 실행 경계와 native `ModelImpl::ImageEmbed`/`BatchPrefill`, request ID를 함께 연결해야 한다.', '',
        '공통 Analyzer는 원시 텐서와 동일 request/pair/transform 문맥을 요구한다. 이번에는 그 입력이 없어 AC/DC 모두 **미평가**이다. 이 정적 표나 아래 환경 진단 값으로 조건을 T/F 관측 판정하지 않는다.', '',
        '## 실제로 기록된 원시 값', '',
        '| 단계 | 관측값 | 원시 이벤트 ID |', '|---|---|---|',
        '| 공식 모델 검증 | 114 files, 2,771,867,899 bytes, 전체 SHA256 일치 | `41e847d8edc64e349a718874a5615b4a` |',
        '| fresh CPU runtime 빌드 | returncode=0 | `cc5b73f61321435fb13ec52cfc151621` |',
        '| C++ factory | returncode=0, model_initialized=false, inference_executed=false | `4fab7e0a05324ef3baacfa2a96f6dfdd` |',
        '| stock compile002 | returncode=1, int32 literal 7247757312 overflow | `575f9b32df2248228f44f2f6de784174` |',
        '| int64-index compile003 | returncode=1, VMCodeGen tirx.Div unsupported | `90a04c224d5240e9beccd6a367bade95` |',
        '| int64+FloorDiv compile005 | returncode=1, VMCodeGen tirx.FloorDiv unsupported | `fb37678d4d0f4cd48dd6336625bfbf40` |', '',
        '실제 명령·stdout·stderr는 `.evidence/raw/siai/mlc-llm/` 아래 해당 run의 `events.pretty.json`에서 읽을 수 있다. 정리 문서: [CPU 재시도 상세](phi35-cpu-retry.md).', '',
        '## 소스 원문 보존', '',
        '최종 readiness run `' + readiness.name + '`의 아래 이벤트에 원본/시험용 소스 전체를 uint8 NPY로 각각 보존했다. 이는 **소스코드 파일 바이트**이며 모델의 이미지·임베딩 원시값이 아니다.', ''])
    for relative, event in snapshot.items():
        lines.append(f"- `{relative}`: sequence={event['sequence']}, event_id=`{event['event_id']}`, original SHA256=`{event['raw']['original_sha256']}`, private SHA256=`{event['raw']['private_sha256']}`.")
    lines.extend(['', '시험용 padding 패치의 주석에 있던 “VM shape lowering supports FloorDiv”는 가설이었다. 실제 compile005가 이를 반증했으며, 실패 당시 코드 바이트 보존을 위해 해당 스냅샷을 수정하지 않았다. 이 패치를 정상 동작하는 구현으로 사용하면 안 된다.', ''])
    with (REVIEW / 'source-review-phi35-cpu-retry.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines))


if __name__ == '__main__':
    main()
