# 공통 공개 출력: publication.py

`../LieMappAnalyzer/analyzer.py`는 원본 증거와 규칙을 평가한다. 이 폴더의 `publication.py`는 그 결과를 읽기 쉽게 공개하는 계층이다.
공개용 문구·매핑·보조 관찰 자료는 판정에 사용하지 않는다. 공격·엔진에 따른 Python 분기 없이 동일 API를 사용한다.

## 출력과 표시 정책

한 실행을 발행하면 다음 파일을 만든다.

- `log_output_dir/<attack-label>-<condition-id>-<engine-label>-LogFile.json`: 규칙에 정의된 조건마다 하나.
  현재 SIAI 규칙은 6개 조건이므로 6개이다. 다른 공격의 조건 수를 코드에 하드코딩하지 않는다.
- `report_output_dir/<attack-label>-<engine-label>-Report.md`: 공개 보고서 하나.
- `analysis_dir/analysis.json`, `report.md`, `publication.json`: 기존 Analyzer 결과와 공개 파일 해시 목록.
  이 디렉터리는 공개 Report·LogFile과 분리한 내부 증거 영역이어야 한다.

표시 이름은 선택 사항이며, 기본 파일명은 규칙의 attack_id와 원본 로그의 engine.id로 만든 안전한 slug다.
명시적으로 `attack_label="SIAI", engine_label="llama.cpp"`를 주면 `SIAI-llama.cpp-Report.md`가 된다.
경로 구분자·제어 문자·상위 경로 참조·예약 파일명은 허용하지 않는다. 표시 이름이 원본 식별자를 바꾸지는 않는다.

| 내부 증거 값 | 공개 verdict | evidence_status | 의미 |
|---|---|---|---|
| `true` | T | `observed_satisfied` | 원시 증거에서 조건 충족 관측 |
| `false` | F | `observed_not_satisfied` | 명시적 반대 증거 관측 |
| `null` | F | `not_evaluated` | 필요한 실행·계측 증거 미확보 또는 비교 불가 |

`not_evaluated`의 `evaluation_reason`은 `scope_unavailable`, `run_incomplete`,
`missing_required_evidence`로 구분한다. 미평가 F를 공격 불가능이나 엔진 안전의 증거로 해석하면 안 된다.
해시 체인·seal·아티팩트가 잘못된 패키지는 발행 자체를 거부하며 F 파일을 만들지 않는다.

## Python API와 CLI

```python
publish(
    log_path, rules_path,
    log_output_dir=condition_json_directory,
    report_output_dir=public_report_directory,
    analysis_dir=private_analysis_directory,
    mapping_path=None,
    presentation_path=None,
    supplement_paths=(),
    attack_label=None,
    engine_label=None,
    replace=False,
    backup_dir=None,
)
```

반환값은 경로·파일 해시·가벼운 요약을 포함한 manifest다. 거대한 원시 이벤트나 내부 analysis 본문을 stdout에 반환하지 않는다.

`render_documents(analysis, *, targets, report_path, presentation, presentation_path, mapping,
mapping_path, internal_file, internal_sha256, supplements, attack_label, engine_label)`은
검증된 입력에서 `(조건 JSON 객체 목록, 보고서 문자열)`을 만드는 공통 읽기 전용 함수다.
실제 발행과 전체 내용 재검증이 같은 함수를 사용한다. 원시 preview·참조 hash를 읽지만 파일을 생성하지 않는다.
재검증은 실제 목적지 경로와 기존 내부 분석 hash를 넘겨 JSON 전체 및 MD 문자열을 정확히 비교할 수 있다.

아래 CLI 예시는 `AI-Forensics/` 저장소 루트에서 실행한다.

```bash
OPENBLAS_NUM_THREADS=1 python LieMapp/internal/publication.py \
  --log /explicit/raw/run/events.jsonl \
  --rules /explicit/conditions.json \
  --log-output-dir /explicit/public/LogFile/engine \
  --report-output-dir /explicit/public/report/engine \
  --analysis-dir /explicit/private/analyses/publication-id \
  --attack-label SIAI --engine-label llama.cpp \
  --presentation /explicit/presentation.json \
  --mapping /explicit/source-mapping.json \
  --supplement /explicit/supplement.json
```

실제 환경에서는 해당 프로젝트의 지정된 Python 환경을 사용한다. 경로는 자동 추정하지 않는다.
보조 JSON 안의 상대 경로만 해당 JSON 파일의 디렉터리를 기준으로 해석한다.

## 조건 JSON 구조

순서는 요약 → 쉬운 질문 → 무엇을 측정하는지 → 실제 측정값과 단위 → 근거 → 소스·이벤트·원본 링크이다.

| 키 | 내용 |
|---|---|
| `summary` | 원본 공격·엔진·조건 ID, 표시 T/F, 원래 true/false/null, 평가 상태와 쉬운 설명 |
| `supplementary_context` | 미평가 조건에 한해 제공된 보조 설명·출처·`used_for_verdict=false`; 원시 측정의 대체가 아님 |
| `question` | 쉬운 질문, 원문 조건, 실험 범위 설명 |
| `measurement_plan` | 확인할 관측 항목을 자연어로 설명 |
| `measurements` | 실제 측정값·단위·기준값과 손실 없는 원본 observation |
| `judgment_basis` | 원래 규칙의 논리적 판단과 정확한 이벤트 참조 |
| `logging_points` | 실제 함수·행·소스 hash, 로깅 이유, 관측 여부, 소스 snapshot |
| `events` | 중복 metadata를 제외한 해당 조건의 원본 context/source/raw와 아티팩트 링크 |
| `provenance` | raw 로그·seal·규칙·내부 분석·표시 데이터 경로 및 hash |

텐서 preview는 저장된 descriptor의 preview를 복사하지 않고 검증된 원본 `.npy`에서 읽는다.
앞 8개 원소임을 명시하고 전체 원소 수·dtype·shape·파일 SHA-256·전체 파일 링크를 함께 남긴다.
원본 배열을 공개 JSON 안에 다시 복제하지 않는다. 이 JSON은 원시 로그를 대체하지 않는 증거 뷰이다.

실제 이벤트와 source의 path/function/line/SHA-256까지 일치하는 매핑만 관측 지점의 로깅 이유로 연결한다.
정적 후보 매핑은 `observed=false`로 표시하며 실제 실행으로 둔갑시키지 않는다.

## 표시 데이터

```json
{
  "attack_id": "example",
  "purpose": "이 실험의 목적",
  "conditions": {
    "AC1": {
      "question": "이 경로가 실제 실행됐나요?",
      "explanation": "코드에 존재하는 것과 실제 호출은 다릅니다.",
      "measurement_plan": ["실제 완료 기록을 확인합니다."]
    }
  },
  "field_labels": {
    "raw.returncode": {"label": "반환 코드(0은 성공)", "unit": "코드"}
  },
  "artifact_labels": {
    "encoder_input.values": {"label": "실제 인코더 입력", "unit": "정규화한 수치"},
    "logits": {"label": "토큰 후보 점수", "unit": "logit"}
  }
}
```

아티팩트 설명은 `stage.artifact-name`을 먼저 찾고, 없으면 `artifact-name`을 찾는다.
단위가 없으면 물리 단위를 임의로 추정하지 않는다. cosine 유사도·거리는 단위 없는 지표로 구분한다.

## 보조 관찰

```json
{
  "attack_id": "example",
  "engine_id": "engine-id",
  "title": "별도 행동 평가",
  "summary": ["이 표는 AC/DC 판정에 사용하지 않습니다."],
  "tables": [{
    "title": "관찰 결과",
    "columns": [{"key": "answer", "label": "실제 답변"}],
    "rows": [{"answer": "원문 답변"}]
  }],
  "limitations": ["표식 출력만으로 완전한 공격 성공을 주장하지 않습니다."],
  "source_runs": [{"log_path": "../raw/heldout/events.jsonl", "events_sha256": "정확한 SHA-256"}]
}
```

보조 관찰의 source_runs도 공통 EvidencePackage로 검증하고 공격·엔진 ID와 hash를 대조한다.
보조 관찰 자체의 정성 해석은 호출자가 명시적으로 제공한 자료이며 raw 규칙 평가와 분리한다.
표시 데이터에 들어 있는 HTML·Markdown 메타 문자는 보고서에서 실행 가능한 내용으로 취급하지 않는다.
5열을 넘거나 긴 원문이 있는 표는 행별 접이식 상세로 표시한다. 질문·응답 원문은 안전한 코드 블록에
손실 없이 보존하며, 짧은 비교 표는 그대로 표로 유지한다. 전체 실행 metadata는 보고서에 한 번만 접어 표시한다.
`requested_model`은 실제 로드 모델과 구분해 '실행 전 검토 모델(로드 성공 의미 아님)'로 표시한다.

## 교체·백업과 실패 처리

처음 발행할 때는 기존 파일을 덮어쓰지 않는다. 교체는 `replace=True`와 새 `backup_dir`를 모두 요구한다.
현재 파일명에 해당하는 공개 파일과 이 publisher가 만든 내부 분석만 교체한다. 다른 사용자 파일은 건드리지 않는다.
공개 디렉터리는 공격·엔진별 전용이어야 한다. 다른 이름의 `*-Report.md` / `*-LogFile.json`이 이미 있으면
label 변경이나 조건 삭제로 이전 판정이 남는 것을 막기 위해 발행을 거부한다. 명시적인 별도 migration이나
새 전용 디렉터리가 필요하며 publisher가 임의로 구 파일을 삭제하지 않는다. 같은 이름의 조건 JSON도
원본 공격·엔진 ID가 다르면 교체하지 않는다.
기존 공개 파일의 백업은 원본 hash와 대조한다. 중간 설치가 실패하면 이전 공개·내부 파일을 복원한다.

모든 내용을 임시 staging에서 완성한 후 파일별로 원자적으로 설치하며 보고서를 마지막에 설치한다.
여러 디렉터리에 걸친 전체 파일 묶음은 파일시스템 수준의 단일 원자적 연산이 아니다. 실행 중 강제 종료나
전원 장애 때는 내부 manifest·백업을 사용해 상태를 확인해야 한다. 정상 반환 후의 파일 hash가 발행 완료 기준이다.
동일 보고서 디렉터리의 동시 발행은 잠금 파일로 거부한다. 원본 raw archive와 겹치는 출력/백업 경로는 거부한다.
