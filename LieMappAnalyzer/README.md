# 공통 LieMapp Analyzer

2026-09-07 출력 안내: [developer.py](../developer.py) / [investigator.py](../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

`analyzer.py`는 추론 엔진 이름이나 공격 이름으로 분기하지 않습니다. `logger.py`가
기록한 동일 이벤트 스키마와 Attack-Library에서 유래한 조건·규칙 JSON을 입력받아
동일 연산으로 평가합니다. 엔진별 차이는 소스 매핑과 계측 계층에서 처리합니다.

```bash
python LieMapp/LieMappAnalyzer/analyzer.py \
  --log LieMapp/.evidence/raw/<attack>/<engine>/<run>/events.jsonl \
  --rules LieMapp/LieMappBench/Logging-Dataset/<attack>/rules.json \
  --output-dir LieMapp/.evidence/analyses/<attack>/<engine>/<new-analysis-id>
```

위 명령은 내부 분석 전용이다. 공개 결과는 `developer.py` 또는 `investigator.py`가
공통 [internal/publication.py](../internal/publication.py)를 통해 엔진당 MD 1개·SIAI 조건 JSON 6개로 발행한다.
기존 공개 파일을 교체하려면 `--replace`를 명시하며 원시 증거는 변경하지 않는다.

Python API: `analyze(log_path, rules_path, output_dir) -> dict`. 결과는 같은 객체를 저장한
`analysis.json`과 사람이 읽는 `report.md`입니다. 비어 있지 않은 결과 디렉터리는
덮어쓰지 않습니다. CLI 성공은 분석 수행 성공이지 공격 성공이나 안전 판정을 의미하지 않습니다.
텐서 연산에는 NumPy가 필요합니다. 비텐서 규칙은 표준 라이브러리만으로 동작합니다.

## 판정과 무결성

아래 표는 내부 과학적 판정이다. 공개 보고서/조건 JSON은 `null`을 유지하면서 표시만
`F / not_evaluated`로 한다. 실제 관측상 불충족 `false / observed_not_satisfied`와
구별하므로, 표시 F만 보고 공격 불가능이나 안전으로 해석하면 안 된다.

| 결과 | JSON 값 | 의미 |
|---|---|---|
| T | `true` | 지정한 관측 조건이 충족됨 |
| F | `false` | 유효한 실제 측정값이 조건과 반대임 |
| 판정불가 | `null` | 필요한 이벤트·필드·대응쌍·적합한 실행 범위가 부족함 |

- 누락 이벤트 또는 `count == 0`만으로 F나 안전을 선언하지 않습니다.
- `failed`·`blocked`로 종료된 실행은 원본 증거의 무결성을 검증하되 모든 조건을 판정불가로 둡니다.
- 해시 체인, 순번, run/metadata 일관성, 종료 `seal.json`, 모든 참조 파일의 크기와 SHA-256을 확인합니다.
- 깨진 해시·누락 seal·잘못된 스키마·아티팩트 경로 탈출은 `EvidenceError`이며 판정 보고서를 생성하지 않습니다.
- 텐서 로드는 `allow_pickle=False`, 읽기 전용 메모리 매핑을 사용합니다. 실수·정수·불리언의 유한 배열만
  계산할 수 있으며, shape/dtype 선언과 실제 배열이 다르면 증거 오류입니다. NaN/Inf, 빈 배열, 호환되지 않는
  shape, 영벡터 cosine은 판정불가입니다.
- 현재 소스 파일을 다시 해시해 과거의 계측 증거와 동일하다고 주장하지 않습니다. 보고서에 있는 source SHA-256은
  수집 당시 logger가 기록한 값입니다. 외부 서명·신뢰 타임스탬프·별도 Chain of Custody까지 검증하는 기능은 아닙니다.
- 판단에는 `raw` 및 검증된 `artifacts`만 사용합니다. `readable`은 판단 입력에서 금지합니다.

AC는 공격 전제 조건, DC는 정의된 사후 관측 조건입니다. DC를 계산할 수 있는 것,
DC가 T인 것, 실제 공격이 성공한 것, 탐지기가 높은 성능을 내는 것은 서로 다른 주장입니다.

## 규칙 JSON

다음은 문법을 설명하는 가상 예시이며 실제 SIAI 조건이 아닙니다.

```json
{
  "attack_id": "example",
  "attack_name": "Example attack",
  "library": {
    "path": "Attack-Library/example.xlsx",
    "sha256": "<workbook SHA-256>",
    "sheet": "refs",
    "row": 2,
    "cells": {"AC": "G2", "DC": "H2"}
  },
  "conditions": [
    {
      "id": "AC1",
      "kind": "AC",
      "text": "실행 중 인코더 성공이 관측되는가?",
      "source_cell": "G2",
      "rule": {
        "op": "compare",
        "scope": "native_runtime",
        "select": {"stage": "encoder_exit", "context": {"role": "clean"}},
        "field": "raw.success",
        "cmp": "eq",
        "value": true,
        "reduce": "all"
      }
    }
  ]
}
```

조건의 원문과 셀은 Attack-Library importer가 가져옵니다. Analyzer는 규칙·라이브러리 출처,
규칙 파일 해시 및 규칙 전체 스냅샷을 결과에 보존합니다. 라이브러리 파일 내용과 셀의 일치 검증은
importer의 책임이며, Analyzer가 임의의 rule 문장이 논문 원문과 동등함까지 보증하지 않습니다.

### 공통 선택·비교

`select`는 `stage`, `context`, `raw`, `metadata`, `source`의 **부분 일치** 객체입니다.
중첩 객체 또는 `"context.role"`처럼 점으로 연결한 경로를 사용할 수 있습니다. 값은 정확히 일치해야 합니다.
`{"raw": {"success": true}}`는 실패 이벤트를 선택하지 않으므로 성공/실패 판정에는 select에서 성공 여부를
필터하지 않고 `field: "raw.success"`로 비교하는 것이 적절합니다.

`scope`는 `metadata.execution_scope` 문자열 또는 허용 문자열 리스트입니다.
축약값 `runtime`은 `runtime`, `native_runtime`, `engine_runtime`, `end_to_end`만 허용합니다.
`structural_probe`, `preflight`, `static_review`는 이 축약값에 포함되지 않습니다.

| op | 필수 및 주요 필드 | 동작 |
|---|---|---|
| `exists` | `select` | 일치 이벤트가 있으면 T, 없으면 판정불가 |
| `compare` | `select`, `field`, `cmp`, `value` | 각 실제 필드 값을 비교 |
| `count` | `select`, `cmp`, `value` | 관측된 이벤트 수 비교; 미관측 0은 판정불가 |
| `all` / `any` | `rules` | 하위 규칙의 3값 논리 AND/OR |
| `tensor_equality` | `left`, `right`, `join_by` | 실제 숫자 배열의 정확한 동등성 |
| `tensor_stat` | `select`, `artifact`, `stat`, `cmp`, `value` | 전체 원본 텐서에서 수치 통계 계산 |
| `pairwise_tensor_distance` | `left`, `right`, `join_by`, `metric`, `cmp`, `value` | `l2`, `linf`, `cosine` 거리 |
| `pairwise_tensor_cosine` | `left`, `right`, `join_by`, `cmp`, `value` | cosine **유사도** |
| `calibrated_tensor_distance` | `calibration`, `test` | 정상 대조군에서만 임계값을 맞춘 뒤 시험군과 비교 |

`cmp`: `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `contains`, `in`.
`reduce`: `all`(기본) 또는 `any`. 빈 집합은 항상 판정불가입니다.
AND는 반대 증거 F가 하나라도 있으면 F, 나머지가 T/판정불가뿐이면 판정불가입니다.
OR는 T가 하나라도 있으면 T, 나머지가 F/판정불가뿐이면 판정불가입니다.

`all`/`any`에 `join_by: ["context.request_id"]`를 지정하면 각 요청 안에서 하위 규칙을
독립적으로 계산하고 `reduce`로 합칩니다. 인코더 성공 이벤트가 요청 A에, 디코더 이벤트가 요청 B에
있다는 이유로 하나의 완료된 흐름으로 합치지 않습니다. 복합 규칙의 `select`는 그룹화 전에 적용합니다.
예를 들어 `select: {"context": {"role": "attack"}}`와 요청 조인을 함께 쓰면 공격 요청만 선택한 뒤
각 요청의 모든 단계가 충족되는지 확인합니다. 선택 결과가 비어 있으면 판정불가입니다.
선택된 이벤트 중 조인 필드가 누락된 항목을 몰래 버리지 않고 판정불가 하위 결과로 남깁니다.

### 텐서 대응쌍과 여러 타일

```json
{
  "op": "tensor_equality",
  "left": {
    "select": {"stage": "projected_embedding"},
    "artifact": "embedding",
    "aggregate": "concat", "axis": 0, "order_by": "sequence"
  },
  "right": {
    "select": {"stage": "decoder_input"},
    "artifact": "embedding",
    "aggregate": "concat", "axis": 0, "order_by": "sequence"
  },
  "join_by": ["context.request_id"]
}
```

기본값 `aggregate: "single"`은 조인 그룹마다 각 측면의 이벤트가 정확히 하나일 때만 계산합니다.
`concat`은 명시적으로 지정한 경우에만 허용합니다. 각 측면의 이벤트 모두 동일한 비어 있지 않은
`request_id`, 동일 dtype, 연결 축 이외의 동일 shape를 가져야 하며 실제 `sequence` 순서로만 연결합니다.
원래 이벤트 ID와 연결 순서를 보고서에 남깁니다. 이 기능은 모델의 여러 이미지 타일을 합치는 등의 명시적
소스 흐름을 위한 것이며, 독립 요청이나 임의로 정렬한 배열을 합치는 용도가 아닙니다.

텐서 비교에는 `join_by`가 필수입니다. 입력 대조군 비교는 `pair_id`와 변환을, 개입 인과 비교는
공유 실험 ID·프롬프트 해시·seed 등을 규칙에서 함께 조인해야 합니다. 잘못 정의된 pairing의 과학적 타당성을
Analyzer가 자동으로 추측하지 않습니다. `cosine` **거리**는 `1 - cosine_similarity`입니다.
두 배열의 shape가 다르면 임의 flatten/reduce/reshape로 비교하지 않습니다.

### 원시 텐서 통계

```json
{
  "op": "tensor_stat",
  "select": {"stage": "decoder_input", "context": {"role": "ablation"}},
  "artifact": "values", "aggregate": "concat", "axis": 0,
  "join_by": ["context.request_id"],
  "stat": "max_abs", "cmp": "eq", "value": 0
}
```

이 예시는 `intervention: true` 같은 선언만 믿지 않고 실제 소비된 전체 배열이 0인지 확인합니다.
지원 통계는 `max_abs`, `l2`, `mean`, `min`, `max`, `count_nonzero`, `size`입니다. 기본적으로 각
이벤트를 독립적으로 검사하며, `concat`에는 요청 등의 명시적 `join_by`가 필요합니다. 통계 수치 계산은
signed-minimum 정수의 절댓값 overflow를 피하도록 float64로 변환합니다. 정확한 큰 정수 동등성 비교는
변환하지 않는 `tensor_equality`를 사용합니다. 원본 아티팩트의 값이나 dtype은 변경하지 않습니다.

### 정상군 임계값 보정

```json
{
  "op": "calibrated_tensor_distance",
  "calibration": {
    "left": {"select": {"stage": "embedding", "context": {"role": "calibration", "transform": "original"}}, "artifact": "embedding"},
    "right": {"select": {"stage": "embedding", "context": {"role": "calibration", "transform": "jpeg"}}, "artifact": "embedding"},
    "join_by": ["context.pair_id"], "metric": "cosine"
  },
  "test": {
    "left": {"select": {"stage": "embedding", "context": {"role": "attack", "transform": "original"}}, "artifact": "embedding"},
    "right": {"select": {"stage": "embedding", "context": {"role": "attack", "transform": "jpeg"}}, "artifact": "embedding"},
    "join_by": ["context.pair_id"], "metric": "cosine"
  },
  "percentile": 95,
  "percentile_method": "higher",
  "min_pairs": 10,
  "cmp": "gt",
  "mode": "available"
}
```

- `calibration`과 `test`는 텐서 대응쌍 명세이며 동일 거리 지표를 사용해야 합니다.
- `min_pairs`는 최소 2, 기본 10입니다. 누락·중복·부적합 쌍을 몰래 버리고 남은 쌍으로 성공 처리하지 않습니다.
- 양쪽 집단에서 같은 이벤트 쌍을 재사용하면 데이터 누출로 판정불가입니다. 이 검사는 동일 이미지의 별도
  이벤트 재사용까지 탐지하지 않으므로 데이터셋의 학습/평가 분리도 별도로 관리해야 합니다.
- `percentile_method`: `linear`(기본), `higher`, `lower`, `nearest`, `midpoint`.
  지표·표본 수·방법·퍼센타일은 시험 결과를 보기 전에 고정해야 합니다.
- `mode: "available"`은 임계값과 시험값의 비교 **가능성**만 판정합니다. T여도 공격/정상 분리가 안 될 수 있습니다.
- `mode: "exceeds"`는 시험값이 정한 임계값 비교를 만족하는지 판정합니다. 이것만으로 탐지 성능이 검증되지는 않습니다.
- 결과에는 정상 거리 전체, n, 퍼센타일, 보정 방법, 임계값, 시험 거리 및 임계값 초과 플래그를 함께 저장합니다.

## 검증

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s LieMapp/tests -p test_analyzer.py -v
```

합성 테스트는 임시 디렉터리에서만 생성하며 연구 `LogFile`/`report`에 섞지 않습니다.
서로 다른 가상 엔진의 동일 규칙 처리, 공통 logger 호환, 누락/실패/정적 실행,
해시 변조·절단·중복·경로 탈출, 텐서 수치 경계, 타일 연결, calibration/test 분리와
임계값 산출을 검증합니다.
