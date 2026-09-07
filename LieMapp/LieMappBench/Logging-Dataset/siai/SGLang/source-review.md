# SIAI / sglang — 소스 매핑 사전 검토

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

기준 커밋: `97c6978369ac1e04c91fcc01c98acc25129a6000`

상태: **정적 후보**. 실제 계측·실행 증거는 별도의 logging-points 및 실행 로그를 확인한다.

## AC / DC 원문

- **AC1** (G10): 현재 요청에서 이미지 인코더와 multimodal fusion 경로가 실제로 활성화되는가?
- **AC2** (G10): 입력 이미지의 adversarial perturbation이 전처리 이후에도 보존되어 이미지 인코더에 도달하는가?
- **AC3** (G10): 생성된 visual embedding이 언어 디코더의 생성 결과에 직접 영향을 미치는 구조인가?
- **DC1** (H10): 원본과 증강 이미지를 동일한 전처리·인코더에 입력할  수 있는가?  - 이미지 증강: JPEG 압축, 가우시안 블러, 랜덤 아핀 변환, 색상 조정, 랜덤 원근 변환
- **DC2** (H10): 동일 계층의 이미지 임베딩을 추출하고 서로 연결할 수 있는가?
- **DC3** (H10): 코사인 유사도를 계산하고 모델별 정상 기준선·threshold와 비교할 수 있는가?

## 매핑 위치와 로깅 근거

|조건|현재 소스 지점|로깅 이유|필요한 raw 값|
|---|---|---|---|
|AC2, DC1|`python/sglang/srt/multimodal/processors/transformers_auto.py:178`<br>`process_mm_data_async`|전처리 전후 및 이미지-증강 계보를 확보하는 경계|input bytes/tensor, output tensor, processor parameters, parent/input ID|
|AC1, AC2, DC1, DC2, DC3|`python/sglang/srt/models/transformers.py:1459`<br>`_encode_modality_items`|이미지 인코딩 성공 여부와 같은 계층의 원시 임베딩을 확보하는 경계|encoder input tensor, embedding tensor, return status, layer/stage ID|
|AC1, AC3|`python/sglang/srt/models/transformers.py:1581`<br>`_forward_hidden_states`|이미지 임베딩을 이용한 언어 디코더 실행 경계|embedding identity, decoder return status, logits, sequence/request ID|

## 판정 한계

- 함수 존재·매핑만 확인함. 계측 적용·실행·T/F 판정을 뜻하지 않음.
- AC2에는 clean/attack 쌍의 encoder-input 차이와 공격 provenance가 필요함.
- AC3 직접 영향 주장은 같은 요청 추적과 통제된 visual ablation이 필요함.
- DC1~3은 탐지 준비도이며 공격 탐지 성능이나 사건 발생 입증과 다름.

## 엑셀의 기존 위치 (이력 보존; 현재 행번호와 다름)

```text
AC1. python/sglang/srt/models/transformers.py:1476 (_encode_modality_items), python/sglang/srt/models/transformers.py:1574 (_forward_hidden_states)
AC2. python/sglang/srt/multimodal/processors/transformers_auto.py:173 (process_mm_data_async), python/sglang/srt/models/transformers.py:1462 (_encode_modality_items)
AC3. python/sglang/srt/models/transformers.py:1574 (_forward_hidden_states)

DC1. python/sglang/srt/models/transformers.py:1463 (_encode_modality_items)
DC2. python/sglang/srt/models/transformers.py:1488 (_encode_modality_items)
DC3. python/sglang/srt/models/transformers.py:1488 (_encode_modality_items).
```
