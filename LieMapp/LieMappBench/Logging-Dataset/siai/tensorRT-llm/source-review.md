# SIAI / TensorRT-LLM — 소스 매핑 사전 검토

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

기준 커밋: `a5f8680e418a1b01eddb4824980495a3670e5168`

상태: **정적 후보**. 실제 계측·실행 증거는 별도의 logging-points 및 실행 로그를 확인한다.

## 2026-09-07 실제 재진단

사용자가 지정한 Phi-3.5 Vision MLC 배포본의 형식과 NVIDIA 공식 요건을 확인하고,
독립 복제본에서 editable 설치·native CMake 구성·CUDA driver/runtime·소스 import를 실제 재시도했다.
CMake는 C++ compiler 확인 후 CUDA compiler 부재로 중단했고, driver 조회에서도
`libcuda.so.1`을 확보하지 못했다. MLC `q4f32_1` 가중치 선택은 CUDA 요구사항을 없애지 않는다.

- [최종 재진단 원시 로그](../../../../.evidence/raw/siai/tensorRT-llm/siai-tensorRT-llm-phi35-readiness-retry-20260907-002/events.pretty.json)
- [실제 명령·실패 원인·공식 자료 상세](readiness-review-20260907.md)
- 실행 범위: `readiness_retry`, 상태: `blocked`, native 추론·공격 실행: 미수행.
- AC/DC 내부 값은 `null`; 공개 표시 `F / not_evaluated`를 실제 반대 관측으로 읽지 않는다.

아래 Qwen2-VL 소스 지점은 일반적인 정적 후보이며, Phi-3.5 Vision의 모델 지원이나
해당 모델에서의 실행 성공을 입증한 매핑이 아니다. 현행 버전은 legacy TensorRT backend가
제거됐으므로 현행 PyTorch/AutoDeploy 경로의 CUDA 요건을 기준으로 해석한다.

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
|AC2, DC1|`tensorrt_llm/_torch/models/modeling_qwen2vl.py:1275`<br>`call_with_text_prompt`|전처리 전후 및 이미지-증강 계보를 확보하는 경계|input bytes/tensor, output tensor, processor parameters, parent/input ID|
|AC1, AC2, DC1, DC2, DC3|`tensorrt_llm/_torch/models/modeling_qwen2vl.py:1495`<br>`forward`|이미지 인코딩 성공 여부와 같은 계층의 원시 임베딩을 확보하는 경계|encoder input tensor, embedding tensor, return status, layer/stage ID|
|AC1, AC3|`tensorrt_llm/_torch/models/modeling_multimodal_utils.py:512`<br>`fuse_input_embeds`|이미지 임베딩이 언어 입력에 결합되는 경계; 후속 디코더 증거도 필요|visual embedding hash, image-token positions, fused embeddings, request ID|

## 판정 한계

- 함수 존재·매핑만 확인함. 계측 적용·실행·T/F 판정을 뜻하지 않음.
- AC2에는 clean/attack 쌍의 encoder-input 차이와 공격 provenance가 필요함.
- AC3 직접 영향 주장은 같은 요청 추적과 통제된 visual ablation이 필요함.
- DC1~3은 탐지 준비도이며 공격 탐지 성능이나 사건 발생 입증과 다름.

## 엑셀의 기존 위치 (이력 보존; 현재 행번호와 다름)

```text
AC1. tensorrt_llm/_torch/models/modeling_qwen2vl.py:1134 (forward), tensorrt_llm/_torch/models/modeling_multimodal_utils.py:604 (fuse_input_embeds)
AC2. tensorrt_llm/_torch/models/modeling_qwen2vl.py:920 (call_with_text_prompt), tensorrt_llm/_torch/models/modeling_qwen2vl.py:1125 (forward)
AC3. tensorrt_llm/_torch/models/modeling_multimodal_utils.py:604 (fuse_input_embeds)

DC1. tensorrt_llm/_torch/models/modeling_qwen2vl.py:1153 (forward)
DC2. tensorrt_llm/_torch/models/modeling_qwen2vl.py:1171 (forward)
DC3. tensorrt_llm/_torch/models/modeling_qwen2vl.py:1171 (forward)
```
