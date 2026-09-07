# SIAI / tensorRT-llm 실행 상태

2026-09-07 출력 안내: [developer.py](../../../../../developer.py) / [investigator.py](../../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

현재는 **정적 매핑·사전 점검 및 별도 소스에서 실제 설치/CMake/runtime 재진단**을 수행했다. 이 폴더는 완성된 native 공격 runner가 아니다.
개별 Transformers 모델 실행, 함수 모의 호출, 과거 실행 로그를 이 엔진의 현재 추론 결과로 대신하지 않았다.

`../shared/run_preflight.py --engine tensorRT-llm`는 공통 logger로 실제 호스트·패키지·소스
요건을 기록하고 동일한 SIAI 규칙을 공통 Analyzer에 전달한다.
사전 점검의 `blocked` 상태는 AC/DC 내부 값 `null`이며 공개본에서 `F / not_evaluated`로 표시한다. 실제 관측상 불충족이나 안전을 의미하지 않는다.

- 소스 후보·로깅 이유: `Logging-Dataset/siai/tensorRT-llm/source-review.md`
- 버전별 CPU 준비 사유: `Logging-Dataset/siai/runtime-profiles.json`
- 공통 최적화 입력: `attack-source/siai/shared/experiment-cpu128-v1/dataset.json`
- 공통 행동 평가 입력: `attack-source/siai/shared/behavior-heldout-v1/dataset.json`

공통 입력을 준비한 것과 이 엔진에서 실행한 것은 다르다. 실행 환경이 준비되면
원본 `LIE`와 분리된 `Instrumented-LIE/siai/tensorRT-llm`에 계측을 적용하고,
동일 logger로 실제 값만 수집해야 한다.

## Phi-3.5 MLC 모델을 사용한 재시도 — 2026-09-07

`retry_readiness.py`는 별도 로컬 소스 복제본과 작은 Python 환경을 만들고,
실제 editable 설치·native CMake 구성·CUDA driver/runtime·소스 import를 재시도한다.
소형 배포 메타데이터와 NVIDIA 공식 문서도 조회 시점·URL·SHA-256·원문 바이트와 함께 공통 logger로 기록한다.
대형 CUDA 의존성, 모델 가중치, Docker 이미지는 자동 다운로드하지 않는다.

```bash
OPENBLAS_NUM_THREADS=1 /tmp/siai-assets-venv/bin/python \
  LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/tensorRT-llm/retry_readiness.py \
  --run-id siai-tensorRT-llm-phi35-readiness-retry-NEW-ID \
  --probe-python /home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/vllm/.venv/bin/python
```

명령은 저장소 루트에서 실행한다. 실행기에 NumPy가 필요하며 `--probe-python`에는 PyTorch가
이미 설치된 환경을 지정한다. 이 환경은 읽기만 하고 TensorRT-LLM 패키지를 설치하지 않는다.
TensorRT-LLM 설치 시도는 자체 `.readiness-venv`에서 수행한다. 예시의 절대 경로는 이 호스트의
환경이므로 다른 호스트에서는 바꿔야 한다. 기존 run ID는 덮어쓸 수 없다.

최종 재진단: `.evidence/raw/siai/tensorRT-llm/siai-tensorRT-llm-phi35-readiness-retry-20260907-002/`.
001은 처음 사용한 NumPy/Pillow 환경에 PyTorch가 없었던 진단 이력이며, 002에서 설치된 CPU
PyTorch 환경으로 추가 확인했다. 두 이력을 현재 native 추론 결과로 취급하지 않는다.

현재 소스는 legacy TensorRT engine backend를 제거한 버전이다. 따라서 “반드시 TensorRT engine으로
먼저 변환해야 한다”는 과거 설명 대신, 현행 PyTorch/AutoDeploy runtime의 CUDA 요건을 확인해야 한다.
MLC `q4f32_1` 가중치를 선택해도 이 요건은 없어지지 않는다.

상세 근거: `Logging-Dataset/siai/tensorRT-llm/readiness-review-20260907.md`.
