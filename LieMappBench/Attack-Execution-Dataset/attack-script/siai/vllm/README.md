# SIAI / vLLM CPU 실행

2026-09-07 출력 안내: [developer.py](../../../../../developer.py) / [investigator.py](../../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

이 폴더의 `run.py`는 계측한 실제 `vllm.LLM.generate` 경로를 실행한다.
NVIDIA GPU 대신 CPU AVX2 extension을 소스에서 빌드했으며, 실제 kernel 실행 및
SmolVLM native 생성 smoke를 확인했다. 최종 전체 실행 여부와 AC/DC 결과는
[현재 프레임워크 안내](../../../../../README.md)와 `internal/experiments.json`이 선택한 봉인 로그·보고서를 확인한다.
과거 run별 선택 이력은 [이전 결과 인덱스](../../../../../.archive/20260907-report-layout/report/siai/README.md)에 보존한다.

- [CPU 환경·빌드·실패와 재개 기록](BUILD_CPU.md)
- [native 실행 명령·격리·소스 계측·원시값](README-native.md)

개별 Transformers 모델 실행, 함수 모의 호출, 과거 실행 로그를 이 엔진의 현재 추론 결과로
대신하지 않았다. 초기 CPU 사전 점검은 설치·빌드 이전 시점의 기록으로 보존한다.

`../shared/run_preflight.py --engine vllm`는 공통 logger로 실제 호스트·패키지·소스
요건을 기록하고 동일한 SIAI 규칙을 공통 Analyzer에 전달한다.
사전 점검의 `blocked` 상태는 AC/DC 내부 값 `null`이며 공개본에서 `F / not_evaluated`로 표시한다. 실제 관측상 불충족이나 안전을 의미하지 않는다.

- 소스 후보·로깅 이유: `Logging-Dataset/siai/vllm/source-review.md`
- 버전별 CPU 준비 사유: `Logging-Dataset/siai/runtime-profiles.json`
- 공통 최적화 입력: `attack-source/siai/shared/experiment-cpu128-v1/dataset.json`
- 공통 행동 평가 입력: `attack-source/siai/shared/behavior-heldout-v1/dataset.json`

원본 `LIE`와 분리된 `Instrumented-LIE/siai/vllm`에만 계측을 적용했다.
최종 로그는 공통 logger만 작성하고, 동일 공통 Analyzer와 조건 규칙으로 판정한다.
