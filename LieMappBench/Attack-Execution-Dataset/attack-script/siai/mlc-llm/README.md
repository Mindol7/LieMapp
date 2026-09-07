# SIAI / mlc-llm 실행 상태

2026-09-07 재시도 결과: **Phi-3.5 Vision 공식 MLC 모델 다운로드 및 fresh CPU C++ runtime 빌드·factory 생성 완료, 모델 LLVM 컴파일 실패, native 추론 0회.** 이 폴더는 완성된 native 공격 runner가 아니다.
개별 Transformers 모델 실행, 함수 모의 호출, 과거 실행 로그를 이 엔진의 현재 추론 결과로 대신하지 않았다.

`../shared/run_preflight.py --engine mlc-llm`는 공통 logger로 실제 호스트·패키지·소스
요건을 기록하고 동일한 SIAI 규칙을 공통 Analyzer에 전달한다.
사전 점검의 `blocked` 상태는 AC/DC 모두 판정불가이며 F/안전을 의미하지 않는다.

최종 공통 공개 보고서의 표시 정책은 **F / 미평가**이다. 이는 기존 core의 unknown을 가독성 있게 표시한 것이며, 실제 조건 불충족을 관측하거나 안전을 입증한 F가 아니다.

## 새 모델 재시도

- 모델: `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC`, pin `2d7104ab34b358b4223aabca1d08e451c6b12728`.
- 획득: `download_phi35.py` — 공식 API/LFS/Git blob 메타데이터와 114개 파일 전체 검증. 같은 모델을 중복 다운로드하지 않고 일치하는 파일을 재사용한다.
- 실제 setup/build/compiler 명령: `record_command.py` — 공통 Logger로 명령·환경 override·stdout·stderr·반환코드 보존.
- 재현: `reproduce_compile.py` — 새 source/output 경로에서 stock 및 두 실패 호환 변형을 명시적으로 선택. 원본 및 현재 private 소스를 덮어쓰지 않는다.
- 최종 진단: `finalize_readiness.py` — 기존 raw seal/hashchain, 공식 모델 전체 SHA256, source 원문과 fresh 바이너리·Cargo.lock 보존. 새 run-id만 허용.
- 모델별 소스 매핑: `generate_source_review.py` — 컴파일 시 IR 작성 함수와 native runtime 관측을 구분. 실행하지 않은 후보에 raw tensor 값을 만들지 않는다.
- 로컬 검증: 전용 MLC `.venv/bin/python -m pytest -q .../test_retry_tools.py`에서 7/7 통과.

최종 raw: `.evidence/raw/siai/mlc-llm/siai-mlc-phi35-readiness-20260907-001/`.
상세: `Logging-Dataset/siai/mlc-llm/phi35-cpu-retry.md`, `source-review-phi35-cpu-retry.md/.json`.

`Instrumented-LIE/siai/mlc-llm/engine`의 두 Python 변경은 **실패한 CPU 호환성 시험 코드**이며 작동하는 계측 버전이 아니다. 이후 실제 실행에는 CPU 이미지 커널 lowering 및 crop 계약 수정을 별도 검증해야 한다. 이번에는 그 포트를 수행하지 않았다. 새 Phi 모델에서 기존 SmolVLM PGD 입력을 쓰는 경우 교차 모델 전이 실험이지만, 이번에는 추론하지 못해 전이 여부 자체가 미평가다.

- 소스 후보·로깅 이유: `Logging-Dataset/siai/mlc-llm/source-review.md`
- 버전별 CPU 준비 사유: `Logging-Dataset/siai/runtime-profiles.json`
- 공통 최적화 입력: `attack-source/siai/shared/experiment-cpu128-v1/dataset.json`
- 공통 행동 평가 입력: `attack-source/siai/shared/behavior-heldout-v1/dataset.json`

공통 입력을 준비한 것과 이 엔진에서 실행한 것은 다르다. 실행 환경이 준비되면
원본 `LIE`와 분리된 `Instrumented-LIE/siai/mlc-llm`에 계측을 적용하고,
동일 logger로 실제 값만 수집해야 한다.
