# SGLang — native CPU SIAI pilot

2026-09-07 출력 안내: [developer.py](../../../../../developer.py) / [investigator.py](../../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

이 디렉터리는 **실제 SGLang Engine / tokenizer / scheduler / TorchNativeAttnBackend** 요청을 실행한다. SGLang 대신 독립 HF 모델을 호출하지 않는다. 로깅·raw `.npy`·봉인은 모두 공통 `LieMappBench/Logging-Dataset/logger.py`가 수행한다. 분석은 수정하지 않은 공통 `LieMappAnalyzer/analyzer.py`와 `Logging-Dataset/siai/conditions.json`으로 수행한다.

## 실험 범위

- 원본 SGLang revision: `97c6978369ac1e04c91fcc01c98acc25129a6000`.
- 모델: cached SmolVLM-256M-Instruct revision `7e3e67edbbed1bf9888184d9df282b700a323964`, 실제 FP32 weights.
- 입력: 사전 고정된 shared `experiment-cpu128-v1/dataset.json` 84개와 attack zero-visual / clean explicit-instruction 대조군 2개.
- CPU 2 threads, TP1, eager Torch native attention, KV prefix/radix cache off, processor cache 0 MB, `SGLANG_VLM_CACHE_SIZE_MB=0`, prefix/global multimodal cache off.
- **명시적 CPU one-tile processor adaptation**: resize와 image splitting을 끄고 512×512 입력을 사용한다. private overlay는 JSON config만 복사하고 원래 weights는 symlink한다. 원본 HF cache는 변경하지 않는다.
- image tokens: PGD source HF 64 / llama.cpp 128 / vLLM **320 (5 parts, longest_edge 1024; 완료된 canonical 포함)** / SGLang **이 변형 64**. 원래 stock SGLang smoke에서는 1088 tokens가 관측됐다. 이 결과를 stock 설정끼리의 공정한 성능 벤치마크 또는 원 논문 ASR 재현으로 주장하지 않는다.

Overlay 생성 시점의 `comparison_layouts.vllm=128`은 당시 예상 설정을 기록한 것이며, 이후 실제 vLLM smoke 관측값은 위의 320이다. SGLang 실행 중 원본 provenance를 바꾸지 않고 여기서 교차 엔진 참고값을 정정한다. SGLang 자체 processor 설정·가중치·64 token 관측에는 변경이 없다.

## 요청 격리와 계측

실제 processor의 `request_obj.rid`, scheduler의 `batch.reqs[*].rid`가 사전 활성화한 request_id **한 개와 정확히 일치**해야 observer가 활성화된다. 초기화/warmup은 비활성 상태다. 각각의 context와 이벤트 raw에 rid를 기록한다.

공격 원본 normal 요청과 zero-visual ablation은 서로 다른 fresh Engine process에서 실행한다. 나머지 calibration/clean/증강/explicit 요청은 캐시를 끈 하나의 Engine에서 순차 실행한다. `context.isolated_process`는 전자에만 True이며 나머지는 False다. attack original은 shared group에서 제외하므로 중복 pair를 만들지 않는다.

임베딩은 실제 engine-owned SmolVLM의 vision_model / connector / text_model forward callback에서 수집한다. 전처리→encoder 입력 및 projection→decoder 소비 값을 bitwise 비교한다. Ablation은 원래 projection 값을 먼저 기록한 뒤 decoder에 전달되는 visual embedding만 0으로 개입한다.

첫 전체 logits는 scheduler에서 private 임시 IPC로 전달하고, Engine.generate completion의 rid를 재검증하여 원문 text/token IDs와 결합한 후 common logger에 기록한다. 임시 IPC는 최종 로그가 아니며 프로세스 그룹 종료 후 정리된다. 최종 raw artifacts는 `.evidence/raw/`에 보존되고 공개 조건 JSON에서 연결한다.

## 실행

프로젝트 root에서, numpy를 포함한 **전용 가상환경 Python으로 부모 runner도 실행**한다.

```bash
python3 LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/SGLang/prepare_overlay.py

LieMapp/Instrumented-LIE/siai/SGLang/.venv/bin/python \
  LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/SGLang/run.py \
  --run-id <NEW-UNIQUE-RUN-ID> \
  --ablate-input evaluation-cassette-attack--original \
  --explicit-input evaluation-cassette-clean--original \
  --max-tokens 64

OPENBLAS_NUM_THREADS=1 /tmp/siai-assets-venv/bin/python \
  LieMapp/developer.py --attack siai --engine SGLang \
  --log LieMapp/.evidence/raw/siai/SGLang/<NEW-UNIQUE-RUN-ID>/events.jsonl \
  --replace
```

선택 smoke는 `--case <input_id>`를 반복한다. `--dataset`으로 동일 shared behavior-heldout manifest를 지정할 수도 있다. 평가 질문/학습 조건/threshold는 결과에 따라 변경하지 않는다.

실제 child Engine seed는 **20260906**, temperature는 0이다. `context.seed`는 입력 manifest의 이미지/증강 생성 seed로서 추론 RNG seed와 구별해야 한다. 완료된 canonical/heldout/repeat는 모두 같은 기본값으로 실제 실행됐다. 실험 종료 후 현재 배포 runner는 **`--seed`를 20260906으로 제한하여 다른 값이면 즉시 거부**하도록 한 줄 guard를 추가했다. 실험 당시 runner 원본은 byte-exact snapshot으로 따로 보존했으며, 당시 custom seed가 child에 전달되지 않던 제한을 기본값이 아닌 실행까지 지원하는 것처럼 남기지 않았다. 원시 로그·엔진 source·overlay는 변경하지 않았다. 자세한 해시와 5개 CLI 테스트는 `Logging-Dataset/siai/SGLang/post-experiment-release-note.md`를 본다.

## 검증과 해석

`test_observer.py`는 요청-ID gating·FP32 손실 없는 복사·overlay 보존에 대한 합성 unit test다. 실제 실험 evidence로 사용하지 않는다. `verify_run.py <run_dir> --output <new_json>`는 실제 수집한 각 요청의 이벤트 수·rid·해시·shape·bitwise 전달·ablation을 독립 검증하지만, 공통 Analyzer 판정을 대체하지 않는다.

`siai-SGLang-native-one-tile-smoke-20260906-003`의 실제 3요청은 AC 3개 T / DC 3개 unknown이다. 증강·정상 baseline이 없는 smoke에서는 DC를 완료했다고 말하지 않는다. 이전 smoke-001/002는 각각 TorchVersion 직렬화와 부모 interpreter의 numpy 부재로 실패했고 별도 run으로 봉인·보존했다.

실제 계측 지점·로깅 근거·source hashes는 `Logging-Dataset/siai/SGLang/logging-points.json/.md`를 본다. 초기 설치·호환성 문제와 stock native smoke는 같은 디렉터리 `cpu-feasibility-review.md`에 정리되어 있다. 어떤 실패도 안전/취약성 부재로 해석하지 않는다.

## 완료된 결과의 진입점

다음 경로는 `LieMapp/` 기준이다. setup/smoke/초기 분석을 삭제하거나 최종 결과로 바꾸지 않고, 최종 선택본을 구별했다.

- 조건 감사 86요청: `.evidence/raw/siai/SGLang/siai-SGLang-native-cpu-one-tile-20260906-001/`.
- 당시 공통 Analyzer 선택본: `.archive/20260907-report-layout/report/siai/SGLang/siai-SGLang-native-cpu-one-tile-20260906-001-reviewed-common-serial/report.md`. 현재 공개본은 `report/siai/SGLang/SIAI-SGLang-Report.md`이다. AC 3개 T / DC 3개 T는 정의한 조건의 근거 충족이며 완전한 공격 성공률이 아니다.
- 실제 LP별 raw 예시: `LieMappBench/Logging-Dataset/siai/SGLang/evidence-examples.md`와 JSON. event ID, JSONL 행/sequence, 원시 반환값, preview 8개, 전체 `.npy` 링크를 함께 제공한다.
- 행동 평가 12요청: `.evidence/raw/siai/SGLang/siai-SGLang-behavior-heldout-one-tile-20260906-001/`; 공통 분석은 동일 run-id의 `-reviewed-common-serial` 보고서다. 조건 감사에 섞이지 않아 AC/DC Unknown이 정상이다.
- 당시 별도 정성 검토: `.archive/20260907-report-layout/report/siai/SGLang/behavior-review.md`. 12개 native 및 8개 HF source 원문, α-marker와 β 의미/질문 보존을 별도로 제공하며 자동 Analyzer 판정이 아니다. 현재 공개본에는 보조 관찰로 통합한다.
- 단독 반복: `.evidence/raw/siai/SGLang/siai-SGLang-native-repeat-one-tile-20260906-001/`. root의 공통 비교 검증 `siai-SGLang-repeat-validation-20260906-001`은 정상 공격 원본 대비 input/projection/decoder/전체 first logits/text/token IDs exact 일치를 확인했다. zero-visual과의 logits 차이와 비개입 반복을 구별한다.

최종 분석은 **`OPENBLAS_NUM_THREADS=1 /tmp/siai-assets-venv/bin/python`**으로 수행했다. 이전 `-reviewed`는 BLAS thread 고정 없이 생성해 최대 2.4425e-15 부동소수 차이가 있었지만 조건 판정 변화는 없었다. 이전 `-reviewed-serial`은 엔진 venv에서 thread 1로 계산했으며 선택한 common-serial과 조건 계산값이 같았다. `analysis-environment-comparison.json`에 이 차이를 남겼으며 기존 보고서를 덮어쓰지 않았다.
