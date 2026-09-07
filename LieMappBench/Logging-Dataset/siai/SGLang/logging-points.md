# SGLang — 실제 계측 지점 및 로깅 근거

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

현재 소스의 실제 native Engine/scheduler 실행 경로다. `source-review.*`의 정적 후보 매핑과 구분한다.

실제 event ID·JSONL 위치·반환값·첫 8개 raw 수치와 **전체 raw artifact 링크**는 [evidence-examples.md](evidence-examples.md)에 별도로 제시한다. 아래 shape는 값 자체가 아니며, 실제 기록 수치는 이 보조문서와 `.npy` 파일을 확인한다.

원본 commit: `97c6978369ac1e04c91fcc01c98acc25129a6000`. 원본 LIE 및 HF cached weights는 수정하지 않았다.

완료 실험 당시 runner와 post-experiment 배포 CLI guard를 구별하는 [릴리즈 노트](post-experiment-release-note.md) 및 [원본 runner snapshot](source-snapshots/3564b8a17cb584778f6e094af6def5bd18fbbb5d771e553e432528197632ffd9-run.py)을 보존했다. 아래 native engine hook source는 변경하지 않았다.

CPU 전처리 변형: resize/splitting 비활성, 512×512 단일 이미지, visual tokens 64. 원래 SGLang 기본 전처리(1088 tokens)와 구분하며 stock benchmark로 주장하지 않는다.

교차 엔진 참고값 정정: overlay 생성 당시 `comparison_layouts.vllm=128`을 예상값으로 기록했으나 실제 vLLM 성공 smoke-003과 이후 완료된 canonical은 320 tokens(5 parts, longest_edge 1024)다. 이 참고값은 SGLang의 실행 설정에 사용되지 않는다. 실행 중 overlay provenance·실제 processor config는 변경하지 않았고, canonical/heldout에서 동일한 SGLang 64-token 설정과 config hash를 사용한다. 준비 script의 후속 참고값 수정도 기존 overlay의 재생성을 의미하지 않는다.

| 이벤트 | 실제 source hook | 원본 엔진의 연결 지점 | AC/DC | raw 값 |
|---|---|---|---|---|
| processor_output | `python/sglang/liemapp_observer.py:91` (processor_output) | `python/sglang/srt/multimodal/processors/transformers_auto.py:225` | AC2, DC1 | [1,3,512,512] FP32 normalized pixels |
| encoder_input | `python/sglang/liemapp_observer.py:112` (vision_pre) | `python/sglang/srt/models/transformers.py:659` | AC1, AC2, DC1 | [1,3,512,512] FP32 actual vision forward input |
| projected_embedding | `python/sglang/liemapp_observer.py:117` (connector_post) | `python/sglang/srt/models/transformers.py:659` | AC1, AC3, DC2, DC3 | [64,576] FP32 projected visual embeddings |
| decoder_input | `python/sglang/liemapp_observer.py:134` (text_post) | `python/sglang/srt/models/transformers.py:1027` | AC1, AC3 | [64,576] FP32 visual rows actually consumed by completed decoder |
| generation_output | `python/sglang/liemapp_observer.py:148` (capture_logits) | `python/sglang/srt/layers/logits_processor.py:506` | AC1, AC3 | [49280] FP32 first-step logits + exact Engine-generated text/token IDs |

## processor_output — 로깅 이유

실제 request_obj.rid가 활성 요청과 일치할 때 HF processor의 최종 FP32 pixel_values 전체를 기록한다. encoder_input과 bitwise 비교하여 같은 입력이 실제 vision encoder로 전달됐는지 확인한다.

## encoder_input — 로깅 이유

Engine가 소유한 실제 SmolVLM vision_model의 forward_pre_hook에서 전처리 후 입력 텐서를 수집한다. callback은 실제 scheduler batch의 rid와 일치한 동안에만 활성화된다.

## projected_embedding — 로깅 이유

실제 vision connector의 성공한 forward 직후 투영된 임베딩 전체를 기록한다. 원본·증강 같은 계층의 값으로 cosine을 계산하고 decoder가 실제 소비한 visual rows와 비교한다. Ablation에서도 원래 projection 결과는 보존하고 전달되는 반환값만 0으로 개입한다.

## decoder_input — 로깅 이유

실제 image_token_id mask로 language decoder에 들어간 visual rows를 선택하고, 해당 text_model forward가 성공한 후 기록한다. 구조적 호출만으로 인과성을 주장하지 않고 별도 fresh-process zero-visual 실험 및 첫 logits 변화와 결합한다.

## generation_output — 로깅 이유

실제 SGLang LogitsProcessor.forward의 첫 전체 next-token logits 벡터를 수집한다. private IPC의 rid를 검증한 후 동일 Engine.generate 응답의 원문·token IDs와 합쳐 common logger가 최종 저장한다. 후속 decode logits 및 warmup은 섞지 않는다.

## 요청 격리와 raw 증거

실제 native rid가 명시한 request_id 한 개와 정확히 일치할 때만 활성화한다. init/warmup 및 다른 요청을 계측 증거에 포함하지 않는다. 공격 원본과 zero-visual ablation은 서로 다른 fresh process이며 나머지는 순차 shared Engine이다. 각 이벤트 context에 실제 isolated_process 값을 기록한다.

processor/encoder/projected/decoder는 전체 FP32 `.npy`, generation은 첫 전체 logits `.npy` 및 원문 text/token IDs다. preview만으로 비교하지 않으며 공통 Analyzer가 hash/shape/finite 값 및 봉인을 확인한다.

함수 `_encode_modality_items`는 정적 후보였지만 이 실행의 실제 visual 경로를 대표하지 않는다. 실제 계측은 위 native wrapper가 소유한 vision_model / connector / text_model의 forward callback이다. 단독 HF 모델 실험으로 SGLang을 대체한 것이 아니다.

선택적 EAGLE/cache-copy CPU extension import의 호출시점 지연은 `cpu-feasibility-review.md` 및 실제 patch를 참조한다. 존재하지 않는 커널을 흉내 내거나 attention 연산을 바꾸지 않았다.
