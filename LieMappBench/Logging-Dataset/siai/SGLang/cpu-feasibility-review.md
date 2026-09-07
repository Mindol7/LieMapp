# SGLang CPU native feasibility review

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

원본 revision: `97c6978369ac1e04c91fcc01c98acc25129a6000`. 원본 `LieMapp/LIE/sglang`는 변경하지 않았다. 아래 결과는 실제 CPU Engine/scheduler smoke이며, 요청별 canonical LP 계측 및 AC/DC 판정과는 구분한다.

## 확인 결과

- **AMX 부재만으로 CPU 실행 불가라고 할 수 없다.** `python/sglang/srt/arg_groups/overrides.py:1353`의 `_attention_backend_platform_fallbacks`는 CPU에 AMX가 없으면 `intel_amx` → `torch_native`로 전환한다.
- `layers/attention/torch_native_backend.py`는 PyTorch SDPA로 prefill/decode를 수행한다. `platforms/cpu.py`의 CPU device에는 gloo/CPU 메모리 조회 경로가 있다. `distributed/bootstrap.py:210`은 비 AMX/비 ARM에서는 특수 shared-memory all-reduce 초기화만 생략한다.
- `kernels/fused_op.py`는 비 AMX CPU에서 원래 존재하는 `forward_native`를 선택한다. `mem_cache/allocation.py`의 일반 prefill writer에도 원래 Torch 경로가 있다.
- 다만 CPU AOT CMake는 x86 전체에 `-march=x86-64-v4`, AVX512, AMX flags를 지정한다. 따라서 이를 AVX2 호스트에서 무검증 실행하지 않았다. 이 사실은 **AOT 빌드의 ISA 설정**이지, Torch attention fallback 전체가 불가능하다는 뜻이 아니다.

## 실제 환경과 최소 호환성 변경

별도 clone: `LieMapp/Instrumented-LIE/siai/SGLang`, 별도 `.venv`.
설치: torch `2.12.0+cpu`, torchvision `0.27.0+cpu`, transformers `5.12.1` 및 원본 CPU manifest의 나머지 Python 의존성.

원본 manifest는 torch 2.12.0과 torchaudio 2.11.0을 동시에 pin한다. matching torchaudio 2.12.0+cpu는 실제 resolver에서 없었으며, image-only 요청을 위해 torchaudio는 설치하지 않았다. 음성 모델을 검증했다고 주장하지 않는다.

Engine import가 선택적 CPU cache-copy / EAGLE speculative extension을 시작 시 요구했다. 다음 8개 파일에서 **import를 실제 호출 위치로만 이동**했다. 연산, scheduler, attention, 가중치는 대체하지 않았고, 그 선택 기능이 호출되면 실제 `sgl_kernel`이 여전히 필요하다.

- `kernels/ops/kvcache/cache_move.py`
- `kernels/ops/speculative/cache_locs.py`
- `kernels/ops/speculative/eagle.py`
- `kernels/ops/speculative/multi_layer_eagle.py`
- `srt/mem_cache/allocation.py`
- `srt/speculative/eagle_utils.py`
- `srt/speculative/eagle_worker_common.py`
- `srt/speculative/spec_utils.py`

개별 setup run의 `compatibility_source.raw.git_diff`에서 실제 실행 시점 수정 원문을 확인한다. 이전 probe-001/002는 해당 기록 기능 도입 이전의 실패 실행이다. 어떤 CUDA 장치/커널 stub도 만들지 않았다.

## 실제 smoke 결과

공통 Logger 로그: `.evidence/raw/siai/SGLang/siai-SGLang-cpu-smoke-20260906-001/events.jsonl`.

실행 설정: `SGLANG_USE_CPU_ENGINE=1`, OMP/MKL 2 threads, `Engine(device='cpu', dtype='float32', model_impl='transformers', attention_backend='torch_native', tp_size=1, disable_overlap_schedule=True, disable_cuda_graph=True, max_total_tokens=2048, context_length=2048, max_running_requests=1, chunked_prefill_size=-1, disable_radix_cache=True)`.

모델은 기존 캐시의 `HuggingFaceTB/SmolVLM-256M-Instruct` revision `7e3e67edbbed1bf9888184d9df282b700a323964`, 입력은 실제 clean cassette image. Native tokenizer → scheduler → `TransformersMultiModalForCausalLM` → engine 반환까지 성공했다. 별도 `HF.generate` 호출은 없다.

- process exit: **0**
- request rid: `liemapp-native-smoke-only-001`
- image tokens: **1088**, prompt tokens: **1143**
- completion tokens: **32**, finish: length limit
- native response latency: **43.06101633500657 s**
- 원문 응답: ` The image depicts a black Sony branded stereo system placed on a wooden surface. The stereo system is a compact, rectangular device with a sleek design. It has a`

이 실행은 raw LP tensor를 수집하지 않은 **native smoke**다. 따라서 공통 Analyzer 결과는 AC 3개/DC 3개 모두 unknown이다. 기본 processor의 17개 image parts는 PGD source HF의 splitting-disabled 1개 part와 다르다. 단순 smoke 출력으로 SIAI 공격 성공이나 방어 성능을 주장하지 않는다.

## 이전 로그의 보존 및 해석 정정

- `torch-20260906-001`: matching torchaudio wheel 부재로 실제 resolver 실패. 보존했다.
- `torch-20260906-002`: 실제 torch 설치는 성공했으나 setup wrapper의 `close(status='complete')` 오타로 **미봉인** 상태다. 원본 이벤트를 사후 수정/봉인하지 않았다. 수정 wrapper의 `torch-20260906-003`에서 설치 상태를 재검증하고 정상 봉인했다.
- `smoke-20260906-001`의 setup wrapper 메타데이터에는 실행 전 상수 `native_inference_executed:false` / `native_inference_claimed:false`가 남았다. **이 두 상수는 실제 stdout의 성공한 Engine 응답과 상충하는 wrapper 표기 오류**다. 원본 로그는 보존하고 여기서 정정한다. 정확한 해석은 위 native smoke 성공 + canonical 계측 미수행이다. 후속 wrapper는 실행 전 `pending`과 실행 후 실제 관측 값을 분리한다.

이 문서는 별도 feasibility 설명이며, common Analyzer의 AC/DC 자동 판정을 대체하지 않는다.
