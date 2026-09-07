# SIAI / llama.cpp 실행

2026-09-07 출력 안내: [developer.py](../../../../../developer.py) / [investigator.py](../../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

이 디렉터리는 실제 `llama-mtmd-cli` CPU 프로세스로 이미지 전처리부터 생성까지 수행한다. 기존 `lab/Logger` 실험 결과, HF 모델 단독 호출, 가짜 이벤트로 실제 엔진 실행을 대체하지 않는다.

## 경계와 역할

- 원본: `LieMapp/LIE/llama.cpp`는 수정하지 않는다.
- 계측본: `LieMapp/Instrumented-LIE/siai/llamacpp`는 원본 커밋을 복제한 독립 작업 트리다.
- 계측: 실제 C++ 버퍼를 `Logging-Dataset/native/bridge.h`로 전송한다. 로그와 원시 텐서를 저장하는 구현은 공통 `logger.py` 하나다.
- 입력: `--dataset`의 각 이미지 경로와 SHA-256을 실행 전에 검증한다.
- 출력: `.evidence/raw/siai/llamacpp/<run-id>/`에 새 실행을 만든다. 기존 실행을 덮어쓰지 않는다.
- 보고서: 공통 `LieMappAnalyzer/analyzer.py`가 생성한다. 이 엔진의 실행 코드가 AC/DC를 임의 판정하거나 MD 보고서를 만들지 않는다.

## 빌드

저장소 루트에서 다음 명령을 실행한다. CPU 전용 빌드이며 원본 디렉터리에는 빌드 파일을 만들지 않는다.

```bash
cmake -S LieMapp/Instrumented-LIE/siai/llamacpp \
  -B LieMapp/Instrumented-LIE/siai/llamacpp/build-liemapp \
  -DGGML_CUDA=OFF -DGGML_VULKAN=OFF -DGGML_NATIVE=ON \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=OFF \
  -DMTMD_VIDEO=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build LieMapp/Instrumented-LIE/siai/llamacpp/build-liemapp \
  --target llama-mtmd-cli -j 6
```

Python 실행 환경에는 NumPy와 Pillow가 필요하다. 모델 기본 경로는 현재 로컬 HF 캐시이며, 다른 장비에서는 `--model`, `--mmproj`로 명시한다.

## 실행과 검증

```bash
python LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/llamacpp/run.py \
  --dataset /absolute/path/to/dataset.json \
  --run-id NEW_UNIQUE_RUN_ID
```

`--case INPUT_ID`로 부분 실행을 선택할 수 있다. `--ablate-input INPUT_ID`는 동일 입력·프롬프트·seed에 대해 visual embedding을 0으로 치환한 통제 요청을 추가한다. `--explicit-input INPUT_ID`는 명시적인 스타일 지시를 넣은 양성 대조 요청을 추가한다. 각 요청은 별도 프로세스라 KV 상태를 공유하지 않는다.

`validate_native.py`는 임베딩 전달 경로의 전체 숫자 동등성과 입력·출력·텐서 해시를 확인한다.
dtype·shape·payload 바이트의 엄밀한 일치는 별도 공통 `../shared/verify_byte_identity.py`로 검증한다.
추가로 같은 바이너리의 계측 OFF 실행과 stdout을 비교한다. 이 검증은 별도로 빌드한 upstream 바이너리와의 동등성 검증은 아니다.

```bash
python LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/llamacpp/validate_native.py \
  --run-dir /absolute/path/to/completed-run \
  --output-run-id NEW_VALIDATION_RUN_ID
python LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/llamacpp/freeze_mapping.py \
  --run-dir /absolute/path/to/completed-run \
  --name NEW_MAPPING_NAME
```

## 원시 값 해석 시 주의

현재 SmolVLM-256M Q8 모델의 512×512 입력은 overview와 tile의 두 이미지 청크로 처리된다. 따라서 한 요청에서 `encoder_input`, `projected_embedding`, `decoder_input` 이벤트가 각각 두 번 발생한다. 같은 요청·stage의 텐서를 **이벤트 순서대로 모두 연결**해야 전체 값을 비교할 수 있다.

| stage | 관측한 실제 값 |
|---|---|
| `processor_output` | 모든 정규화 픽셀 버퍼를 연결한 1D float32 및 각 part의 HWC shape |
| `encoder_input` | `clip_image_batch_encode`에 전달되는 실제 픽셀 버퍼 |
| `projected_embedding` | 성공한 vision encoder/projector의 `[이미지 토큰, 임베딩 차원]` 출력 |
| `decoder_batch` | 실제 `llama_decode` 호출에 전달된 배치와 반환 코드 |
| `decoder_input` | 한 청크의 모든 디코더 배치가 성공한 후 기록한 전체 소비 버퍼 |
| `intervention` | visual embedding을 0으로 치환했다는 통제 실험 기록 |
| `generation_output` | 첫 생성 토큰의 전체 logits, 생성 텍스트, 토큰 ID |
| `runtime_output` | 원문 stdout/stderr, 무손실 출력 바이트, 종료 코드 |

데이터셋에 attack 역할이 지정되어 있어도 공격 성공을 뜻하지 않는다. 다른 VLM에서 생성한 PGD 이미지를 이 GGUF 모델에 입력하면 양자화·이미지 토큰 구성 등의 차이가 있는 전이 실험이며 원 논문의 동일 조건 재현으로 표현하지 않는다.
