# TensorRT-LLM / Phi-3.5-vision MLC 재진단

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

결론: **이 호스트에서는 native TensorRT-LLM SIAI 추론을 실행하지 못했다.**
실측 AC/DC 값은 `not_evaluated`이며, 설치 실패나 모델 형식 불일치를 조건의 실측 F로 해석하지 않는다.
기존 Qwen2-VL 소스 매핑은 정적 후보이며 이번 Phi3V 모델의 실행 매핑으로 바꾸어 부르지 않는다.

## 실제 재시도와 증거

기준 소스는 `a5f8680e418a1b01eddb4824980495a3670e5168` (`1.3.0rc26`).
원본 `LIE/TensorRT-LLM`의 HEAD와 git 작업 상태는 재시도 전후 동일했다.
`Instrumented-LIE/siai/tensorRT-llm`에 로컬 복제본을 만들었지만 추론 계측 패치를 적용하지 않았다.

최종 원본 증거: [events.pretty.json](../../../../.evidence/raw/siai/tensorRT-llm/siai-tensorRT-llm-phi35-readiness-retry-20260907-002/events.pretty.json),
[events.jsonl](../../../../.evidence/raw/siai/tensorRT-llm/siai-tensorRT-llm-phi35-readiness-retry-20260907-002/events.jsonl),
[seal.json](../../../../.evidence/raw/siai/tensorRT-llm/siai-tensorRT-llm-phi35-readiness-retry-20260907-002/seal.json).
공통 logger가 명령·return code·stdout/stderr 및 손실 없는 byte artifact를 저장했다.

|실제 시도|관측 결과|원시 event ID|
|---|---|---|
|독립 Python 환경에서 `pip install --no-build-isolation --no-deps -e ...`|return code 1. native `bindings` 사전 빌드가 없어 설치 불가|`7f6be881b39c43949ab72907dc0cb60e`|
|실제 native CMake configure|return code 1. `No CUDA compiler found`; `cuda_configuration.cmake:246` → `CMakeLists.txt:185`|`16a697b6fc1c49ac9cd16574450f8be6`|
|CUDA driver 동적 로드|return code 3. `libcuda.so.1` 없음; `/dev/nvidia0`, `/dev/nvidiactl` 없음|`454535bf8bf04f09bbc402999dd73a69`|
|설치된 `torch 2.13.0+cpu` 환경의 CUDA 확인|CUDA 사용 불가, device count 0, CUDA 초기화 실오류|`c04bf07f3b07455885f45f195ea64fb0`|
|실제 소스 package import|return code 1. `nvtx` 미설치에서 정지. 이 보조 오류만으로 하드웨어 불가를 판정하지 않음|`548386e499764889aebd3defc42cfd2d`|

`nvidia-smi`와 `nvcc`도 실행 파일이 없었다. `/dev/dxg`의 존재는 Windows 그래픽 인터페이스를
뜻할 뿐 이 프로세스에서 CUDA 장치를 사용할 수 있다는 증거가 아니다. CPU-only PyTorch의 결과 역시
단독으로 물리 GPU 부재를 증명하지 않으므로 driver·도구·현재 소스·공식 지원 요건과 함께 해석한다.
001 이력의 `torch` 패키지 부재는 002에서 실제 설치된 CPU PyTorch 환경으로 재검사했다.

## 모델 형식과 장치 요건은 별개다

요청한 `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC`는 배포자가 MLC-LLM/WebLLM용으로 명시한
MLC 형식이다. 고정 revision `2d7104ab34b358b4223aabca1d08e451c6b12728`에서 확인한
`mlc-chat-config.json`은 `model_type=phi3_v`, `quantization=q4f32_1`이다.
이 파일과 MLC tensor-cache 가중치를 현행 TensorRT-LLM의 HF checkpoint로 직접 취급할 수 없다.
모델 가중치는 MLC 담당자가 받은 파일을 공유하며 이 진단은 중복 다운로드하지 않았다.
[MLC 배포자 모델 카드](https://huggingface.co/mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC).

Microsoft 원본 config의 아키텍처는 `Phi3VForCausalLM`이다. 현재 소스의 직접 PyTorch registry에는
그 이름이 없고 `Phi3ForCausalLM`은 별도로 등록되어 있다. 텍스트 Phi 계열의 등록을 동일한 vision
모델 지원으로 혼동하지 않는다. 이 검사는 모든 AutoDeploy 확장 가능성을 부정하는 검사가 아니다.
[Microsoft config](https://huggingface.co/microsoft/Phi-3.5-vision-instruct/blob/12b77fb40b63a2c73c68243d3f767aab688a1b2a/config.json),
[고정 소스 registry](https://github.com/NVIDIA/TensorRT-LLM/blob/a5f8680e418a1b01eddb4824980495a3670e5168/tensorrt_llm/_torch/models/_arch_index.py).

## CPU 경로를 다시 검토한 근거

현재 TensorRT-LLM은 legacy TensorRT engine backend를 제거하고 PyTorch/AutoDeploy를 사용한다.
따라서 오래된 engine 변환 절차를 현재 버전의 필수 절차라고 쓰지 않는다. 다만 backend 이름이
PyTorch라는 이유만으로 CPU-only native 실행이 제공되는 것은 아니다.
[공식 migration 문서](https://nvidia.github.io/TensorRT-LLM/latest/legacy/tensorrt-backend-removal.html).

|현재 고정 소스 지점|확인한 내용|이 근거의 범위|
|---|---|---|
|`cpp/CMakeLists.txt:185,187,239`|CUDA compiler 설정, CUDA 언어 활성화, 필수 CUDA Toolkit 라이브러리|현재 native core 빌드 경로|
|`tensorrt_llm/_torch/pyexecutor/py_executor_creator.py:871`|모델 실행을 위한 `torch.cuda.Stream()` 생성|기본 public executor 경로|
|`tensorrt_llm/_torch/auto_deploy/shim/ad_executor.py:1139`|public AutoDeploy executor의 `torch.cuda.set_device(rank)` 호출|`device='cpu'` 인자만으로 이 경로를 제거하지 못함|
|`tensorrt_llm/_torch/auto_deploy/llm_args.py:272`|모델 device 설정은 존재|부분 모델·시험 경로의 CPU 설정을 full engine CPU 지원으로 단정하지 않음|

공식 지원 하드웨어는 NVIDIA GPU이며, 현재 설치 가이드도 CUDA Toolkit 및 NVIDIA driver를 전제로 한다.
소스의 CPU offload·calibration·일부 단위시험 경로는 GPU 없이 전체 scheduler→vision→decoder→generation이
동작한다는 증거가 아니다. HF forward 또는 MLC 실행으로 대체하여 TensorRT-LLM 실험이라고 기록하지 않았다.
[지원 하드웨어](https://nvidia.github.io/TensorRT-LLM/supported-hardware.html),
[설치 가이드](https://nvidia.github.io/TensorRT-LLM/installation/installation-guide.html).

## 재개 조건

현재 소스가 지원하는 NVIDIA CUDA 장치와 build/runtime 환경, 그리고 TensorRT-LLM이 실제로 로드하는
호환 vision checkpoint가 필요하다. 그 뒤 해당 모델 경로에 공통 logger 계측을 적용하고 native SIAI
실행을 별도로 검증해야 한다. 이 호스트에서 모델 파일 형식만 바꾸어 실행을 완료할 수 있다고 판단할
근거는 찾지 못했다. 큰 CUDA 의존성·컨테이너를 하드웨어 없이 무작정 설치하지 않았다.
