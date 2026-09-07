# MLC-LLM / Phi-3.5 Vision: CPU 재시도 기록

최종 상태: **공식 모델 다운로드·fresh CPU runtime 빌드·C++ engine factory 생성 완료. PhiV LLVM 모델 컴파일은 실패하여 native 추론 0회 / AC·DC 미평가.**

최종 sealed run: `siai-mlc-phi35-readiness-20260907-001` (12 events, status=`blocked`). `events.jsonl` SHA256: `765c10cc70fa3dbeadb488a8bdd7e30a4b0b445356866f34a4d64454293c8b06`.

공통 보고서에 포함할 보조 정보는 `.evidence/supplements/siai/mlc-llm.json`에 저장했다. 보조 정보는 Analyzer T/F 규칙의 입력이 아니다. 상세 로깅 후보는 [모델별 소스 매핑](source-review-phi35-cpu-retry.md)에 따로 정리했으며, 정적 후보와 실제 계측값을 구분한다.

기존 SmolVLM 미지원 진단 이후, 사용자의 명시적인 모델 변경·다운로드 승인에 따른 별도 재시도다. 원본 `LIE/mlc-llm`과 모델 배포 파일은 수정하지 않는다. 패치·빌드는 `Instrumented-LIE/siai/mlc-llm/engine` 안에서만 수행한다.

## 고정 출처와 실험 의미

| 항목 | 확인값 |
|---|---|
| MLC 소스 | `9fa644f54b04983adea4d0168f49fc6af4a893ba` |
| TVM 서브모듈 | `837cb9de1127b48ce48e4cefe09e83215b9d4ba7` |
| TVM-FFI 서브모듈 | `21e30c3b1d4421f95fd69a6ba3fd0285c7b69e9c` |
| 공식 모델 | `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC` |
| 모델 revision | `2d7104ab34b358b4223aabca1d08e451c6b12728` |
| 배포 파일 | 114개 / 2,771,867,899 bytes; 각 Git blob 또는 LFS SHA와 바이트 길이 검사 |
| 양자화 | q4f32_1: group 32, int4/uint32 저장, float32 모델·scale |
| 기반 모델 라이선스 | Microsoft Phi-3.5 Vision, MIT; 원문과 해시 별도 보존 |
| 공격 입력 | 앞서 SmolVLM-256M에서 생성한 동일 PGD 이미지. **교차 모델 전이 실험**이며 Phi-3.5 대상 재학습 또는 원문 재현 성공을 의미하지 않음 |

공식 근거: [모델 저장소](https://huggingface.co/mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC), [Microsoft 원모델](https://huggingface.co/microsoft/Phi-3.5-vision-instruct), [MLC 모델 컴파일 문서](https://llm.mlc.ai/docs/compilation/compile_models.html), [MLC 양자화 문서](https://llm.mlc.ai/docs/compilation/configure_quantization.html).

모델 원문·라이선스·파일별 해시: `Attack-Execution-Dataset/attack-source/siai/mlc-llm/phi35-provenance/manifest.json` 및 같은 디렉터리의 API JSON과 LICENSE.

## 이미 수행한 실제 단계

모든 실행은 공통 `logger.py`로 `.evidence/raw/siai/mlc-llm/` 아래 보존했다. 아래 `001` 등의 번호는 동일 접두사 내 번호이며 로그 전체 ID로 조회한다.

| 실제 run ID | 결과와 의미 |
|---|---|
| `siai-mlc-phi35-model-verified-20260907-002` | 완료. 공식 원본 114개 전체 재검증; 모델 획득의 우선 참조 증거 |
| `siai-mlc-phi35-source-clone-20260907-001` | 완료. 원본과 같은 commit의 별도 clone |
| `siai-mlc-phi35-source-submodules-20260907-001` | 완료. CPU 빌드에 필요한 고정 서브모듈 획득 |
| `siai-mlc-phi35-python-dependencies-20260907-001` | 완료. 전용 Python 3.12 가상환경 |
| `siai-mlc-phi35-cpu-cmake-20260907-001` | 실패. Ninja 부재; 이후 전용 환경에 설치 |
| `siai-mlc-phi35-cpu-cmake-20260907-002` | 실패. Cargo 부재; 이후 프로젝트 전용 Rust 1.90.0 설치 |
| `siai-mlc-phi35-cpu-cmake-20260907-003` | 완료. 새 C++ 런타임 빌드 구성 |
| `siai-mlc-phi35-cpu-runtime-build-20260907-001` | 완료(returncode=0). private Rust 1.90.0/Cargo, TVM runtime, MLC C++ 공유 라이브러리 빌드 |
| `siai-mlc-phi35-fresh-runtime-factory-20260907-001` | 완료(returncode=0). 새 libmlc_llm.so와 새 libtvm_runtime.so를 실제 로드하여 C++ engine module 생성. model_initialized=false, inference_executed=false |
| `siai-mlc-phi35-fresh-runtime-import-20260907-001` | runtime-only Python import 실패. serve/embedding_engine의 Relax compiler 등록 의존성으로 RegisterOpAttr 부재. C++ factory 성공과 구분 |
| `siai-mlc-phi35-llvm-model-compile-20260907-002` | 실패. context 축소 적용 후에도 `RewriteDataflowReshape` 중 int32 상수 `7247757312` overflow |
| `siai-mlc-phi35-llvm-model-compile-20260907-003` | LLVM int64 index 유지 패치로 앞 단계 통과, VMCodeGen `tirx.Div` 미지원으로 실패 |
| `siai-mlc-phi35-llvm-model-compile-20260907-004` | 동일 오류 재확인 및 6개 컴파일 IR 단계 덤프 보존 |
| `siai-mlc-phi35-llvm-model-compile-20260907-005` | padding 정수 나눗셈을 FloorDiv로 표현해도 VMCodeGen `tirx.FloorDiv` 직접 인자 미지원으로 실패 |

실패를 기록한 실행에서도 로그의 `Compilation complete!` 문자열만으로 완료라고 판단하지 않았다. 이 메시지 다음 VM 코드 생성에서 오류가 나며, 실제 반환코드가 1이고 모델 `.so` 생성이 확인되지 않았다.

초기 `model-download-...-001`의 한 setup 소스 위치가 helper 파일을 잘못 가리키는 문제가 있어 원본을 보존하고 helper를 수정한 뒤 `model-verified-...-002`에서 실제 호출 위치와 전체 파일을 다시 검증했다. 입력 바이트가 바뀐 것이 아니며 초기 로그를 덮어쓰지 않았다.

## CPU 컴파일의 사전 제한

실제 compile 명령에는 첫 시도부터 다음 공식 override를 사용했다. 성공률이나 출력 결과를 보고 조정한 설정이 아니다.

```text
--device {"kind":"llvm","mcpu":"haswell"}
--host x86_64-linux-gnu
--overrides context_window_size=4096;prefill_chunk_size=2048;max_batch_size=1
--opt O0
```

CPU 구조: AVX2, NVIDIA GPU 없음. 문맥 4096은 기본 긴 문맥 131072를 줄이는 CPU 실행 예산 제한이다. 컴파일 출력의 첫 config 표는 override 적용 전 값이므로, 실제 `compile.py`에서 적용 후 출력한 config와 등록 metadata를 확인해야 한다.

## 소스 계약 검토 결과 — 런타임 재현과 구분

- `model/vision/image_processing.py`: rescale·normalize·pad의 직접 GPU thread binding; pad가 symbolic 나눗셈 결과를 TIR 호출의 scalar 인자로 전달한다. 현재 VM 오류는 이러한 scalar 표현식의 직접 전달에서 관측했다.
- `model/phi3v/phi3v_image.py`: 동적 반복과 연결 커널에 GPU thread binding이 있다. LLVM 빌드 성공 전에는 CPU 지원으로 단정할 수 없다.
- `cpp/support/vlm_utils.cc`: `hd_num=4`; 512×512 입력은 672×672로 resize, 2×2 crop.
- `model/phi3v/phi3v_model.py`: image preprocess는 기본 16개 crop으로 zero padding한다.
- `model/phi3v/phi3v_image.py`: global 이외 16 crop을 실제 개수로 자르지 않고 `h_crop×w_crop`으로 재배열한다. 512 정사각의 2×2 crop 조건에서는 중간 hidden 차원이 16384가 되지만 다음 reshape는 4096을 요구해 원소 수가 4배 다르다. 이는 독립적인 소스 정적 감사로 확인한 계약 불일치이며, 실제 모델 런타임 shape 오류를 재현한 결과는 아니다.
- `serve/data.py`: Phi3V의 이미지 길이를 `1921`로 고정한 TODO가 있다. 실제 2×2 crop의 기대 길이 `24×(24+1)+1+156=757`과 다르다. 공개 `ImageData(image, embed_size)` 생성자는 길이를 명시할 수 있으므로 하드코딩 편의 함수를 반드시 경유해야 하는 것은 아니다.

실제 GPU용 image TIR의 CPU 포트, crop 계약 수정은 하지 않았다. 해당 작업은 벤치마크 대상 구현을 의미 있게 바꾸므로 별도의 설계·수치 검증이 필요하다. 현재 호스트와 고정 revision에서 이번 시도는 모델 컴파일 단계까지이며, 모든 MLC 버전/다른 하드웨어에서 영구적으로 불가능하다는 주장이 아니다.

## 바이너리·실패 패치 원문 보존

- fresh `engine/build/libmlc_llm.so` SHA256: `61362dbae126738c63f6addcc8106740f54db39da129dcbfb1a2b546fe777813`.
- `tokenizers-cpp/rust/Cargo.lock` SHA256: `8b68fab848ea4e0e9cfab815acac63a9ce1a1ab9fb705d5966620b7d0f948362`. 실제 해결된 Rust 의존성 80개를 고정한 원문을 final readiness artifact로 보존했다.
- 실패 당시 `pipeline.py` SHA256: `7f63d2b332a127d1277e92f206884edfa552c1ebb31c7ab62fc68d50bb4b14a2`.
- 실패 당시 `image_processing.py` SHA256: `811fe59e1d4e570af44f83e8c602e21112fd2974673c092811d624c408d8da12`.

마지막 두 파일은 **정상 동작이 검증된 CPU 포트가 아닌 실패한 최소 호환 실험 코드**다. 원본과 시험용 파일 전체 바이트를 최종 readiness의 7개 `static_source_snapshot` 이벤트에 각각 보존했다. FloorDiv 주석의 지원 예상은 compile005의 실제 실패로 반증되었으므로 성공 근거로 인용하면 안 된다.

컴파일용 캐시는 LLVM 17을 포함하는 `/tmp/mlc-tvm-837c-build`이며 TVM Python source pin과 TVM-FFI source를 대조했다. 초기 compiler 실행은 기존 MLC shared library로 Python FFI 타입 등록을 제공했으며, 그 사실을 stock fresh native 모델 실행으로 해석하지 않는다. fresh C++ 라이브러리는 이후 별도로 성공적으로 빌드·로드했다.

## 재현과 검증

`Attack-Execution-Dataset/attack-script/siai/mlc-llm/reproduce_compile.py`는 기존 소스를 덮어쓰지 않고 새 `compile-replay/<run-id>`로 복사한다. `stock`, `int64-index`, `int64-index-floordiv` 변형을 명시적으로 분리하며, 출력 모델 라이브러리도 새 경로만 사용한다. 현재 workspace의 고정 compiler cache와 모델이 필요하다. 재현 스크립트 자체의 CLI/안전한 경로/봉인 검증은 **7/7 tests 통과**했지만, 이 새 래퍼로 추가 모델 컴파일을 다시 실행한 것은 아니다. 실제 컴파일 증거는 위 원시 5회다.

```bash
/tmp/siai-assets-venv/bin/python LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/mlc-llm/reproduce_compile.py --run-id siai-mlc-phi35-replay-new-001 --variant stock
```

이 문서는 **환경·소스 호환성 진단**이다. 정상 이미지/공격 이미지의 실제 요청 수명주기, 원시 전처리·임베딩·decoder 입력·첫 logits·생성 token은 이번 시도에서 수집되지 않았다. 공통 보고서의 표시 F / 미평가는 실제 공격 조건 불충족을 관측한 F가 아니다.
