# MLC-LLM CPU 실행 가능성 재검토

검토일: 2026-09-06. 범위: 현재 원본과 이미 존재하는 로컬 compiler/runtime·가중치·모델 라이브러리. 설치·네트워크 다운로드·원본 변경·다른 모델로의 대체 추론은 수행하지 않았다.

## 결론

**CPU compiler 자체는 실제로 사용 가능한 상태다.** 서브모듈이 초기화되지 않았거나 GPU가 없다는 이유만으로 MLC의 CPU 실행이 불가능하다고 결론 내릴 수 없다.

현재 실행을 막는 구체적 준비 부족은 다음과 같다.

1. 현재 MLC `9fa644f54b04983adea4d0168f49fc6af4a893ba`는 가중치가 캐시된 **SmolVLM/Idefics3를 모델 레지스트리에 등록·구현하지 않는다**.
2. 지원 모델인 **Phi3V/LLaVA의 실제 가중치와 MLC model library는 확인한 캐시에 없다**. `/tmp/mlc-llava-config.json`은 설정 파일뿐이다.
3. 설치된 Python 모델 구현은 상당 부분 현재 소스와 같지만 compiler pass 3개가 다르고, 현재 source와 compiler/runtime 전체의 동일성 및 native 모델 실행은 아직 검증하지 않았다.

따라서 이번 조건에서는 **native 멀티모달 SIAI 요청 미실행 / AC·DC 모두 판정불가**다. 원본이나 compiler가 CPU를 지원하지 않는다는 뜻, 또는 공격에 안전하다는 뜻은 아니다. 다른 지원 VLM을 선택하면 모델·전이 실험 조건이 바뀌므로 사용자 선택 후 별도 가중치 확보·변환·계측 실험이 필요하다.

## 1. 현재 원본과 서브모듈

실행 위치: `/home/mindol/AI-Forensics`.

```sh
git -C LieMapp/LIE/mlc-llm rev-parse HEAD
git -C LieMapp/LIE/mlc-llm ls-tree HEAD 3rdparty/tvm
git -C LieMapp/LIE/mlc-llm submodule status
```

핵심 출력:

```text
9fa644f54b04983adea4d0168f49fc6af4a893ba
160000 commit 837cb9de1127b48ce48e4cefe09e83215b9d4ba7  3rdparty/tvm
-837cb9de1127b48ce48e4cefe09e83215b9d4ba7 3rdparty/tvm
```

서브모듈 앞 `-`는 checkout 미초기화 표시다. 이미 빌드된 외부 compiler를 사용할 가능성과 별개의 사실이다. 실제 캐시가 존재하므로 이 상태만으로 실행을 포기하거나 CPU 미지원으로 기록하면 부정확하다.

## 2. cached compiler의 실제 로드 확인

확인 경로:

|경로|확인 결과|
|---|---|
|`/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so`|약 79 MiB, 실제 `ctypes.CDLL` 로드 성공|
|`/tmp/mlc-tvm-837c-build/lib/libtvm_runtime.so`|약 3.4 MiB, ldd 의존 경로 해결|
|`/tmp/mlc-exact-python/tvm_ffi`|기존 FFI Python 및 native 라이브러리|
|`/tmp/mlc-exact-venv/bin/python`|위 FFI로 compiler를 로드한 interpreter|
|`/tmp/mlc-llvm17-root/usr/lib/llvm-17/lib/libLLVM-17.so.1`|compiler가 실제 참조하는 LLVM 17 라이브러리|

실행한 read-only probe와 동등한 명령:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/mlc-exact-python /tmp/mlc-exact-venv/bin/python - <<'PY'
import ctypes
import tvm_ffi
ctypes.CDLL('/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so', mode=ctypes.RTLD_GLOBAL)
print(tvm_ffi.get_global_func('target.llvm_version_major')())
print(tvm_ffi.get_global_func('target.build.llvm', allow_missing=True) is not None)
PY
ldd /tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so
```

출력: `17`, `True`. `ldd`에서 unresolved dependency가 없었다. `TVMBuildOptions.txt`는 `USE_LLVM=/tmp/mlc-llvm17-root/usr/lib/llvm-17/bin/llvm-config --link-shared`, CUDA/Vulkan OFF를 기록한다.

```text
libtvm_compiler.so SHA-256
7872f5110b7b13eb8dbb8a5690f967280592f89383b6636533815ff38fe81b08
libtvm_runtime.so SHA-256
c91a3e645d490712b6e5f3cb5cd269f38a70960f7e3cb45f427ee60dbc1eb87b
```

한계: 디렉터리 이름 `837c`와 현재 gitlink는 대응하는 후보지만, 이번 probe는 binary의 원본 commit을 암호학적으로 증명한 것이 아니다. CMake cache는 과거 경로 `/home/mindol/AI-Forensics/lab/mlc-llm/3rdparty/tvm`를 참조한다. 모델 컴파일·생성까지 실행한 결과도 아니다.

## 3. 모델 지원과 가중치

```sh
rg -n 'phi3_v|llava|smolvlm|idefics3' LieMapp/LIE/mlc-llm/python/mlc_llm/model/model.py
rg -n 'smolvlm|idefics3|SmolVLM|Idefics' LieMapp/LIE/mlc-llm/python LieMapp/LIE/mlc-llm/cpp
rg --files /tmp /home/mindol/.cache -g ndarray-cache.json -g mlc-chat-config.json -g '*params_shard*'
```

레지스트리 확인:

```json
{
  "phi3_v_registered": true,
  "llava_registered": true,
  "smolvlm_registered": false,
  "idefics3_registered": false
}
```

`model.py`의 Phi3V 등록은 328행, LLaVA 등록은 543행이다. source search exit 1은 해당 문자열 일치가 없다는 뜻이다.

가중치 후보 확인:

- `/home/mindol/.cache/mlc_llm/model_weights`: 파일 없음.
- `/home/mindol/.cache/mlc_llm/model_lib`: 파일 없음.
- `/tmp`와 `.cache`의 `ndarray-cache.json`, `mlc-chat-config.json`, `params_shard*` 검색: 후보 없음.
- `/tmp/mlc-llava-config.json`: 3,089 bytes의 설정 파일만 존재. 실제 tensor shard가 아니다.
- Hugging Face cache의 실제 SmolVLM 가중치는 존재하지만 현재 MLC에서 해당 architecture를 직접 실행하는 구현을 찾지 못했다.
- `LiquidAI/LFM2.5-VL-1.6B` cache는 2,376 bytes와 136 bytes의 설정성 blob 2개뿐이며 실제 모델 가중치가 아니다. 현재 MLC에서 해당 모델 등록도 찾지 못했다.

위 결과는 **검사한 경로에서 후보를 찾지 못했다**는 뜻이다. 시스템 전체의 모든 저장 장치에 가중치가 없음을 입증했다고 확대하지 않는다. GGUF나 임의 tensor, Transformers forward를 MLC native 모델의 대체 증거로 사용하지 않았다.

## 4. 설치본과 fresh source의 차이

기존 `/tmp/mlc-siai-venv`에서 확인한 distribution:

```text
mlc-llm-nightly-cpu 0.26.dev5
mlc-ai-nightly-cpu 0.26.dev246
apache-tvm-ffi 0.1.13.post3
```

설치본 `tvm`과 `mlc_llm` import는 성공했다. 반면 `/tmp/mlc-exact-venv`의 기본 검색 경로에서는 tvm/tvm_ffi/mlc_llm 모듈이 발견되지 않는다. 이는 위의 수동 FFI 경로를 추가한 compiler 로드 성공과 모순되지 않는다.

현재 `python/mlc_llm/*.py`와 `/tmp/mlc-siai-venv/lib/python3.12/site-packages/mlc_llm/*.py`를 재귀적으로 byte 비교한 결과:

- 동일 319개, 누락 0개, 차이 3개.
- Phi3V/LLaVA 모델 구현은 동일하다.
- 다른 파일: `compiler_pass/lift_global_buffer_alloc.py`, `compiler_pass/low_batch_specialization.py`, `compiler_pass/fuse_dequantize_transpose.py`.

따라서 '설치본의 모델 구현이 전부 다른 버전'이라고 설명하면 과장이다. 다만 compiler pass·binary까지 현재 소스와 동일함을 가정할 수 없으므로 actual native run 검증은 별도로 필요하다.

## 5. 재실행 가능한 공통 로그와 보고서

조사 명령·출력·버전·가중치 부재 근거는 [run_mlc_cpu_feasibility.py](../../../Attack-Execution-Dataset/attack-script/siai/shared/run_mlc_cpu_feasibility.py)가 공통 `logger.py`로 기록했다. 실행 자체는 계측 추론이 아니라 preflight다.

```sh
PYTHONDONTWRITEBYTECODE=1 /tmp/siai-assets-venv/bin/python LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/shared/run_mlc_cpu_feasibility.py
```

기존 run은 보존했다. 새 run `siai-mlc-llm-cpu-feasibility-20260906-002`는 `blocked`로 seal되었고, 동일 공통 Analyzer와 동일 `conditions.json`을 사용한 결과는 AC 3개·DC 3개 모두 Unknown이다.

- 로그: `LieMappAnalyzer/LogFile/siai/mlc-llm/siai-mlc-llm-cpu-feasibility-20260906-002/`
- 보고서: `report/siai/mlc-llm/siai-mlc-llm-cpu-feasibility-20260906-002-reviewed/report.md`

스크립트는 기존 run을 덮어쓰지 않는다. 향후 재검토는 새로운 run ID로 기록해야 한다. 지원 VLM 선택·추가 가중치 확보 또는 SmolVLM 구현 포팅은 사용자 선택 후 진행한다.
