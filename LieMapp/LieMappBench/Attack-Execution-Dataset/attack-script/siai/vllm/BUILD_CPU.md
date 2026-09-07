# vLLM의 독립 CPU 빌드 환경

2026-09-07 출력 안내: [developer.py](../../../../../developer.py) / [investigator.py](../../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

이 문서는 **빌드 환경**을 설명한다. 빌드 성공과 native 추론 성공, AC/DC 판정은 서로 다른 결과이며, 각각의 원시 로그와 seal을 확인해야 한다.

## 고정한 원본과 환경

- 원본: `LieMapp/LIE/vllm`, HEAD `a1541f5742a29864a80087af313ad460066a1524`.
- 작업본: `LieMapp/Instrumented-LIE/siai/vllm`. 원본에서 `git clone --local --no-hardlinks`로 분리했다. 원본 소스와 기존 `/tmp` 가상환경은 수정하지 않았다.
- 환경 관리: `LieMapp/.tooling/bin/uv` 0.12.10, 작업본의 `.venv`, Python 3.12.
- 공식 CPU requirements에 따라 PyTorch `2.13.0+cpu`를 설치했다. 프로젝트 `AGENTS.md`에 따라 모든 Python 실행은 `.venv/bin/python`, 설치는 `uv`로 수행한다. `pre-commit` 및 해당 private clone의 hook도 설치했다.
- CPU: Intel i7-8700, AVX2 지원, AVX512/AMX 미지원. GCC 13.3.0으로 실제 CPU extension을 소스 빌드한다. GPU 부재만으로 vLLM 실행 불가라고 판단하지 않는다.
- 빌드가 가져온 oneDNN: tag `v3.13`, 실제 HEAD `0e2a5bfeef1bfbffc3137464606540233086ce9b`.

## 시스템 설치를 하지 않는 native 의존성

아래 Ubuntu 패키지는 `apt-get download`로 작업본 `.native-deps/packages/`에 내려받고, `dpkg-deb --extract`로 `.native-deps/`에만 추출한다. 시스템 package database나 `/usr`에는 설치하지 않는다.

| 패키지 | 버전 | 용도 |
|---|---|---|
| libnuma-dev | 2.0.18-1ubuntu0.24.04.1 | NUMA 헤더와 링크 파일 |
| libnuma1 | 2.0.18-1ubuntu0.24.04.1 | NUMA 런타임 |
| libtcmalloc-minimal4t64 | 2.15-3build1 | CPU 실행 시 메모리 allocator |

빌드 스크립트가 `CPATH`, `LIBRARY_PATH`, `LD_LIBRARY_PATH`, `CMAKE_PREFIX_PATH`를 작업본 경로로 설정한다. 런타임에는 해당 NUMA 경로와 `.venv/lib/libiomp5.so`가 필요하다. 공식 문서에 따라 TCMalloc과 Intel OpenMP를 `LD_PRELOAD`에 지정한다.

## 실행 명령

작업 디렉터리는 private vLLM clone이다. 아래 `<script>`는 이 디렉터리의 `build_cpu.py` 절대 경로이다. run ID는 매 실행마다 새로 지정한다. 기존 증거 디렉터리를 덮어쓰지 않는다.

```bash
.venv/bin/python <script> --phase dependencies --run-id <new-dependencies-id>
.venv/bin/python <script> --phase native-dependencies --run-id <new-native-deps-id>
.venv/bin/python <script> --phase build --run-id <new-build-id> --timeout 1200
```

소스 빌드의 핵심 명령은 `uv pip install -e . --no-build-isolation --no-deps --verbose`이며 `VLLM_TARGET_DEVICE=cpu`, `MAX_JOBS=4`를 사용한다. Rust frontend는 upstream에서 optional인 상태를 그대로 사용한다. C++ CPU kernel이나 모델 계산을 우회하는 대체 구현을 삽입하지 않는다.

## 증거와 해석 범위

공통 `logger.py`가 `.evidence/raw/siai/vllm/<run-id>/`에 다음을 저장한다.

- 실제 명령, 반환 코드, 원문 stdout/stderr, 실행 시간.
- 원본 Git revision, 스크립트 해시, 격리 환경 변수.
- `execution_scope: environment_build`와 완료/실패 seal.

실패나 미완료 빌드를 native inference 결과로 세지 않는다. 실제 추론 계측은 별도의 `run.py`를 사용한다.

## 2026-09-06 실제 결과

| 실행 ID | 결과 | 해석 |
|---|---|---|
| siai-vllm-cpu-dependencies-20260906-001 | completed | 공식 CPU Python 의존성 설치 |
| siai-vllm-cpu-native-deps-20260906-001 | completed | private NUMA/TCMalloc 추출 |
| siai-vllm-cpu-source-build-20260906-001 | failed | 컴파일 오류가 아니라 초회 audit 상한 1200초 초과 |
| siai-vllm-cpu-source-build-resume-20260906-001 | completed | 동일 CMake/Ninja cache를 복원해 364.7초 추가 빌드 후 설치 성공 |
| siai-vllm-avx2-kernel-verification-20260906-002 | completed | AVX2 extension만 로딩하고 실제 CPU SwiGLU 연산을 수치 검증 |

초회 timeout 이후 남은 C++ 프로세스 그룹은 PID/소스 경로를 확인해 종료했다. 보존된 generated build cache를 원래 `/tmp/tmpc6kzgxm8.build-temp` 경로에 복원했으며, oneDNN부터 다시 빌드하지 않았다. `resume_cpu.py`는 같은 build-temp를 사용하는 공식 `setup.py build ... develop --no-deps` 경로를 실행한다. 설치 도구의 deprecation warning은 원문 stderr에 보존했다.

```bash
.venv/bin/python <resume_cpu.py> \
  --run-id <new-resume-id> \
  --build-temp /tmp/tmpc6kzgxm8.build-temp \
  --cache-backup /home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/vllm/.build-recovery-20260906-001 \
  --timeout 3600
```

`verify_environment.py`는 `/proc/self/maps`에서 `_C_AVX2.abi3.so`만 로드되었고 AVX512/AMX variant가 강제로 로드되지 않았음을 확인한다. `torch.ops._C.silu_and_mul`을 실제 호출해 input/output/reference 원시 tensor, binary SHA-256, 명시적인 Torch library 검색 경로를 반영한 `ldd` 결과를 공통 logger에 저장했다. 해당 검사는 `execution_scope=kernel_readiness`이며 전체 LLM 추론은 아니다.

verification001은 검증 스크립트가 `torch.__version__`의 `TorchVersion` 타입을 일반 문자열로 명시 변환하지 않아 logger 검증에 실패한 실행이다. 이를 삭제하지 않고 보존했으며 002가 `supersedes`로 명시한다.
