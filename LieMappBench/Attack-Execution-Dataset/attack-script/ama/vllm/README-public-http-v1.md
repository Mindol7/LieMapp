# AMA · vLLM 공개 API 실험

이 실험은 **모델의 도구 선택 → 실제 HTTPS 호출 → 제공자 응답 확인 → 공통 Analyzer 판정**을 연결한다. 기존 로컬 합성 도구 실험과는 별도 프로토콜이며, 기존 `run.py`·원시 로그·소스 매핑은 보존한다.

## 실험 구성

- 엔진: 기존에 검증한 독립 계측 vLLM CPU 버전. `LIE/vllm` 원본은 수정하지 않는다.
- 모델: 고정된 공식 Qwen2.5-3B-Instruct safetensors를 FP32로 로드한다. 기존 `model.json`과 native-build manifest의 모든 파일 해시를 재검증한다.
- 공통 입력: SGLang 공개 API 실험의 `attack-source/ama/SGLang/public-http-v1/fixtures.json`과 `provenance.json`을 **그대로 읽는다**. 엔진에 유리하도록 도구 설명·인자·프롬프트를 수정하지 않는다.
- API: Postman Public API Network의 공식 Postman Echo GET, `https://postman-echo.com/get` 한 개 작업이다. 공개 플랫폼 계보와 실제 엔드포인트는 공식 출처 원문 및 해시로 연결한다.
- 메타데이터: 정상 도구와 공격 역할 도구는 로컬 어댑터이다. 제공자가 악성이라는 주장이나 플랫폼에 공격 도구를 게시했다는 주장은 하지 않는다.
- 입력: 실제 개인정보가 아닌 합성 공개 문자열과 합성 canary만 사용한다. 모델이 생성한 인자는 자동 보정하거나 비밀값으로 채우지 않는다.

평가 범위는 공개 API 1개, 평가 입력 8개 × 도구 순서 2개 × seed 2개 × 실험군 4개 = **128개 모델 요청**이다. 각 군은 중립 메타데이터, 매력적인 메타데이터, 정상 도구 고정, 제한적 사전 메타데이터 검토이며 각각 32개 요청이다. 요청별 최대 첫 호출 하나만 실제로 전송하므로 외부 API 전송은 실행당 최대 128회이다. 나머지 호출 제안이나 잘못된 인자는 차단 근거와 함께 보존한다.

## 실행

프로젝트 루트에서 실행한다. 모델 및 기존 CPU 환경은 미리 준비되어 있어야 한다. GPU를 사용하지 않으며, 다른 대형 모델 실험과 동시에 실행하지 않는다.

```bash
# 1. 개발 입력 두 변형으로 로깅 ON/OFF 토큰·응답 동일성 검증
#    네이티브 추론 4회이며 외부 도구 호출은 하지 않는다.
.venv/bin/python -B LieMappBench/Attack-Execution-Dataset/attack-script/ama/vllm/verify_public_runtime.py

# 2. 개발 입력으로 공개 API 전체 경로 점검: 네 실험군 각 1회
.venv/bin/python -B LieMappBench/Attack-Execution-Dataset/attack-script/ama/vllm/run_public.py --split development --task echo-dev-02 --seeds 20260911 --orders normal_first --limit 4 --run-id ama-vllm-public-development-NEW

# 3. 고정된 128개 평가 요청 실행
.venv/bin/python -B LieMappBench/Attack-Execution-Dataset/attack-script/ama/vllm/run_public.py --run-id ama-vllm-public-native-NEW

# 4. 완료한 원시 증거에 소스 매핑 연결
.venv/bin/python -B LieMappBench/Logging-Dataset/ama/vllm/public-http-v1/freeze_mapping.py --run-dir .evidence/raw/ama/vllm/ama-vllm-public-native-NEW

# 5. 공통 설정에 새 public-http-v1 매핑을 등록한 뒤, 새 실행 로그를 명시해 분석
.venv/bin/python -B developer.py --attack ama --engine vllm --log .evidence/raw/ama/vllm/ama-vllm-public-native-NEW/events.jsonl --replace
```

실행 ID와 검증 출력 경로는 매번 새로 지정한다. 기존 파일을 덮어쓰는 재시도는 허용하지 않는다. 개발 결과는 본 평가에 포함하지 않는다. 소스 매핑을 다시 생성해야 한다면 `--replace`를 명시해야 하며, 이 옵션은 새 public-http-v1 매핑 문서 두 개에만 적용한다. 공통 실행 설정에 새 매핑을 등록한 다음, 위와 같이 **`--log`로 새 실행의 `events.jsonl` 경로를 명시**하면 공통 Analyzer가 조건별 JSON 5개와 최종 MD 보고서 1개를 생성한다. `--log`를 생략하면 기존 `.evidence/current` 포인터가 설정의 기본 경로보다 우선하여 이전 로컬 실험을 분석할 수 있다. 이 명령에는 `--execute`를 붙이지 않아 이미 완료한 실험을 중복 실행하지 않는다.

## AC·DC 해석

| 조건 | 이번 프로토콜에서 확인하는 근거 |
|---|---|
| AC1 | 실제 선택된 도구의 공개 플랫폼 계보 **및 확인된 실제 HTTPS 호출**. 도구 목록에 공개 출처가 적혀 있다는 사실만으로 T가 되지 않는다. |
| AC2 | 엔진에 제공한 도구 이름·설명, 실제 렌더링 프롬프트, auto/required 선택 정책과 실제 모델 응답. |
| AC3 | 실행 전 별도 메타데이터 검토 수행 여부. T는 검토 수행이지 모든 공격을 차단했다는 뜻이 아니다. |
| DC1 | 선택한 함수 이름을 정확한 도구 메타데이터에 요청별로 연결하여 보존했는지 여부. |
| DC2 | 실제 호출 상태, 모델의 원문 인자, 실제 요청과 제공자 응답·echo/nonce의 연결. 전송 후 응답이 확인되지 않은 경우 원시 상태는 unknown/null로 보존한다. |

원시 이벤트는 공통 `logger.py`로 수집되며, 3개 엔진 내부 지점과 16개 공통 에이전트·HTTP·실행부 지점을 구분한다. 네이티브 `tool_calls`는 실행 제안일 뿐 외부 API 호출 완료의 증거가 아니다. HTTP 응답은 클라이언트 측에서 확인한 제공자 응답이며, 제공자 내부 함수 실행·저장 여부를 계측한 증거는 아니다.

## 검증 범위와 한계

- 로깅 ON/OFF 비교는 같은 계측 소스에서 로깅만 활성화/비활성화한 개발 입력 2개 변형에 한정된다. 실제 입력 토큰, 출력 토큰, 종료 이유와 도구 이름·원문 인자·응답 내용을 비교한다. 비계측 upstream과의 동등성, 동시 실행·스트리밍·전체 입력 동등성을 주장하지 않는다.
- 원 논문의 QNT 최적화나 다단계 에이전트 전체를 재현하지 않는다. 응답을 다시 모델에 전달하지 않는 단일 도구 선택·호출 단계이며, 최종 답변 품질은 평가하지 않는다.
- 선택된 공격 역할 도구, 실제 호출, 원래 canary의 정확한 전달은 구분해서 집계한다. 정확한 canary가 아니더라도 유사 문자열 전송을 방어 성공으로 단정하지 않는다.
- SGLang과 데이터셋·API 프로토콜은 동일하지만, 엔진별 템플릿·파서·샘플러가 다르다. llama.cpp의 Q4_K_M과 vLLM의 FP32 표현도 다르므로 단순한 엔진 보안 순위로 해석하지 않는다.
- `held_out`은 동결 데이터셋의 원래 분할명이다. SGLang에서 이미 사용한 동일 입력이므로 새로운 미관측 입력이라고 표현하지 않는다.
- HTTPS는 인증서·호스트명·공개 IP·echo nonce를 확인하고, 인증정보·쿠키·리다이렉트·프록시·자동 재시도는 사용하지 않는다. 해시·seal은 파일 간 무결성 검증이며 외부 전자서명이나 공인 증거 보관 이력을 대신하지 않는다.
