# AMA · SGLang 네이티브 계측과 CPU 환경

## 원본 보존과 계측 경계

원본 커밋 `97c6978369ac1e04c91fcc01c98acc25129a6000`을 `--local --no-hardlinks`로 독립 복제하였다. `LIE/sglang`, 기존 SIAI 소스·가상환경, 기존 llama.cpp·vLLM 실험은 수정하지 않는다. 새 저장소는 원본 Git 객체 저장소를 참조하는 alternates를 사용하지 않는다.

수정 사항은 다음과 같다.

1. HTTP 입력, 실제 렌더링 프롬프트, 실제 생성·파싱 응답에 관측 코드 추가.
2. 요청 스키마에 진단용 `liemapp_request_id`와 `liemapp_context`를 명시적으로 선언. 두 값은 템플릿·샘플링 입력에 전달하지 않음.
3. 기존에 확인한 선택적 CPU 커널의 import 지연 8건 적용. 아래 기능의 계산을 대체하거나 가짜 커널을 추가하지 않음.

원시 로그 저장·이벤트 연결·소스 해시 기록은 모두 공통 `LieMappBench/Logging-Dataset/logger.py`의 Collector가 수행한다. 관측기는 공통 Client의 전송 기능만 호출한다. 요청 라벨은 매 요청별 객체로 복사하며, 전역 환경변수를 요청별로 바꾸지 않는다.

## CPU 실행 방식

| 항목 | 현재 설정과 의미 |
| --- | --- |
| 모델 | 공식 Qwen2.5-3B-Instruct, revision `aa8e72537993ba99e69dfaafa59ed015b17504d1` |
| 모델 구현 | `--model-impl sglang`: SGLang 자체의 `Qwen2ForCausalLM`; 독립 HF.generate 호출 아님 |
| 정밀도 | 공식 BF16 safetensors를 FP32로 로드 |
| attention | 원본 `TorchNativeAttnBackend`의 PyTorch SDPA |
| CPU | AVX2, 최대 6 threads, TP1·PP1·DP1 |
| 캐시·스케줄 | radix cache·overlap schedule 비활성화, 동시 요청 1개, context/max total tokens 4096 |
| CUDA graph | prefill·decode 모두 비활성화 |
| 도구 파서 | 원본 Hermes 파서 |
| 샘플링 기본값 | `--sampling-defaults openai`; 요청별 temperature/top_p/top_k/repetition_penalty/seed 별도 기록 |

CPU에 AVX512·AMX가 없으므로 해당 ISA를 요구하는 SGLang AOT 커널은 빌드하거나 실행하지 않는다. 기본 연산에는 원본의 `forward_native`, FP32 선형 연산, Torch attention 경로를 사용한다. 모든 SGLang 기능을 이 환경에서 지원한다는 뜻은 아니다.

기존 SIAI 가상환경은 **읽기 전용 의존성**이다. Python 3.12.3, PyTorch 2.12.0+cpu, Transformers 5.12.1, XGrammar 0.2.1을 재사용한다. SGLang 소스는 AMA의 `PYTHONPATH`로 로드하고 바이트코드 기록을 끈다. SIAI의 관측 코드나 모델 전처리 변형은 복사하지 않는다. 이 환경에는 설치된 `sglang`/`sgl-kernel` 배포 메타데이터가 없으며, 소스 실행을 패키지 설치로 표시하지 않는다.

## 최소 CPU 호환성 변경

다음 8개 파일의 선택적 import를 실제 호출 위치로 옮긴 기존 검증 변경만 재사용한다.

- `kernels/ops/kvcache/cache_move.py`
- `kernels/ops/speculative/cache_locs.py`
- `kernels/ops/speculative/eagle.py`
- `kernels/ops/speculative/multi_layer_eagle.py`
- `srt/mem_cache/allocation.py`
- `srt/speculative/eagle_utils.py`
- `srt/speculative/eagle_worker_common.py`
- `srt/speculative/spec_utils.py`

위 경로는 모두 `python/sglang/` 아래에 있다. 일반 비추측 생성에서는 필요하지 않은 선택적 CPU 확장을 시작 시 강제로 가져오는 문제만 해소한다. 해당 기능을 실제 선택하면 여전히 원래 CPU 확장이 필요하고, 없으면 실패한다. attention·가중치·샘플러·scheduler의 계산 구현을 바꾸지 않는다. 전체 변경은 `native-instrumentation.patch`와 manifest의 파일별 변경 목적·수정 전후 해시에 기록한다.

## 네트워크와 종료 처리

네이티브 HTTP 서버는 `127.0.0.1`에만 바인딩한다. 분산 rendezvous는 원본이 제공하는 `SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE=file://...`를 사용하고 Gloo는 `lo` 인터페이스로 제한한다. 새로운 분산 알고리즘이나 TCPStore 패치를 넣지 않는다.

서버와 자식 프로세스의 현재 TCP 수신 소켓을 시작 중 및 요청 종료 후 점검하고, 비루프백 수신 주소가 있으면 중단한다. 이 점검은 수신 소켓 스냅샷이며 패킷 캡처나 모든 외부 통신의 부재를 증명하는 것은 아니다. 외부 API의 실제 호출·허용 주소·데이터 범위는 에이전트 실행부에서 별도로 통제·기록한다. 네이티브 SGLang의 `tool_server`·원격 모델 코드·사용자 지정 logit processor는 활성화하지 않는다. 모델 로드는 offline이다.

IPC와 file-store 경로는 짧고 비공개인 전용 임시 디렉터리에 둔다. 서버 종료 시 해당 부모 프로세스의 정상 종료를 먼저 요청하고, 필요할 때만 자신이 시작한 전용 프로세스 그룹을 정리한다. 실험 로그와 캐시는 실행 디렉터리에 남긴다.

## 재현과 manifest 해석

`native_runtime.py`는 `validate_runtime()`과 `server(args, model_path, output_dir, socket_path=None)` 인터페이스를 제공한다. 서버 문맥은 `(base_url, command)`를 반환한다. `args`에는 `threads`, `context_size`, `startup_timeout`이 필요하다. 새 실행 디렉터리를 사용하며 기존 서버 로그를 덮어쓰지 않는다.

`native-build-manifest.json`은 원본 커밋, 12개 변경·신규 소스, 실행기, 공통 logger, 인터프리터 및 주요 PyTorch 공유 라이브러리 해시와 버전을 검증한다. 전체 가상환경 파일을 모두 해시한 컨테이너 이미지나 공급망 인증서는 아니다. 이 manifest는 준비 상태를 고정한 자료이며 실제 추론·공격 성공을 주장하지 않는다. 이후 결과는 별도 실행 증거로 확인한다.

다른 서버에서 동일 패치를 적용하는 것만으로 동일 환경이 보장되지 않는다. 호환 가상환경을 준비한 후 새 manifest·스냅샷·계측 켬/끔 검증을 별도로 생성해야 한다. 과거 실험의 manifest나 원시 증거를 새 환경에 맞춰 덮어쓰지 않는다.

## 검증 결과와 한계

- 관측기 단위 테스트 4개 통과: 비활성화 시 무기록, 동시 요청 8개의 문맥 분리, 잘못된 문맥 거부, 호출 없음의 엄격한 정규화.
- 실제 개발용 capability probe `ama-SGLang-native-probe-20260911-001` 통과: 194 입력 토큰, 22 생성 토큰, `lookup_public_record(query="Python programming")` 도구 선택 응답.
- 위 probe는 전체 프롬프트·파싱 전 실제 생성문과 토큰·HTTP 응답 일치·요청 연결·루프백 수신 소켓을 확인했다. **도구 함수나 외부 API를 호출하지 않았으며 AMA 공격 결과가 아니다.**
- probe 후 실행기의 종료 처리를 부모 우선 종료 방식으로 개선하였다. 모델·네이티브 계측 소스는 동일하지만 해당 probe의 실행기 해시와 현재 실행기 해시는 다르므로 최종 실험과 계측 켬/끔 검증은 현재 manifest로 수행한다.
- 최종 동결된 공개 API 프로토콜의 계측 켬/끔 검증 통과: `echo-dev-02`의 중립·매력적 메타데이터 입력 각각에서 정확한 입력/출력 토큰 ID, 응답 내용, 종료 사유, 도구명·인자 문자열이 일치하였다. 두 변형의 생성 토큰은 각각 54개·55개이며, 요청당 네이티브 이벤트는 계측 켬 3개·끔 0개였다. 원시 감사 자료는 `.evidence/audits/ama-SGLang-public-runtime-validation-final.json`에 있다. 14개 소스·설정·출처 파일을 추론 전에 별도 스냅샷으로 보관하고 전후 해시 일치를 확인하였다. 앞선 `ama-SGLang-public-runtime-validation.json`은 이전 검증 단계의 기록으로 그대로 보존한다.
- 위 동등성 검증은 temperature=0 및 동일 seed에서 **같은 계측 소스의 로깅 활성화 여부**만 비교한 것이다. 원본 엔진 대비 검증이나 모든 입력·스트리밍에 대한 증명은 아니다. 두 모드 모두 응답 관측용 `return_token_ids=true`를 사용하였다. 외부 API 호출은 수행하지 않았으며, 감사 자료에 기록된 소스 버전에 한정한다.
- 전체 AC/DC 판단에는 공개 플랫폼 출처·메타데이터 검토·실제 외부 호출 증거가 추가로 필요하다. 엔진이 함수명을 생성한 사실만으로 AC1이나 DC2를 충족했다고 판단하지 않는다.

## 실제 실행에 로깅 지도 연결

`freeze_mapping.py --run-dir <완료된 원시 실행 디렉터리> --replace`는 3개 네이티브 지점과 16개 공통 에이전트·HTTP 클라이언트·실행부 지점을 실제 로그에 연결한다. 전체 이벤트 해시 연결과 seal을 검증한 뒤 소스 함수·행·해시·원본 및 계측 소스 스냅샷·원시 필드·관측 수를 JSON과 Markdown으로 저장한다. 실행·조건 규칙·보고서 자체는 변경하지 않는다.

개발 실행으로 미리 확인하려면 `--output-dir .evidence/audits/<새 미리보기 디렉터리>`를 지정한다. 현재 파일이 실행 시점과 달라진 경우 `--source-archive <프로젝트 상대경로 구조의 과거 소스 보관 디렉터리>`에서 정확히 같은 해시의 소스를 찾아야 한다. 과거 소스를 현재 파일로 대체하여 행 번호나 관측 사실을 맞추지 않는다.
