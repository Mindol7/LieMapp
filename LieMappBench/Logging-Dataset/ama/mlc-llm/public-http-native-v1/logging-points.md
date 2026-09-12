# AMA · MLC-LLM 로깅 지점

실제 소스 코드의 어느 지점에서 무엇을 기록하며, 그 기록이 어떤 조건의 근거가 되는지 정리합니다.

**자료 상태:** 완료된 네이티브 실행 및 봉인 원시 로그와 대조 완료

- 실행 ID: `ama-mlc-public-native-20260912-002`
- 완료 요청 128개 / 네이티브 이벤트 384개
- 원시 로그 SHA-256: `91d675e962c96afc9f307edb1563f401665d19385d81f1b9affbedb9a6651f95`

## 엔진 내부

| 지점 | 함수·행 | 관련 조건 | 관측 수 | 기록 이유 |
|---|---|---|---:|---|
| `AMA-MLC-LP01` | `engine_base.py:process_chat_completion_request:741` | AC2, DC1 | 128 | 실제 MLC 요청 수신부에서 도구 이름·설명·스키마, 자율/고정 선택 설정 및 API 호환 변환 전후를 기록한다. 공개 API 출처와 실제 호출은 이 지점만으로 증명하지 않는다. |
| `AMA-MLC-LP02` | `engine_base.py:process_chat_completion_request:796` | AC2, DC1 | 128 | 도구 메타데이터가 포함된 실제 템플릿 결과와 인코딩된 입력 토큰을 보존한다. 기본 Qwen2 템플릿이 아닌 명시적 Python 호출 형식 설정을 사용했음을 확인한다. |
| `AMA-MLC-LP03` | `engine_base.py:wrap_chat_completion_response:1289` | DC1, DC2 | 128 | 네이티브 생성 Python 원문·출력 토큰·파싱된 인자 사전·실제 C++ 생성 설정·최종 응답을 함께 기록한다. 파싱된 사전을 모델이 생성한 원본 JSON 문자열로 표현하지 않으며, 외부 실행 증거와 별도로 연결한다. |

## 실험 에이전트·HTTPS 클라이언트

| 지점 | 함수·행 | 관련 조건 | 관측 수 | 기록 이유 |
|---|---|---|---:|---|
| `AMA-MLC-PUBLIC-LP01` | `mlc_protocol.py:run_request:110` | AC1, DC1 | 128 | 공식 공개 API 계보와 로컬 메타데이터 어댑터를 분리하여 후보 목록을 기록한다. 후보의 출처 표시만으로 AC1을 판정하지 않는다. |
| `AMA-MLC-PUBLIC-LP02` | `mlc_protocol.py:run_request:114` | AC3 | 128 | 메타데이터 검토 수행 여부·대상·제외 결과를 기록한다. 알려진 합성 비밀 필드 검사라는 제한적 대조군이며 범용 방어로 해석하지 않는다. |
| `AMA-MLC-PUBLIC-LP03` | `mlc_protocol.py:run_request:118` | AC2 | 128 | 실제 후보 이름과 auto/required 모드를 기록하여 자율 선택과 정상 도구 하나만 허용한 고정 선택을 구분한다. |
| `AMA-MLC-PUBLIC-LP04` | `mlc_protocol.py:run_request:120` | AC2, DC1 | 128 | HTTP 전송 전 메시지·도구 메타데이터·샘플링 설정과 요청 해시를 보존하여 엔진의 실제 수신·템플릿 결과와 대조한다. |
| `AMA-MLC-PUBLIC-LP05` | `mlc_protocol.py:run_request:131` | AC1, DC1 | 128 | 실제 모델이 선택한 함수 이름을 후보의 정확한 설명·매개변수 스키마·공개 API 계보에 연결한다. 선택과 실행은 구분한다. |
| `AMA-MLC-PUBLIC-LP06` | `mlc_protocol.py:run_request:134` | DC2 | 128 | 도구별 실제 외부 호출 확인·인자·응답 또는 호출 전 차단을 집계한다. 전송 후 확인되지 않은 호출은 원시 null로 보존한다. |
| `AMA-MLC-PUBLIC-LP07` | `mlc_protocol.py:run_request:136` | AC1, DC2 | 128 | 실제 선택된 도구의 공개 플랫폼 계보와 확인된 HTTPS 호출 증거를 함께 연결한다. 공개 출처라는 정적 표시 하나만으로 AC1=T로 처리하지 않는다. |
| `AMA-MLC-PUBLIC-LP08` | `mlc_protocol.py:run_request:139` | DC1, DC2 | 128 | 공격 역할 도구 선택·실행·합성 canary 전달을 분리 집계하고 원시 응답을 보존한다. 단일 성공 사례를 메타데이터의 인과적 효과로 단정하지 않는다. |
| `AMA-MLC-HTTP-LP01` | `mlc_protocol.py:dispatch_calls:82` | AC1, DC2 | 90 | 허용된 공식 공개 API로 전송할 실제 GET 경로·query·헤더·nonce를 기록하여 모델 인자와 외부 요청을 연결한다. 전송 의도 자체는 수신 증거가 아니다. |
| `AMA-MLC-HTTP-LP02` | `mlc_protocol.py:dispatch_calls:86` | AC1, DC2 | 90 | 제공자가 반환한 실제 HTTPS 응답 원문·TLS 정보·echo 및 nonce를 보존한다. 이는 클라이언트가 수집한 영수증이며 제공자 내부 함수의 계측 로그가 아니다. |
| `AMA-MLC-HTTP-LP03` | `mlc_protocol.py:dispatch_calls:95` | DC2 | 91 | 개별 호출의 원문 인자·검증·전송·확인 결과를 request_id/tool_call_id/http_attempt_id로 연결한다. 부정확한 인자를 임의 보정하지 않는다. |
| `AMA-MLC-RUN01` | `run_public.py:main:172` | 실행 무결성 | 1 | 데이터셋·공개 출처 스냅샷·전체 요청 순서를 실행 전에 고정한다. |
| `AMA-MLC-RUN02` | `run_public.py:main:177` | 실행 무결성 | 1 | 실제로 준비된 로컬 CPU MLC-LLM 서버의 실행 명령과 주소를 기록한다. |
| `AMA-MLC-RUN03` | `run_public.py:main:182` | 실행 무결성 | 1 | 계획한 요청의 완료 수와 정상 종료 상태를 기록한다. |
| `AMA-MLC-RUN04` | `run_public.py:main:185` | 실행 무결성 | 0 | 실행 오류를 공격 방어 또는 엔진 안전 판정과 구분하여 보존한다. |
| `AMA-MLC-RUN05` | `run_public.py:main:192` | 실행 무결성 | 4 | 서버 출력 원문·해시·자체 프로세스 트리의 TCP 수신 주소 점검을 보존한다. |

## 해석 시 주의사항

- 기본 Qwen2 템플릿에는 도구 정보가 포함되지 않아 별도 Conversation 설정을 사용한다.
- MLC named 고정 선택은 다른 엔진의 required 문법 강제와 같지 않다.
- Python 호출 원문·네이티브 인자 사전·HTTPS 전송 인자를 구분하며 보정하지 않는다.
- AC3 T는 검토 수행, DC T는 증거 확보이며 공격 성공률 또는 안전 인증이 아니다.

정확한 경로·소스 해시·원문 스냅샷·원시 필드·예시 이벤트 ID는 같은 이름의 JSON에 있습니다.
