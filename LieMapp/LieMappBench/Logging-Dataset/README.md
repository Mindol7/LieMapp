# 공통 로깅 및 소스 매핑

2026-09-07 출력 안내: [developer.py](../../developer.py) / [investigator.py](../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

`logger.py`가 모든 엔진의 최종 증거를 기록한다. 엔진·공격별 코드를 이 로거 안에
분기하지 않는다. Python 계측은 `Logger.emit` 또는 `Client.emit`을 사용하고,
C/C++ 계측은 `native/bridge.h`로 동일한 요청을 로컬 `Collector`에 전달한다.
네이티브 어댑터는 JSON/텐서를 전달할 뿐, 최종 로그나 증거 파일을 직접 만들지 않는다.

`library.py`는 Attack Library XLSX의 원문과 셀 위치를 읽는다. XLSX는 수정하지 않는다.
각 공격 디렉터리의 규칙 JSON은 원문 AC/DC를 관측 가능한 검사로 구체화한다.
분석기는 이 규칙을 동일한 연산자로 처리하며 엔진 이름으로 판정 방식을 선택하지 않는다.

## 기록 형식

모든 이벤트는 같은 최상위 구조를 갖는다.

| 필드 | 의미 |
|---|---|
| `schema_version`, `run_id`, `event_id`, `sequence` | 스키마·실험·개별 관측 식별 및 순서 |
| `metadata` | 공격, 엔진 커밋, 모델, 실행 범위, 입력 manifest 등의 실험 조건 |
| `timestamp_utc`, `monotonic_ns` | 수집 시각과 동일 호스트에서의 시간 순서 |
| `stage`, `context` | 처리 단계와 request/input/parent/pair/transform 관계 |
| `source` | 실제 소스 파일, 함수, 행, LP ID와 수집 시 소스 SHA-256 |
| `raw` | 반환값·토큰 수·텍스트 등 가공하지 않은 관측값 |
| `artifacts` | 전체 원시 텐서의 상대 경로·SHA-256·dtype·shape·크기 |
| `readable` | 사람이 읽는 설명. 분석 판정의 입력으로 신뢰하지 않음 |
| `previous_event_hash`, `event_hash` | 이벤트 순서 및 내용의 해시 연결 |

원시 텐서는 숫자형 `.npy`로 손실 없이 저장한다. `preview`와 min/max는 미리보기일 뿐,
전체 원시값은 `artifacts/*.npy`에 있다. `allow_pickle=False`로 읽는다.
JSONL에는 NaN/Infinity나 Python 객체의 임의 문자열 표현을 기록하지 않는다.

실험 출력은 `.evidence/raw/<attack>/<engine>/<run_id>/`에 둔다.

```text
<run_id>/
  run.json             실험 환경 및 provenance
  events.jsonl         순서대로 수집한 공통 원본 로그
  events.pretty.json   같은 로그의 들여쓰기 버전(raw와 직관적 설명 모두 포함)
  artifacts/           손실 없는 원시 텐서·입출력 바이트
  seal.json            종료 상태, 이벤트 수, 마지막 해시, JSONL 전체 해시
```

기존 run 디렉터리는 덮어쓰지 않는다. 오류가 난 실험은 `failed`, 환경 검사에서 막힌
실험은 `blocked`로 구분한다. 이 경우 실제 AC/DC가 거짓이라는 결론을 내리지 않는다.
`Logger(..., enabled=False)`는 파일이나 소켓을 만들지 않는다. 네이티브 로깅은
`LIEMAPP_SOCKET`이 설정된 경우에만 활성화된다.

## Python 사용

경로에 하이픈이 있으므로 `importlib.util.spec_from_file_location`으로 `logger.py`를
불러온 뒤 다음 공통 API를 사용한다. 실제 엔진 실행 예시는 SIAI의 `run.py`를 참고한다.

```python
with Logger(new_run_dir, metadata, source_root=workspace_root) as log:
    with Collector(log) as collector:
        # 자식 엔진에 LIEMAPP_SOCKET=collector.socket_path 전달
        log.emit("request_started", {"status": "started"}, context=request_context)
        # Python 소스 계측은 배열을 그대로 전달할 수 있다.
        log.emit("encoder_input", {"returncode": 0}, context=request_context,
                 source=source_location, tensors={"values": actual_array})
```

네이티브 전달은 UTF-8 NDJSON 한 메시지와 JSON ACK를 사용한다. 텐서는
`{name, dtype, shape, data_base64}` 구조의 little-endian 숫자 버퍼다.
단일 메시지 상한은 64 MiB이고, 소켓은 접근 제한된 로컬 임시 디렉터리에만 생성한다.
collector가 기록을 거부하면 호출 측에도 오류가 전달된다. 벡터를 잘라 저장하거나
오류를 숨겨 실험을 성공 처리하지 않는다.

## 연구 해석과 무결성의 한계

- AC 충족은 공격의 선행조건에 관한 증거이지 공격 성공의 증거가 아니다.
- DC 충족은 해당 관측·비교 절차를 수행할 수 있다는 뜻이며, 탐지 정확도가 검증됐다는 뜻이 아니다.
- static mapping과 runtime 계측 완료를 구분한다. 소스 함수가 존재한다고 실행됐다고 기록하지 않는다.
- 해시 연결은 우발적 변경·누락 탐지용이다. 로그와 seal을 함께 다시 작성할 수 있는 공격자에 대한
  전자서명이나 외부 신뢰 기반의 chain of custody를 제공하지 않는다.
- 원시 프롬프트·응답·이미지는 민감정보일 수 있다. 실험 디렉터리는 기본 0700, 파일은 0600이다.
  실제 사건에서는 별도 수집 권한·접근 제어·보존 정책이 필요하다.
