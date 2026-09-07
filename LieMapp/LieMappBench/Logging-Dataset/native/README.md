# 공통 Python 로거로 연결하는 네이티브 전송 계층

`bridge.h`는 별도의 로거가 아닙니다. C/C++의 실제 관측값을 Unix-domain socket으로 `logger.py`에 전송하며 JSONL·pretty JSON·NumPy 파일은 만들지 않습니다. Python 추론 엔진과 C/C++ 추론 엔진의 저장·해시·스키마 처리는 모두 같은 `logger.py`가 수행합니다.

- 활성화: `LIEMAPP_SOCKET`에 공통 Collector의 소켓 경로를 설정합니다.
- 요청 연결: `LIEMAPP_CONTEXT_JSON`의 요청 ID·입력 ID·역할·변환·쌍 식별자를 전달합니다.
- 원시 텐서: IEEE 754 float32를 명시적인 little-endian 바이트로 직렬화한 뒤 base64로 전송합니다. 요약 통계로 원본을 대체하지 않습니다.
- 완료 확인: 이벤트마다 `{"ok": true}` 응답을 확인합니다. 기록 실패는 예외로 노출되어 실험이 성공으로 처리되지 않습니다.
- 비활성화: 환경변수가 없으면 native hook이 텐서를 복사하거나 파일·소켓을 만들지 않습니다.
- 제한: Linux/POSIX, nlohmann JSON 헤더 필요. 메시지 최대 64 MiB. 통신 타임아웃 30초. 큰 텐서는 관측 지점에서 의미 있는 부분으로 분할해야 합니다.

`test_bridge.cpp`는 원시 값 `[0.0, -1.0, 0.125, 2.5]`의 전송 정확성을 검사하기 위한 작은 fixture입니다. 실제 엔진 실행을 대신하는 실험 데이터가 아닙니다.
