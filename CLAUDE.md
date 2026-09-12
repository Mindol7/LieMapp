# LieMapp — 세션 시작 시 반드시 읽을 것

## 먼저 할 일

**[internal/WORKLOG.md](internal/WORKLOG.md)를 읽어라.** 연구 배경, 현재 상태, 지금까지의 결정과 그 이유,
함정 목록, 남은 일이 전부 거기 있다. 이 파일은 요약이자 안전장치일 뿐이다.

읽는 순서: `internal/WORKLOG.md` → (필요시) `README.md` 사용법 → `LieMappAnalyzer/README.md` 규칙 DSL

## 이 저장소가 하는 일

LLM 추론 엔진(llama.cpp / vLLM / SGLang / MLC-LLM / TensorRT-LLM)이 알려진 공격에
노출돼 있는지를, **엔진 소스 코드가 남긴 증거**로 판정하는 포렌식 프레임워크다.

공격을 두 종류 조건으로 정형화한다.
- **AC** (Attack Condition) — 공격 성립에 필요한 선행 조건 → 배포 전 사전 진단
- **DC** (Detection Condition) — 로그로 탐지하는 데 필요한 관측 조건 → 사고 후 사후 입증

## 지금 하고 있는 일 (2026-09-12 기준)

**AMA(Attractive Metadata Attack)를 TensorRT-LLM에서 실행하는 것.** 5개 엔진 중 마지막이다.

- 나머지 4개 엔진은 CPU에서 완료됐다.
- TensorRT-LLM은 CPU 경로가 없어 **GPU 서버에서만** 돌릴 수 있다.
- 대상 버전은 **v1.2.1**(안정 태그). 휠은 PyPI가 아니라 `https://pypi.nvidia.com`에 있다.
- `attack-script/ama/tensorRT-llm/` 등 관련 디렉터리는 **전부 비어 있다.** 약 55개 파일을 새로 써야 한다.
  MLC-LLM 구현(`attack-script/ama/mlc-llm/`)이 템플릿이다.

자세한 계획·관문·미해결 사항은 internal/WORKLOG.md의 6절과 6.5절에 있다.

## 절대 어기면 안 되는 것 (어기면 연구 주장이 무너진다)

### 1. 공통 스키마 · 단일 Analyzer
`LieMappBench/Logging-Dataset/logger.py` 하나가 모든 엔진의 증거를 쓴다.
`LieMappAnalyzer/analyzer.py` 하나가 모든 공격·엔진을 판정한다.
**이 두 파일에 엔진 이름이나 공격 이름으로 분기하는 코드를 넣지 마라.** (현재 0건)
엔진 차이는 규칙 JSON의 `select`가 어떤 `stage`를 고르느냐로만 흡수한다. 규칙은 코드가 아니라 데이터다.

### 2. Attack Library(xlsx)가 조건의 유일한 권위
`LieMappBench/Attack-Library/attack_library.xlsx`의 셀 본문에 `AC1:`, `AC2:`처럼 번호가 직접 적혀 있고,
테스트가 규칙 파일과 워크북을 1:1로 강제한다.
**규칙 파일에서만 조건 번호를 바꾸면 테스트가 깨지고 출처 사슬이 거짓이 된다.**
워크북을 고치면 **모든 공격**의 규칙 파일 `library.sha256`을 갱신해야 한다(siai를 빠뜨리기 쉽다).

### 3. 판정은 3값이다
`true`=T, `false`=F(반대 증거 관측), `null`=판정불가.
**`false`와 `null`을 섞지 마라.** 이벤트가 없다는 것만으로 F를 선언하지 않는다.
공개 표시에서는 둘 다 F로 보이지만 `evidence_status`로 구분한다
(`observed_not_satisfied` vs `not_evaluated`).

### 4. `raw`만 판정에 쓴다
이벤트의 `raw`와 검증된 `artifacts`만 판정 입력이다. `readable`은 사람용 설명이며 판정 금지.

### 5. 증거를 손대지 마라
`.evidence/raw/` 아래 봉인된 실행은 절대 수정·삭제하지 않는다.
기존 실행·매핑을 덮어쓰지 않는다. 재실험은 새 run-id로 한다.
중단된 실행도 보존한다(부분 로그가 증거다).

## 자주 물리는 함정

- **실행 중 `internal/experiments.json`을 건드리지 마라.** 파이프라인이 매 단계 사이에 재해시한다.
- **데이터셋을 다시 만들지 마라.** `attack-source/ama/SGLang/public-http-v1/` 8개 파일(219,233 B)은
  재생성이 불가능하다. 다시 import하면 provenance 다이제스트가 달라져 모든 실행이 죽는다.
- **6단계 파이프라인은 한 머신에서 끝내라.** 절대경로가 이벤트 해시에 들어간다.
  단, 증거와 **동결된 매핑을 함께** 가져오면 다른 머신에서 재발행은 가능하다.
  가져온 매핑을 그 머신에서 **다시 동결하면 안 된다.**
- **AMA는 실제로 외부 HTTPS를 호출한다**(postman-echo.com). 합성 데이터만 보낸다.
- **완료 판단은 `pipeline-result.json`의 status와 최종 독립 감사로 한다.** tmux 종료 코드가 아니다.
- **행 번호를 믿지 마라.** TensorRT-LLM은 리비전마다 파일 구조가 크게 다르다
  (`openai_server.py`가 v1.2.1에서 1,139행, 최신에서 3,426행). 함수 이름으로 찾아라.

## 검증

```bash
# 전체 테스트 (2026-09-12 기준 502개 통과)
PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 \
  .venv/bin/python -m unittest discover -s tests -p 'test_*.py'

# 엔진·공격 이름 분기가 없는지 (0건이어야 정상)
grep -c -i "llamacpp\|vllm\|sglang\|mlc\|tensorrt" \
  LieMappAnalyzer/analyzer.py LieMappBench/Logging-Dataset/logger.py
```

서버 체크아웃에는 다른 엔진의 증거가 없으므로 일부 테스트가 실패·스킵될 수 있다.
**실험 실행 자체는 막지 않는다.** 자세한 것은 internal/WORKLOG.md 6.5절.

## 작업 방식

- 사용자는 한국어로 소통한다. **짧고 쉬운 말로 설명한다.** 전문 용어는 한 번 풀어 쓴 뒤 사용한다.
  결론을 먼저 말하고 근거를 뒤에 붙인다. 긴 산문보다 표와 짧은 목록을 쓴다.
- 추측으로 사실을 만들지 않는다. 확인하지 못한 것은 **확인하지 못했다고 말한다.**
  이 저장소는 포렌식 연구용이며, 근거 없는 주장은 연구 결과를 훼손한다.
- 무언가를 바꾸면 **internal/WORKLOG.md의 해당 절(현재 상태 / 결정 / 함정 / 남은 일)을 함께 갱신한다.**
