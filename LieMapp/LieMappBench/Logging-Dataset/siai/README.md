# SIAI — 조건과 계측 지점

2026-09-07 출력 안내: [developer.py](../../../developer.py) / [investigator.py](../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

조건의 기준은 [Attack Library](../../Attack-Library/attack_library.xlsx)의 `AI 포렌식!G10:H10`이다. 엑셀 파일은 수정하지 않았다. `library.py`가 조건 원문·셀 주소·workbook SHA-256을 [library.json](../library.json)으로 추출한다. 서식만 있는 행이나 숨김 시트의 학술대회 목록은 공격 레코드로 세지 않는다.

## 여기서 읽을 파일

- `엔진/source-review.md`: 엑셀의 예전 위치를 현재 원본 소스의 함수·클래스·행번호에 다시 매핑한 설명.
- `엔진/source-review.json`: 위 설명의 기계 판독본. 커밋과 소스 SHA-256을 포함한다.
- 실제 계측이 추가되면 생성되는 `logging-points.*`: 적용한 로깅 호출·원시값·근거. 정적 후보와 구분한다.
- 실행 시 생성되는 원시 로그는 `.evidence/raw/siai/엔진`에 저장하며, 여기에 정적 자료와 섞어 두지 않는다.

모든 `source-review`는 **정적 후보**이다. 함수가 존재한다는 사실은 로깅 함수가 활성화됐거나 AC/DC가 T라는 뜻이 아니다. MLC-LLM의 Python graph-building 함수는 특히 컴파일 시점과 runtime을 구분해야 한다.

## 판정에 필요한 증거

|조건|관측해야 하는 사실|그 사실만으로 결론 내리면 안 되는 것|
|---|---|---|
|AC1|같은 요청의 인코딩 성공과 이미지-언어 결합 경로|모든 공격이 성공한다|
|AC2|clean/공격 쌍의 provenance와 전처리 후 인코더 입력 차이|수치 차이만으로 공격 목적의 효력 보존|
|AC3|visual embedding이 실제 decoder에 전달되고 소비됨; 직접 영향은 통제 ablation의 logits/응답 비교|함수 진입만으로 생성에 대한 인과성|
|DC1|원본-증강 계보와 동일 모델·전처리·인코더|파일 해시만으로 증강 관계|
|DC2|동일 layer/stage의 원시 embedding, dtype/shape, 연결 식별자|벡터 min/max만으로 cosine 재계산|
|DC3|정상 전용 calibration에서 정한 threshold와 실제 cosine 비교|탐지 준비도를 검증된 탐지 성능으로 해석|

증거 부족은 F(조건이 실제로 거짓)와 구분해야 한다. 어떤 경로를 시험하지 못했다고 해당 엔진이 안전하다고 결론 내리지 않는다. 사후 재현 로그는 조사 당시 환경에서의 가설 검증 증거이며, 과거 사건에서 공격이 실제 발생했다는 단독 증거가 아니다.

## 논문과 LieMapp의 추가 설계

SIAI 원문 §6.2 / PDF 14~15쪽은 이미지와 그 증강본의 embedding cosine을 이용한 anomaly defense를 제시한다. LLaVA에서는 정상·공격 분포가 겹치므로 방어 효과가 없을 수 있다고 명시한다. 원문의 보편 threshold는 없다.

현재 실험의 `distance = 1 - cosine`, 정상 calibration 10장, 변환별 95 percentile (`higher`) 기준은 **LieMapp 파일럿 설계**이며 논문의 검증된 판정 기준으로 표기하지 않는다. AC/DC의 절차적 T와 실제 공격 성공·탐지 효과는 보고서에서 별도 결과로 취급한다.
