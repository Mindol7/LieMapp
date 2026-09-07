# SIAI 공통 규칙 검토 — 2026-09-06

2026-09-07 출력 안내: [developer.py](../../../developer.py) / [investigator.py](../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

최종 판정 보고서 생성 전, `build_rules.py`와 `conditions.json`의 문법·출처·요청 연결을 독립 검토했다.
이 검토는 새로운 공격 실험 결과를 만드는 작업이 아니며 원본 JSONL·seal·수집 아티팩트를 수정하지 않는다.

## 확인 사항

- `AI 포렌식!G10:H10`의 AC1~AC3/DC1~DC3 원문 및 셀 주소를 그대로 가져온다.
- workbook SHA-256: `069bdc201aef0babcb9eecabfc50627548dae616e618aac1b20cf9418a1a4981`.
- 동일한 규칙 JSON을 엔진별 이름 분기 없이 공통 Analyzer에 전달한다.
- 84개 기본 입력(정상 보정 70, 평가 clean 7, 학습 공격 후보 7)과 zero-visual/명시적 지시 대조 각각 1개로
  구성된 manifest·runner 연결 정보를 검사했다. 열린 실행 스트림을 완성된 증거로 판정하지 않았다.
- clean/attack 입력은 공유 `attack_pair_id`·변환·질문·프롬프트 해시·seed로 대응한다.
- 인과 비교에는 동일 입력·질문·프롬프트·seed·temperature·토큰 제한·모델 revision을 조인하며,
  원본 요청과 개입 요청의 실제 request ID는 서로 달라야 한다.
- DC3는 정상 보정 10장만 사용한 변환별 95 percentile (`higher`)이고, clean/attack 시험군은 보정군과 분리한다.
  DC2의 cosine 계산 가능성, DC3의 임계값 비교 가능성, 실제 탐지 성능은 구분한다.

## 최종 분석 전 보수적 정확성 보완

1. **AC1 요청 간 오연결 방지:** 선택한 공격 원본 요청마다 인코딩·디코딩·생성 성공을 함께 요구하도록
   `all.select` 및 `join_by=request_id`를 적용했다. 요청 A의 성공으로 요청 B의 누락 단계를 메우지 않는다.
2. **AC3 실제 개입 확인:** 정상 decoder의 `intervention=false`와 개입 decoder의 전체 원시값
   `max_abs=0`을 요구한다. 개입 플래그만 참인 경우에는 통과할 수 없다.
3. **관측 정의 표시:** 원본 AC/DC 문장과 이번 파일럿의 operationalization을 보고서에서 구분해 보여준다.
4. **불완전 조인 보존:** 선택된 증거에서 조인 키가 빠졌다면 그 이벤트를 버리지 않고 판정불가로 남긴다.

이는 관측된 결과를 유리하게 만드는 임계값 조정이 아니라, 요청 연결과 실제 개입 검증을 강화한 정확성 수정이다.
정상 표본 수, 변환 종류, 거리 지표, percentile 및 계산 방법, 입력 섭동 한도는 변경하지 않았다.
이 시점의 최종 규칙 SHA-256은 `48d5cdd2a4784819f3fd0e706c9df119d0d7156685009925f0a4686e406ce16f`이다.
이는 규칙의 최종 판정 시점 동결 기록이며, 모든 설계가 외부에 사전 등록되었다는 뜻은 아니다.

## 남는 한계

- 정상과 zero-visual 실행 사이의 logits 차이는 생성 경로의 계산적 영향과 양립한다. 하지만 동일 입력의
  비개입 logits 반복 대조가 없으므로 수치적 비결정성까지 분리한 확정적 인과 효과로 표현하지 않는다.
- AC2의 입력/인코더 차이는 섭동의 비소실에 대한 관측이다. 공격 의도의 완전한 보존이나 실제 공격 성공을
  충분히 증명하지 않는다.
- 실제 공개 API의 이미지 계보, 보정/평가 집단의 독립성, 공격 provenance의 과학적 타당성을 범용 Analyzer가
  자동으로 추론하지 않는다. 이 실험의 manifest·학습 provenance·source mapping이 함께 필요하다.

검증은 `LieMapp/tests/test_siai_rules.py` 및 공통 Analyzer 회귀 테스트에 포함했다.

## 최종 표시 검토본 (`-reviewed`)

최초 분석 이후 요약 표현을 검토하여 다음 표시 문제를 수정했다. 조건 규칙과 모든 측정·판정값은 바꾸지 않았다.

- DC2의 cosine **유사도**를 거리라고 부르던 요약 문구를 수정했다.
- AC2의 uint8 픽셀 차이와 float32 인코더 입력 차이를 하나의 범위로 합치지 않고 아티팩트·dtype별로 표시했다.
- DC3의 clean/attack 초과 횟수를 분리하고, 12개 변환별 비교의 n·threshold·실측값·초과 여부를 본문 표에 표시했다.
- 모델의 긴 경로·해시는 실행 메타데이터 링크로 분리했다. 원본 값과 파일 접근성은 그대로 유지했다.

최종 표시본의 공통 Analyzer SHA-256:
`1ece41340efd348562b1a50fe5ad69ecd8f49ffa1cd7ab716bf13efae049c09c`.
공통 규칙 SHA-256은 위 `48d5cdd2…ce16f`와 동일하다.

다섯 엔진의 표시 검토본은 해당 실행 ID 뒤에 `-reviewed`를 붙인 report 디렉터리에 생성했다.
기존 보고서는 삭제·덮어쓰기하지 않았다. 이전 결과와 비교하여 조건별 T/F/null, 모든 기존 수치,
원본 증거, 규칙 스냅샷 및 원본 로그 SHA-256이 일치함을 확인했다. 추가된 `quantity`·`left_dtype`·
`right_dtype`는 측정 결과를 정확히 표시하기 위한 기술 필드이며 새로운 판정 입력이 아니다.

최종 공통 테스트 56개를 모두 통과했다. llama.cpp 본 실험은 1,120개 이벤트·1,204개 아티팩트 참조의
무결성을 확인했고, 다른 네 엔진의 당시 preflight 로그는 모든 AC/DC를 판정불가로 유지했다.
