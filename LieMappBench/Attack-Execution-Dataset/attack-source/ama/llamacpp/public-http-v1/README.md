# AMA 공개 API 평가 입력 — llama.cpp

이번 평가는 SGLang의 `ama-public-http-v1` 평가와 **동일한 파일을 직접 참조**한다. 이 디렉터리는 입력의 위치와 재사용 범위를 설명하며, 기존 상위 디렉터리의 로컬 합성 `fixtures.json`을 교체하지 않는다.

- [공통으로 재사용하는 평가 입력](../../SGLang/public-http-v1/fixtures.json)
- [공개 API 출처와 원문 해시](../../SGLang/public-http-v1/provenance.json)
- [원문 자료와 로컬 메타데이터의 구분](../../SGLang/public-http-v1/README.md)
- [공개 API 실행기](../../../../attack-script/ama/llamacpp/run_public.py)

평가 입력 SHA-256: `b0263b3f9f1e0dedc4961f55a9a6f68357fe992591eaab14efe15f29aad3b371`.
출처 manifest SHA-256: `9290850e00956389a17fb513eab5d082b933beb8222cb164b37eaf2be95aa280`.

공식 Postman Public API Network의 Postman Echo GET 연산을 사용한다. 실제 HTTPS 호출에는 실험용 합성 문자열만 전송한다. API 자체는 악성 서비스가 아니며, 비교 대상 도구의 이름·설명·인자 의미는 로컬에서 작성한 어댑터이다. 플랫폼에 악성 도구를 게시하거나 검색하는 과정을 재현하지 않는다.

평가 구성은 8개 입력 × 후보 순서 2개 × seed 2개 × 실험군 4개 = 128요청이다. 개발 입력과 평가 입력은 분리하지만 평가 입력은 이미 SGLang에서 사용되었으므로 연구 전체에서 처음 보는 검증 자료가 아니다. 엔진별 출력에 맞추어 설명·입력·성공 기준을 수정하지 않는다.

동일한 API 프로토콜을 적용하더라도 llama.cpp의 Q4_K_M과 SGLang/vLLM의 FP32 모델은 정밀도가 다르다. 템플릿·파서·샘플러 구현도 다르므로 관찰 차이를 엔진 자체의 보안성 차이로 단정하지 않는다. 실제 수행 결과와 AC/DC는 새 실행 로그·보고서를 기준으로 확인한다.
