# SIAI / mlc-llm 입력 데이터

공격 원본·정상 대조군·증강 입력은 `../shared/`의 해시 고정 manifest를 공통으로 사용한다.
이 디렉터리에 중복 이미지나 가상의 엔진별 공격 결과를 만들지 않았다.
현재 mlc-llm native 실행은 미완료이며 상세 상태는 대응 attack-script 폴더와 공통 보고서를 따른다.

2026-09-07 추가: 사용자가 지정한 `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC`의 공식 API·MIT 기반 모델 라이선스·114개 파일 전체 해시를 `phi35-provenance/`에 보존했다. 큰 모델 파일은 `Instrumented-LIE/siai/mlc-llm/models/`에 한 벌만 존재한다. fresh CPU runtime 빌드에는 성공했지만 모델 LLVM compile 실패로 native 입력/출력 수집은 0회다. 모델 가중치는 공격 데이터가 아니며, 이 provenance를 공격 성공의 증거로 사용하지 않는다.
