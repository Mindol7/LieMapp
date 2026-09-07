# SIAI / vllm 입력 데이터

공격 원본·정상 대조군·증강 입력은 `../shared/`의 해시 고정 manifest를 공통으로 사용한다.
이 디렉터리에 중복 이미지나 가상의 엔진별 공격 결과를 만들지 않았다.
실행은 [native runner 안내](../../../attack-script/siai/vllm/README-native.md)를 따른다.
동일 512×512 입력을 vLLM의 longest-edge 1024 프로세서 설정으로 처리하며,
5 image parts / 320 visual tokens가 관측된다. HF 학습 또는 다른 엔진과 전처리가 동일하지 않다.
실제 완료된 실행과 판정은 [결과 인덱스](../../../../../report/siai/README.md)에서 확인한다.
