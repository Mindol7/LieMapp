# SIAI / SGLang 입력 데이터

공격 원본·정상 대조군·증강 입력은 `../shared/`의 해시 고정 manifest를 공통으로 사용한다.
이 디렉터리에 중복 이미지나 가상의 엔진별 공격 결과를 만들지 않았다.
실행은 [native runner 안내](../../../attack-script/siai/SGLang/README.md)를 따른다.
CPU용 private processor overlay는 512×512 입력을 resize·split 없이 처리하여
1 image part / 64 visual tokens를 만든다. 원본 모델 가중치와 HF cache는 변경하지 않는다.
실제 완료된 실행과 판정은 [결과 인덱스](../../../../../report/siai/README.md)에서 확인한다.
