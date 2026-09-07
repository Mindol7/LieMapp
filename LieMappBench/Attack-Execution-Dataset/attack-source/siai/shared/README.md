# SIAI — 출처, 입력 데이터, CPU 실험

## 출처와 고정 버전

- 논문: [Self-interpreting Adversarial Images](../../../../Attack-Library/refs/Self-interpreting%20Adversarial%20Images.pdf), USENIX Security 2025. PDF SHA-256: `3a803dc83e3b25d2e626c621777f5e7c1b5e666bfb067b539a99fc254694e32e`.
- 저자 저장소: [Tingwei-Zhang/Soft-Prompts-Go-Hard](https://github.com/Tingwei-Zhang/Soft-Prompts-Go-Hard/tree/ddc8a60efd1b87cb4eab44b11225cd8a296295cd), 고정 커밋 `ddc8a60efd1b87cb4eab44b11225cd8a296295cd`. 로컬 `upstream/`에 원문 코드·clean 이미지·QA 자료·MIT 라이선스를 함께 보존했다. 저자 소스는 수정하지 않는다.
- 이 커밋의 실제 파일 목록을 검토했다. PGD 최종 입력인 `bad_prompt.bmp`는 배포되어 있지 않다. `interesting_examples`의 PNG/PDF는 대화·도표를 담은 예시 figure이므로 원본 공격 이미지로 사용하지 않는다.

## 생성 파일의 역할

|위치|내용|해석|
|---|---|---|
|`upstream/`|저자 공개 코드 및 clean 이미지|코드 출처; 공격 산출물이 배포된 것은 아님|
|`calibration-v1/`|정상 10장×원본·6종 증강 + 평가용 clean 1장×7 = 77개|미리 수집 가능한 정상·관측 경로 데이터|
|`training-pilot-8/`|실제 CPU PGD 8-step 시운전|속도·gradient·전처리 검증. heldout 생성 평가 안 함|
|`training-cpu-128/`|사전 고정 128-step 실제 CPU PGD 및 독립 heldout 응답|학습된 공격 후보. 성공 여부를 이름으로 단정하지 않음|
|최종 `experiment-cpu128-v1/`|10 calibration + clean/공격 각 1장과 각각 6종 증강 = 84개|공통 엔진 입력 manifest|

학습 코드: [generate_attack.py](../../../attack-script/siai/shared/generate_attack.py). 데이터셋 코드: [prepare_dataset.py](../../../attack-script/siai/shared/prepare_dataset.py). 출력 디렉터리가 비어 있지 않으면 덮어쓰기를 거부한다.

## 원문 방법론과 이번 실험의 차이

원문 §3~4 / PDF 7~8쪽에서 성공은 (1) 공격 meta-objective 만족과 (2) 질문·이미지 내용에 맞는 응답을 함께 요구한다. 본 실험은 무해한 pirate 스타일 `Arrr`와 cassette player의 색·위치·기능 설명을 사용한다. 표식 매칭은 편의상 쓰는 제한적인 proxy이며 전체 의미 일치나 공격 성공을 자동 보증하지 않는다.

원문은 MiniGPT-4·LLaVA·InstructBLIP, 주로 `L∞ ε=32/255`, step `1/255`, 2,000회, batch 8, 합성 QA 40/60 분할을 사용했다(§5.1 / PDF 9~10쪽). 이번 실험은 GPU 없이 로컬 SmolVLM-256M FP32 CPU, batch 1, 수기 학습 QA 4개/분리된 평가 질문 4개, **128회 고정**을 사용한다. 결과를 본 뒤 checkpoint나 step 수를 고르지 않는다. 모델·예산·데이터셋이 다른 방법론 적용 실험이며 원문 규모의 동일 조건 재현이 아니다.

원본 cassette player를 Lanczos로 512×512 정규화한 후 이를 clean 기준으로 삼는다. PGD는 그 이미지의 [0,1] raw 픽셀에 적용하고 `|δ|∞ ≤ 32/255`를 매 step 보장한다. 최종 PNG 양자화 후 실제 픽셀 차이도 별도 계산한다. 학습에 사용한 differentiable normalization `2*x-1`과 Hugging Face processor 입력을 직접 비교하여 오차를 기록한다.

HF source 모델의 동일 snapshot `7e3e67edbbed1bf9888184d9df282b700a323964`를 고정한다. 실제 native llama.cpp GGUF 엔진은 별도의 target이다. GGUF quantization·이미지 splitting/token layout·prompt rendering 차이를 숨기지 않고 **transfer 평가**로 취급한다. HF에서 성공해도 native 엔진 성공을 가정하지 않는다.

## DC 실험

원문 §6.2 / PDF 14~15쪽의 비교 대상은 `x` 대 `augment(x)` 및 `x_adv` 대 `augment(x_adv)`이다. §5.3의 clean 대 attack 의미 보존 지표와 혼동하지 않는다. 원문 6종 JPEG·GaussianBlur·RandomAffine·ColorJitter·RandomHorizontalFlip·RandomPerspective를 사용하되 이번의 세부 매개변수는 `dataset.json`에 고정 기록한 LieMapp 설정이다. Workbook H10에는 horizontal flip이 명시되지 않았으므로 원문 확장 항목으로 표시한다.

정상 COCO 10장만 calibration에 사용하며 cassette 평가 이미지나 공격 이미지를 섞지 않는다. 변환별 `1-cosine`의 정상 95th percentile (`higher`)은 **추가 파일럿 기준**이다. 원문이 제시한 보편 threshold가 아니다. N=10의 한계와 LLaVA에서 분포가 겹친다는 원문 한계를 보고서에서 유지한다.

## 공통 manifest 규칙

- `path`: dataset.json 부모 디렉터리 기준 raw PNG 경로.
- `input_id`: 각 입력 파일의 고유 ID. `input_sha256`: 파일 SHA-256.
- `role`: `calibration`, `clean`, `attack`. 증강본도 원본 역할을 유지한다.
- `transform`: `original`, `jpeg`, `gaussian_blur`, `affine`, `color_adjustment`, `horizontal_flip`, `perspective`.
- `pair_id`: 한 원본과 그 6종 증강의 공통 키. 원본마다 다르다.
- `parent_id`: 증강의 원본 input_id. 원본에서는 null.
- `attack_pair_id`: clean과 그 공격 후보를 연결하는 별도 키. 정상 calibration에서는 null.
- `seed`와 `transform_parameters`: 실제로 적용된 변환을 재생성할 수 있는 값.

원시 값·해시·연결 정보는 측정 재검증을 위한 자료이지 변조 불가능한 전자서명이나 법적 chain of custody를 대신하지 않는다.
