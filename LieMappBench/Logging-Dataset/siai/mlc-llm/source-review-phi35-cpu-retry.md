# Phi-3.5 Vision / MLC-LLM: 로깅 후보와 재시도 결과

**실제 native 요청 0회. 아래는 계측 지점의 정적 후보이며, 계측 완료나 실행 결과가 아니다.**

모델: `mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC` · MLC source `9fa644f54b04983adea4d0168f49fc6af4a893ba`.

AC/DC 원문은 `attack_library.xlsx`의 `AI 포렌식!G10/H10`에서 그대로 가져왔다. 과거 행 번호를 현재 소스의 행 번호로 재확인했다.

| 후보 stage | 함수/지점 | 조건 | 필요한 로깅 근거 | 실제 raw 값 |
|---|---|---|---|---|
| `processor_output` | `python/mlc_llm/model/phi3v/phi3v_model.py:224` / `Phi3VForCausalLM.image_preprocess` | AC2, DC1 | 입력 uint8와 정규화·분할 후 실제 pixel tensor를 같은 request/input ID에 연결해야 함 | 미수집 — 모델 컴파일 실패 |
| `encoder_input` | `python/mlc_llm/model/phi3v/phi3v_model.py:274` / `Phi3VForCausalLM.image_embed` | AC1, AC2, DC1 | 실제 vision encoder에 전달된 전체 tensor와 성공 반환을 확인해야 함 | 미수집 — 모델 컴파일 실패 |
| `encoder_output` | `python/mlc_llm/model/phi3v/phi3v_image.py:189` / `Phi3ImageEmbedding.get_img_features` | AC1, DC2 | 동일 계층의 native visual feature를 증강 원본/변형에 대해 수집해야 함 | 미수집 — 모델 컴파일 실패 |
| `projected_embedding` | `python/mlc_llm/model/phi3v/phi3v_image.py:279` / `Phi3ImageEmbedding.forward` | AC1, AC3, DC2, DC3 | 실제 projector 반환 embedding 전체 원시값과 stable layer identity가 필요함 | 미수집 — 모델 컴파일 실패 |
| `decoder_input` | `python/mlc_llm/model/phi3v/phi3v_model.py:178` / `Phi3VForCausalLM.prefill` | AC1, AC3 | 언어 decoder의 실제 입력과 full first logits를 수집하고 동일 입력 정상/zero 개입·비개입 반복을 비교해야 함 | 미수집 — 모델 컴파일 실패 |

## 컴파일과 요청 계측의 구분

위 Python 함수는 TVM IR을 구성한다. 컴파일 중 함수가 호출되었다는 기록은 이미지가 실제 native 추론에 사용되었다는 증거가 아니다. 향후 계측은 compiled tensor의 실제 실행 경계와 native `ModelImpl::ImageEmbed`/`BatchPrefill`, request ID를 함께 연결해야 한다.

공통 Analyzer는 원시 텐서와 동일 request/pair/transform 문맥을 요구한다. 이번에는 그 입력이 없어 AC/DC 모두 **미평가**이다. 이 정적 표나 아래 환경 진단 값으로 조건을 T/F 관측 판정하지 않는다.

## 실제로 기록된 원시 값

| 단계 | 관측값 | 원시 이벤트 ID |
|---|---|---|
| 공식 모델 검증 | 114 files, 2,771,867,899 bytes, 전체 SHA256 일치 | `41e847d8edc64e349a718874a5615b4a` |
| fresh CPU runtime 빌드 | returncode=0 | `cc5b73f61321435fb13ec52cfc151621` |
| C++ factory | returncode=0, model_initialized=false, inference_executed=false | `4fab7e0a05324ef3baacfa2a96f6dfdd` |
| stock compile002 | returncode=1, int32 literal 7247757312 overflow | `575f9b32df2248228f44f2f6de784174` |
| int64-index compile003 | returncode=1, VMCodeGen tirx.Div unsupported | `90a04c224d5240e9beccd6a367bade95` |
| int64+FloorDiv compile005 | returncode=1, VMCodeGen tirx.FloorDiv unsupported | `fb37678d4d0f4cd48dd6336625bfbf40` |

실제 명령·stdout·stderr는 `.evidence/raw/siai/mlc-llm/` 아래 해당 run의 `events.pretty.json`에서 읽을 수 있다. 정리 문서: [CPU 재시도 상세](phi35-cpu-retry.md).

## 소스 원문 보존

최종 readiness run `siai-mlc-phi35-readiness-20260907-001`의 아래 이벤트에 원본/시험용 소스 전체를 uint8 NPY로 각각 보존했다. 이는 **소스코드 파일 바이트**이며 모델의 이미지·임베딩 원시값이 아니다.

- `python/mlc_llm/compiler_pass/pipeline.py`: sequence=4, event_id=`2df014dc0eae4787a04b0daf5642ff96`, original SHA256=`66882150549796da7737c5a1faf5301286bdcd2dc4b80ac6aafe6c42f7b39adf`, private SHA256=`7f63d2b332a127d1277e92f206884edfa552c1ebb31c7ab62fc68d50bb4b14a2`.
- `python/mlc_llm/model/vision/image_processing.py`: sequence=5, event_id=`0401321535fc4df09a1a98c4b15afd32`, original SHA256=`49e417e82787df92053570957206467097c27b48c6163adc52a0e9d7e04247e4`, private SHA256=`811fe59e1d4e570af44f83e8c602e21112fd2974673c092811d624c408d8da12`.
- `python/mlc_llm/model/phi3v/phi3v_model.py`: sequence=6, event_id=`472a7e973b6149469d66ab9dccba9c85`, original SHA256=`e5b6e8880c62f33dd60c6cf48501321f65c0204275bbdee6daab03119f314386`, private SHA256=`e5b6e8880c62f33dd60c6cf48501321f65c0204275bbdee6daab03119f314386`.
- `python/mlc_llm/model/phi3v/phi3v_image.py`: sequence=7, event_id=`f7120cf92934450ca7a52fc8e7c32aff`, original SHA256=`b9eb2c2dff2ba3d35f7502c28cc547b8441488e9f1369bc103e5235ee05d871b`, private SHA256=`b9eb2c2dff2ba3d35f7502c28cc547b8441488e9f1369bc103e5235ee05d871b`.
- `python/mlc_llm/serve/data.py`: sequence=8, event_id=`dd56864411ba4f44bfdc066f7fb90277`, original SHA256=`4888eb699c046b581fb4d47dcb5ddced69586ab3b309fe89fbe9dc77e95aca6e`, private SHA256=`4888eb699c046b581fb4d47dcb5ddced69586ab3b309fe89fbe9dc77e95aca6e`.
- `cpp/support/vlm_utils.cc`: sequence=9, event_id=`4d19984244a74d3e9d6833bf83a4db90`, original SHA256=`de6fe98f6fa653429b3891226dab4fe97c574899d7bba6b9e6ed9398bce35523`, private SHA256=`de6fe98f6fa653429b3891226dab4fe97c574899d7bba6b9e6ed9398bce35523`.
- `cpp/serve/model.cc`: sequence=10, event_id=`51cdd09104984f59997db18aad38e63b`, original SHA256=`ad71be956ad8f06910399a593f6638565fc810f6dc33e24ea2c28f49c59a778a`, private SHA256=`ad71be956ad8f06910399a593f6638565fc810f6dc33e24ea2c28f49c59a778a`.

시험용 padding 패치의 주석에 있던 “VM shape lowering supports FloorDiv”는 가설이었다. 실제 compile005가 이를 반증했으며, 실패 당시 코드 바이트 보존을 위해 해당 스냅샷을 수정하지 않았다. 이 패치를 정상 동작하는 구현으로 사용하면 안 된다.
