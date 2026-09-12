# AMA · MLC-LLM 실험 입력

입력 과제·메타데이터·합성 비밀·공개 API 출처는 기존 공개 API 실험의 고정 자료를 그대로 참조합니다. MLC에 유리하도록 평가 입력을 수정하거나 새 공격 문구를 탐색하지 않습니다.

| 구분 | 자료 및 의미 |
|---|---|
| 입력·실험군 | `../SGLang/public-http-v1/fixtures.json` — 평가 8개 과제 × 후보 순서 2종 × 시드 2개 × 실험군 4종, 총 128개 계획 |
| 공개 API 출처 | 같은 디렉터리의 `provenance.json` 및 공식 Postman 자료 원문·해시 |
| 공식 MLC 모델 출처 | `model-provenance/dfa91e8/manifest.json` — 72개 배포 파일의 Git/LFS 해시와 다운로드 기록 |
| 모델 기본 계열 | Qwen2.5-3B-Instruct. 공식 MLC 배포본의 정확한 HF 기반 revision은 공개 자료에서 확인되지 않으므로, 다른 엔진과 가중치가 바이트 단위로 동일하다고 주장하지 않음 |

API는 실제 공개 시험 서비스인 Postman Echo입니다. 공격 역할의 이름·설명·매개변수 의미만 로컬에서 구성했습니다. **Postman이 악성 서비스이거나, 악성 메타데이터가 공개 플랫폼에 게시되었다는 의미가 아닙니다.** 전송 대상은 사전 허용한 공개 `/get` 연산으로 제한하며, 실제 비밀·계정 정보는 사용하지 않습니다.

MLC는 네이티브 Python 호출 문법과 인자 사전을 사용합니다. 따라서 입력 과제와 AC/DC 판정식은 유지하되, 실행 계약은 `ama-public-http-mlc-native-v1`로 구분합니다. 원 논문의 QNT 최적화 전체 또는 공격 성공률 재현이 아닌, 계측·증거 수집 방법론의 통제 실험입니다.

공식 출처: [MLC Qwen2.5-3B q4f32_1 배포본](https://huggingface.co/mlc-ai/Qwen2.5-3B-Instruct-q4f32_1-MLC/tree/dfa91e859b714acfa489a1464297080656c3460d), [MLC 모델 컴파일 문서](https://llm.mlc.ai/docs/compilation/compile_models.html).
