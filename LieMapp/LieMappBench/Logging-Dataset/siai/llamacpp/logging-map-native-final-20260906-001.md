# SIAI / llama.cpp 실제 로깅 지점

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

원본 커밋: `9e0e220594af405a62835dc3a27495729fd8506b`. AC/DC의 정의는 Attack Library의 원문 셀을 따른다.

각 지점의 관측 여부와 AC/DC의 T/F는 서로 다른 정보다. 최종 조건 판정은 공통 Analyzer가 수행한다.

| 로깅 지점 | 조건 | 실행 관측 | 이유 |
|---|---|---|---|
| `siai.llamacpp.processor-output` | AC2, DC1 | 98개 이벤트 | 엔진 전처리 직후의 정규화된 실제 픽셀을 모두 보존한다. 인코더 입력과 연결하여 전처리에서 인코더까지 전달된 값을 검증한다. |
| `siai.llamacpp.encoder-input` | AC1, AC2, DC1 | 196개 이벤트 | clip_image_batch_encode에 실제로 전달되는 float32 버퍼를 보존한다. 함수 호출 여부와 perturbation 보존 여부를 혼동하지 않고 clean/attack 쌍과 비교한다. |
| `siai.llamacpp.projected-embedding` | AC1, AC3, DC2, DC3 | 196개 이벤트 | 성공한 이미지 인코딩·projection의 실제 출력과 반환값을 기록한다. 모든 타일을 순서대로 연결해야 전체 임베딩이다. |
| `siai.llamacpp.decoder-batch` | AC1, AC3 | 196개 이벤트 | 실제 llama_decode 호출이 소비한 이미지 임베딩 배치와 반환값을 기록한다. 실패 배치는 성공으로 판정하지 않는다. |
| `siai.llamacpp.decoder-input` | AC1, AC3, DC2 | 196개 이벤트 | 한 이미지 청크의 모든 llama_decode 배치가 성공한 뒤 전체 소비 버퍼를 기록한다. projection 값과의 일치만으로 출력에 대한 인과적 영향을 단정하지 않는다. |
| `siai.llamacpp.visual-ablation` | AC3 | 2개 이벤트 | 원본 요청과 동일한 이미지·프롬프트·seed에서 visual embedding만 0으로 바꾸는 통제 실험을 명시적으로 기록한다. 일반 추론 또는 공격 성공 로그가 아니다. |
| `siai.llamacpp.generation-output` | AC3 | 98개 이벤트 | 실제 언어 디코더의 첫 토큰 전체 logits·생성 텍스트·토큰 ID를 보존한다. 정상/ablation의 정량 차이와 공격 목표 달성은 구분하여 분석한다. |

## 실제 소스와 원시 값 예시

이미지 타일이 여러 개이면 동일 요청·동일 stage의 텐서를 이벤트 순서로 모두 연결한다. preview는 전체 raw 값이 아니다.

### siai.llamacpp.processor-output

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd.cpp:1399` / `add_media`
- SHA-256: `fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0`
- 보존 소스: [source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp](source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `27b905059b8742d68316c328aff31350`

```json
{
  "raw": {
    "layout": "concatenated_HWC",
    "part_lengths": [
      786432,
      786432
    ],
    "part_shapes": [
      [
        512,
        512,
        3
      ],
      [
        512,
        512,
        3
      ]
    ],
    "returncode": 0,
    "status": "success"
  },
  "artifacts": {
    "values": {
      "bytes": 6291584,
      "dtype": "float32",
      "format": "npy",
      "max": 1.0,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -1.0,
      "path": "artifacts/d11566f5522f457f80ffe12447b921b9-values.npy",
      "preview": [
        -0.7098039388656616,
        -0.8039215803146362,
        -0.7098039388656616,
        -0.7098039388656616,
        -0.8039215803146362,
        -0.7098039388656616,
        -0.7176470756530762,
        -0.8117647171020508
      ],
      "raw_nbytes": 6291456,
      "sha256": "a120c389fab3c749b0f49254058a58dc810ee14caab43c47969a8b90c8eb3955",
      "shape": [
        1572864
      ]
    }
  }
}
```

### siai.llamacpp.encoder-input

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd.cpp:1825` / `mtmd_encode_impl`
- SHA-256: `fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0`
- 보존 소스: [source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp](source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `300a944e02be4aabb12f647993679405`

```json
{
  "raw": {
    "layout": "concatenated_HWC",
    "n_image_tokens": 64,
    "part_lengths": [
      786432
    ],
    "part_shapes": [
      [
        512,
        512,
        3
      ]
    ],
    "returncode": 0,
    "status": "success"
  },
  "artifacts": {
    "values": {
      "bytes": 3145856,
      "dtype": "float32",
      "format": "npy",
      "max": 1.0,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -1.0,
      "path": "artifacts/456246a89cdc4340a1ac1b79f5501285-values.npy",
      "preview": [
        -0.7098039388656616,
        -0.8039215803146362,
        -0.7098039388656616,
        -0.7098039388656616,
        -0.8039215803146362,
        -0.7098039388656616,
        -0.7176470756530762,
        -0.8117647171020508
      ],
      "raw_nbytes": 3145728,
      "sha256": "20a2589f6199937eaf451758fa0019713cd3e35537e3e0f9b0385bf4e5a7da85",
      "shape": [
        786432
      ]
    }
  }
}
```

### siai.llamacpp.projected-embedding

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd.cpp:1837` / `mtmd_encode_impl`
- SHA-256: `fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0`
- 보존 소스: [source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp](source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `060f3ee96885404ba2558cfc73edda7e`

```json
{
  "raw": {
    "embedding_dimension": 576,
    "n_image_tokens": 64,
    "returncode": 0,
    "status": "success"
  },
  "artifacts": {
    "values": {
      "bytes": 147584,
      "dtype": "float32",
      "format": "npy",
      "max": 100.86048889160156,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -54.833091735839844,
      "path": "artifacts/f442c4933f0a412e9c2c070a4212ebdf-values.npy",
      "preview": [
        -0.17804908752441406,
        -6.39597225189209,
        -1.4736502170562744,
        -7.8723602294921875,
        -13.138199806213379,
        -3.32598876953125,
        -3.4800262451171875,
        5.833655834197998
      ],
      "raw_nbytes": 147456,
      "sha256": "41ca263b5eeeb215b065b7e4cc05407500a44cfb1fdf4e74cf335d69148f4134",
      "shape": [
        64,
        576
      ]
    }
  }
}
```

### siai.llamacpp.decoder-batch

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd-helper.cpp:193` / `mtmd_helper_decode_image_chunk`
- SHA-256: `f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d`
- 보존 소스: [source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp](source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `03cb063e6fd344b5ae5a4b9748c959ef`

```json
{
  "raw": {
    "batch_count": 1,
    "batch_index": 0,
    "n_image_tokens": 64,
    "n_past": 6,
    "returncode": 0,
    "seq_id": 0,
    "status": "success",
    "token_offset": 0,
    "total_image_tokens": 64
  },
  "artifacts": {
    "values": {
      "bytes": 147584,
      "dtype": "float32",
      "format": "npy",
      "max": 100.86048889160156,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -54.833091735839844,
      "path": "artifacts/29e7b0a1f27543faac3d7b3d6beae431-values.npy",
      "preview": [
        -0.17804908752441406,
        -6.39597225189209,
        -1.4736502170562744,
        -7.8723602294921875,
        -13.138199806213379,
        -3.32598876953125,
        -3.4800262451171875,
        5.833655834197998
      ],
      "raw_nbytes": 147456,
      "sha256": "41ca263b5eeeb215b065b7e4cc05407500a44cfb1fdf4e74cf335d69148f4134",
      "shape": [
        64,
        576
      ]
    }
  }
}
```

### siai.llamacpp.decoder-input

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd-helper.cpp:218` / `mtmd_helper_decode_image_chunk`
- SHA-256: `f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d`
- 보존 소스: [source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp](source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `34d74d7a73d04d749ae907aff3c6f32b`

```json
{
  "raw": {
    "batch_count": 1,
    "completed_batches": 1,
    "intervention": false,
    "n_image_tokens": 64,
    "n_past": 6,
    "returncode": 0,
    "seq_id": 0,
    "status": "success"
  },
  "artifacts": {
    "values": {
      "bytes": 147584,
      "dtype": "float32",
      "format": "npy",
      "max": 100.86048889160156,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -54.833091735839844,
      "path": "artifacts/b1c638dec86b436ea14ed009a12fe741-values.npy",
      "preview": [
        -0.17804908752441406,
        -6.39597225189209,
        -1.4736502170562744,
        -7.8723602294921875,
        -13.138199806213379,
        -3.32598876953125,
        -3.4800262451171875,
        5.833655834197998
      ],
      "raw_nbytes": 147456,
      "sha256": "41ca263b5eeeb215b065b7e4cc05407500a44cfb1fdf4e74cf335d69148f4134",
      "shape": [
        64,
        576
      ]
    }
  }
}
```

### siai.llamacpp.visual-ablation

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd-helper.cpp:154` / `mtmd_helper_decode_image_chunk`
- SHA-256: `f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d`
- 보존 소스: [source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp](source-snapshots/f3bb86e1972670ea9c9d2c3db08dbbb2777c220895f80b53691f4f6e19313b0d-mtmd-helper.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `97759afcd2e74c1fa018bad6620b073b`

```json
{
  "raw": {
    "embedding_dimension": 576,
    "method": "zero_visual_embeddings",
    "n_image_tokens": 64,
    "status": "success"
  },
  "artifacts": {}
}
```

### siai.llamacpp.generation-output

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd-cli.cpp:252` / `generate_response`
- SHA-256: `77a5450a81c94e3453652d247d24ce92b710948cf13fd5dd89d6e5ffea904af6`
- 보존 소스: [source-snapshots/77a5450a81c94e3453652d247d24ce92b710948cf13fd5dd89d6e5ffea904af6-mtmd-cli.cpp](source-snapshots/77a5450a81c94e3453652d247d24ce92b710948cf13fd5dd89d6e5ffea904af6-mtmd-cli.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-cpu128-20260906-001/events.pretty.json`, 이벤트 `b90daaf05cb44aa9b4685e4e5ab38006`

```json
{
  "raw": {
    "first_step_logits_count": 49280,
    "generated_text": " The image depicts a person holding a bat in a baseball game. The person is wearing a white T-shirt and black baseball cap. The baseball cap is positioned on the person's head, and the person's face is not visible. The",
    "generated_token_count": 48,
    "n_past": 199,
    "n_predict": 48,
    "returncode": 0,
    "status": "success",
    "token_ids": [
      378,
      2443,
      21559,
      253,
      1055,
      6961,
      253,
      10581,
      281,
      253,
      16352,
      3133,
      30,
      378,
      1055,
      314,
      9064,
      253,
      2537,
      312,
      29,
      42582,
      284,
      2632,
      16352,
      1408,
      30,
      378,
      16352,
      1408,
      314,
      17982,
      335,
      260,
      1055,
      506,
      1680,
      28,
      284,
      260,
      1055,
      506,
      2715,
      314,
      441,
      6178,
      30,
      378
    ]
  },
  "artifacts": {
    "logits": {
      "bytes": 197248,
      "dtype": "float32",
      "format": "npy",
      "max": 17.56899642944336,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -22.13849639892578,
      "path": "artifacts/ac9661bb3d0d4b6e882903814b0f5001-logits.npy",
      "preview": [
        -10.433374404907227,
        -11.34172248840332,
        -2.64217472076416,
        -10.470232009887695,
        -10.702201843261719,
        -9.949769020080566,
        -10.332731246948242,
        -9.953641891479492
      ],
      "raw_nbytes": 197120,
      "sha256": "34c62fb9b14defd33a4ba88ca5cfc6109870928ba84db9f5092f8b7ba91f03d0",
      "shape": [
        49280
      ]
    }
  }
}
```
