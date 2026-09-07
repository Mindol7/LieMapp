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
| `siai.llamacpp.processor-output` | AC2, DC1 | 3개 이벤트 | 엔진 전처리 직후의 정규화된 실제 픽셀을 모두 보존한다. 인코더 입력과 연결하여 전처리에서 인코더까지 전달된 값을 검증한다. |
| `siai.llamacpp.encoder-input` | AC1, AC2, DC1 | 6개 이벤트 | clip_image_batch_encode에 실제로 전달되는 float32 버퍼를 보존한다. 함수 호출 여부와 perturbation 보존 여부를 혼동하지 않고 clean/attack 쌍과 비교한다. |
| `siai.llamacpp.projected-embedding` | AC1, AC3, DC2, DC3 | 6개 이벤트 | 성공한 이미지 인코딩·projection의 실제 출력과 반환값을 기록한다. 모든 타일을 순서대로 연결해야 전체 임베딩이다. |
| `siai.llamacpp.decoder-batch` | AC1, AC3 | 6개 이벤트 | 실제 llama_decode 호출이 소비한 이미지 임베딩 배치와 반환값을 기록한다. 실패 배치는 성공으로 판정하지 않는다. |
| `siai.llamacpp.decoder-input` | AC1, AC3, DC2 | 6개 이벤트 | 한 이미지 청크의 모든 llama_decode 배치가 성공한 뒤 전체 소비 버퍼를 기록한다. projection 값과의 일치만으로 출력에 대한 인과적 영향을 단정하지 않는다. |
| `siai.llamacpp.visual-ablation` | AC3 | 2개 이벤트 | 원본 요청과 동일한 이미지·프롬프트·seed에서 visual embedding만 0으로 바꾸는 통제 실험을 명시적으로 기록한다. 일반 추론 또는 공격 성공 로그가 아니다. |
| `siai.llamacpp.generation-output` | AC3 | 3개 이벤트 | 실제 언어 디코더의 첫 토큰 전체 logits·생성 텍스트·토큰 ID를 보존한다. 정상/ablation의 정량 차이와 공격 목표 달성은 구분하여 분석한다. |

## 실제 소스와 원시 값 예시

이미지 타일이 여러 개이면 동일 요청·동일 stage의 텐서를 이벤트 순서로 모두 연결한다. preview는 전체 raw 값이 아니다.

### siai.llamacpp.processor-output

- 소스: `/home/mindol/AI-Forensics/LieMapp/Instrumented-LIE/siai/llamacpp/tools/mtmd/mtmd.cpp:1399` / `add_media`
- SHA-256: `fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0`
- 보존 소스: [source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp](source-snapshots/fdb5ce3a03a314d048eda8271b434404420102413f229c44fb1cd1df520123e0-mtmd.cpp)
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `ad6562a34fd242b2920861c00413d679`

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
      "path": "artifacts/09d9357319184799aa2d1f5405ce1925-values.npy",
      "preview": [
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0
      ],
      "raw_nbytes": 6291456,
      "sha256": "e9414311043b9b63027cb2ca12fccc7fa58d9691477336ebae8e48123211e962",
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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `1c1d75b0c78e45de967fbf623e540860`

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
      "path": "artifacts/9c4f9fc8c7144f20ba6636460c264c56-values.npy",
      "preview": [
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        -1.0
      ],
      "raw_nbytes": 3145728,
      "sha256": "77d501ba8bf1de711a6eb358948aa5a00c087e8a8013bdb70307428edf9aefb4",
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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `552d9eb98e5e4b0dbbfb229b6fa4cc5a`

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
      "max": 92.3424072265625,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -57.103424072265625,
      "path": "artifacts/40537ba252ac44e8a28fdcc0ff4c9db2-values.npy",
      "preview": [
        2.7397537231445312,
        -0.04154372215270996,
        5.695981025695801,
        1.3109580278396606,
        -10.825913429260254,
        -2.2612688541412354,
        -2.520362377166748,
        4.239512920379639
      ],
      "raw_nbytes": 147456,
      "sha256": "d17368b6286889f34d79853cf1ea9432a2fa82bc41344ee126da70d73c361053",
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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `9645b468772f4fb682e0d4c525b8e9f9`

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
      "max": 92.3424072265625,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -57.103424072265625,
      "path": "artifacts/9b1f240a98e94d908747b17793ff5a8c-values.npy",
      "preview": [
        2.7397537231445312,
        -0.04154372215270996,
        5.695981025695801,
        1.3109580278396606,
        -10.825913429260254,
        -2.2612688541412354,
        -2.520362377166748,
        4.239512920379639
      ],
      "raw_nbytes": 147456,
      "sha256": "d17368b6286889f34d79853cf1ea9432a2fa82bc41344ee126da70d73c361053",
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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `37b38f8ac13842edaead1ca08b2fa7d6`

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
      "max": 92.3424072265625,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -57.103424072265625,
      "path": "artifacts/fd508bec920047e08227e413b52ec8a1-values.npy",
      "preview": [
        2.7397537231445312,
        -0.04154372215270996,
        5.695981025695801,
        1.3109580278396606,
        -10.825913429260254,
        -2.2612688541412354,
        -2.520362377166748,
        4.239512920379639
      ],
      "raw_nbytes": 147456,
      "sha256": "d17368b6286889f34d79853cf1ea9432a2fa82bc41344ee126da70d73c361053",
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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `ca39e11345c3417eb46efb871c761190`

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
- 로그: `/home/mindol/AI-Forensics/LieMapp/.evidence/raw/siai/llamacpp/siai-llamacpp-native-smoke-20260906-001/events.pretty.json`, 이벤트 `7a87c18c65054cdb910d6cdd0ceb34b0`

```json
{
  "raw": {
    "first_step_logits_count": 49280,
    "generated_text": " The image depicts a chain saw or a similar power tool situated on a metallic table",
    "generated_token_count": 16,
    "n_past": 163,
    "n_predict": 16,
    "returncode": 0,
    "status": "success",
    "token_ids": [
      378,
      2443,
      21559,
      253,
      5891,
      3680,
      355,
      253,
      1887,
      1149,
      1763,
      13010,
      335,
      253,
      20120,
      3252
    ]
  },
  "artifacts": {
    "logits": {
      "bytes": 197248,
      "dtype": "float32",
      "format": "npy",
      "max": 16.902198791503906,
      "meaning": "Lossless raw tensor; preview is not the complete value",
      "min": -22.702360153198242,
      "path": "artifacts/e2497f73d8754c88a965003ecb7114ed-logits.npy",
      "preview": [
        -10.880873680114746,
        -10.778565406799316,
        -1.0169506072998047,
        -9.835248947143555,
        -10.280394554138184,
        -9.99522590637207,
        -12.892446517944336,
        -9.999412536621094
      ],
      "raw_nbytes": 197120,
      "sha256": "1c20d5de55d7e9dd2a2e4690d9a2154d580b991ed64097f40c6dc8a916df6ead",
      "shape": [
        49280
      ]
    }
  }
}
```
