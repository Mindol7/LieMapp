# SGLang — 실험 동결본과 배포용 seed guard·출력 경로 구분

2026-09-07 출력 안내: [developer.py](../../../../developer.py) / [investigator.py](../../../../investigator.py)가 공통 결과를 발행합니다.
현재 공개 결과는 `LieMapp/` 기준 `report/siai/<engine>/`의 **MD 1개**와
`LieMappAnalyzer/LogFile/siai/<engine>/`의 **조건 JSON 6개**입니다. 원시 로그는
`.evidence/raw/siai/<engine>/<run>/`, 과거 run별 보고서는
`.archive/20260907-report-layout/report/siai/`에 구분해 보존합니다.

이 변경은 canonical 86 / heldout 12 / fresh repeat 1의 **실제 실행 및 검증이 모두 끝난 뒤** 적용했다. 해당 원시 이벤트·봉인·run metadata·native engine source·model overlay·가중치·공통 logger/analyzer/rules는 변경하지 않았다.

## 정확히 변경한 내용

실험 당시 부모 runner는 `--seed` 인자를 받았으나 자식 실행 명령에는 전달하지 않았다. 이 연구에서 실행한 모든 run은 기본값 20260906을 사용하여 실제 child Engine 역시 20260906이었다. 즉 기존 실험의 seed가 잘못된 것이 아니라, 지원하지 않는 custom seed 값을 CLI가 받아들이는 편의 인터페이스의 제한이었다.

첫 배포 변경은 다른 seed를 조용히 수용하지 않도록 다음 한 줄 guard를 추가한 것이다.
이후 2026-09-07에는 원시 증거와 공개 조건 JSON을 분리하기 위해 기본 출력 경로도 변경했다.
두 변경 모두 원실험 이후의 배포 변경이며 새로운 seed 실험이나 사후 최적화가 아니다.

```diff
-    parser.add_argument('--seed',type=int,default=20260906)
+    parser.add_argument('--seed',type=int,default=20260906,choices=[20260906])
-    directory=ROOT/'LieMappAnalyzer/LogFile/siai/SGLang'/args.run_id
+    directory=ROOT/'.evidence/raw/siai/SGLang'/args.run_id
```

|구분|SHA-256|보관 위치|
|---|---|---|
|실제 canonical/heldout/repeat 당시 runner|`3564b8a17cb584778f6e094af6def5bd18fbbb5d771e553e432528197632ffd9`|[byte-exact source snapshot](source-snapshots/3564b8a17cb584778f6e094af6def5bd18fbbb5d771e553e432528197632ffd9-run.py)|
|첫 배포 변경, 기본 seed 고정 guard 추가(이력)|`527e81aef6acec2674cdb6d00fe4d0dab064e79afdc09b42a1c6494cc0d26d6f`|현재 파일 이전의 변경 단계이며 원실험 SHA가 아님|
|2026-09-07 배포본, seed guard와 원시 출력 경로 변경|`6c22ab9286c3fcf751b3bb6bcb7748c8b515cbda89a783aa6cfd17886a3c9a83`|[현재 run.py](../../../Attack-Execution-Dataset/attack-script/siai/SGLang/run.py)|

기존 event의 `source`가 runner 파일을 지칭할 때는 **그 event가 기록한 원래 해시와 위 snapshot**을 대조해야 한다. 현재 배포 파일 해시를 과거 실행의 해시로 바꾸면 안 된다. 두 곳 모두 줄 수를 유지한 치환이므로 다른 소스 지점의 line number는 이동하지 않았다. 동결 원시 로그 내부의 과거 경로 문자열도 고치지 않았다.

현재 seed 제한은 부모·자식 CLI 모두 적용되며, 잘못된 값은 dataset 로드·Engine 초기화·로그 생성 전에 argparse가 exit 2로 거부한다. `context.seed`는 별도로 manifest에 기록된 이미지/증강 생성 seed이며, 실제 추론 Engine seed와 동일하다고 해석하지 않는다.

## 검증

[test_runner_cli.py](../../../Attack-Execution-Dataset/attack-script/siai/SGLang/test_runner_cli.py)의 5개 테스트가 통과했다.

- 부모 custom seed 거부, dataset 접근 전 종료.
- 자식 custom seed 거부, native engine import 전 종료.
- 기본값 생략 시 CLI 허용.
- 명시적 `--seed 20260906` 허용.
- 원래 source snapshot 해시 일치 및 현재 파일과의 차이가 위 두 곳뿐임을 byte 단위 확인.

```bash
OPENBLAS_NUM_THREADS=1 /tmp/siai-assets-venv/bin/python \
  LieMapp/LieMappBench/Attack-Execution-Dataset/attack-script/siai/SGLang/test_runner_cli.py
```

이 테스트는 합성 CLI 검사이며 새 SIAI 실험 evidence가 아니다. 기존 실제 반복 대조 결과는 별도 공통 verifier 로그 `siai-SGLang-repeat-validation-20260906-001`에서 확인한다.
