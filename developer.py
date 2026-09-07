"""공통 분석·정형 출력 진입점. --execute를 명시한 경우에만 새 실험을 실행한다."""
from internal.workflow import main


if __name__ == '__main__':
    raise SystemExit(main())
