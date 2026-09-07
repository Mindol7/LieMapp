"""기존 증거를 공통 분석·정형 출력으로 발행한다. 공격 재실행은 허용하지 않는다."""
from internal.workflow import main


if __name__ == '__main__':
    raise SystemExit(main(actor='investigator'))
