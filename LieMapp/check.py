"""등록된 공격·추론 엔진을 확인하는 읽기 전용 진입점."""
import argparse
import json
from pathlib import Path
import sys

from internal.workflow import list_experiments, load_config


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='등록된 공격과 추론 엔진을 확인합니다. 실험 실행이나 결과 변경은 하지 않습니다.',
        allow_abbrev=False,
    )
    parser.add_argument(
        '--config', type=Path,
        default=Path(__file__).resolve().parent / 'internal' / 'experiments.json',
        help='등록 목록을 읽을 설정 파일',
    )
    parser.add_argument(
        '--list', action='store_true',
        help='공격·엔진 ID와 실행 명령 등록 여부(can_execute)를 표시',
    )
    args = parser.parse_args(argv)
    if not args.list:
        parser.print_help()
        return 0
    try:
        print(json.dumps(list_experiments(load_config(args.config)), ensure_ascii=False, indent=2))
    except (KeyError, ValueError, OSError) as error:
        print('목록 확인 실패: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
