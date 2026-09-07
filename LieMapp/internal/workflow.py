"""Shared, configuration-driven developer/investigator publication workflow."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SAFE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


def resolve(value, root=ROOT):
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def identifier(value):
    if not SAFE_ID.fullmatch(value):
        raise ValueError('Unsafe attack/engine identifier: ' + value)
    return value


def load_config(path):
    config = json.loads(Path(path).read_text(encoding='utf-8'))
    if config.get('schema_version') != '1.0.0' or not isinstance(config.get('attacks'), dict):
        raise ValueError('Invalid experiment configuration')
    for attack_id, attack in config['attacks'].items():
        identifier(attack_id)
        if not isinstance(attack.get('engines'), dict) or not attack['engines']:
            raise ValueError('Each attack requires engine configuration')
        for engine in attack['engines']:
            identifier(engine)
    return config


def list_experiments(config):
    """Return registered attacks/engines; can_execute means a command is registered."""
    return {
        attack_id: [
            {'id': engine_id, 'label': row['label'], 'can_execute': 'execute' in row}
            for engine_id, row in attack['engines'].items()
        ]
        for attack_id, attack in config['attacks'].items()
    }


def save_current(path, record):
    """Only this small selection pointer changes; sealed raw evidence does not."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.selection-', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def selected_source(engine, state_path, override=None):
    if override is not None:
        return resolve(override)
    if state_path.exists():
        return resolve(json.loads(state_path.read_text(encoding='utf-8'))['source_log'])
    return resolve(engine['source_log'])


def verify_selection(record, *, attack_id, engine_id, source_log, events_sha256):
    """A saved selection pins identity and bytes, not just a mutable pathname."""
    if (record.get('attack_id') != attack_id or record.get('engine_id') != engine_id
            or resolve(record['source_log']) != source_log.resolve()
            or record.get('source_log_sha256') != events_sha256):
        raise ValueError('저장된 선택 정보와 현재 증거의 식별자·해시가 다릅니다. 확인한 새 증거는 --log로 명시하세요.')


def build_command(execution, *, run_id, python=None, root=ROOT):
    command = execution.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(s, str) and s for s in command):
        raise ValueError('Execution command must be a nonempty argument list, never shell text')
    variables = {'root': str(root), 'python': python or sys.executable, 'run_id': identifier(run_id)}
    return [part.format_map(variables) for part in command]


def main(argv=None, *, actor='developer'):
    parser = argparse.ArgumentParser(description='공통 분석으로 엔진별 Report 1개와 조건별 JSON을 생성합니다.')
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('experiments.json'))
    parser.add_argument('--attack', default='siai')
    parser.add_argument('--engine', default='all', help='설정 파일의 engine ID 또는 all')
    parser.add_argument('--log', type=Path, help='새 원시 증거를 명시(한 엔진만 선택해야 함)')
    parser.add_argument('--execute', action='store_true', help='명시적으로 새 엔진 실험을 실행한 뒤 발행')
    parser.add_argument('--replace', action='store_true', help='기존 공개 결과를 복구 가능한 백업 후 교체')
    parser.add_argument('--list', action='store_true', help='설정된 실험을 읽기 전용으로 표시')
    args = parser.parse_args(argv)
    if actor == 'investigator' and args.execute:
        parser.error('수사관 진입점은 기존 증거 분석 전용입니다. 새 실험은 developer.py --execute를 사용하세요.')
    if args.log and (args.engine == 'all' or args.execute):
        parser.error('--log는 단일 --engine과 사용하며 --execute와 함께 사용할 수 없습니다.')
    try:
        config = load_config(args.config)
        if args.list:
            print(json.dumps(list_experiments(config), ensure_ascii=False, indent=2))
            return 0
        identifier(args.attack)
        attack = config['attacks'][args.attack]
        selected = list(attack['engines']) if args.engine == 'all' else [identifier(args.engine)]
        if any(e not in attack['engines'] for e in selected):
            raise ValueError('Unknown engine ID; inspect --list')
        if args.execute:
            unavailable = [e for e in selected if 'execute' not in attack['engines'][e]]
            if unavailable:
                raise ValueError('실행 명령이 준비되지 않은 엔진: ' + ', '.join(unavailable))
        if not args.replace:
            for engine_id in selected:
                for directory in (ROOT / 'report' / args.attack / engine_id,
                                  ROOT / 'LieMappAnalyzer/LogFile' / args.attack / engine_id):
                    if directory.exists() and any(directory.iterdir()):
                        raise FileExistsError('기존 공개 결과가 있습니다. 백업 후 교체하려면 --replace: ' + str(directory))
        # Pin reductions before importing NumPy through the common Analyzer.
        os.environ['OPENBLAS_NUM_THREADS'] = '1'
        from internal.publication import publish
        from LieMappAnalyzer.analyzer import EvidencePackage
        outcomes = []
        failed_execution = False
        for engine_id in selected:
            engine = attack['engines'][engine_id]
            current = ROOT / '.evidence/current' / args.attack / (engine_id + '.json')
            selection = (json.loads(current.read_text(encoding='utf-8'))
                         if current.exists() and not args.log and not args.execute else None)
            log_path = (resolve(selection['source_log']) if selection is not None
                        else resolve(args.log if args.log else engine['source_log']))
            publication_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
            if args.execute:
                run_id = f'{args.attack}-{engine_id}-native-{publication_id}'
                command = build_command(engine['execute'], run_id=run_id)
                print(json.dumps({'engine': engine_id, 'command': command}, ensure_ascii=False), flush=True)
                completed = subprocess.run(command, cwd=resolve(engine['execute'].get('cwd', '.')),
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, check=False)
                log_path = ROOT / '.evidence/raw' / args.attack / engine_id / run_id / 'events.jsonl'
                failed_execution |= completed.returncode != 0
            package = EvidencePackage(log_path)
            if package.metadata['attack_id'] != args.attack or package.metadata['engine']['id'] != engine_id:
                raise ValueError('선택한 공격·엔진과 원시 증거의 식별자가 다릅니다.')
            if selection is not None:
                verify_selection(selection, attack_id=args.attack, engine_id=engine_id,
                                 source_log=log_path, events_sha256=package.seal['events_sha256'])
            # An old model's behavior review must not silently attach to a new run/model.
            supplements = [resolve(p) for p in engine.get('supplements', [])]
            if log_path.resolve() != resolve(engine['source_log']):
                supplements = []
            result = publish(log_path, resolve(attack['rules']),
                log_output_dir=ROOT / 'LieMappAnalyzer/LogFile' / args.attack / engine_id,
                report_output_dir=ROOT / 'report' / args.attack / engine_id,
                analysis_dir=ROOT / '.evidence/analyses' / args.attack / engine_id / publication_id,
                mapping_path=resolve(engine['mapping']) if engine.get('mapping') else None,
                presentation_path=resolve(attack['presentation']) if attack.get('presentation') else None,
                supplement_paths=supplements, attack_label=attack['label'], engine_label=engine['label'],
                replace=args.replace, backup_dir=(ROOT / '.archive/publications' / publication_id / engine_id
                                                if args.replace else None))
            save_current(current, {'attack_id': args.attack, 'engine_id': engine_id,
                'source_log': str(log_path.resolve()), 'source_log_sha256': package.seal['events_sha256'],
                'publication_id': publication_id, 'actor': actor})
            outcomes.append({'engine': engine_id, 'source_log': str(log_path), 'publication': result})
        print(json.dumps({'outputs': outcomes, 'some_native_execution_failed': failed_execution},
                         ensure_ascii=False, indent=2, default=str))
        return 1 if failed_execution else 0
    except (KeyError, ValueError, OSError) as error:
        print('작업 중단: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
