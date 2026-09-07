"""Record reproducible CPU preflight evidence, not simulated engine inference.

No install, original-source mutation, model download or GPU request is performed.
Every output uses the common Logger and unchanged common Analyzer/rules.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())
LOGGING = ROOT / 'LieMappBench/Logging-Dataset'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    item = importlib.util.module_from_spec(spec)
    sys.modules[name] = item
    spec.loader.exec_module(item)
    return item


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=45,
                                cwd=ROOT, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        return {'command': args, 'returncode': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'command': args, 'returncode': None, 'error': str(error)}


def run(profile, suffix, logger_module, analyzer):
    repo = ROOT / 'LIE' / profile['repository']
    git = command(['git', '-C', str(repo), 'rev-parse', 'HEAD'])
    run_id = f"siai-{profile['id']}-cpu-preflight-{suffix}"
    log_dir = ROOT / '.evidence/raw/siai' / profile['id'] / run_id
    metadata = {'run_id': run_id, 'attack_id': 'siai', 'execution_scope': 'preflight',
                'engine': {'id': profile['id'], 'revision': git.get('stdout', '').strip(),
                           'source_root': str(repo)},
                'runtime': {'device': 'cpu', 'platform': platform.platform()},
                'profile_sha256': logger_module.sha256_file(LOGGING / 'siai/runtime-profiles.json'),
                'logger_sha256': logger_module.sha256_file(LOGGING / 'logger.py'),
                'runner_sha256': logger_module.sha256_file(Path(__file__)),
                'native_inference_executed': False}
    logger = logger_module.Logger(log_dir, metadata, source_root=ROOT.parent)
    def emit(stage, raw, summary):
        logger.emit(stage, raw, readable={'summary': summary},
                    source={'path': str(Path(__file__).resolve()), 'function': 'run.emit',
                            'line': inspect.currentframe().f_lineno, 'logging_point_id': f'common.preflight.{stage}'})
    try:
        cpu_text = Path('/proc/cpuinfo').read_text()
        flags = next((line.split(':', 1)[1].strip().split() for line in cpu_text.splitlines()
                      if line.startswith('flags')), [])
        cpu_name = next((line.split(':', 1)[1].strip() for line in cpu_text.splitlines()
                         if line.startswith('model name')), platform.processor())
        emit('hardware_preflight', {'cpu_model': cpu_name, 'cpu_flags': flags,
             'nvidia_smi_path': shutil.which('nvidia-smi'), 'nvcc_path': shutil.which('nvcc'),
             'nvidia_device_nodes': sorted(str(p) for p in Path('/dev').glob('nvidia*')),
             'required_cpu_features': profile['required_cpu_features'],
             'missing_required_cpu_features': [f for f in profile['required_cpu_features'] if f not in flags]},
             '실제 호스트 CPU 명령어·NVIDIA 도구 및 장치 존재 여부; 추론 이벤트 아님')
        emit('source_preflight', {'revision_probe': git,
             'worktree_probe': command(['git', '-C', str(repo), 'status', '--porcelain']),
             'submodule_probe': command(['git', '-C', str(repo), 'submodule', 'status'])},
             '원본 커밋·수정 여부·의존 서브모듈 상태를 읽기 전용 확인')
        probe = (
            'import importlib.util,importlib.metadata,json,sys; '\
            'names=json.loads(sys.argv[1]); '\
            'print(json.dumps({n:{"available":importlib.util.find_spec(n) is not None,'\
            '"origin":str(getattr(importlib.util.find_spec(n),"origin",None))} for n in names},ensure_ascii=False))'
        )
        emit('package_preflight', command([profile['python'], '-c', probe, json.dumps(profile['packages'])]),
             '기존 격리 환경에서 패키지 위치만 조사; 설치본 버전과 현재 소스의 일치를 가정하지 않음')
        emit('torch_preflight', command([profile['python'], '-c',
             'import torch,json;print(json.dumps({"torch":torch.__version__,"cuda_build":torch.version.cuda,"cuda_available":torch.cuda.is_available()}))']),
             '현재 사용 가능한 PyTorch 버전과 GPU 가용성의 실제 조회 결과')
        for relative in profile['documents']:
            document = repo / relative
            emit('source_requirement', {'path': str(document), 'sha256': logger_module.sha256_file(document),
                 'text': document.read_text(encoding='utf-8')},
                 '해당 커밋의 공식 설치·지원 문서 원문; 정적 근거이며 runtime 증거가 아님')
        emit('execution_unavailable', {'native_inference_executed': False, 'profile': profile,
             'reason': profile['reason'], 'next_step': profile['next_step']},
             '현재 실행 준비 미완료/하드웨어 제약을 명시. AC/DC에 F나 안전 판정을 부여하지 않음')
        logger.close(status='blocked', reason=profile['reason'])
    except BaseException as error:
        logger.close(status='failed', reason=str(error))
        raise
    report_dir = ROOT / '.evidence/analyses/siai' / profile['id'] / run_id
    result = analyzer.analyze(log_dir / 'events.jsonl', LOGGING / 'siai/conditions.json', report_dir)
    print(json.dumps({'engine': profile['id'], 'log': str(log_dir), 'report': str(report_dir),
                      'summary': result['summary']}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', action='append', help='Folder engine ID; omit to preflight all four pending engines')
    parser.add_argument('--suffix', default=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6])
    args = parser.parse_args()
    profiles = json.loads((LOGGING / 'siai/runtime-profiles.json').read_text())['engines']
    if args.engine and set(args.engine) - {p['id'] for p in profiles}:
        parser.error('Unknown engine profile')
    logger_module = module('liemapp_preflight_logger', LOGGING / 'logger.py')
    analyzer = module('liemapp_preflight_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
    for profile in profiles:
        if not args.engine or profile['id'] in args.engine:
            run(profile, args.suffix, logger_module, analyzer)


if __name__ == '__main__':
    main()
