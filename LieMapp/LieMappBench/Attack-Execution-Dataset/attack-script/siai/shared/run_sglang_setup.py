"""Auditable native SGLang CPU environment/setup commands, never model-only inference."""
from __future__ import annotations

import argparse
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tomllib

from run_preflight import ROOT, LOGGING, module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=['torch', 'dependencies', 'probe', 'smoke'])
    parser.add_argument('--suffix', required=True)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    tree = ROOT / 'Instrumented-LIE/siai/SGLang'
    python = tree / '.venv/bin/python'
    uv = ROOT / '.tooling/bin/uv'
    commands = {
        'torch': [str(uv), 'pip', 'install', '--python', str(python), '--index-url',
                  'https://download.pytorch.org/whl/cpu', 'torch==2.12.0+cpu',
                  'torchvision==0.27.0+cpu'],
        'probe': [str(python), '-c', 'import torch,sglang; print(torch.__version__); print(sglang.__file__); from sglang.srt.entrypoints.engine import Engine; print(Engine)'],
        'smoke': [str(python), str(Path(__file__).with_name('sglang_native_smoke.py'))],
    }
    deps = tomllib.loads((tree / 'python/pyproject_cpu.toml').read_text())['project']['dependencies']
    deps = [v for v in deps if not v.startswith(('torch==', 'torchaudio==', 'torchvision=='))]
    commands['dependencies'] = [str(uv), 'pip', 'install', '--python', str(python), *deps]
    command = commands[args.phase]
    run_id = f'siai-SGLang-cpu-{args.phase}-{args.suffix}'
    writer = module('liemapp_sglang_setup_writer', LOGGING / 'logger.py')
    analyzer = module('liemapp_sglang_setup_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
    log_dir = ROOT / '.evidence/raw/siai/SGLang' / run_id
    logger = writer.Logger(log_dir, {'run_id': run_id, 'attack_id': 'siai',
        'engine': {'id': 'SGLang', 'revision': '97c6978369ac1e04c91fcc01c98acc25129a6000'},
        'execution_scope': 'environment_build' if args.phase in ('torch','dependencies') else 'preflight',
        'native_inference_status': 'pending' if args.phase == 'smoke' else 'not_requested', 'device': 'cpu',
        'dependency_deviation': 'Upstream CPU manifest pins torch 2.12.0 but torchaudio 2.11.0. Matching torchaudio 2.12.0+cpu unavailable in actual resolver attempt; omit optional audio package for image-only request. No model or kernel substitution.',
        'runner_sha256': writer.sha256_file(Path(__file__))}, source_root=ROOT.parent)
    diff = subprocess.run(['git','-C',str(tree),'diff','--no-ext-diff'],capture_output=True,text=True,check=True)
    logger.emit('compatibility_source', {'git_diff':diff.stdout,
        'source_revision':'97c6978369ac1e04c91fcc01c98acc25129a6000',
        'smoke_script_sha256':writer.sha256_file(Path(__file__).with_name('sglang_native_smoke.py'))},
        source={'path':str(Path(__file__).resolve()),'function':'main',
                'line':inspect.currentframe().f_lineno,'logging_point_id':'common.sglang.compatibility-source'},
        readable={'summary':'실행 전 계측 트리의 호환성 수정 원문. 원본 LIE는 변경하지 않음.'})
    env = {**os.environ, 'PYTHONPATH': str(tree/'python'), 'SGLANG_USE_CPU_ENGINE':'1',
           'OMP_NUM_THREADS':'2', 'MKL_NUM_THREADS':'2', 'TOKENIZERS_PARALLELISM':'false',
           'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1', 'PYTHONDONTWRITEBYTECODE':'1'}
    start = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, env=env,
                                timeout=args.timeout, cwd=tree)
        raw = {'command': command, 'returncode': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr,
               'elapsed_seconds': time.monotonic()-start,
               'native_inference_executed': args.phase == 'smoke' and result.returncode == 0 and '"native_engine_output"' in result.stdout,
               'canonical_instrumentation_claimed': False}
        status = 'completed' if result.returncode == 0 else 'blocked'
    except subprocess.TimeoutExpired as error:
        raw = {'command': command, 'returncode': None, 'timeout_seconds':args.timeout,
               'stdout': (error.stdout or b'').decode(errors='replace'),
               'stderr': (error.stderr or b'').decode(errors='replace'),
               'elapsed_seconds':time.monotonic()-start, 'native_inference_executed':None,
               'canonical_instrumentation_claimed':False}
        status = 'blocked'
    logger.emit('environment_command', raw, source={'path':str(Path(__file__).resolve()),
        'function':'main', 'line':inspect.currentframe().f_lineno,
        'logging_point_id':f'common.sglang.environment.{args.phase}'},
        readable={'summary':'실제 CPU 설정/Engine 경로 점검. 요청별 계측 데이터가 아니므로 AC/DC 증거로 사용하지 않음.'})
    logger.close(status=status, reason=f'{args.phase} exit={raw["returncode"]}; native evidence requires separately instrumented requests')
    report_dir = ROOT/'.evidence/analyses/siai/SGLang'/run_id
    summary = analyzer.analyze(log_dir/'events.jsonl', LOGGING/'siai/conditions.json', report_dir)
    print(json.dumps({'status':status, 'log_dir':str(log_dir), 'summary':summary['summary']},ensure_ascii=False))
    print(raw['stdout'][-10000:])
    print(raw['stderr'][-16000:], file=sys.stderr)


if __name__ == '__main__':
    main()
