"""Replay a failed Phi3V LLVM compile in a NEW isolated source/output directory.

No model download, source patch in place, original modification, or inference.
Requires the explicitly recorded local toolchain/cache paths. A failure is kept
as a sealed common logger run, not interpreted as an observed attack condition.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

from record_command import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--variant', choices=['stock', 'int64-index', 'int64-index-floordiv'], default='stock')
    args = parser.parse_args()
    if not args.run_id.replace('-', '').replace('_', '').isalnum():
        parser.error('run-id must contain letters, numbers, hyphens or underscores only')
    private = ROOT / 'Instrumented-LIE/siai/mlc-llm'
    engine = private / 'engine'
    revision = '9fa644f54b04983adea4d0168f49fc6af4a893ba'
    actual = subprocess.check_output(['git', '-C', str(engine), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != revision:
        raise ValueError('Unexpected private source revision')
    destination = private / 'compile-replay' / args.run_id
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(engine / 'python', destination / 'python', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    originals = {}
    for relative in ('python/mlc_llm/compiler_pass/pipeline.py', 'python/mlc_llm/model/vision/image_processing.py'):
        originals[relative] = subprocess.check_output(['git', '-C', str(engine), 'show', f'{revision}:{relative}'])
        (destination / relative).write_bytes(originals[relative])
    if args.variant != 'stock':
        relative = 'python/mlc_llm/compiler_pass/pipeline.py'
        current = (engine / relative).read_bytes()
        if hashlib.sha256(current).hexdigest() != '7f63d2b332a127d1277e92f206884edfa552c1ebb31c7ab62fc68d50bb4b14a2':
            raise ValueError('Recorded experimental int64-index source hash changed')
        (destination / relative).write_bytes(current)
    if args.variant == 'int64-index-floordiv':
        relative = 'python/mlc_llm/model/vision/image_processing.py'
        current = (engine / relative).read_bytes()
        if hashlib.sha256(current).hexdigest() != '811fe59e1d4e570af44f83e8c602e21112fd2974673c092811d624c408d8da12':
            raise ValueError('Recorded experimental FloorDiv source hash changed')
        (destination / relative).write_bytes(current)
    model = private / 'models/Phi-3.5-vision-instruct-q4f32_1-MLC'
    recorder = Path(__file__).with_name('record_command.py')
    env = {
        'PYTHONPATH': ':'.join(['/tmp/mlc-exact-python', str(engine / '3rdparty/tvm/python'), str(destination / 'python')]),
        'TVM_LIBRARY_PATH': '/tmp/mlc-tvm-837c-build/lib',
        'MLC_LIBRARY_PATH': str(engine / 'build'),
        'PYTHONDONTWRITEBYTECODE': '1', 'OMP_NUM_THREADS': '4', 'OPENBLAS_NUM_THREADS': '1'}
    command = [sys.executable, str(recorder), '--run-id', args.run_id, '--phase', 'replay_compile_' + args.variant]
    for key, value in env.items():
        command.extend(['--env', f'{key}={value}'])
    command.extend(['--', str(private / '.venv/bin/python'), '-m', 'mlc_llm', 'compile', str(model),
                    '--device', '{"kind":"llvm","mcpu":"haswell"}', '--host', 'x86_64-linux-gnu',
                    '--overrides', 'context_window_size=4096;prefill_chunk_size=2048;max_batch_size=1',
                    '--opt', 'O0', '-o', str(destination / 'phi35-cpu.so')])
    print('Replay uses the recorded compiler cache plus fresh MLC runtime; it does not run inference.', flush=True)
    raise SystemExit(subprocess.run(command, check=False).returncode)


if __name__ == '__main__':
    main()
