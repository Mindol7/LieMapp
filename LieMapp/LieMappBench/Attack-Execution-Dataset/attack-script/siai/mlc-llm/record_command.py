"""Record real MLC setup/build/probe commands with the common evidence writer."""
from __future__ import annotations
import argparse
import importlib.util
import inspect
import os
from pathlib import Path
import subprocess
import time

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())


def common():
    spec = importlib.util.spec_from_file_location('mlc_setup_common_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source(point):
    frame = inspect.currentframe().f_back
    return {'path': str(Path(frame.f_code.co_filename).resolve()), 'function': frame.f_code.co_name,
            'line': frame.f_lineno, 'logging_point_id': point}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--phase', required=True)
    parser.add_argument('--scope', choices=['environment_build', 'preflight', 'structural_probe'], default='environment_build')
    parser.add_argument('--cwd', type=Path, default=ROOT.parent)
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--env', action='append', default=[], help='Explicit non-secret KEY=VALUE overrides only')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('A real command is required')
    overrides = dict(value.split('=', 1) for value in args.env)
    forbidden = {'HOME', 'home', 'CODEX_HOME'}
    if forbidden.intersection(overrides):
        parser.error('Do not repurpose system home variables')
    writer = common()
    metadata = {'run_id': args.run_id, 'attack_id': 'siai', 'engine': {'id': 'mlc-llm',
                'revision': '9fa644f54b04983adea4d0168f49fc6af4a893ba'}, 'execution_scope': args.scope,
                'phase': args.phase, 'model': {'name': 'Phi-3.5-vision-instruct-q4f32_1-MLC',
                'revision': '2d7104ab34b358b4223aabca1d08e451c6b12728'},
                'logger_sha256': writer.sha256_file(ROOT / 'LieMappBench/Logging-Dataset/logger.py'),
                'native_inference_claim': False}
    directory = ROOT / '.evidence/raw/siai/mlc-llm' / args.run_id
    with writer.Logger(directory, metadata, source_root=ROOT.parent) as log:
        log.emit('setup_started', {'command': command, 'cwd': str(args.cwd.resolve()), 'env_overrides': overrides},
                 source=source('siai.mlc.setup-command-started'))
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=args.cwd, env={**os.environ, **overrides},
                                    capture_output=True, timeout=args.timeout)
            raw = {'returncode': result.returncode, 'elapsed_seconds': time.monotonic()-start,
                   'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}
        except subprocess.TimeoutExpired as error:
            raw = {'returncode': None, 'elapsed_seconds': time.monotonic()-start, 'timed_out': True,
                   'stdout': (error.stdout or b'').decode(errors='replace'),
                   'stderr': (error.stderr or b'').decode(errors='replace')}
        log.emit('setup_result', raw, source=source('siai.mlc.setup-command-result'))
        print(raw['stdout'][-16000:], flush=True)
        print(raw['stderr'][-10000:], flush=True)
        log.close('completed' if raw['returncode'] == 0 else 'blocked',
                  reason=None if raw['returncode'] == 0 else 'Actual setup/build/probe command failed; no native attack verdict')
    print(directory, flush=True)
    raise SystemExit(0 if raw['returncode'] == 0 else 1)


if __name__ == '__main__':
    main()
