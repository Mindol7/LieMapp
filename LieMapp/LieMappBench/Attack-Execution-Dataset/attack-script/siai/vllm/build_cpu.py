"""Record a bounded, isolated exact-source vLLM CPU build attempt."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'LIE').is_dir() and (p / 'LieMappBench').is_dir())
ENGINE = ROOT / 'Instrumented-LIE/siai/vllm'
UV = ROOT / '.tooling/bin/uv'


def source():
    frame = inspect.currentframe().f_back
    return {'path': str(Path(__file__).resolve()), 'function': frame.f_code.co_name,
            'line': frame.f_lineno, 'logging_point_id': 'siai.vllm.environment-build'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--phase', choices=('dependencies', 'native-dependencies', 'build'), required=True)
    parser.add_argument('--timeout', type=int, default=1200)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('common_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    environment = os.environ.copy()
    environment.update(VIRTUAL_ENV=str(ENGINE / '.venv'),
                       VLLM_TARGET_DEVICE='cpu', MAX_JOBS='4',
                       VLLM_REQUIRE_RUST_FRONTEND='0')
    environment['PATH'] = str(ENGINE / '.venv/bin') + ':' + str(UV.parent) + ':' + environment['PATH']
    native = ENGINE / '.native-deps/usr'
    if native.exists():
        environment['CPATH'] = str(native / 'include')
        environment['LIBRARY_PATH'] = str(native / 'lib/x86_64-linux-gnu')
        environment['LD_LIBRARY_PATH'] = str(native / 'lib/x86_64-linux-gnu')
        environment['CMAKE_PREFIX_PATH'] = str(native)
    command_cwd = ENGINE
    commands = (
        [[str(UV), 'pip', 'install', '-r', 'requirements/lint.txt'],
         [str(ENGINE / '.venv/bin/pre-commit'), 'install'],
         [str(UV), 'pip', 'install', '-r', 'requirements/build/cpu.txt', '-r', 'requirements/cpu.txt',
          '--torch-backend', 'cpu', '--index-strategy', 'unsafe-best-match']]
        if args.phase == 'dependencies' else
        [[str(UV), 'pip', 'install', '-e', '.', '--no-build-isolation', '--no-deps', '--verbose']]
    )
    if args.phase == 'native-dependencies':
        command_cwd = ENGINE / '.native-deps/packages'
        command_cwd.mkdir(parents=True, exist_ok=True)
        packages = [
            ('libnuma-dev', '2.0.18-1ubuntu0.24.04.1'),
            ('libnuma1', '2.0.18-1ubuntu0.24.04.1'),
            ('libtcmalloc-minimal4t64', '2.15-3build1'),
        ]
        commands = [['apt-get', 'download', *[f'{name}={version}' for name, version in packages]]]
        commands += [['dpkg-deb', '--extract', str(command_cwd / f'{name}_{version}_amd64.deb'),
                      str(ENGINE / '.native-deps')] for name, version in packages]
    metadata = {'run_id': args.run_id, 'attack_id': 'siai',
                'engine': {'id': 'vllm', 'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ENGINE, text=True).strip()},
                'execution_scope': 'environment_build', 'phase': args.phase,
                'environment': {key: environment[key] for key in ('VIRTUAL_ENV', 'VLLM_TARGET_DEVICE', 'MAX_JOBS', 'VLLM_REQUIRE_RUST_FRONTEND')},
                'source_root': str(ENGINE), 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'limitation': 'A successful build is not a successful inference or an AC/DC result.'}
    directory = ROOT / '.evidence/raw/siai/vllm' / args.run_id
    with common.Logger(directory, metadata, source_root=ROOT.parent) as logger:
        for index, command in enumerate(commands):
            start = time.perf_counter()
            logger.emit('build_command_started', {'command': command, 'status': 'started'},
                        context={'request_id': f'build-{index}'}, source=source(),
                        readable={'summary': 'Execute the documented CPU build setup in an isolated environment'})
            print(json.dumps({'command': command}), flush=True)
            try:
                result = subprocess.run(command, cwd=command_cwd, env=environment,
                                        capture_output=True, text=True, timeout=args.timeout)
                raw = {'command': command, 'returncode': result.returncode,
                       'stdout': result.stdout, 'stderr': result.stderr,
                       'seconds': time.perf_counter() - start,
                       'status': 'success' if result.returncode == 0 else 'error'}
            except subprocess.TimeoutExpired as error:
                raw = {'command': command, 'status': 'error', 'error': 'timeout',
                       'stdout': (error.stdout or b'').decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout,
                       'stderr': (error.stderr or b'').decode(errors='replace') if isinstance(error.stderr, bytes) else error.stderr,
                       'seconds': time.perf_counter() - start}
                logger.emit('build_command_result', raw, context={'request_id': f'build-{index}'}, source=source())
                raise
            logger.emit('build_command_result', raw, context={'request_id': f'build-{index}'}, source=source(),
                        readable={'summary': 'Unmodified stdout/stderr and exit status from the real dependency/build command'})
            print(json.dumps({'returncode': result.returncode, 'seconds': raw['seconds'],
                              'stderr_tail': result.stderr[-1200:]}), flush=True)
            if result.returncode != 0:
                raise RuntimeError(f'Build step failed: {command}; see sealed evidence')


if __name__ == '__main__':
    main()
