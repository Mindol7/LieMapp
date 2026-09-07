"""Retry TensorRT-LLM installation/build/runtime prerequisites without fake inference.

The original LIE stays untouched. Only an isolated local clone and a small venv
are prepared; CUDA wheels, model weights, Docker images and kernel packages are
not automatically downloaded. All diagnostic output is recorded by logger.py.
The result is readiness evidence, never a native SIAI execution or an AC/DC F.
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
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import numpy as np

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())
ORIGINAL = ROOT / 'LIE/TensorRT-LLM'
PRIVATE = ROOT / 'Instrumented-LIE/siai/tensorRT-llm'
MODEL_ID = 'mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC'
MODEL_REVISION = '2d7104ab34b358b4223aabca1d08e451c6b12728'
MODEL_DIR = ROOT / 'Instrumented-LIE/siai/mlc-llm/models/Phi-3.5-vision-instruct-q4f32_1-MLC'


def load_logger():
    path = ROOT / 'LieMappBench/Logging-Dataset/logger.py'
    spec = importlib.util.spec_from_file_location('trt_retry_common_logger', path)
    item = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = item
    spec.loader.exec_module(item)
    return item


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Recorder:
    def __init__(self, logger):
        self.logger = logger
        self.results = {}

    def emit(self, stage, raw, *, source_path=None, function='main', line=None, tensors=None):
        source = {'path': str(source_path or Path(__file__).resolve()), 'function': function,
                  'line': line or inspect.currentframe().f_back.f_lineno,
                  'logging_point_id': 'siai.tensorRT-llm.readiness.' + stage}
        return self.logger.emit(stage, raw=raw, source=source, tensors=tensors or {},
                                readable={'summary': raw.get('meaning', stage)})

    def command(self, name, argv, *, cwd=ROOT.parent, env=None, timeout=120):
        start = time.monotonic()
        command_env = os.environ.copy()
        command_env.update({'PYTHONDONTWRITEBYTECODE': '1', 'OPENBLAS_NUM_THREADS': '1',
                            'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1'})
        for key in ('TRTLLM_USE_PRECOMPILED', 'TRTLLM_PRECOMPILED_LOCATION'):
            command_env.pop(key, None)
        command_env.update(env or {})
        try:
            process = subprocess.run([str(v) for v in argv], cwd=cwd, env=command_env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
            code, stdout, stderr, error = process.returncode, process.stdout, process.stderr, None
        except FileNotFoundError as exc:
            code, stdout, stderr, error = 127, b'', str(exc).encode(), 'executable_not_found'
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr, error = None, exc.stdout or b'', exc.stderr or b'', 'timeout'
        raw = {'name': name, 'argv': [str(v) for v in argv], 'cwd': str(cwd),
               'returncode': code, 'process_error': error, 'wall_seconds': time.monotonic() - start,
               'stdout': stdout.decode('utf-8', errors='replace'), 'stderr': stderr.decode('utf-8', errors='replace'),
               'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
               'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
               'environment_overrides': env or {}, 'meaning': '실제 명령과 원본 출력; 추론 결과가 아닌 실행 전 진단'}
        tensors = {key: np.frombuffer(value, dtype=np.uint8) for key, value in
                   (('stdout_utf8_bytes', stdout), ('stderr_utf8_bytes', stderr)) if value}
        event = self.emit('readiness_command', raw, tensors=tensors)
        self.results[name] = {'returncode': code, 'process_error': error, 'event_id': event['event_id'],
                              'stdout': raw['stdout'], 'stderr': raw['stderr']}
        print(json.dumps({'command': name, 'returncode': code, 'event_id': event['event_id']}), flush=True)
        return self.results[name]

    def reference(self, name, url):
        start = datetime.now(timezone.utc).isoformat()
        try:
            with urlopen(Request(url, headers={'User-Agent': 'LieMapp-readiness-audit/1.0'}), timeout=30) as response:
                body = response.read(4 * 1024 * 1024 + 1)
                if len(body) > 4 * 1024 * 1024:
                    raise ValueError('Reference exceeds small-document download bound')
                raw = {'name': name, 'url': url, 'resolved_url': response.url, 'http_status': response.status,
                       'accessed_at_utc': start, 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'bytes': len(body), 'headers': {k: response.headers.get(k) for k in
                       ('Content-Type', 'ETag', 'Last-Modified', 'X-Repo-Commit')},
                       'meaning': '공식 문서/배포자 메타데이터의 조회 시점 원문 바이트'}
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            body = b''
            raw = {'name': name, 'url': url, 'accessed_at_utc': start, 'error': str(error),
                   'meaning': '외부 1차 자료 조회 실패; 내용을 확인한 것으로 취급하지 않음'}
        event = self.emit('external_reference', raw, tensors={'response_bytes': np.frombuffer(body, dtype=np.uint8)} if body else {})
        return body, event['event_id']

    def source(self, relative, start, end, meaning):
        path = PRIVATE / relative
        lines = path.read_text(encoding='utf-8').splitlines()
        return self.emit('source_readiness', {'relative_path': relative, 'revision': self.revision,
                         'line_start': start, 'line_end': end,
                         'excerpt': '\n'.join(f'{n}: {lines[n-1]}' for n in range(start, min(end, len(lines)) + 1)),
                         'meaning': meaning, 'execution_observed': False},
                         source_path=path, function='static_source_review', line=start)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--probe-python', type=Path, default=Path('/tmp/siai-assets-venv/bin/python'))
    args = parser.parse_args(argv)
    common = load_logger()
    revision = subprocess.check_output(['git', '-C', str(ORIGINAL), 'rev-parse', 'HEAD'], text=True).strip()
    initial_status = subprocess.check_output(['git', '-C', str(ORIGINAL), 'status', '--porcelain'], text=True)
    metadata = {'run_id': args.run_id, 'attack_id': 'siai', 'execution_scope': 'readiness_retry',
                'engine': {'id': 'tensorRT-llm', 'name': 'TensorRT-LLM', 'revision': revision,
                           'original_source_root': str(ORIGINAL), 'private_source_root': str(PRIVATE)},
                'requested_model': {'id': MODEL_ID, 'revision': MODEL_REVISION, 'format': 'MLC q4f32_1'},
                'runtime': {'platform': platform.platform(), 'python': sys.version, 'device_target': 'current_host'},
                'script_sha256': digest(__file__), 'logger_sha256': digest(ROOT / 'LieMappBench/Logging-Dataset/logger.py'),
                'purpose': 'Real prerequisite/install/configure retry; not a native inference or an AC/DC verdict',
                'initial_original_git_status': initial_status}
    destination = ROOT / '.evidence/raw/siai/tensorRT-llm' / args.run_id
    with common.Logger(destination, metadata, source_root=ROOT.parent) as logger:
        record = Recorder(logger)
        record.revision = revision
        record.command('original_source_identity', ['git', '-C', ORIGINAL, 'status', '--short'])
        record.command('kernel', ['uname', '-a'])
        record.command('cpu', ['lscpu', '-J'])
        record.command('nvidia_smi', ['nvidia-smi', '-L'])
        driver_probe = '''import ctypes,json,os
from pathlib import Path
result={'cuda_visible_devices':os.environ.get('CUDA_VISIBLE_DEVICES'),
'device_nodes':{str(p):p.exists() for p in map(Path,['/dev/nvidiactl','/dev/nvidia0','/dev/dxg'])}}
try:
 lib=ctypes.CDLL('libcuda.so.1');result['libcuda_loaded']=True
 result['cuInit_returncode']=lib.cuInit(0)
 count=ctypes.c_int(-1);result['cuDeviceGetCount_returncode']=lib.cuDeviceGetCount(ctypes.byref(count));result['cuda_device_count']=count.value
except OSError as e: result.update(libcuda_loaded=False,error=str(e))
print(json.dumps(result));raise SystemExit(0 if result.get('cuda_device_count',0)>0 else 3)
'''
        driver = record.command('cuda_driver_runtime', [args.probe_python, '-c', driver_probe])
        record.command('torch_cuda_runtime', [args.probe_python, '-c',
                       'import torch,json;print(json.dumps({"torch":str(torch.__version__),"torch_cuda_build":torch.version.cuda,"cuda_available":torch.cuda.is_available(),"cuda_device_count":torch.cuda.device_count()}));torch.cuda.init()'])
        record.command('cuda_compiler', ['nvcc', '--version'])
        if (PRIVATE / '.git').exists():
            record.command('existing_private_identity', ['git', '-C', PRIVATE, 'rev-parse', 'HEAD'])
            current = subprocess.check_output(['git', '-C', str(PRIVATE), 'rev-parse', 'HEAD'], text=True).strip()
            if current != revision:
                raise ValueError('Existing private source does not match original; refusing overwrite')
        else:
            clone = record.command('local_private_clone', ['git', 'clone', '--local', ORIGINAL, PRIVATE], timeout=120)
            if clone['returncode'] != 0:
                raise RuntimeError('Private clone failed; no original source modified')
        record.command('private_source_identity', ['git', '-C', PRIVATE, 'rev-parse', 'HEAD'])
        venv = PRIVATE / '.readiness-venv'
        if not venv.exists():
            record.command('isolated_python_environment', [sys.executable, '-m', 'venv', venv], timeout=120)
        python = venv / 'bin/python'
        record.command('small_packaging_prerequisites', [python, '-m', 'pip', 'install', '--disable-pip-version-check',
                       '--no-deps', 'setuptools', 'wheel', 'packaging'], timeout=180)
        record.command('editable_install_attempt', [python, '-m', 'pip', 'install', '--disable-pip-version-check',
                       '--no-build-isolation', '--no-deps', '-e', PRIVATE], cwd=PRIVATE, timeout=120)
        build = PRIVATE / '.readiness-cmake' / args.run_id
        record.command('native_cmake_configure', ['cmake', '-S', PRIVATE / 'cpp', '-B', build,
                       f'-DPython_EXECUTABLE={python}', f'-DTRTLLM_VERSION_H_INCLUDE_DIR={build / "include"}',
                       '-DBUILD_TESTS=OFF', '-DBUILD_BENCHMARKS=OFF'], cwd=PRIVATE, timeout=120)
        record.command('source_package_import', [args.probe_python, '-c',
                       'import tensorrt_llm;print("package",tensorrt_llm.__file__,tensorrt_llm.__version__);from tensorrt_llm import LLM,SamplingParams;print("PUBLIC_RUNTIME_IMPORT_SUCCEEDED")'],
                       cwd=PRIVATE, env={'PYTHONPATH': str(PRIVATE)}, timeout=90)
        references = [
            ('official_supported_hardware', 'https://nvidia.github.io/TensorRT-LLM/supported-hardware.html'),
            ('official_installation', 'https://nvidia.github.io/TensorRT-LLM/installation/installation-guide.html'),
            ('official_backend_migration', 'https://nvidia.github.io/TensorRT-LLM/latest/legacy/tensorrt-backend-removal.html'),
            ('official_supported_models', 'https://nvidia.github.io/TensorRT-LLM/models/supported-models.html'),
            ('requested_model_card', f'https://huggingface.co/{MODEL_ID}/resolve/{MODEL_REVISION}/README.md'),
            ('requested_mlc_config', f'https://huggingface.co/{MODEL_ID}/resolve/{MODEL_REVISION}/mlc-chat-config.json'),
            ('base_hf_config', 'https://huggingface.co/microsoft/Phi-3.5-vision-instruct/resolve/main/config.json'),
        ]
        reference_ids, documents = {}, {}
        for name, url in references:
            body, event_id = record.reference(name, url)
            reference_ids[name] = event_id
            documents[name] = body
        for filename in ('README.md', 'mlc-chat-config.json', 'ndarray-cache.json'):
            path = MODEL_DIR / filename
            if path.is_file():
                data = path.read_bytes()
                record.emit('shared_model_metadata', {'path': str(path), 'bytes': len(data), 'sha256': digest(path),
                            'meaning': 'MLC 담당자가 받은 모델 메타데이터 읽기 재사용; weight 다운로드/변환 없음'},
                            tensors={'file_bytes': np.frombuffer(data, dtype=np.uint8)})
        source_ids = []
        for args_source in [
            ('docs/source/supported-hardware.md', 1, 7, '현재 소스의 공식 지원 장치는 NVIDIA GPU이다'),
            ('cpp/CMakeLists.txt', 183, 240, 'native C++ 빌드는 CUDA 언어와 필수 CUDAToolkit 라이브러리를 사용한다'),
            ('setup.py', 53, 69, 'editable 설치 전 native bindings 및 kernel bundle 사전 빌드 검증'),
            ('tensorrt_llm/_torch/pyexecutor/py_executor_creator.py', 865, 874, '기본 PyExecutor의 모델 실행용 CUDA stream 생성'),
            ('tensorrt_llm/_torch/auto_deploy/shim/ad_executor.py', 1116, 1147, 'AutoDeploy public executor도 CUDA device 초기화 수행'),
            ('tensorrt_llm/_torch/auto_deploy/llm_args.py', 268, 292, 'AutoDeploy device 인자만 보고 full engine CPU 지원으로 단정할 수 없음'),
            ('tensorrt_llm/_torch/models/_arch_index.py', 80, 103, '등록된 Phi3ForCausalLM과 Phi3 vision 아키텍처의 구분'),
        ]:
            source_ids.append(record.source(*args_source)['event_id'])
        try:
            mlc_config = json.loads(documents['requested_mlc_config'])
            base_config = json.loads(documents['base_hf_config'])
            requested_architectures = base_config.get('architectures', [])
            registry_text = (PRIVATE / 'tensorrt_llm/_torch/models/_arch_index.py').read_text()
            format_facts = {'mlc_model_type': mlc_config.get('model_type'), 'mlc_quantization': mlc_config.get('quantization'),
                            'hf_base_architectures': requested_architectures,
                            'direct_pytorch_registry_name_present': {arch: f'"{arch}"' in registry_text for arch in requested_architectures},
                            'meaning': '배포 형식/직접 registry 지원 점검. AutoDeploy의 모든 가능한 모델 지원 여부를 단정하지 않음'}
            record.emit('model_format_readiness', format_facts)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            record.emit('model_format_readiness', {'status': 'incomplete', 'error': str(error), 'meaning': '외부 config 파싱 실패'})
        final_status = subprocess.check_output(['git', '-C', str(ORIGINAL), 'status', '--porcelain'], text=True)
        source_unchanged = initial_status == final_status and subprocess.check_output(
            ['git', '-C', str(ORIGINAL), 'rev-parse', 'HEAD'], text=True).strip() == revision
        record.command('final_original_source_identity', ['git', '-C', ORIGINAL, 'status', '--short'])
        blockers = []
        if driver['returncode'] != 0:
            blockers.append('No accessible NVIDIA CUDA device/driver in the current host runtime')
        if record.results['native_cmake_configure']['returncode'] != 0:
            blockers.append('Native TensorRT-LLM CMake configuration did not complete; inspect exact compiler diagnostics')
        if record.results['editable_install_attempt']['returncode'] != 0:
            blockers.append('Editable installation did not complete; native package prerequisites are missing')
        conclusion = {'status': 'blocked' if blockers else 'additional_native_validation_required',
                      'native_inference_executed': False, 'attack_executed': False,
                      'ac_dc_evaluation': 'not_evaluated', 'blockers': blockers, 'original_source_unchanged': source_unchanged,
                      'reference_event_ids': reference_ids, 'source_event_ids': source_ids,
                      'command_event_ids': {name: value['event_id'] for name, value in record.results.items()},
                      'format_conclusion': 'The requested artifact is MLC q4f32_1 for MLC-LLM/WebLLM, not a directly accepted TensorRT-LLM checkpoint.',
                      'backend_version_caveat': 'Current TensorRT-LLM removed the legacy TensorRT-engine backend; its PyTorch/AutoDeploy runtime still uses CUDA.',
                      'not_attempted': ['No multi-GB CUDA dependency/container downloads on a host lacking CUDA hardware',
                                        'No weight conversion, simulated execution, or HF/MLC inference relabelled as TensorRT-LLM'],
                      'meaning': '현재 호스트에서 실제 설치·빌드 전제를 재시도했으나 native SIAI를 실행하지 못함. AC/DC 거짓의 실측 증거가 아님'}
        record.emit('readiness_conclusion', conclusion)
        logger.close('blocked', reason='; '.join(blockers) or 'Readiness diagnostics are not native inference')
    print(json.dumps({'run_dir': str(destination), 'status': 'blocked', 'original_source_unchanged': source_unchanged}))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
