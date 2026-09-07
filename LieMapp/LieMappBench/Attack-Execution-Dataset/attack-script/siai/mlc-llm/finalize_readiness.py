"""Seal the observed Phi-3.5 CPU retry, without fabricating native inference.

Read-only with respect to source, model, old logs, compiler outputs and toolchain.
Creates a NEW common-logger run plus optional new publisher supplement.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import numpy as np

from record_command import ROOT, common, source

ENGINE = ROOT / 'Instrumented-LIE/siai/mlc-llm/engine'
ORIGINAL = ROOT / 'LIE/mlc-llm'
RAW = ROOT / '.evidence/raw/siai/mlc-llm'
MODEL = ROOT / 'Instrumented-LIE/siai/mlc-llm/models/Phi-3.5-vision-instruct-q4f32_1-MLC'
PROVENANCE = ROOT / 'LieMappBench/Attack-Execution-Dataset/attack-source/siai/mlc-llm/phi35-provenance'
REVIEW = ROOT / 'LieMappBench/Logging-Dataset/siai/mlc-llm'
REVISION = '9fa644f54b04983adea4d0168f49fc6af4a893ba'
MODEL_REVISION = '2d7104ab34b358b4223aabca1d08e451c6b12728'


def git(*args):
    return subprocess.check_output(['git', '-C', str(ENGINE), *args])


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def new_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def sealed_events(directory, writer):
    seal = json.loads((directory / 'seal.json').read_text())
    content = (directory / 'events.jsonl').read_bytes()
    if digest_bytes(content) != seal['events_sha256']:
        raise ValueError(f'Seal mismatch: {directory}')
    events = [json.loads(line) for line in content.splitlines()]
    previous = None
    for index, event in enumerate(events, 1):
        unhashed = {key: value for key, value in event.items() if key != 'event_hash'}
        if (event['sequence'] != index or event['previous_event_hash'] != previous or
                digest_bytes(writer.canonical(unhashed)) != event['event_hash']):
            raise ValueError(f'Event chain mismatch: {directory}:{index}')
        previous = event['event_hash']
    if len(events) != seal['event_count'] or previous != seal['last_event_hash']:
        raise ValueError(f'Seal tail mismatch: {directory}')
    return events, seal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--supplement', type=Path)
    args = parser.parse_args()
    writer = common()
    if args.supplement and args.supplement.exists():
        parser.error('Refusing to overwrite an existing supplement')
    if git('rev-parse', 'HEAD').decode().strip() != REVISION:
        raise ValueError('Unexpected private revision')
    original_status = subprocess.check_output(['git', '-C', str(ORIGINAL), 'status', '--porcelain'], text=True)
    original_revision = subprocess.check_output(['git', '-C', str(ORIGINAL), 'rev-parse', 'HEAD'], text=True).strip()
    if original_status or original_revision != REVISION:
        raise ValueError('Original source identity changed; do not seal a clean-source claim')

    all_runs = sorted(p for p in RAW.iterdir() if p.is_dir() and p.name.startswith('siai-mlc-phi35-') and
                      p.name != args.run_id and (p / 'seal.json').is_file())
    sources, attempts = [], []
    by_name = {}
    for directory in all_runs:
        events, seal = sealed_events(directory, writer)
        sources.append({'log_path': '../../raw/siai/mlc-llm/' + directory.name + '/events.jsonl',
                        'events_sha256': seal['events_sha256']})
        by_name[directory.name] = (events, seal)
        for event in events:
            if event['stage'] == 'setup_result':
                raw = event['raw']
                ending = [line for line in raw['stderr'].splitlines() if line.strip()]
                attempts.append({'run_id': directory.name, 'returncode': raw['returncode'],
                                 'elapsed_seconds': raw['elapsed_seconds'], 'status': seal['status'],
                                 'last_stderr_line': ending[-1] if ending else '',
                                 'event_id': event['event_id'], 'sequence': event['sequence']})

    expected_compiles = [f'siai-mlc-phi35-llvm-model-compile-20260907-{i:03d}' for i in range(1, 6)]
    for name in expected_compiles:
        if by_name[name][1]['status'] != 'blocked':
            raise ValueError('A compile outcome changed; this frozen readiness narrative requires review')
    for name in ('siai-mlc-phi35-cpu-runtime-build-20260907-001',
                 'siai-mlc-phi35-fresh-runtime-factory-20260907-001'):
        if by_name[name][1]['status'] != 'completed':
            raise ValueError('Fresh runtime completion was not validated')

    metadata = {'run_id': args.run_id, 'attack_id': 'siai', 'execution_scope': 'preflight',
                'engine': {'id': 'mlc-llm', 'revision': REVISION, 'original_root': str(ORIGINAL),
                           'private_root': str(ENGINE)},
                'model': {'name': 'mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC', 'revision': MODEL_REVISION},
                'runtime': {'device': 'cpu', 'target': 'llvm/haswell', 'context_window_size': 4096,
                            'prefill_chunk_size': 2048, 'max_batch_size': 1},
                'native_inference_claim': False, 'native_request_count': 0,
                'script_sha256': writer.sha256_file(Path(__file__)),
                'logger_sha256': writer.sha256_file(ROOT / 'LieMappBench/Logging-Dataset/logger.py'),
                'interpretation': 'Setup/readiness evidence only; no observed AC/DC false or attack-success verdict'}
    directory = RAW / args.run_id
    with writer.Logger(directory, metadata, source_root=ROOT.parent) as log:
        log.emit('source_identity', {'original_git_status': original_status,
                 'original_revision': original_revision, 'private_git_diff': git('diff').decode(),
                 'submodules': git('submodule', 'status', '--recursive').decode(),
                 'meaning': '원본 불변; private의 두 실패 호환 패치는 stock과 구분'}, source=source('siai.mlc.readiness.source'))
        manifest = json.loads((PROVENANCE / 'manifest.json').read_text())
        checked = []
        for item in manifest['files']:
            path = Path(item['path'])
            actual = writer.sha256_file(path)
            if actual != item['sha256'] or path.stat().st_size != item['bytes']:
                raise ValueError(f'Model changed: {path}')
            checked.append({'filename': item['filename'], 'bytes': item['bytes'], 'sha256': actual})
        acquisition = log.emit('model_acquisition_verified', {'model_id': manifest['model_id'],
                               'revision': manifest['revision'], 'file_count': len(checked),
                               'total_bytes': sum(item['bytes'] for item in checked), 'files': checked,
                               'manifest_path': str(PROVENANCE / 'manifest.json'),
                               'manifest_sha256': writer.sha256_file(PROVENANCE / 'manifest.json'),
                               'base_license': 'MIT; original license bytes saved, not legal advice',
                               'base_license_sha256': writer.sha256_file(PROVENANCE / 'base-model-LICENSE.txt')},
                               source=source('siai.mlc.readiness.model-files'))
        log.emit('historical_attempts_verified', {'source_runs': sources, 'attempts': attempts,
                 'meaning': '기존 raw JSONL의 seal 및 전체 event hash chain을 재검증한 실제 명령 결과'},
                 source=source('siai.mlc.readiness.attempts'))
        for relative in ('python/mlc_llm/compiler_pass/pipeline.py',
                         'python/mlc_llm/model/vision/image_processing.py',
                         'python/mlc_llm/model/phi3v/phi3v_model.py',
                         'python/mlc_llm/model/phi3v/phi3v_image.py',
                         'python/mlc_llm/serve/data.py', 'cpp/support/vlm_utils.cc', 'cpp/serve/model.cc'):
            original = git('show', f'{REVISION}:{relative}')
            current = (ENGINE / relative).read_bytes()
            log.emit('static_source_snapshot', {'relative_path': relative,
                     'original_sha256': digest_bytes(original), 'private_sha256': digest_bytes(current),
                     'changed': original != current, 'instrumented': False, 'executed_native_request': False,
                     'meaning': '파일 원문 전체 byte 보존; 소스 검토는 런타임 계측값이 아니다'},
                     tensors={'original_source_bytes': np.frombuffer(original, dtype=np.uint8),
                              'private_source_bytes': np.frombuffer(current, dtype=np.uint8)},
                     source=source('siai.mlc.readiness.static-source-snapshot'))
        binaries = []
        for relative in ('libmlc_llm.so', 'libmlc_llm_module.so', 'lib/libtvm_runtime.so',
                         'lib/libtvm_runtime_extra.so', 'lib/libtvm_ffi.so'):
            path = ENGINE / 'build' / relative
            binaries.append({'path': str(path), 'bytes': path.stat().st_size, 'sha256': writer.sha256_file(path)})
        lock = ENGINE / '3rdparty/tokenizers-cpp/rust/Cargo.lock'
        log.emit('native_runtime_build_verified', {'binaries': binaries, 'rust_version': '1.90.0',
                 'cargo_lock_path': str(lock), 'cargo_lock_sha256': writer.sha256_file(lock),
                 'cpp_factory_module_created': True, 'model_initialized': False,
                 'native_request_count': 0, 'meaning': 'fresh C++ 라이브러리 로드·미초기화 engine factory 생성만 성공'},
                 tensors={'cargo_lock_bytes': np.frombuffer(lock.read_bytes(), dtype=np.uint8)},
                 source=source('siai.mlc.readiness.runtime-binaries'))
        compiled_libraries = [str(path) for path in MODEL.glob('*.so')]
        if compiled_libraries:
            raise ValueError('A model library now exists; review readiness instead of asserting the old blocker')
        result = log.emit('readiness_result', {'ready': False, 'native_request_count': 0,
                          'model_download_complete': True, 'fresh_runtime_build_complete': True,
                          'cpp_factory_module_created': True, 'model_library_available': False,
                          'model_compile_attempt_count': 5, 'model_compile_success_count': 0,
                          'reason_code': 'phi3v_llvm_model_compilation_failed',
                          'blocking_observations': ['int32 constant 7247757312 overflow during stock CPU lowering',
                              'LLVM int64-index variant: VMCodeGen cannot handle tirx.Div argument',
                              'LLVM int64+FloorDiv variant: VMCodeGen cannot handle tirx.FloorDiv argument'],
                          'source_review_only': ['GPU thread-binding image kernels need validated CPU lowering',
                              '16 padded crop features versus native 2x2 crop dimensions require contract repair',
                              'ImageData.from_url hard-coded 1921 length disagrees with expected 757 for 2x2 crops'],
                          'scope_boundary': 'No additional CPU image-kernel port was performed; this would change the benchmark implementation',
                          'condition_evidence_status': 'not_evaluated',
                          'meaning': '모델을 바꿔 실제 다운로드·빌드·컴파일 재시도했지만 native SIAI 추론까지 도달하지 못함'},
                          source=source('siai.mlc.readiness.result'))
        seal = log.close('blocked', reason='Phi-3.5 Vision LLVM model compilation failed; native inference was not executed')
    sources.append({'log_path': '../../raw/siai/mlc-llm/' + args.run_id + '/events.jsonl',
                    'events_sha256': seal['events_sha256']})
    if args.supplement:
        important = [row for row in attempts if any(term in row['run_id'] for term in
                     ('llvm-model-compile', 'cpu-runtime-build', 'fresh-runtime-import', 'fresh-runtime-factory'))]
        rows = [{'check': row['run_id'], 'returncode': row['returncode'],
                 'actual': row['last_stderr_line'] or ('실제 명령 완료; 원문 stdout은 원시 이벤트 참조'),
                 'event_id': row['event_id']} for row in important]
        rows.insert(0, {'check': '공식 모델 전체 바이트 재검증', 'returncode': '완료',
                       'actual': f"{len(checked)} files / {sum(item['bytes'] for item in checked):,} bytes; all SHA256 verified",
                       'event_id': acquisition['event_id']})
        rows.append({'check': '최종 readiness', 'returncode': 'blocked',
                     'actual': 'model_compile 0/5 success; native inference 0회; model .so 없음',
                     'event_id': result['event_id']})
        supplement = {'attack_id': 'siai', 'engine_id': 'mlc-llm',
            'title': 'Phi-3.5 Vision 모델 변경 후 실제 CPU 다운로드·빌드·컴파일 재시도',
            'summary': [
                '공식 MLC Phi-3.5-vision-instruct-q4f32_1-MLC 모델의 고정 revision 2d7104ab34b358b4223aabca1d08e451c6b12728을 다운로드하고 114개 파일 전체 해시를 검증했습니다.',
                '같은 MLC source 9fa644f에서 fresh CPU C++ runtime을 빌드했으며, 실제 라이브러리 로드와 미초기화 C++ engine factory 생성까지 성공했습니다. 이는 모델 로딩·추론 성공이 아닙니다.',
                'PhiV 모델의 LLVM 컴파일 5회는 모두 실패했습니다. 원본 CPU 경로의 int32 overflow, 최소 int64-index 호환 변형의 tirx.Div 오류, 추가 FloorDiv 표현 변형의 동일 계열 오류를 각각 원시 로그로 보존했습니다.',
                'GPU 전용 이미지 커널의 CPU 포트 및 crop 계약 수정을 더 진행하면 벤치마크 대상 구현이 달라지므로 이번 범위에서는 진행하지 않았습니다. native 이미지 요청과 생성은 0회입니다.',
                '본 보충 내용은 공통 Analyzer T/F 규칙의 입력이 아닌 환경·빌드 설명입니다. 공개 표시는 F / 미평가이며, 실제 실행에서 AC/DC 불충족을 관측한 F가 아닙니다.'],
            'tables': [{'title': '실제 재시도와 원시 결과', 'columns': [
                {'key': 'check', 'label': '시도/점검'}, {'key': 'returncode', 'label': '반환값'},
                {'key': 'actual', 'label': '원시 출력 핵심'}, {'key': 'event_id', 'label': '원본 이벤트 ID'}], 'rows': rows}],
            'limitations': [
                '새 모델에 기존 SmolVLM PGD 이미지를 입력할 경우 교차 모델 전이 실험이다. 이번에는 모델 컴파일 단계에서 멈춰 전이 성공률 자체를 측정하지 못했다.',
                '컴파일 중간의 Compilation complete! 메시지 뒤 VMCodeGen에서 실제 실패했다. 반환코드와 모델 공유 라이브러리 부재를 최종 판단 근거로 사용했다.',
                '초기 compile001은 host 지정도 부정확했고 compile002부터 올바른 x86_64-linux-gnu를 사용했다. 최소 호환 패치는 stock 성공 사례로 취급하지 않는다.',
                '초기 compile bootstrap은 캐시된 exact TVM compiler와 이전 MLC runtime으로 Python FFI 등록을 제공했다. 이후 fresh runtime은 별도 빌드·factory 검사에 성공했다. 전체 native 모델 실행에 성공했다는 주장은 하지 않는다.',
                'crop16/2x2 및 1921/757 계약 문제는 소스 정적 감사 결과이다. 모델 런타임의 shape 오류로 재현한 결과와 구분한다.',
                '모델, 원본 LIE, 과거 raw 로그를 수정하거나 삭제하지 않았으며 추가 CPU 커널 포트는 수행하지 않았다.'],
            'source_runs': sources}
        new_json(args.supplement, supplement)
    print(json.dumps({'run_dir': str(directory), 'events_sha256': seal['events_sha256'],
                      'event_count': seal['event_count'], 'native_request_count': 0,
                      'supplement': str(args.supplement) if args.supplement else None}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
