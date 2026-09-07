"""Validate native evidence identity and replay one request without logging."""
from __future__ import annotations

import argparse
import inspect
import json
import os
from pathlib import Path
import subprocess

import numpy as np

from run import LIEMAPP, digest, load_logger


def source(point: str) -> dict:
    caller = inspect.currentframe().f_back
    return {'path': str(Path(caller.f_code.co_filename).resolve()),
            'function': caller.f_code.co_name, 'line': caller.f_lineno,
            'logging_point_id': point}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--output-run-id', required=True)
    parser.add_argument('--skip-disabled-replay', action='store_true')
    parser.add_argument('--supersedes', help='Previous validation run, if this recheck corrects its tooling metadata')
    args = parser.parse_args()
    directory = args.run_dir.resolve(strict=True)
    events = [json.loads(line) for line in (directory / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    metadata = json.loads((directory / 'run.json').read_text(encoding='utf-8'))
    seal = json.loads((directory / 'seal.json').read_text(encoding='utf-8'))
    if digest(directory / 'events.jsonl') != seal['events_sha256']:
        raise ValueError('Event file does not match seal')
    grouped = {}
    artifact_count = 0
    for event in events:
        grouped.setdefault(event['context']['request_id'], []).append(event)
        for descriptor in event['artifacts'].values():
            path = directory / descriptor['path']
            if digest(path) != descriptor['sha256']:
                raise ValueError(f'Artifact hash mismatch: {path}')
            values = np.load(path, allow_pickle=False)
            if list(values.shape) != descriptor['shape'] or str(values.dtype) != descriptor['dtype']:
                raise ValueError(f'Artifact format mismatch: {path}')
            artifact_count += 1
    checks = []
    replay_group = None
    for request_id, rows in grouped.items():
        def values(stage):
            arrays = [np.load(directory / e['artifacts']['values']['path'], allow_pickle=False).reshape(-1)
                      for e in rows if e['stage'] == stage and 'values' in e['artifacts']]
            return np.concatenate(arrays) if arrays else None

        processor, encoder = values('processor_output'), values('encoder_input')
        projected, decoder = values('projected_embedding'), values('decoder_input')
        context = rows[0]['context']
        ablated = context.get('run_kind') == 'zero_visual_embeddings'
        processor_equal = processor is not None and encoder is not None and np.array_equal(processor, encoder)
        projection_equal = projected is not None and decoder is not None and np.array_equal(projected, decoder)
        expected_decoder = bool(np.count_nonzero(decoder) == 0) if ablated and decoder is not None else projection_equal
        checks.append({'request_id': request_id, 'input_id': context['input_id'], 'role': context['role'],
                       'processor_encoder_bitwise_equal': processor_equal,
                       'projected_decoder_bitwise_equal': projection_equal,
                       'decoder_is_zero_ablation': ablated, 'expected_decoder_matches': expected_decoder})
        if not processor_equal or not expected_decoder:
            raise ValueError(f'Native dataflow evidence mismatch for {request_id}')
        if replay_group is None and not ablated:
            replay_group = rows
    replay = {'performed': False}
    if not args.skip_disabled_replay and replay_group:
        command = next(e['raw']['command'] for e in replay_group if e['stage'] == 'request_started')
        original_output = next(e['raw']['stdout'] for e in replay_group if e['stage'] == 'runtime_output')
        environment = os.environ.copy()
        for name in ('LIEMAPP_SOCKET', 'LIEMAPP_CONTEXT_JSON', 'LIEMAPP_ZERO_VISUAL'):
            environment.pop(name, None)
        environment['OMP_NUM_THREADS'] = str(metadata['runtime']['threads'])
        environment['TOKENIZERS_PARALLELISM'] = 'false'
        completed = subprocess.run(command, capture_output=True, env=environment,
                                   cwd=metadata['engine']['source_root'], timeout=600, check=False)
        replay = {'performed': True, 'returncode': completed.returncode,
                  'stdout_equal': completed.stdout.decode('utf-8', errors='replace') == original_output,
                  'stdout': completed.stdout.decode('utf-8', errors='replace'),
                  'stderr': completed.stderr.decode('utf-8', errors='replace'), 'command': command,
                  'limitation': 'Same instrumented binary with logging disabled; not a separately built upstream binary'}
        if completed.returncode != 0 or not replay['stdout_equal']:
            raise ValueError('Logging-disabled replay differs from observed enabled stdout')
    logger_module = load_logger()
    output = LIEMAPP / '.evidence/raw/siai/llamacpp' / args.output_run_id
    validation_metadata = {'run_id': args.output_run_id, 'attack_id': 'siai',
                           'engine': metadata['engine'], 'execution_scope': 'instrumentation_validation',
                           'validated_run': str(directory), 'validated_events_sha256': seal['events_sha256']}
    if args.supersedes:
        validation_metadata['supersedes'] = args.supersedes
        validation_metadata['correction'] = 'Validator source attribution now points to validate_native.py rather than its imported helper module; native experiment evidence is unchanged.'
    with logger_module.Logger(output, validation_metadata, source_root=LIEMAPP.parent) as logger:
        logger.emit('native_validation', {'status': 'success', 'artifact_count': artifact_count,
                    'request_count': len(grouped), 'checks': checks, 'disabled_replay': replay},
                    context={'request_id': 'validation'}, source=source('siai.llamacpp.native-validation'),
                    readable={'summary': 'Raw tensor hashes, dataflow equality, and logging-disabled output replay checked'})
    print(json.dumps({'output': str(output), 'artifacts_verified': artifact_count,
                      'requests_verified': len(grouped), 'disabled_replay_stdout_equal': replay.get('stdout_equal')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
