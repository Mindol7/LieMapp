"""Verify actual byte identity across canonical tensor stages in a sealed run.

Numeric equality alone does not distinguish +0.0/-0.0 or differing dtypes. This
supplement records shape/dtype and payload hashes without modifying source logs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
from pathlib import Path
import sys

import numpy as np

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    item = importlib.util.module_from_spec(spec)
    sys.modules[name] = item
    spec.loader.exec_module(item)
    return item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    analyzer = module('byte_check_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
    common = module('byte_check_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
    package = analyzer.EvidencePackage(args.log)
    if package.seal['status'] != 'completed':
        raise ValueError('A completed run is required')
    groups = {}
    for event in package.events:
        request = event['context'].get('request_id')
        if request:
            groups.setdefault(request, []).append(event)
    metadata = {'run_id': args.run_id, 'attack_id': package.metadata['attack_id'],
                'engine': package.metadata['engine'], 'execution_scope': 'instrumentation_validation',
                'source_run_id': package.metadata['run_id'], 'source_log': str(args.log.resolve()),
                'source_log_sha256': common.sha256_file(args.log),
                'validation_script_sha256': common.sha256_file(Path(__file__))}
    run_dir = ROOT / '.evidence/raw' / metadata['attack_id'] / metadata['engine']['id'] / args.run_id
    def aggregate(events, stage):
        selected = [e for e in events if e['stage'] == stage]
        if not selected:
            raise ValueError(f'Missing stage {stage}')
        arrays = []
        for event in selected:
            value, error = package.tensor(event, 'values')
            if error:
                raise ValueError(error)
            arrays.append(value)
        if len({str(a.dtype) for a in arrays}) != 1:
            raise ValueError('Inconsistent tile dtype')
        return np.concatenate(arrays, axis=0), [e['event_id'] for e in selected]
    checked = 0
    with common.Logger(run_dir, metadata, source_root=ROOT.parent) as logger:
        for request, events in groups.items():
            context = events[0]['context']
            for left_stage, right_stage in [('processor_output', 'encoder_input'),
                                             ('projected_embedding', 'decoder_input')]:
                left, left_ids = aggregate(events, left_stage)
                right, right_ids = aggregate(events, right_stage)
                left_hash = hashlib.sha256(left.tobytes(order='C')).hexdigest()
                right_hash = hashlib.sha256(right.tobytes(order='C')).hexdigest()
                identical = left.shape == right.shape and left.dtype == right.dtype and left_hash == right_hash
                intervention = context.get('run_kind') == 'zero_visual_embeddings' and right_stage == 'decoder_input'
                valid = bool(np.count_nonzero(right) == 0) if intervention else identical
                logger.emit('byte_identity_validation', {'left_stage': left_stage, 'right_stage': right_stage,
                    'left_shape': list(left.shape), 'right_shape': list(right.shape),
                    'left_dtype': str(left.dtype), 'right_dtype': str(right.dtype),
                    'left_payload_sha256': left_hash, 'right_payload_sha256': right_hash,
                    'left_event_ids': left_ids, 'right_event_ids': right_ids,
                    'byte_identical': identical, 'intervention': intervention,
                    'expected_zero_intervention_verified': bool(np.count_nonzero(right) == 0) if intervention else None,
                    'validation_passed': valid}, context={'request_id': request, 'input_id': context.get('input_id')},
                    readable={'summary': '전체 배열의 dtype/shape/바이트를 검증. 명시적 zero 개입은 별도 확인'},
                    source={'path': str(Path(__file__).resolve()), 'function': 'main',
                            'line': inspect.currentframe().f_lineno, 'logging_point_id': 'common.validation.byte-identity'})
                if not valid:
                    raise ValueError(f'Byte identity / explicit intervention mismatch: {request}/{right_stage}')
                checked += 1
    print(f'Validated {checked} stage pairs across {len(groups)} requests: {run_dir}')


if __name__ == '__main__':
    main()
