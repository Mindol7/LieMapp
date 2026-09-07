"""Compare one fresh, non-intervened attack request with one independent repeat.

All input packages are verified by the common Analyzer. Only the common Logger
writes the new instrumentation_validation run; neither input is modified. A
measured difference is a completed comparison (exit 1), not a hidden failure.
An invalid/missing comparison contract is blocked (exit 2). Matching one repeat
does not prove determinism or attack success, or identify an intervention effect.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys

import numpy as np

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())
CONTEXT_KEYS = ('input_id', 'input_sha256', 'question_id', 'prompt', 'prompt_sha256',
                'seed', 'temperature', 'max_tokens', 'model_revision')
METADATA_KEYS = ('attack_id', 'engine', 'model', 'runtime', 'logger_sha256', 'runner_sha256')
STAGES = (('input_received', 'input_pixels'), ('projected_embedding', 'values'),
          ('decoder_input', 'values'), ('generation_output', 'logits'))
NATIVE_SCOPES = {'native_runtime', 'engine_runtime', 'end_to_end'}


class ContractError(ValueError):
    """Evidence cannot support the requested controlled comparison."""


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    item = importlib.util.module_from_spec(spec)
    sys.modules[name] = item
    spec.loader.exec_module(item)
    return item


def exact(left, right):
    """Do not silently accept bool/int or int/float substitutions in metadata."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(exact(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def require(condition, message):
    if not condition:
        raise ContractError(message)


def is_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def has_model_digest(value):
    if not isinstance(value, dict):
        return False
    return any((key.endswith('_sha256') and (is_digest(item) or
               isinstance(item, dict) and bool(item) and all(is_digest(v) for v in item.values())))
               or isinstance(item, dict) and has_model_digest(item)
               for key, item in value.items())


def choose_request(package, *, ablation=False):
    selection = {'evaluation': 'condition_audit', 'role': 'ablation' if ablation else 'attack',
                 'transform': 'original', 'run_kind': 'zero_visual_embeddings' if ablation else 'normal'}
    if ablation:
        selection['base_role'] = 'attack'
    selected = [e for e in package.events if e['stage'] == 'generation_output'
                and all(exact(e['context'].get(k), v) for k, v in selection.items())]
    require(len(selected) == 1, f'Expected exactly one generation_output for {selection}; found {len(selected)}')
    generation = selected[0]
    context = generation['context']
    require(context.get('isolated_process') is True, 'Selected request must declare isolated_process=true')
    require(isinstance(context.get('request_id'), str) and context['request_id'], 'Missing request_id')
    for key in CONTEXT_KEYS:
        require(key in context and context[key] is not None, f'Missing context.{key}')
    for key in ('input_id', 'question_id', 'model_revision'):
        require(isinstance(context[key], str) and bool(context[key]), f'Invalid context.{key}')
    require(isinstance(context['prompt'], str), 'Prompt must be a string')
    require(is_digest(context['input_sha256']) and is_digest(context['prompt_sha256']), 'Invalid input/prompt digest')
    require(hashlib.sha256(context['prompt'].encode()).hexdigest() == context['prompt_sha256'], 'Prompt digest mismatch')
    require(type(context['seed']) is int and type(context['max_tokens']) is int and context['max_tokens'] > 0,
            'Seed/max_tokens must be explicit integers')
    require(type(context['temperature']) in (int, float), 'Temperature must be numeric, not bool')
    events = [e for e in package.events if e['context'].get('request_id') == context['request_id']]
    for event in events:
        if event['stage'] not in {stage for stage, _ in STAGES}:
            continue
        require(all(key in event['context'] and exact(event['context'][key], context[key]) for key in CONTEXT_KEYS),
                f'Context changed within selected request at {event["event_id"]}')
        require(event['context'].get('isolated_process') is True, 'Stage isolation context is missing/inconsistent')
        if event['stage'] != 'input_received':
            require(type(event['raw'].get('returncode')) is int and event['raw']['returncode'] == 0,
                    f'Unsuccessful/missing returncode at {event["event_id"]}')
        if event['stage'] == 'decoder_input':
            require(event['raw'].get('intervention') is ablation, 'Decoder intervention flag does not match selected run')
    return generation, events


def aggregate(package, events, stage, artifact):
    selected = sorted((e for e in events if e['stage'] == stage), key=lambda e: e['sequence'])
    require(bool(selected), f'Missing stage {stage}')
    if stage in ('input_received', 'generation_output'):
        require(len(selected) == 1, f'{stage} must have exactly one event')
    arrays, sources = [], []
    for event in selected:
        value, error = package.tensor(event, artifact)
        require(error is None, f'{stage}/{artifact}: {error}')
        require(value is not None and value.ndim > 0 and value.size > 0, f'Empty/scalar {stage}/{artifact}')
        arrays.append(value)
        require(isinstance(event.get('source'), dict), f'Missing source provenance for {stage}')
        sources.append({k: event['source'][k] for k in ('path', 'function', 'line', 'logging_point_id', 'sha256')})
    dtype = arrays[0].dtype
    require(all(a.dtype == dtype and a.shape[1:] == arrays[0].shape[1:] for a in arrays),
            f'Incompatible tile dtype/layout in {stage}')
    combined = np.concatenate(arrays, axis=0, dtype=dtype, casting='no')
    descriptor = {'dtype': dtype.str, 'shape': list(combined.shape), 'elements': int(combined.size),
                  'payload_sha256': hashlib.sha256(combined.tobytes(order='C')).hexdigest(),
                  'part_shapes': [list(a.shape) for a in arrays], 'sources': sources,
                  'event_ids': [e['event_id'] for e in selected],
                  'artifact_sha256': [e['artifacts'][artifact]['sha256'] for e in selected]}
    if stage == 'generation_output':
        raw = selected[0]['raw']
        require(type(raw.get('first_step_logits_count')) is int and raw['first_step_logits_count'] == combined.size,
                'Full first-token logits count must match the complete logits artifact')
    return combined, descriptor


def tensor_comparison(left, left_info, right, right_info):
    same_shape = left.shape == right.shape
    same_dtype = left.dtype == right.dtype
    same_bytes = left_info['payload_sha256'] == right_info['payload_sha256']
    distance = None
    if same_shape:
        with np.errstate(over='ignore', invalid='ignore'):
            distance = float(np.max(np.abs(left.astype(np.float64) - right.astype(np.float64))))
        if not np.isfinite(distance):
            distance = None
    return {'left': left_info, 'right': right_info, 'shape_identical': same_shape,
            'dtype_identical': same_dtype, 'payload_identical': same_bytes,
            'byte_identical': same_shape and same_dtype and same_bytes,
            'part_layout_identical': left_info['part_shapes'] == right_info['part_shapes'],
            'max_abs_distance': distance,
            'numeric_comparison': 'computed' if distance is not None else 'shape_mismatch_or_float64_overflow'}


def output_fields(generation):
    raw = generation['raw']
    require(isinstance(raw.get('generated_text'), str), 'Missing raw.generated_text')
    tokens = raw.get('token_ids')
    require(isinstance(tokens, list) and all(type(t) is int and t >= 0 for t in tokens), 'Missing/invalid raw.token_ids')
    require(type(raw.get('generated_token_count')) is int and raw['generated_token_count'] == len(tokens),
            'Generated token count must match full token IDs')
    return {'generated_text': raw['generated_text'], 'token_ids': tokens,
            'generated_token_count': len(tokens), 'event_id': generation['event_id']}


def compare_packages(reference, repeat):
    require(reference.path.resolve() != repeat.path.resolve(), 'A run cannot be its own repeat')
    require(reference.run_id != repeat.run_id, 'Reference and repeat run_id must differ')
    require(not ({e['event_id'] for e in reference.events} & {e['event_id'] for e in repeat.events}),
            'Reference and repeat share event IDs')
    for package in (reference, repeat):
        require(package.seal['status'] == 'completed', 'Both input runs must be completed')
        require(package.metadata['execution_scope'] in NATIVE_SCOPES, 'Both packages must be native runtime evidence')
        engine = package.metadata.get('engine', {})
        require(isinstance(engine.get('revision'), str) and engine['revision'], 'Missing engine revision')
        fingerprints = engine.get('instrumented_file_sha256')
        require(isinstance(fingerprints, dict) and fingerprints and all(is_digest(v) for v in fingerprints.values()),
                'Missing instrumented source hashes')
        require(has_model_digest(package.metadata.get('model')), 'Missing model file hash provenance')
        runtime = package.metadata.get('runtime')
        require(isinstance(runtime, dict) and all(runtime.get(k) is not None for k in ('device', 'platform', 'threads')),
                'Runtime device/platform/threads are required')
        for key in ('logger_sha256', 'runner_sha256'):
            require(is_digest(package.metadata.get(key)), f'Missing metadata.{key}')
    checks = [{'field': f'metadata.{key}', 'equal': exact(reference.metadata.get(key), repeat.metadata.get(key))}
              for key in METADATA_KEYS]
    # Compare additional recorded environment/code fingerprints when either run supplies them.
    for key in ('environment', 'software', 'transport_sha256'):
        if key in reference.metadata or key in repeat.metadata:
            checks.append({'field': f'metadata.{key}', 'equal': key in reference.metadata and key in repeat.metadata
                           and exact(reference.metadata[key], repeat.metadata[key])})
    require(all(c['equal'] for c in checks), f'Recorded source/model/runtime mismatch: {checks}')
    left_gen, left_events = choose_request(reference)
    right_gen, right_events = choose_request(repeat)
    require(left_gen['context']['request_id'] != right_gen['context']['request_id'], 'Request IDs must differ')
    for key in CONTEXT_KEYS:
        require(exact(left_gen['context'][key], right_gen['context'][key]), f'Context mismatch: {key}')
        checks.append({'field': f'context.{key}', 'equal': True})
    results, tensors = {}, {}
    for stage, artifact in STAGES:
        left, left_info = aggregate(reference, left_events, stage, artifact)
        right, right_info = aggregate(repeat, right_events, stage, artifact)
        require(exact(left_info['sources'], right_info['sources']), f'Actual logging source sites differ for {stage}')
        results[stage] = tensor_comparison(left, left_info, right, right_info)
        tensors[stage] = (left, left_info)
    left_output, right_output = output_fields(left_gen), output_fields(right_gen)
    outputs = {'reference': left_output, 'repeat': right_output,
               'text_identical': left_output['generated_text'] == right_output['generated_text'],
               'tokens_identical': left_output['token_ids'] == right_output['token_ids']}
    identical = all(r['byte_identical'] and r['part_layout_identical'] for r in results.values())
    identical = identical and outputs['text_identical'] and outputs['tokens_identical']
    ablation = {'status': 'unavailable', 'reason': 'No verified, uniquely matched zero-visual-embedding request'}
    try:
        zero_gen, zero_events = choose_request(reference, ablation=True)
        require(zero_gen['context']['request_id'] not in (left_gen['context']['request_id'], right_gen['context']['request_id']),
                'Ablation must have a different request ID')
        require(all(exact(zero_gen['context'][k], left_gen['context'][k]) for k in CONTEXT_KEYS), 'Ablation context mismatch')
        comparisons = {}
        for stage, artifact in STAGES:
            zero, zero_info = aggregate(reference, zero_events, stage, artifact)
            base, base_info = tensors[stage]
            comparisons[stage] = tensor_comparison(base, base_info, zero, zero_info)
            if stage == 'decoder_input':
                require(bool(np.count_nonzero(zero) == 0), 'Ablation decoder input is not exactly zero')
        require(comparisons['input_received']['byte_identical'], 'Ablation input image differs')
        ablation = {'status': 'measured', 'request_id': zero_gen['context']['request_id'],
                    'comparisons': comparisons, 'output': output_fields(zero_gen),
                    'repeat_logits_max_abs': results['generation_output']['max_abs_distance'],
                    'ablation_logits_max_abs': comparisons['generation_output']['max_abs_distance']}
    except ContractError as error:
        ablation['reason'] = str(error)
    return {'status': 'measured', 'repeat_identical': bool(identical), 'recorded_contract_checks': checks,
            'reference_request_id': left_gen['context']['request_id'], 'repeat_request_id': right_gen['context']['request_id'],
            'context': {k: left_gen['context'][k] for k in CONTEXT_KEYS}, 'tensors': results,
            'outputs': outputs, 'canonical_ablation': ablation,
            'limitations': ['One repeat of one request; not a proof of general determinism or attack success.',
                            'Recorded seed equality is not independent verification of effective engine RNG seeding.',
                            'Only recorded source/model/runtime fields are compared; unrecorded environment state remains unknown.',
                            'Hash consistency establishes internal evidence linkage, not external custody or authenticity.']}


def verify(reference_path, repeat_path, run_id, *, log_root=None):
    analyzer = module('repeat_check_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
    common = module('repeat_check_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
    # An invalid reference cannot safely identify the destination engine/attack.
    reference = analyzer.EvidencePackage(reference_path)
    repeat_path = Path(repeat_path).resolve(strict=True)
    metadata = {'run_id': run_id, 'attack_id': reference.metadata['attack_id'], 'engine': reference.metadata['engine'],
                'execution_scope': 'instrumentation_validation', 'validation': 'independent_fresh_normal_repeat',
                'reference': {'run_id': reference.run_id, 'log_path': str(reference.path),
                              'log_sha256': common.sha256_file(reference.path),
                              'seal_sha256': common.sha256_file(reference.root / 'seal.json')},
                'repeat': {'log_path': str(repeat_path), 'log_sha256': common.sha256_file(repeat_path)},
                'validation_script_sha256': common.sha256_file(Path(__file__)),
                'analyzer_sha256': common.sha256_file(ROOT / 'LieMappAnalyzer/analyzer.py'),
                'logger_sha256': common.sha256_file(ROOT / 'LieMappBench/Logging-Dataset/logger.py')}
    base = Path(log_root) if log_root is not None else ROOT / '.evidence/raw'
    # The logger validates run_id; metadata IDs must not escape this destination.
    for key in (metadata['attack_id'], metadata['engine']['id']):
        require(isinstance(key, str) and key not in ('.', '..') and '/' not in key and '\\' not in key, 'Unsafe destination ID')
    run_dir = base / metadata['attack_id'] / metadata['engine']['id'] / run_id
    with common.Logger(run_dir, metadata, source_root=ROOT.parent) as logger:
        try:
            repeat = analyzer.EvidencePackage(repeat_path)
            result = compare_packages(reference, repeat)
            result['repeat_seal_sha256'] = common.sha256_file(repeat.root / 'seal.json')
        except (ContractError, analyzer.EvidenceError) as error:
            result = {'status': 'blocked', 'repeat_identical': None, 'reason': str(error)}
        logger.emit('repeat_validation', raw=result,
                    readable={'summary': '정상 경로 1회 반복의 원시 텐서·출력을 비교. 범용 결정론이나 공격 성공 판정이 아님'},
                    source={'path': str(Path(__file__).resolve()), 'function': 'verify',
                            'line': inspect.currentframe().f_lineno, 'logging_point_id': 'common.validation.normal-repeat'})
        if result['status'] == 'blocked':
            logger.close('blocked', reason=result['reason'])
    return {'run_dir': str(run_dir), 'status': result['status'], 'repeat_identical': result['repeat_identical']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--repeat', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args(argv)
    result = verify(args.reference, args.repeat, args.run_id)
    print(json.dumps(result, ensure_ascii=False))
    return 2 if result['status'] == 'blocked' else 0 if result['repeat_identical'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
