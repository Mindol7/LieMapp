"""Produce source-anchored logging mappings from sealed, newly executed runs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
LIEMAPP = next(parent for parent in HERE.parents if (parent / 'LIE').is_dir() and (parent / 'LieMappBench').is_dir())
OUT = LIEMAPP / 'LieMappBench/Logging-Dataset/siai/llamacpp'
POINTS = {
    'siai.llamacpp.processor-output': (['AC2', 'DC1'], '엔진 전처리 직후의 정규화된 실제 픽셀을 모두 보존한다. 인코더 입력과 연결하여 전처리에서 인코더까지 전달된 값을 검증한다.'),
    'siai.llamacpp.encoder-input': (['AC1', 'AC2', 'DC1'], 'clip_image_batch_encode에 실제로 전달되는 float32 버퍼를 보존한다. 함수 호출 여부와 perturbation 보존 여부를 혼동하지 않고 clean/attack 쌍과 비교한다.'),
    'siai.llamacpp.projected-embedding': (['AC1', 'AC3', 'DC2', 'DC3'], '성공한 이미지 인코딩·projection의 실제 출력과 반환값을 기록한다. 모든 타일을 순서대로 연결해야 전체 임베딩이다.'),
    'siai.llamacpp.decoder-batch': (['AC1', 'AC3'], '실제 llama_decode 호출이 소비한 이미지 임베딩 배치와 반환값을 기록한다. 실패 배치는 성공으로 판정하지 않는다.'),
    'siai.llamacpp.decoder-input': (['AC1', 'AC3', 'DC2'], '한 이미지 청크의 모든 llama_decode 배치가 성공한 뒤 전체 소비 버퍼를 기록한다. projection 값과의 일치만으로 출력에 대한 인과적 영향을 단정하지 않는다.'),
    'siai.llamacpp.visual-ablation': (['AC3'], '원본 요청과 동일한 이미지·프롬프트·seed에서 visual embedding만 0으로 바꾸는 통제 실험을 명시적으로 기록한다. 일반 추론 또는 공격 성공 로그가 아니다.'),
    'siai.llamacpp.generation-output': (['AC3'], '실제 언어 디코더의 첫 토큰 전체 logits·생성 텍스트·토큰 ID를 보존한다. 정상/ablation의 정량 차이와 공격 목표 달성은 구분하여 분석한다.'),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, action='append', required=True)
    parser.add_argument('--name', required=True, help='New output basename; existing files are never replaced')
    args = parser.parse_args()
    if Path(args.name).name != args.name or not args.name:
        raise ValueError('name must be a filename component')
    review = json.loads((OUT / 'source-review.json').read_text(encoding='utf-8'))
    collected = {}
    runs = []
    reproducibility = []
    snapshot_dir = OUT / 'source-snapshots'
    snapshot_dir.mkdir(exist_ok=True)
    for run_dir in args.run_dir:
        run_dir = run_dir.resolve(strict=True)
        seal = json.loads((run_dir / 'seal.json').read_text(encoding='utf-8'))
        metadata = json.loads((run_dir / 'run.json').read_text(encoding='utf-8'))
        if digest(run_dir / 'events.jsonl') != seal['events_sha256']:
            raise ValueError(f'Run event hash mismatch: {run_dir}')
        runs.append({'path': str(run_dir), 'seal': seal})
        for key, original in (
            ('logger_sha256', LIEMAPP / 'LieMappBench/Logging-Dataset/logger.py'),
            ('transport_sha256', LIEMAPP / 'LieMappBench/Logging-Dataset/native/bridge.h'),
            ('runner_sha256', HERE / 'run.py'),
        ):
            expected = metadata[key]
            target = snapshot_dir / (expected + '-' + original.name)
            if target.exists():
                if digest(target) != expected:
                    raise ValueError(f'Reproducibility snapshot corrupted: {target}')
            else:
                if digest(original) != expected:
                    raise ValueError(f'Runtime source changed before snapshot: {original}')
                shutil.copyfile(original, target)
            reproducibility.append({'run_id': metadata['run_id'], 'kind': key,
                                    'source_path': str(original), 'sha256': expected,
                                    'snapshot': str(target.relative_to(OUT))})
        binaries = {Path(metadata['engine']['binary']).resolve()}
        binaries.update(path.resolve() for path in Path(metadata['engine']['binary']).parent.glob('lib*.so'))
        for binary in sorted(binaries):
            actual_hash = digest(binary)
            if binary == Path(metadata['engine']['binary']).resolve() and actual_hash != metadata['engine']['binary_sha256']:
                raise ValueError('Native executable changed after execution')
            reproducibility.append({'run_id': metadata['run_id'], 'kind': 'native_binary',
                                    'path': str(binary), 'sha256': actual_hash,
                                    'bytes': binary.stat().st_size,
                                    'hash_observed': 'mapping_freeze_after_completed_run',
                                    'binary_copied': False})
        for line in (run_dir / 'events.jsonl').read_text(encoding='utf-8').splitlines():
            event = json.loads(line)
            point = (event.get('source') or {}).get('logging_point_id')
            if point not in POINTS:
                continue
            existing = collected.setdefault(point, [])
            existing.append({'event': event, 'run_dir': run_dir})
    mappings = []
    for point, (conditions, reason) in POINTS.items():
        items = collected.get(point, [])
        if not items:
            mappings.append({'logging_point_id': point, 'condition_ids': conditions, 'reason': reason, 'observed': False})
            continue
        first = items[0]['event']
        source = first['source']
        actual = Path(source['path'])
        if digest(actual) != source['sha256']:
            raise ValueError(f'Source changed since execution: {actual}')
        snapshot = snapshot_dir / (source['sha256'] + '-' + actual.name)
        if not snapshot.exists():
            shutil.copyfile(actual, snapshot)
        elif digest(snapshot) != source['sha256']:
            raise ValueError(f'Source snapshot hash mismatch: {snapshot}')
        example = {'run_dir': str(items[0]['run_dir']), 'event_id': first['event_id'],
                   'sequence': first['sequence'], 'context': first['context'],
                   'raw': first['raw'], 'artifacts': first['artifacts']}
        mappings.append({'logging_point_id': point, 'condition_ids': conditions, 'reason': reason,
                         'stage': first['stage'], 'source': source,
                         'source_snapshot': str(snapshot.relative_to(OUT)),
                         'observed': True, 'observed_events': len(items), 'example': example})
    output = {'schema_version': '1.0.0', 'attack_id': 'siai', 'engine_id': 'llamacpp',
              'source_commit': review['source_commit'], 'condition_authority': review['library_source'],
              'conditions': review['conditions'], 'runs': runs, 'logging_points': mappings,
              'reproducibility_files': reproducibility,
              'interpretation_limits': [
                  'A source mapping is not itself an AC/DC truth value.',
                  'Concatenate all same-request stage tensors in event order; one image may have multiple tiles.',
                  'Lossless raw tensor values are in .npy artifacts, not only the preview.',
                  'Native inference completion, causal visual dependence, and attack success are separate claims.']}
    with (OUT / (args.name + '.json')).open('x', encoding='utf-8') as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    lines = ['# SIAI / llama.cpp 실제 로깅 지점', '',
             f'원본 커밋: `{review["source_commit"]}`. AC/DC의 정의는 Attack Library의 원문 셀을 따른다.', '',
             '각 지점의 관측 여부와 AC/DC의 T/F는 서로 다른 정보다. 최종 조건 판정은 공통 Analyzer가 수행한다.', '',
             '| 로깅 지점 | 조건 | 실행 관측 | 이유 |', '|---|---|---|---|']
    for mapping in mappings:
        lines.append(f'| `{mapping["logging_point_id"]}` | {", ".join(mapping["condition_ids"])} | {mapping.get("observed_events", 0)}개 이벤트 | {mapping["reason"]} |')
    lines.extend(['', '## 실제 소스와 원시 값 예시', '',
                  '이미지 타일이 여러 개이면 동일 요청·동일 stage의 텐서를 이벤트 순서로 모두 연결한다. preview는 전체 raw 값이 아니다.', ''])
    for mapping in mappings:
        if not mapping['observed']:
            continue
        src = mapping['source']
        example = mapping['example']
        lines.extend([f'### {mapping["logging_point_id"]}', '',
                      f'- 소스: `{src["path"]}:{src["line"]}` / `{src["function"]}`',
                      f'- SHA-256: `{src["sha256"]}`',
                      f'- 보존 소스: [{mapping["source_snapshot"]}]({mapping["source_snapshot"]})',
                      f'- 로그: `{example["run_dir"]}/events.pretty.json`, 이벤트 `{example["event_id"]}`',
                      '', '```json', json.dumps({'raw': example['raw'], 'artifacts': example['artifacts']}, ensure_ascii=False, indent=2), '```', ''])
    with (OUT / (args.name + '.md')).open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines))
    print(OUT / (args.name + '.json'))


if __name__ == '__main__':
    main()
