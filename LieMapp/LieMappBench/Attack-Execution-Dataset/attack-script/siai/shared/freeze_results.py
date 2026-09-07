"""Create a hash-index of explicit final reports and supporting evidence.

This is an index, not an additional Analyzer or a security verdict. Each sealed
package is revalidated with the common Analyzer before it is added. Open builds,
smoke runs and old reports are not silently selected as final experiment results.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

import numpy as np

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'LieMappBench').is_dir())


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def reference(path):
    path = Path(path).resolve(strict=True)
    return {'path': path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path),
            'sha256': digest(path), 'bytes': path.stat().st_size}


def verify_analysis(analyzer, path):
    """Recompute with the one common Analyzer; never trust copied verdict fields."""
    path = Path(path)
    result = analyzer._json(path.read_text(encoding='utf-8'), str(path))
    if result['attack_id'] != 'siai':
        raise ValueError('This experiment index is for SIAI only')
    provenance = result['provenance']
    if digest(ROOT / 'LieMappAnalyzer/analyzer.py') != provenance['analyzer_sha256']:
        raise ValueError('Current Analyzer does not match selected report version')
    if digest(provenance['rules_path']) != provenance['rules_sha256']:
        raise ValueError('Current rules do not match frozen analysis')
    # Reuse analyze(), including all package validation and generic rule evaluation.
    # Temporary reports are not experiment outputs and are automatically removed.
    with tempfile.TemporaryDirectory(prefix='liemapp-index-audit-') as temporary:
        recomputed = analyzer.analyze(provenance['log_path'], provenance['rules_path'], temporary)
    deterministic = lambda value: {k: v for k, v in value.items() if k != 'generated_at_utc'}
    if analyzer.canonical_json(deterministic(result)) != analyzer.canonical_json(deterministic(recomputed)):
        changed = sorted(k for k in set(result) | set(recomputed)
                         if k != 'generated_at_utc' and result.get(k) != recomputed.get(k))
        raise ValueError('Selected analysis differs from recomputation: ' + ', '.join(changed))
    report = path.parent / 'report.md'
    if report.read_text(encoding='utf-8') != analyzer.render_report(result):
        raise ValueError('Selected Markdown report differs from common Analyzer rendering')
    return result


def verify_readable_views(analyzer, package):
    paths = package.root / 'run.json', package.root / 'events.pretty.json'
    for path, original in zip(paths, (package.metadata, package.events)):
        value = analyzer._json(path.read_text(encoding='utf-8'), str(path))
        if analyzer.canonical_json(value) != analyzer.canonical_json(original):
            raise ValueError(f'Readable {path.name} differs from raw event evidence')
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis', type=Path, action='append', required=True)
    parser.add_argument('--support', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('frozen_index_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    experiments, rule_hashes, seen = [], set(), set()
    for path in args.analysis:
        result = verify_analysis(analyzer, path)
        if result['run_id'] in seen:
            raise ValueError('Select one final analysis per run')
        seen.add(result['run_id'])
        package = analyzer.EvidencePackage(result['provenance']['log_path'])
        if package.run_id != result['run_id'] or package.metadata != result['metadata']:
            raise ValueError('Analysis is not linked to the stated evidence package')
        run_file, pretty_file = verify_readable_views(analyzer, package)
        if digest(package.path) != result['provenance']['log_sha256']:
            raise ValueError('Analysis/log hash mismatch')
        if digest(package.root / 'seal.json') != result['provenance']['seal_sha256']:
            raise ValueError('Analysis/seal hash mismatch')
        if digest(result['provenance']['rules_path']) != result['provenance']['rules_sha256']:
            raise ValueError('Current rules do not match frozen analysis; preserve the matching rule file first')
        if digest(ROOT / 'LieMappAnalyzer/analyzer.py') != result['provenance']['analyzer_sha256']:
            raise ValueError('Current Analyzer does not match selected report version')
        rule_hashes.add(result['provenance']['rules_sha256'])
        experiments.append({'engine': package.metadata['engine'], 'run_id': package.run_id,
            'execution_scope': package.metadata['execution_scope'], 'run_status': package.seal['status'],
            'run_reason': package.seal.get('reason'), 'conditions': [
                {'id': c['id'], 'value': c['value'], 'status': c['status']} for c in result['conditions']],
            'summary': result['summary'], 'integrity': result['integrity'],
            'analysis': reference(path), 'report': reference(path.parent / 'report.md'),
            'events': reference(package.path), 'seal': reference(package.root / 'seal.json'),
            'run_metadata': reference(run_file), 'readable_events': reference(pretty_file),
            'rules_sha256': result['provenance']['rules_sha256']})
    if len(rule_hashes) != 1:
        raise ValueError('This cross-engine index requires exactly the same rule file hash')
    output = {'schema_version': '1.0.0', 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'attack_id': 'siai', 'meaning': 'Explicit final report and evidence index; not an external notarization',
        'verification': 'Common Analyzer re-evaluation of every analysis and exact Markdown re-rendering',
        'verification_environment': {'python': sys.version, 'platform': platform.platform(),
            'numpy': np.__version__, 'numpy_build': getattr(np.__config__, 'CONFIG', {}),
            'thread_environment': {key: os.environ.get(key) for key in
                ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS')}},
        'same_rules_across_engines': True, 'rules_sha256': next(iter(rule_hashes)),
        'experiments': experiments, 'supporting_files': [reference(p) for p in args.support],
        'framework': [reference(ROOT / 'LieMappBench/Logging-Dataset/logger.py'),
                      reference(ROOT / 'LieMappAnalyzer/analyzer.py'),
                      reference(ROOT / 'LieMappBench/Logging-Dataset/siai/conditions.json'),
                      reference(ROOT / 'LieMappBench/Attack-Library/attack_library.xlsx'),
                      reference(ROOT / 'requirements-common.txt'),
                      reference(Path(__file__))],
        'limitations': ['Native runtime, preflight and environment_build are different evidence scopes.',
                        'AC/DC values do not substitute attack success or validated detection performance.',
                        'Hash consistency does not establish external custody or authenticity.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'verified_reports': len(experiments),
                      'same_rules_sha256': next(iter(rule_hashes))}))


if __name__ == '__main__':
    main()
