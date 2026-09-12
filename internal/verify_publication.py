"""Read-only audit of the configured public filenames, evidence, and judgments."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['OPENBLAS_NUM_THREADS'] = '1'

from LieMappAnalyzer.analyzer import EvidencePackage, analyze
from internal import publication
from internal.workflow import load_config, resolve, selected_protocol, selected_supplements, verify_selection


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit(config, *, root=ROOT, recompute=False):
    outputs, checked_hashes = [], {}

    def check_ref(reference, directory):
        path = (directory / reference['path']).resolve(strict=True)
        if path not in checked_hashes:
            checked_hashes[path] = digest(path)
        require(checked_hashes[path] == reference['sha256'], 'Referenced bytes changed: ' + str(path))

    for attack_id, attack in config['attacks'].items():
        for engine_id, engine in attack['engines'].items():
            current = read(root / '.evidence/current' / attack_id / (engine_id + '.json'))
            raw = resolve(current['source_log'], root)
            package = EvidencePackage(raw)
            protocol = selected_protocol(attack, package.metadata, root=root)
            rules_path = protocol['rules']
            rules = read(rules_path)
            verify_selection(current, attack_id=attack_id, engine_id=engine_id,
                             source_log=raw, events_sha256=package.seal['events_sha256'])
            internal = root / '.evidence/analyses' / attack_id / engine_id / current['publication_id']
            analysis = read(internal / 'analysis.json')
            manifest = read(internal / 'publication.json')
            require(manifest['raw_log_sha256'] == package.seal['events_sha256'], 'Publication source mismatch')
            require(manifest['rules_sha256'] == digest(rules_path), 'Publication rules changed')
            require(manifest['publisher_sha256'] == digest(Path(__file__).with_name('publication.py')),
                    'Publisher changed after publication; regenerate final outputs')
            for reference in manifest['files']:
                check_ref(reference, root)
            log_dir = root / 'LieMappAnalyzer/LogFile' / attack_id / engine_id
            report_dir = root / 'report' / attack_id / engine_id
            expected_logs = {f"{attack['label']}-{c['id']}-{engine['label']}-LogFile.json" for c in rules['conditions']}
            expected_reports = {f"{attack['label']}-{engine['label']}-Report.md"}
            require({p.name for p in log_dir.iterdir()} == expected_logs, 'Unexpected condition files: ' + str(log_dir))
            require({p.name for p in report_dir.iterdir()} == expected_reports, 'Unexpected report files: ' + str(report_dir))
            events = {e['event_id']: e for e in package.events}
            conditions = {c['id']: c for c in analysis['conditions']}
            verdicts = {}
            for name in sorted(expected_logs):
                document = read(log_dir / name)
                summary = document['summary']
                condition = conditions[summary['condition_id']]
                require(summary['engine_id'] == engine_id and summary['attack_id'] == attack_id,
                        'Public identity mismatch')
                require(summary['evidence_value'] is condition['value'], 'Underlying judgment changed')
                require(summary['verdict'] == ('T' if condition['value'] is True else 'F'), 'Invalid T/F policy')
                expected_status = ('observed_satisfied' if condition['value'] is True else
                                   'observed_not_satisfied' if condition['value'] is False else 'not_evaluated')
                require(summary['evidence_status'] == expected_status, 'Evidence status changed')
                require({e['event_id'] for e in document['events']} == set(condition['evidence_ids']),
                        'Condition event selection differs')
                for key in ('raw_log', 'seal', 'rules', 'internal_analysis', 'mapping', 'presentation'):
                    if document['provenance'].get(key):
                        check_ref(document['provenance'][key], log_dir)
                for event in document['events']:
                    original = events[event['event_id']]
                    for key in ('raw', 'context', 'source', 'sequence', 'stage', 'timestamp_utc'):
                        require(json.dumps(event[key], sort_keys=True) == json.dumps(original[key], sort_keys=True),
                                'Raw event data changed: ' + event['event_id'])
                    require(set(event['artifacts']) == set(original['artifacts']), 'Artifact selection differs')
                    for key, artifact in event['artifacts'].items():
                        descriptor = original['artifacts'][key]
                        check_ref(artifact['full_value'], log_dir)
                        for field in ('shape', 'dtype', 'sha256', 'bytes'):
                            require(artifact['full_value'][field] == descriptor[field], 'Artifact descriptor differs')
                verdicts[summary['condition_id']] = {'verdict': summary['verdict'], 'status': expected_status}
            if recompute:
                with tempfile.TemporaryDirectory(prefix='liemapp-publication-audit-') as temporary:
                    fresh = analyze(raw, rules_path, Path(temporary) / 'analysis')
                    for key in fresh:
                        if key != 'generated_at_utc':
                            require(json.dumps(fresh[key], sort_keys=True) == json.dumps(analysis[key], sort_keys=True),
                                    'Recomputed analysis differs: ' + key)
            else:
                fresh = analysis
            presentation, presentation_path = publication._checked_data(
                protocol['presentation'], fresh)
            mapping, mapping_path = publication._checked_data(
                resolve(engine['mapping'], root) if engine.get('mapping') else None, fresh, engine=True)
            supplement_paths = selected_supplements(engine, raw, root=root)
            supplements = publication._supplements(supplement_paths, fresh)
            targets = {c['id']: log_dir / f"{attack['label']}-{c['id']}-{engine['label']}-LogFile.json"
                       for c in rules['conditions']}
            report_path = report_dir / next(iter(expected_reports))
            rebuilt, report_text = publication.render_documents(fresh,
                targets=targets, report_path=report_path, presentation=presentation,
                presentation_path=presentation_path, mapping=mapping, mapping_path=mapping_path,
                internal_file=internal / 'analysis.json', internal_sha256=digest(internal / 'analysis.json'),
                supplements=supplements, attack_label=attack['label'], engine_label=engine['label'])
            for document in rebuilt:
                path = targets[document['summary']['condition_id']]
                require(json.dumps(document, sort_keys=True) == json.dumps(read(path), sort_keys=True),
                        'Public JSON differs from reconstructed evidence: ' + path.name)
            require(report_path.read_text(encoding='utf-8') == report_text,
                    'Public Markdown differs from reconstructed evidence: ' + report_path.name)
            outputs.append({'attack': attack_id, 'engine': engine_id, 'report_count': 1,
                            'condition_file_count': len(expected_logs), 'conditions': verdicts,
                            'source_log_sha256': package.seal['events_sha256'],
                            'recomputed_with_unchanged_analyzer': recompute,
                            'public_documents_reconstructed': True})
    return {'status': 'verified', 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
            'referenced_files_hash_checked': len(checked_hashes), 'outputs': outputs,
            'notice': 'Layout and evidence consistency audit, not an attack success or security certification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('experiments.json'))
    parser.add_argument('--recompute', action='store_true', help='Re-run every condition using the original Analyzer')
    parser.add_argument('--output', type=Path, help='Optional NEW audit JSON, outside public report/LogFile')
    args = parser.parse_args()
    if args.output:
        destination = args.output.resolve()
        for public in (ROOT / 'report', ROOT / 'LieMappAnalyzer/LogFile'):
            require(not destination.is_relative_to(public), 'Keep audits outside the public result directories')
        require(not destination.exists(), 'Audit output already exists')
    result = audit(load_config(args.config), recompute=args.recompute)
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x', encoding='utf-8') as stream:
            stream.write(text)
    print(text, end='')


if __name__ == '__main__':
    main()
