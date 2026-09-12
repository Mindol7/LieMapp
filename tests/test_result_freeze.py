"""Synthetic index tests; no files are written into research LogFile/report."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


logger = load('index_test_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
analyzer = load('index_test_analyzer', ROOT / 'LieMappAnalyzer/analyzer.py')
freeze = load('index_test_freeze', ROOT / 'LieMappBench/Attack-Execution-Dataset/attack-script/siai/shared/freeze_results.py')


class ResultFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='liemapp-index-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / 'rules.json'
        self.rules.write_text(json.dumps({
            'attack_id': 'siai', 'attack_name': 'SYNTHETIC index test, NOT a research result',
            'library': {'path': 'synthetic.xlsx', 'sha256': '0' * 64},
            'conditions': [{'id': 'AC1', 'kind': 'AC', 'text': 'Synthetic condition',
                'source_cell': 'A1', 'rule': {'op': 'compare', 'select': {'stage': 'synthetic'},
                    'field': 'raw.ok', 'cmp': 'eq', 'value': True}}]
        }), encoding='utf-8')

    def result(self, status='completed'):
        with logger.Logger(self.root / 'run', {'attack_id': 'siai',
                'engine': {'id': 'synthetic-engine'}, 'execution_scope': 'synthetic_unit_test'}) as writer:
            writer.emit('synthetic', {'ok': True})
            writer.close(status, reason='Synthetic blocked test' if status == 'blocked' else None)
        self.report_dir = self.root / 'report'
        result = analyzer.analyze(self.root / 'run/events.jsonl', self.rules, self.report_dir)
        self.path = self.report_dir / 'analysis.json'
        return result

    def save_modified(self, result):
        self.path.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')

    def test_valid_report_is_recomputed(self):
        original = self.result()
        self.assertEqual(freeze.verify_analysis(analyzer, self.path), original)

    def test_blocked_report_remains_unknown(self):
        self.result(status='blocked')
        self.assertIsNone(freeze.verify_analysis(analyzer, self.path)['conditions'][0]['value'])

    def test_changed_verdict_and_summary_rejected_despite_valid_log(self):
        result = self.result()
        result['conditions'][0]['value'] = False
        result['summary']['AC'].update(true=0, false=1)
        self.save_modified(result)
        with self.assertRaisesRegex(ValueError, 'differs from recomputation'):
            freeze.verify_analysis(analyzer, self.path)

    def test_changed_rule_snapshot_or_integrity_rejected(self):
        original = self.result()
        for field in ('rule_snapshot', 'integrity'):
            with self.subTest(field=field):
                result = copy.deepcopy(original)
                result[field] = {}
                self.save_modified(result)
                with self.assertRaisesRegex(ValueError, 'differs from recomputation'):
                    freeze.verify_analysis(analyzer, self.path)

    def test_markdown_must_match_analysis_exactly(self):
        self.result()
        with (self.report_dir / 'report.md').open('a', encoding='utf-8') as stream:
            stream.write('\nUnsupported extra verdict\n')
        with self.assertRaisesRegex(ValueError, 'Markdown report differs'):
            freeze.verify_analysis(analyzer, self.path)

    def test_foreign_attack_rejected(self):
        result = self.result()
        result['attack_id'] = 'different-attack'
        self.save_modified(result)
        with self.assertRaisesRegex(ValueError, 'SIAI only'):
            freeze.verify_analysis(analyzer, self.path)

    def test_verdict_integer_cannot_replace_boolean(self):
        result = self.result()
        result['conditions'][0]['value'] = 1
        self.save_modified(result)
        with self.assertRaisesRegex(ValueError, 'differs from recomputation'):
            freeze.verify_analysis(analyzer, self.path)

    def test_pretty_json_must_preserve_raw_types(self):
        self.result()
        package = analyzer.EvidencePackage(self.root / 'run/events.jsonl')
        freeze.verify_readable_views(analyzer, package)
        pretty = copy.deepcopy(package.events)
        pretty[0]['raw']['ok'] = 1
        (package.root / 'events.pretty.json').write_text(json.dumps(pretty), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'events.pretty.json differs'):
            freeze.verify_readable_views(analyzer, package)

    def test_readable_run_metadata_must_match(self):
        self.result()
        package = analyzer.EvidencePackage(self.root / 'run/events.jsonl')
        metadata = copy.deepcopy(package.metadata)
        metadata['engine']['id'] = 'unsupported-relabel'
        (package.root / 'run.json').write_text(json.dumps(metadata), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'run.json differs'):
            freeze.verify_readable_views(analyzer, package)


if __name__ == '__main__':
    unittest.main()
