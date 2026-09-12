"""Synthetic final-audit tests; production research evidence is never touched."""
import importlib.util
import json
from pathlib import Path
import unittest

import test_publication as fixture

PATH = Path(__file__).resolve().parents[1] / 'internal/verify_publication.py'
spec = importlib.util.spec_from_file_location('publication_audit_test', PATH)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


class PublicAuditTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.PublicationTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        c = self.case
        c.logs = c.root / 'LieMappAnalyzer/LogFile/synthetic-attack/engine-a'
        c.reports = c.root / 'report/synthetic-attack/engine-a'
        c.internal = c.root / '.evidence/analyses/synthetic-attack/engine-a/synthetic-publication'
        self.manifest = c.publish()
        self.current = c.root / '.evidence/current/synthetic-attack/engine-a.json'
        self.current.parent.mkdir(parents=True)
        self.selection = {'attack_id': 'synthetic-attack', 'engine_id': 'engine-a',
                          'source_log': str(c.log_path), 'source_log_sha256': fixture.publication._hash(c.log_path),
                          'publication_id': 'synthetic-publication'}
        self.current.write_text(json.dumps(self.selection))
        self.config = {'attacks': {'synthetic-attack': {'label': 'synthetic-attack',
                       'rules': str(c.rules_path), 'engines': {'engine-a': {'label': 'engine-a'}}}}}

    def test_valid_output_and_full_recomputation(self):
        result = audit_module.audit(self.config, root=self.case.root, recompute=True)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['outputs'][0]['condition_file_count'], 6)
        self.assertEqual(result['outputs'][0]['report_count'], 1)

    def test_extra_report_is_rejected(self):
        (self.case.reports / 'old-Report.md').write_text('synthetic old result')
        with self.assertRaisesRegex(ValueError, 'Unexpected report files'):
            audit_module.audit(self.config, root=self.case.root)

    def test_saved_source_hash_mismatch_is_rejected(self):
        self.selection['source_log_sha256'] = 'b' * 64
        self.current.write_text(json.dumps(self.selection))
        with self.assertRaises(ValueError):
            audit_module.audit(self.config, root=self.case.root)

    def test_changed_raw_value_rejected_even_with_rehashed_public_file(self):
        path = self.case.logs / 'synthetic-attack-AC1-engine-a-LogFile.json'
        document = json.loads(path.read_text())
        document['events'][0]['raw']['ok'] = False
        path.write_text(json.dumps(document))
        for item in self.manifest['files']:
            if item['path'] == str(path):
                item['sha256'] = fixture.publication._hash(path)
        (self.case.internal / 'publication.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, 'Raw event data changed'):
            audit_module.audit(self.config, root=self.case.root)

    def refresh_public_hash(self, path):
        for item in self.manifest['files']:
            if item['path'] == str(path):
                item['sha256'] = fixture.publication._hash(path)
        (self.case.internal / 'publication.json').write_text(json.dumps(self.manifest))

    def test_rehashed_measurement_tampering_is_rejected(self):
        path = self.case.logs / 'synthetic-attack-AC1-engine-a-LogFile.json'
        document = json.loads(path.read_text())
        document['measurements']['items'][0]['actual_value'] = 'fabricated measurement'
        path.write_text(json.dumps(document))
        self.refresh_public_hash(path)
        with self.assertRaisesRegex(ValueError, 'Public JSON differs'):
            audit_module.audit(self.config, root=self.case.root, recompute=True)

    def test_rehashed_markdown_tampering_is_rejected(self):
        path = self.case.reports / 'synthetic-attack-engine-a-Report.md'
        path.write_text('All attacks succeeded. SYNTHETIC MALFORMED TEST ONLY')
        self.refresh_public_hash(path)
        with self.assertRaisesRegex(ValueError, 'Public Markdown differs'):
            audit_module.audit(self.config, root=self.case.root, recompute=True)


if __name__ == '__main__':
    unittest.main()
