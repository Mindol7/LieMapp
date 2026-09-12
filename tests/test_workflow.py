"""Synthetic tests for the shared entry point; no engine is executed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workflow_test_target', ROOT / 'internal/workflow.py')
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class WorkflowTests(unittest.TestCase):
    def test_real_config_has_five_unique_engines_and_labels(self):
        engines = workflow.load_config(ROOT / 'internal/experiments.json')['attacks']['siai']['engines']
        self.assertEqual(len(engines), 5)
        self.assertEqual(len({e['label'] for e in engines.values()}), 5)
        for item in engines.values():
            self.assertTrue(workflow.resolve(item['source_log']).is_file())

    def test_path_traversal_identifiers_are_rejected(self):
        for value in ('../escape', '/absolute', '', 'a/b', '.hidden'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                workflow.identifier(value)

    def test_execution_is_argument_list_not_shell(self):
        execution = {'command': ['{python}', '{root}/runner.py', '--id', '{run_id}', 'literal;not-a-shell']}
        args = workflow.build_command(execution, run_id='synthetic-001', python='/safe/python', root=Path('/safe/root'))
        self.assertEqual(args, ['/safe/python', '/safe/root/runner.py', '--id', 'synthetic-001', 'literal;not-a-shell'])
        with self.assertRaises(ValueError):
            workflow.build_command({'command': 'python runner.py'}, run_id='x')

    def test_investigator_cannot_execute(self):
        with self.assertRaises(SystemExit) as caught:
            workflow.main(['--execute'], actor='investigator')
        self.assertEqual(caught.exception.code, 2)

    def test_log_override_requires_single_engine(self):
        with self.assertRaises(SystemExit):
            workflow.main(['--log', 'not-opened.jsonl'])

    def test_pointer_is_atomic_and_only_selects_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'selection/current.json'
            workflow.save_current(path, {'source_log': '/first/events.jsonl'})
            workflow.save_current(path, {'source_log': '/second/events.jsonl'})
            self.assertEqual(json.loads(path.read_text()), {'source_log': '/second/events.jsonl'})
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_explicit_source_overrides_current_pointer(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'current.json'
            workflow.save_current(path, {'source_log': '/current/events.jsonl'})
            engine = {'source_log': '/configured/events.jsonl'}
            self.assertEqual(workflow.selected_source(engine, path), Path('/current/events.jsonl'))
            self.assertEqual(workflow.selected_source(engine, path, '/explicit/events.jsonl'), Path('/explicit/events.jsonl'))

    def test_listing_never_executes_a_command(self):
        with patch.object(workflow.subprocess, 'run') as run:
            self.assertEqual(workflow.main(['--list']), 0)
            run.assert_not_called()

    def test_saved_selection_checks_identity_path_and_bytes(self):
        record = {'attack_id': 'synthetic', 'engine_id': 'engine-a',
                  'source_log': '/evidence/events.jsonl', 'source_log_sha256': 'a' * 64}
        arguments = dict(attack_id='synthetic', engine_id='engine-a',
                         source_log=Path('/evidence/events.jsonl'), events_sha256='a' * 64)
        workflow.verify_selection(record, **arguments)
        for key, value in [('attack_id', 'other'), ('engine_id', 'other'),
                           ('source_log', '/different/events.jsonl'), ('source_log_sha256', 'b' * 64)]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                workflow.verify_selection({**record, key: value}, **arguments)

    def test_incomplete_saved_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            workflow.verify_selection({'source_log': '/evidence/events.jsonl'},
                attack_id='synthetic', engine_id='engine-a',
                source_log=Path('/evidence/events.jsonl'), events_sha256='a' * 64)


if __name__ == '__main__':
    unittest.main()
