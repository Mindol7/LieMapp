"""Read-only CLI regressions; never run engines or publish research outputs."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from internal import workflow


class CheckTests(unittest.TestCase):
    def run_check(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(workflow, 'main', side_effect=AssertionError('Workflow invoked')) as main, \
                patch.object(subprocess, 'run', side_effect=AssertionError('Command executed')) as run, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            # Import under the guards so even a directly imported runner is caught.
            spec = importlib.util.spec_from_file_location('check_test_target', ROOT / 'check.py')
            check = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(check)
            result = check.main(argv)
        main.assert_not_called()
        run.assert_not_called()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_default_listing_is_data_only(self):
        config = json.loads((ROOT / 'internal/experiments.json').read_text(encoding='utf-8'))
        expected = {
            attack: [{'id': engine, 'label': row['label'], 'can_execute': 'execute' in row}
                     for engine, row in item['engines'].items()]
            for attack, item in config['attacks'].items()
        }
        result, stdout, stderr = self.run_check(['--list'])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout), expected)
        self.assertEqual(stderr, '')

    def test_custom_config_lists_labels_and_registered_commands(self):
        config = {'schema_version': '1.0.0', 'attacks': {
            'synthetic': {'engines': {
                'registered': {'label': '등록된 엔진', 'execute': {}},
                'read-only': {'label': 'Evidence only'},
            }},
            'second': {'engines': {'another': {'label': 'Another engine'}}},
        }}
        expected = {
            'synthetic': [
                {'id': 'registered', 'label': '등록된 엔진', 'can_execute': True},
                {'id': 'read-only', 'label': 'Evidence only', 'can_execute': False},
            ],
            'second': [{'id': 'another', 'label': 'Another engine', 'can_execute': False}],
        }
        with tempfile.TemporaryDirectory(prefix='liemapp-check-config-') as temporary:
            path = Path(temporary) / 'custom.json'
            contents = json.dumps(config, ensure_ascii=False)
            path.write_text(contents, encoding='utf-8')
            result, stdout, stderr = self.run_check(['--list', '--config', str(path)])
            self.assertEqual(path.read_text(encoding='utf-8'), contents)
            self.assertEqual(list(Path(temporary).iterdir()), [path])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout), expected)
        self.assertIn('등록된 엔진', stdout)
        self.assertEqual(stderr, '')

    def test_missing_config_returns_two_without_traceback(self):
        with tempfile.TemporaryDirectory(prefix='liemapp-check-missing-') as temporary:
            path = Path(temporary) / 'missing.json'
            result, stdout, stderr = self.run_check(['--list', '--config', str(path)])
            self.assertFalse(path.exists())
        self.assertEqual(result, 2)
        self.assertEqual(stdout, '')
        self.assertIn('missing.json', stderr)
        self.assertNotIn('Traceback', stderr)

    def test_bad_config_returns_two_without_traceback(self):
        with tempfile.TemporaryDirectory(prefix='liemapp-check-invalid-') as temporary:
            path = Path(temporary) / 'invalid.json'
            for contents in ('{not valid json', '{"schema_version": "invalid", "attacks": {}}'):
                with self.subTest(contents=contents):
                    path.write_text(contents, encoding='utf-8')
                    result, stdout, stderr = self.run_check(['--list', '--config', str(path)])
                    self.assertEqual(result, 2)
                    self.assertEqual(stdout, '')
                    self.assertTrue(stderr.strip())
                    self.assertNotIn('Traceback', stderr)
                    self.assertEqual(path.read_text(encoding='utf-8'), contents)

    def test_no_arguments_print_help_without_loading_config(self):
        with patch.object(workflow, 'load_config', side_effect=AssertionError('Config loaded')):
            result, stdout, stderr = self.run_check([])
        self.assertEqual(result, 0)
        self.assertIn('usage:', stdout)
        self.assertIn('--list', stdout)
        self.assertIn('--config', stdout)
        self.assertEqual(stderr, '')

    def test_none_argv_reads_process_arguments(self):
        with patch.object(sys, 'argv', ['check.py', '--list']):
            result, stdout, stderr = self.run_check(None)
        self.assertEqual(result, 0)
        self.assertIsInstance(json.loads(stdout), dict)
        self.assertEqual(stderr, '')

    def test_mutating_flags_are_rejected(self):
        for flag in ('--execute', '--replace'):
            for argv in ([flag], ['--list', flag]):
                with self.subTest(argv=argv), self.assertRaises(SystemExit) as caught:
                    self.run_check(argv)
                self.assertEqual(caught.exception.code, 2)

    def test_unrelated_cwd_and_stdlib_only_listing_match_developer(self):
        with tempfile.TemporaryDirectory(prefix='liemapp-check-cwd-') as temporary:
            outputs = []
            for script in ('check.py', 'developer.py'):
                with self.subTest(script=script):
                    completed = subprocess.run(
                        [sys.executable, '-B', '-S', str(ROOT / script), '--list'],
                        cwd=temporary, capture_output=True, text=True, timeout=30, check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stderr, '')
                    self.assertIsInstance(json.loads(completed.stdout), dict)
                    outputs.append(completed.stdout)
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
