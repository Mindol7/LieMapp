"""Relocation regressions; never execute an engine or rewrite research outputs."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / 'internal'


def load_module(name):
    spec = importlib.util.spec_from_file_location('internal_layout_test_' + name,
                                                INTERNAL / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalLayoutTests(unittest.TestCase):
    def test_support_files_are_colocated(self):
        for filename in ('prepare_siai_supplements.py', 'publication-schema.md',
                         'publication.py', 'verify_publication.py', 'workflow.py',
                         'experiments.json'):
            with self.subTest(filename=filename):
                self.assertTrue((INTERNAL / filename).is_file())

    def test_project_root_and_evidence_paths_do_not_move(self):
        workflow = load_module('workflow')
        self.assertEqual(workflow.ROOT, ROOT)
        self.assertEqual(workflow.resolve('.evidence/raw'), ROOT / '.evidence/raw')
        self.assertEqual(load_module('verify_publication').ROOT, ROOT)
        self.assertEqual(load_module('prepare_siai_supplements').ROOT, ROOT)

    def test_publisher_still_uses_the_common_analyzer(self):
        publication = load_module('publication')
        self.assertEqual(Path(publication.analyzer.__file__).resolve(),
                         ROOT / 'LieMappAnalyzer/analyzer.py')

    def test_entry_points_find_default_config_from_an_unrelated_cwd(self):
        config = json.loads((INTERNAL / 'experiments.json').read_text(encoding='utf-8'))
        expected = {attack: {engine for engine in item['engines']}
                    for attack, item in config['attacks'].items()}
        with tempfile.TemporaryDirectory(prefix='liemapp-entrypoint-unit-') as temporary:
            for script in ('developer.py', 'investigator.py', 'internal/workflow.py'):
                with self.subTest(script=script):
                    completed = subprocess.run([sys.executable, str(ROOT / script), '--list'],
                        cwd=temporary, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                        capture_output=True, text=True, timeout=30, check=False)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    listed = json.loads(completed.stdout)
                    self.assertEqual({attack: {engine['id'] for engine in engines}
                                      for attack, engines in listed.items()}, expected)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_publication_cli_imports_from_an_unrelated_cwd(self):
        with tempfile.TemporaryDirectory(prefix='liemapp-internal-cli-unit-') as temporary:
            for script in ('publication.py', 'verify_publication.py'):
                with self.subTest(script=script):
                    completed = subprocess.run([sys.executable, str(INTERNAL / script), '--help'],
                        cwd=temporary, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                                            'OPENBLAS_NUM_THREADS': '1'},
                        capture_output=True, text=True, timeout=30, check=False)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn('--help', completed.stdout)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_audit_default_config_is_in_internal(self):
        audit_module = load_module('verify_publication')
        with patch.object(sys, 'argv', ['verify_publication.py']), \
                patch.object(audit_module, 'load_config', wraps=audit_module.load_config) as load, \
                patch.object(audit_module, 'audit', return_value={'status': 'synthetic'}) as audit, \
                contextlib.redirect_stdout(io.StringIO()):
            audit_module.main()
        load.assert_called_once_with(INTERNAL / 'experiments.json')
        audit.assert_called_once()

    def test_supplement_preparation_imports_common_analyzer(self):
        supplements = load_module('prepare_siai_supplements')
        with tempfile.TemporaryDirectory(prefix='liemapp-supplement-import-unit-') as temporary:
            with patch.object(supplements, 'ROOT', Path(temporary)), \
                    patch.object(supplements, 'CONFIG', []):
                supplements.main()
            output = Path(temporary) / '.evidence/supplements/siai'
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
