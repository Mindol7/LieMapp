"""Synthetic contract tests; these are not native engine experiment results."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item


HERE = Path(__file__).resolve().parent
repeat = load('tested_repeat', HERE / 'verify_repeat.py')
common = load('repeat_fixture_logger', repeat.ROOT / 'LieMappBench/Logging-Dataset/logger.py')
analyzer = load('repeat_fixture_analyzer', repeat.ROOT / 'LieMappAnalyzer/analyzer.py')


class RepeatTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='liemapp-repeat-unit-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def package(self, name, *, change=None, ablation=False, duplicate=False,
                missing=None, status='completed', context_changes=None, metadata_changes=None):
        digest = common.sha256_file(Path(__file__))
        metadata = {'run_id': name, 'attack_id': 'siai', 'execution_scope': 'native_runtime',
                    'engine': {'id': 'synthetic-test-only', 'revision': 'test-revision',
                               'instrumented_file_sha256': {'test_repeat.py': digest}},
                    'model': {'name': 'synthetic-not-a-real-model', 'weights_sha256': 'a' * 64},
                    'runtime': {'device': 'synthetic', 'platform': 'unit-test', 'threads': 1},
                    'logger_sha256': digest, 'runner_sha256': digest}
        metadata.update(metadata_changes or {})
        logger = common.Logger(self.root / name, metadata, source_root=repeat.ROOT.parent, durable=False)
        prompt = 'Synthetic test prompt'
        context = {'request_id': name + '-request', 'evaluation': 'condition_audit', 'role': 'attack',
                   'base_role': 'attack', 'run_kind': 'normal', 'transform': 'original',
                   'isolated_process': True, 'input_id': 'input1', 'input_sha256': 'b' * 64,
                   'question_id': 'audit-default', 'prompt': prompt,
                   'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                   'seed': 42, 'temperature': 0.0, 'max_tokens': 2, 'model_revision': 'model-test-revision'}
        context.update(context_changes or {})
        roles = [False, True] if ablation else [False]
        for is_zero in roles:
            current = copy.deepcopy(context)
            if is_zero:
                current.update(request_id=name + '-ablation', run_kind='zero_visual_embeddings', role='ablation')
            for stage, artifact in repeat.STAGES:
                if stage == missing:
                    continue
                value = np.asarray([[1, 2], [3, 4]], dtype=np.uint8) if stage == 'input_received' else np.asarray([0., 1., 2.], dtype=np.float32)
                raw = {'status': 'success', 'returncode': 0}
                if stage == 'decoder_input':
                    raw['intervention'] = is_zero
                    if is_zero:
                        value = np.zeros_like(value)
                if stage == 'generation_output':
                    if is_zero:
                        value = value + 10
                    raw.update(first_step_logits_count=int(value.size), generated_text='one two',
                               token_ids=[1, 2], generated_token_count=2)
                if change is not None and not is_zero:
                    value, raw = change(stage, value, raw)
                source = {'path': str(Path(__file__).resolve()), 'function': 'package', 'line': 1,
                          'logging_point_id': 'test.' + stage}
                logger.emit(stage, raw, context=current, source=source, tensors={artifact: value})
                if duplicate and stage == 'generation_output' and not is_zero:
                    logger.emit(stage, raw, context=current, source=source, tensors={artifact: value})
        logger.close(status)
        return analyzer.EvidencePackage(self.root / name / 'events.jsonl')

    def test_exact_repeat_and_real_zero_ablation(self):
        result = repeat.compare_packages(self.package('reference', ablation=True), self.package('repeat'))
        self.assertTrue(result['repeat_identical'])
        self.assertEqual(result['canonical_ablation']['status'], 'measured')
        self.assertEqual(result['canonical_ablation']['repeat_logits_max_abs'], 0)
        self.assertEqual(result['canonical_ablation']['ablation_logits_max_abs'], 10)

    def test_measured_logits_change_is_not_hidden(self):
        def changed(stage, value, raw):
            return value + 1 if stage == 'generation_output' else value, raw
        result = repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))
        self.assertEqual(result['status'], 'measured')
        self.assertFalse(result['repeat_identical'])
        self.assertEqual(result['tensors']['generation_output']['max_abs_distance'], 1)

    def test_signed_zero_is_not_byte_identity(self):
        def changed(stage, value, raw):
            if stage == 'generation_output':
                value[0] = -0.0
            return value, raw
        result = repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))
        measurement = result['tensors']['generation_output']
        self.assertFalse(measurement['byte_identical'])
        self.assertEqual(measurement['max_abs_distance'], 0)

    def test_dtype_change_is_not_byte_identity(self):
        def changed(stage, value, raw):
            return value.astype(np.float64) if stage == 'generation_output' else value, raw
        result = repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))
        self.assertFalse(result['repeat_identical'])
        self.assertFalse(result['tensors']['generation_output']['dtype_identical'])

    def test_shape_mismatch_is_measured(self):
        def changed(stage, value, raw):
            return value.reshape(1, 3) if stage == 'generation_output' else value, raw
        result = repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))
        self.assertFalse(result['repeat_identical'])
        self.assertIsNone(result['tensors']['generation_output']['max_abs_distance'])

    def test_output_changes_are_measured(self):
        def changed(stage, value, raw):
            if stage == 'generation_output':
                raw.update(generated_text='one three', token_ids=[1, 3])
            return value, raw
        result = repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))
        self.assertFalse(result['repeat_identical'])
        self.assertFalse(result['outputs']['text_identical'])
        self.assertFalse(result['outputs']['tokens_identical'])

    def test_same_input_package_rejected(self):
        reference = self.package('reference')
        with self.assertRaisesRegex(repeat.ContractError, 'own repeat'):
            repeat.compare_packages(reference, reference)

    def test_duplicate_generation_rejected(self):
        with self.assertRaisesRegex(repeat.ContractError, 'exactly one generation_output'):
            repeat.compare_packages(self.package('reference'), self.package('repeat', duplicate=True))

    def test_missing_or_nonfresh_context_rejected(self):
        for index, changes in enumerate(({'isolated_process': False}, {'seed': None}, {'seed': True})):
            with self.subTest(changes=changes), self.assertRaises(repeat.ContractError):
                repeat.compare_packages(self.package(f'ref{index}'), self.package(f'rep{index}', context_changes=changes))

    def test_metadata_mismatch_rejected(self):
        with self.assertRaisesRegex(repeat.ContractError, 'source/model/runtime mismatch'):
            repeat.compare_packages(self.package('reference'), self.package('repeat', metadata_changes={'runner_sha256': 'c' * 64}))

    def test_full_logits_count_required(self):
        def changed(stage, value, raw):
            if stage == 'generation_output':
                raw['first_step_logits_count'] = 2
            return value, raw
        with self.assertRaisesRegex(repeat.ContractError, 'Full first-token logits'):
            repeat.compare_packages(self.package('reference'), self.package('repeat', change=changed))

    def test_missing_stage_saved_as_blocked_in_new_common_log(self):
        reference = self.package('reference')
        repeated = self.package('repeat', missing='projected_embedding')
        before = common.sha256_file(reference.path), common.sha256_file(repeated.path)
        result = repeat.verify(reference.path, repeated.path, 'validation', log_root=self.root / 'validations')
        self.assertEqual(result['status'], 'blocked')
        output = analyzer.EvidencePackage(Path(result['run_dir']) / 'events.jsonl')
        self.assertEqual(output.seal['status'], 'blocked')
        self.assertIsNone(output.events[0]['raw']['repeat_identical'])
        self.assertEqual(before, (common.sha256_file(reference.path), common.sha256_file(repeated.path)))

    def test_measured_difference_sealed_completed(self):
        reference = self.package('reference')
        def changed(stage, value, raw):
            return value + 1 if stage == 'generation_output' else value, raw
        repeated = self.package('repeat', change=changed)
        result = repeat.verify(reference.path, repeated.path, 'validation', log_root=self.root / 'validations')
        self.assertFalse(result['repeat_identical'])
        output = analyzer.EvidencePackage(Path(result['run_dir']) / 'events.jsonl')
        self.assertEqual(output.seal['status'], 'completed')
        self.assertEqual(output.events[0]['raw']['status'], 'measured')

    def test_tampered_repeat_sealed_blocked(self):
        reference, repeated = self.package('reference'), self.package('repeat')
        # Test-only mutation of our disposable synthetic evidence.
        rows = repeated.path.read_text().splitlines()
        event = json.loads(rows[-1]); event['raw']['generated_text'] = 'tampered'
        rows[-1] = json.dumps(event)
        repeated.path.write_text('\n'.join(rows) + '\n')
        result = repeat.verify(reference.path, repeated.path, 'validation', log_root=self.root / 'validations')
        self.assertEqual(result['status'], 'blocked')


if __name__ == '__main__':
    unittest.main()
