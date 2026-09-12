import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('common_test_logger', ROOT / 'LieMappBench/Logging-Dataset/logger.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class LoggerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'run'
        self.meta = {'attack_id': 'test_attack', 'engine': {'id': 'arbitrary_engine'}, 'execution_scope': 'native_runtime'}

    def test_exact_raw_artifact_and_hash_chain(self):
        original = np.arange(12, dtype=np.float32).reshape(3, 4)[:, ::2]
        with mod.Logger(self.path, self.meta) as logger:
            first = logger.emit('encoder_input', {'count': 3, 'active': True}, readable={'summary': '임베딩 원시값'}, tensors={'values': original})
            second = logger.emit('done', {'status': 'success'})
        self.assertEqual(first['raw'], {'count': 3, 'active': True})
        self.assertEqual(second['previous_event_hash'], first['event_hash'])
        digest = first['event_hash']
        self.assertEqual(digest, hashlib.sha256(mod.canonical({k: v for k, v in first.items() if k != 'event_hash'})).hexdigest())
        descriptor = first['artifacts']['values']
        actual = np.load(self.path / descriptor['path'], allow_pickle=False)
        np.testing.assert_array_equal(original, actual)
        self.assertEqual(descriptor['sha256'], mod.sha256_file(self.path / descriptor['path']))
        self.assertEqual(json.loads((self.path / 'seal.json').read_text())['event_count'], 2)
        self.assertEqual(json.loads((self.path / 'events.pretty.json').read_text())[0], first)

    def test_disabled_has_no_files_or_serialization(self):
        with mod.Logger(self.path, self.meta, enabled=False) as logger:
            self.assertIsNone(logger.emit('x', {'bad': object()}, tensors={'x': object()}))
        self.assertFalse(self.path.exists())

    def test_invalid_raw_and_tensors_rejected(self):
        with mod.Logger(self.path, self.meta) as logger:
            for raw in ({'x': float('nan')}, {'x': float('inf')}, {1: 'value'}, {'x': object()}):
                with self.assertRaises((ValueError, TypeError)):
                    logger.emit('x', raw)
            for array in (np.array([object()], dtype=object), np.array([np.inf]), np.array([]), np.array([1+2j])):
                with self.assertRaises(ValueError):
                    logger.emit('x', tensors={'values': array})
        self.assertEqual(json.loads((self.path / 'seal.json').read_text())['event_count'], 0)
        self.assertEqual(list((self.path / 'artifacts').iterdir()), [])

    def test_no_overwrite_and_no_emit_after_seal(self):
        logger = mod.Logger(self.path, self.meta)
        with self.assertRaises(FileExistsError):
            mod.Logger(self.path, self.meta)
        logger.close('blocked', reason='missing runtime')
        self.assertEqual(logger.close()['status'], 'blocked')
        with self.assertRaises(RuntimeError):
            logger.emit('late', {})

    def test_source_hash_and_scope(self):
        source = Path(self.temp.name) / 'hook.py'
        source.write_text('pass\n')
        data = {'path': str(source), 'function': 'hook', 'line': 1, 'logging_point_id': 'lp1'}
        with mod.Logger(self.path, self.meta, source_root=self.temp.name) as logger:
            event = logger.emit('x', source=data)
            self.assertEqual(event['source']['sha256'], mod.sha256_file(source))
            with self.assertRaises(ValueError):
                logger.emit('x', source={**data, 'path': __file__})

    def test_multithreaded_single_sequence(self):
        with mod.Logger(self.path, self.meta, durable=False) as logger:
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda n: logger.emit('x', {'n': n}), range(80)))
        records = [json.loads(s) for s in (self.path / 'events.jsonl').read_text().splitlines()]
        self.assertEqual([r['sequence'] for r in records], list(range(1, 81)))
        self.assertEqual(len({r['event_id'] for r in records}), 80)

    def test_native_protocol_and_python_client_share_writer(self):
        value = np.array([[1.25, -2.5]], dtype='<f4')
        with mod.Logger(self.path, self.meta) as logger:
            with mod.Collector(logger) as collector:
                mod.Client(collector.socket_path).emit('python_hook', {'returncode': 0}, tensors={'values': value})
                packet = {'stage': 'native_hook', 'raw': {'returncode': 0}, 'context': {}, 'source': None,
                          'tensors': [{'name': 'values', 'dtype': 'float32', 'shape': [1, 2],
                                       'data_base64': base64.b64encode(value.tobytes()).decode()}]}
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                    stream.connect(collector.socket_path)
                    stream.sendall(mod.canonical(packet) + b'\n')
                    self.assertTrue(json.loads(stream.makefile('rb').readline())['ok'])
        records = json.loads((self.path / 'events.pretty.json').read_text())
        self.assertEqual([r['stage'] for r in records], ['python_hook', 'native_hook'])
        self.assertEqual(set(records[0]), set(records[1]))
        for r in records:
            np.testing.assert_array_equal(np.load(self.path / r['artifacts']['values']['path'], allow_pickle=False), value)

    def test_rejected_wire_message_is_not_silent(self):
        with mod.Logger(self.path, self.meta) as logger:
            with self.assertRaises(RuntimeError):
                with mod.Collector(logger) as collector:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                        stream.connect(collector.socket_path)
                        stream.sendall(b'{"stage":"x","unknown":"field"}\n')
                        self.assertFalse(json.loads(stream.makefile('rb').readline())['ok'])

    def test_scalar_shape_and_64_bit_integer_fidelity(self):
        with mod.Logger(self.path, self.meta) as logger:
            event = logger.emit('x', {'integer': 2**62 + 7}, tensors={'values': np.array(2**62 + 7, dtype=np.int64)})
        value = np.load(self.path / event['artifacts']['values']['path'], allow_pickle=False)
        self.assertEqual(value.shape, ())
        self.assertEqual(value.item(), 2**62 + 7)


if __name__ == '__main__':
    unittest.main()
