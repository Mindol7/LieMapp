"""Small local tests of readiness sealing and safe replay argument handling."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from finalize_readiness import sealed_events
from record_command import common


def test_valid_sealed_setup_is_not_native_evidence(tmp_path):
    writer = common()
    directory = tmp_path / 'setup'
    with writer.Logger(directory, {'attack_id': 'siai', 'engine': {'id': 'mlc-llm'},
                                  'execution_scope': 'preflight'}) as log:
        log.emit('readiness_result', {'ready': False, 'native_request_count': 0})
        log.close('blocked', reason='Compiler failed before model execution')
    events, seal = sealed_events(directory, writer)
    assert seal['status'] == 'blocked'
    assert events[0]['metadata']['execution_scope'] == 'preflight'
    assert events[0]['raw']['native_request_count'] == 0


def test_changed_event_bytes_fail_seal(tmp_path):
    writer = common()
    directory = tmp_path / 'setup'
    with writer.Logger(directory, {'attack_id': 'siai', 'engine': {'id': 'mlc-llm'}}) as log:
        log.emit('readiness_result', {'ready': False})
    path = directory / 'events.jsonl'
    path.write_text(path.read_text().replace('"ready":false', '"ready":true'))
    with pytest.raises(ValueError, match='Seal mismatch'):
        sealed_events(directory, writer)


@pytest.mark.parametrize('run_id', ['../escape', 'with/slash', '..', 'with space'])
def test_replay_rejects_unsafe_run_id_before_writes(run_id):
    result = subprocess.run([sys.executable, HERE / 'reproduce_compile.py', '--run-id', run_id],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert 'run-id must contain' in result.stderr


def test_replay_unknown_variant_is_rejected():
    result = subprocess.run([sys.executable, HERE / 'reproduce_compile.py', '--run-id', 'test-only',
                             '--variant', 'fake-cuda'], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'invalid choice' in result.stderr
