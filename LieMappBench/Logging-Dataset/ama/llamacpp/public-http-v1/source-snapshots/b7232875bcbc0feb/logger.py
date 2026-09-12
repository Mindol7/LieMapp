"""One evidence writer for all LieMapp engines, including native clients.

Python hooks call Logger.emit, or Client.emit while a Collector is running.
C/C++ hooks send the same NDJSON message to the private Unix-domain socket.
Only this module writes final events, numeric artifacts, and the final seal.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any
import uuid

SCHEMA_VERSION = '1.0.0'
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _plain(value: Any) -> Any:
    """Reject non-JSON objects, non-string keys and non-finite numbers."""
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError('JSON object keys must be strings')
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if value is None or type(value) in (bool, int, float, str):
        canonical(value)
        return value
    raise TypeError(f'Explicitly convert {type(value).__name__} to a JSON value or numeric tensor')


def _new_json(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


class Logger:
    """An exclusive run writer. Existing run directories are never overwritten.

    Metadata must include attack_id and engine.id. Set execution_scope accurately
    (native_runtime, structural_probe, preflight, or static_review). Disabled
    instances do not create directories, serialize data, or persist artifacts.
    """
    def __init__(self, run_dir: str | Path, metadata: dict, *, enabled: bool = True,
                 durable: bool = True, source_root: str | Path | None = None,
                 stages: set[str] | None = None):
        self.run_dir = Path(run_dir).absolute()
        self.enabled = enabled
        self.durable = durable
        self.source_root = Path(source_root).resolve() if source_root else None
        self.stages = stages
        self.metadata = _plain(copy.deepcopy(metadata))
        if not isinstance(self.metadata.get('attack_id'), str) or not self.metadata['attack_id']:
            raise ValueError('metadata.attack_id is required')
        engine = self.metadata.get('engine')
        if not isinstance(engine, dict) or not isinstance(engine.get('id'), str) or not engine['id']:
            raise ValueError('metadata.engine.id is required')
        self.metadata.setdefault('execution_scope', 'unspecified')
        self.run_id = self.metadata.get('run_id') or uuid.uuid4().hex
        if not isinstance(self.run_id, str) or not _NAME.fullmatch(self.run_id):
            raise ValueError('Invalid run_id')
        self.metadata['run_id'] = self.run_id
        self._lock = threading.RLock()
        self._sequence = 0
        self._last_hash = None
        self._closed = False
        self._stream = None
        self._records = []
        if self.enabled:
            self.run_dir.mkdir(parents=True, exist_ok=False)
            os.chmod(self.run_dir, 0o700)
            (self.run_dir / 'artifacts').mkdir(mode=0o700)
            self._stream = (self.run_dir / 'events.jsonl').open('x', encoding='utf-8')
            os.chmod(self.run_dir / 'events.jsonl', 0o600)
            _new_json(self.run_dir / 'run.json', self.metadata)

    def _source(self, source: dict | None) -> dict | None:
        if source is None:
            return None
        result = _plain(source)
        for field in ('path', 'function', 'logging_point_id'):
            if not isinstance(result.get(field), str) or not result[field]:
                raise ValueError(f'source.{field} is required')
        if type(result.get('line')) is not int or result['line'] < 1:
            raise ValueError('source.line must be a positive integer')
        path = Path(result['path'])
        if not path.is_absolute():
            path = (self.source_root or Path.cwd()) / path
        path = path.resolve(strict=True)
        if self.source_root and not path.is_relative_to(self.source_root):
            raise ValueError('Source is outside the configured source root')
        if not path.is_file():
            raise ValueError('Source must refer to a regular file')
        result['path'] = str(path)
        result['sha256'] = sha256_file(path)
        return result

    def _save_tensor(self, name: str, array: Any) -> dict:
        import numpy as np
        if not _NAME.fullmatch(name):
            raise ValueError('Invalid tensor name')
        array = np.asarray(array)
        if array.dtype.kind not in 'biuf' or array.dtype.hasobject:
            raise ValueError('Only real numeric/bool tensors are allowed')
        if array.size == 0 or not np.isfinite(array).all():
            raise ValueError('Tensor must be nonempty and finite')
        if not array.flags.c_contiguous:
            array = array.copy(order='C')
        path = self.run_dir / 'artifacts' / f'{uuid.uuid4().hex}-{name}.npy'
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            np.save(stream, array, allow_pickle=False)
            stream.flush()
            if self.durable:
                os.fsync(stream.fileno())
        flat = array.reshape(-1)
        return {'path': path.relative_to(self.run_dir).as_posix(),
                'sha256': sha256_file(path), 'dtype': str(array.dtype),
                'shape': list(array.shape), 'bytes': path.stat().st_size,
                'raw_nbytes': array.nbytes, 'format': 'npy',
                'preview': flat[:8].tolist(), 'min': flat.min().item(), 'max': flat.max().item(),
                'meaning': 'Lossless raw tensor; preview is not the complete value'}

    def emit(self, stage: str, raw: dict | None = None, *, readable: dict | None = None,
             context: dict | None = None, source: dict | None = None,
             tensors: dict | list | None = None) -> dict | None:
        if not self.enabled or (self.stages is not None and stage not in self.stages):
            return None
        if not isinstance(stage, str) or not _NAME.fullmatch(stage):
            raise ValueError('Invalid stage')
        raw = _plain(raw if raw is not None else {})
        readable = _plain(readable if readable is not None else {})
        context = _plain(context if context is not None else {})
        if not all(isinstance(item, dict) for item in (raw, readable, context)):
            raise ValueError('raw, readable and context must be objects')
        source = self._source(source)
        # Native clients provide lossless base64 buffers; Python hooks may provide arrays.
        arrays = {}
        if isinstance(tensors, list):
            import numpy as np
            for tensor in tensors:
                name = tensor['name']
                if name in arrays:
                    raise ValueError('Duplicate tensor name')
                dtype = np.dtype(tensor['dtype'])
                if dtype.kind not in 'biuf' or dtype.hasobject:
                    raise ValueError('Invalid wire tensor dtype')
                shape = tensor['shape']
                if not isinstance(shape, list) or len(shape) > 16 or any(type(n) is not int or n < 1 for n in shape):
                    raise ValueError('Invalid tensor shape')
                count = 1
                for n in shape:
                    count *= n
                if count * dtype.itemsize > MAX_MESSAGE_BYTES:
                    raise ValueError('Tensor exceeds the transport limit')
                buffer = base64.b64decode(tensor['data_base64'], validate=True)
                if len(buffer) != count * dtype.itemsize:
                    raise ValueError('Tensor byte length does not match dtype/shape')
                # Native wire representation is explicitly little endian.
                arrays[name] = np.frombuffer(buffer, dtype=dtype.newbyteorder('<')).reshape(shape)
        elif isinstance(tensors, dict):
            arrays = tensors
        elif tensors is not None:
            raise ValueError('tensors must be a name/array map or wire-tensor list')
        with self._lock:
            if self._closed:
                raise RuntimeError('Run is sealed')
            artifacts = {}
            try:
                for name, array in arrays.items():
                    artifacts[name] = self._save_tensor(name, array)
                event = {'schema_version': SCHEMA_VERSION, 'event_id': uuid.uuid4().hex,
                         'run_id': self.run_id, 'sequence': self._sequence + 1,
                         'timestamp_utc': datetime.now(timezone.utc).isoformat(timespec='microseconds'),
                         'monotonic_ns': time.monotonic_ns(), 'metadata': copy.deepcopy(self.metadata),
                         'stage': stage, 'context': context, 'source': source,
                         'raw': raw, 'readable': readable, 'artifacts': artifacts,
                         'previous_event_hash': self._last_hash}
                event['event_hash'] = hashlib.sha256(canonical(event)).hexdigest()
                self._stream.write(canonical(event).decode('utf-8') + '\n')
                self._stream.flush()
                if self.durable:
                    os.fsync(self._stream.fileno())
                self._sequence += 1
                self._last_hash = event['event_hash']
                self._records.append(event)
                return copy.deepcopy(event)
            except Exception:
                # Artifacts of a rejected event are our new files, never user files.
                for descriptor in artifacts.values():
                    (self.run_dir / descriptor['path']).unlink(missing_ok=True)
                raise

    def close(self, status: str = 'completed', *, reason: str | None = None) -> dict | None:
        if status not in ('completed', 'failed', 'blocked'):
            raise ValueError('Invalid completion status')
        if not self.enabled:
            return None
        with self._lock:
            if self._closed:
                return json.loads((self.run_dir / 'seal.json').read_text(encoding='utf-8'))
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            seal = {'schema_version': SCHEMA_VERSION, 'run_id': self.run_id,
                    'event_count': self._sequence, 'last_event_hash': self._last_hash,
                    'status': status, 'reason': reason,
                    'events_sha256': sha256_file(self.run_dir / 'events.jsonl')}
            _new_json(self.run_dir / 'events.pretty.json', self._records)
            _new_json(self.run_dir / 'seal.json', seal)
            self._closed = True
            return seal

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close('failed' if exc else 'completed', reason=str(exc) if exc else None)


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False
    block_on_close = True


class Collector:
    """Private, acknowledged, local transport into the single Logger writer."""
    def __init__(self, logger: Logger):
        self.logger = logger
        self.socket_path = None
        self.errors = []
        self._temp = None
        self._server = None
        self._thread = None

    def __enter__(self):
        if not self.logger.enabled:
            raise ValueError('Cannot serve a disabled logger')
        collector = self
        self._temp = tempfile.TemporaryDirectory(prefix='liemapp-collector-')
        self.socket_path = str(Path(self._temp.name) / 'events.sock')

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(60)
                while True:
                    line = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
                    if not line:
                        return
                    try:
                        if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b'\n'):
                            raise ValueError('Oversized or incomplete message')
                        data = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
                        if not isinstance(data, dict) or set(data) - {'stage', 'raw', 'readable', 'context', 'source', 'tensors'}:
                            raise ValueError('Unexpected message fields')
                        event = collector.logger.emit(**data)
                        reply = {'ok': True, 'event_id': event['event_id'] if event else None}
                    except Exception as exc:
                        collector.errors.append(f'{type(exc).__name__}: {exc}')
                        reply = {'ok': False, 'error': collector.errors[-1]}
                    self.wfile.write(canonical(reply) + b'\n')
                    self.wfile.flush()
                    if not reply['ok']:
                        return

        self._server = _Server(self.socket_path, Handler)
        os.chmod(self.socket_path, 0o600)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._temp.cleanup()
        if self.errors and exc is None:
            raise RuntimeError('Evidence collector rejected messages: ' + '; '.join(self.errors[:3]))


class Client:
    def __init__(self, socket_path: str | None = None, *, enabled: bool = True):
        self.socket_path = socket_path or os.environ.get('LIEMAPP_SOCKET')
        self.enabled = enabled

    def emit(self, stage: str, raw: dict | None = None, *, readable: dict | None = None,
             context: dict | None = None, source: dict | None = None, tensors: dict | None = None):
        if not self.enabled or not self.socket_path:
            return None
        message = {'stage': stage, 'raw': raw or {}, 'readable': readable or {},
                   'context': context if context is not None else json.loads(os.environ.get('LIEMAPP_CONTEXT_JSON', '{}')),
                   'source': source, 'tensors': []}
        if tensors:
            import numpy as np
            for name, value in tensors.items():
                array = np.asarray(value)
                if array.dtype.kind not in 'biuf' or array.dtype.hasobject:
                    raise ValueError('Invalid tensor dtype')
                array = array.astype(array.dtype.newbyteorder('<'), copy=False)
                if not array.flags.c_contiguous:
                    array = array.copy(order='C')
                message['tensors'].append({'name': name, 'dtype': str(array.dtype),
                                          'shape': list(array.shape),
                                          'data_base64': base64.b64encode(array.tobytes()).decode('ascii')})
        payload = canonical(_plain(message)) + b'\n'
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ValueError('Message exceeds transport limit')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(60)
            stream.connect(self.socket_path)
            stream.sendall(payload)
            with stream.makefile('rb') as reply_stream:
                reply = json.loads(reply_stream.readline(65536))
        if not reply.get('ok'):
            raise RuntimeError(reply.get('error', 'Collector rejected event'))
        return reply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True, help='Metadata JSON, never a previous log')
    parser.add_argument('--source-root', type=Path)
    args = parser.parse_args()
    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    with Logger(args.run_dir, json.loads(args.metadata.read_text(encoding='utf-8')), source_root=args.source_root) as logger:
        with Collector(logger) as collector:
            print(json.dumps({'socket_path': collector.socket_path, 'run_dir': str(logger.run_dir)}), flush=True)
            while not stopped.wait(0.25):
                pass


if __name__ == '__main__':
    main()
