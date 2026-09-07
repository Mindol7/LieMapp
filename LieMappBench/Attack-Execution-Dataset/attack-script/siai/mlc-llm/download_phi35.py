"""Acquire the explicitly approved, pinned official MLC Phi-3.5 Vision model.

No remote Python model code is executed. Every repository file is validated
against official API size and LFS SHA-256 / Git blob SHA-1 before reuse.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import time
import urllib.request

from record_command import ROOT, common, source

MODEL_ID = 'mlc-ai/Phi-3.5-vision-instruct-q4f32_1-MLC'
PIN = '2d7104ab34b358b4223aabca1d08e451c6b12728'
DEST = ROOT / 'Instrumented-LIE/siai/mlc-llm/models/Phi-3.5-vision-instruct-q4f32_1-MLC'
PROVENANCE = ROOT / 'LieMappBench/Attack-Execution-Dataset/attack-source/siai/mlc-llm/phi35-provenance'


def read_url(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        return response.read()


def validate(path, item):
    if not path.is_file() or path.stat().st_size != item['size']:
        return False
    sha = hashlib.sha256()
    git = hashlib.sha1(f"blob {item['size']}\0".encode())
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            sha.update(block)
            git.update(block)
    expected = item.get('lfs', {}).get('sha256')
    return sha.hexdigest() == expected if expected else git.hexdigest() == item['blobId']


def acquire(item):
    relative = Path(item['rfilename'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe repository path')
    path = DEST / relative
    if path.exists():
        if not validate(path, item):
            raise ValueError(f'Existing file does not match pinned source: {path}')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_suffix(path.suffix + '.partial')
        for attempt in range(4):
            try:
                with urllib.request.urlopen(f'https://huggingface.co/{MODEL_ID}/resolve/{PIN}/{relative.as_posix()}', timeout=120) as response:
                    with partial.open('wb') as stream:
                        for block in iter(lambda: response.read(1024*1024), b''):
                            stream.write(block)
                if not validate(partial, item):
                    raise ValueError(f'Download hash/size mismatch: {relative}')
                partial.rename(path)
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(min(8, 2 ** attempt))
    return {'path': str(path), 'filename': relative.as_posix(), 'bytes': path.stat().st_size,
            'sha256': common().sha256_file(path), 'official_file_metadata': item}


def write_once(path, payload):
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError(f'Refusing to overwrite different provenance: {path}')
        return
    with path.open('xb') as stream:
        stream.write(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    writer = common()
    directory = ROOT / '.evidence/raw/siai/mlc-llm' / args.run_id
    with writer.Logger(directory, {'run_id': args.run_id, 'attack_id': 'siai',
         'engine': {'id': 'mlc-llm'}, 'execution_scope': 'environment_build',
         'model': {'id': MODEL_ID, 'revision': PIN}, 'phase': 'approved_model_download',
         'native_inference_claim': False}, source_root=ROOT.parent) as log:
        api_url = f'https://huggingface.co/api/models/{MODEL_ID}/revision/{PIN}?blobs=true'
        api_bytes = read_url(api_url)
        api = json.loads(api_bytes)
        if api['sha'] != PIN or api.get('gated') or api.get('private'):
            raise ValueError('Official repository pin/access changed')
        PROVENANCE.mkdir(parents=True, exist_ok=True)
        write_once(PROVENANCE / 'model-api.json', api_bytes)
        log.emit('model_download_started', {'url': api_url, 'official_metadata': api,
                 'total_bytes': sum(item['size'] for item in api['siblings']),
                 'destination': str(DEST)}, source=source('siai.mlc.model-download-start'))
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(acquire, item) for item in api['siblings']]
            for future in as_completed(futures):
                record = future.result()
                results.append(record)
                log.emit('model_file_verified', record, source=source('siai.mlc.model-file-verified'))
                print(f"{len(results)}/{len(futures)} {record['filename']} {record['bytes']}", flush=True)
        base_api_bytes = read_url('https://huggingface.co/api/models/microsoft/Phi-3.5-vision-instruct')
        base_api = json.loads(base_api_bytes)
        base_pin = base_api['sha']
        write_once(PROVENANCE / 'base-model-api.json', base_api_bytes)
        license_url = f'https://huggingface.co/microsoft/Phi-3.5-vision-instruct/resolve/{base_pin}/LICENSE'
        license_bytes = read_url(license_url)
        write_once(PROVENANCE / 'base-model-LICENSE.txt', license_bytes)
        summary = {'model_id': MODEL_ID, 'revision': PIN, 'files': sorted(results, key=lambda x:x['filename']),
                   'downloaded_bytes': sum(item['bytes'] for item in results),
                   'base_model': {'id': 'microsoft/Phi-3.5-vision-instruct', 'revision': base_pin,
                                  'license': base_api.get('cardData', {}).get('license'), 'license_url': license_url,
                                  'license_sha256': hashlib.sha256(license_bytes).hexdigest()},
                   'remote_code_executed': False,
                   'experiment_interpretation': 'Existing SmolVLM PGD inputs are cross-model transfer, not Phi-trained attacks'}
        write_once(PROVENANCE / 'manifest.json', (json.dumps(summary, ensure_ascii=False, indent=2)+'\n').encode())
        log.emit('model_download_completed', {'status': 'success', 'manifest_path': str(PROVENANCE/'manifest.json'),
                 'manifest_sha256': writer.sha256_file(PROVENANCE/'manifest.json'),
                 'files': len(results), 'bytes': summary['downloaded_bytes'], 'base_model_license': summary['base_model']},
                 source=source('siai.mlc.model-download-completed'))
    print(directory, flush=True)


if __name__ == '__main__':
    main()
