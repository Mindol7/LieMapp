"""Create a provenance-labelled CPU processor variant; never alter cached weights."""
import hashlib
import json
from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
SOURCE = Path('/home/mindol/.cache/huggingface/hub/models--HuggingFaceTB--SmolVLM-256M-Instruct/snapshots/7e3e67edbbed1bf9888184d9df282b700a323964')
DEST = ROOT/'Instrumented-LIE/siai/SGLang/.model-cpu-one-tile'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    if DEST.exists():
        record=json.loads((DEST/'liemapp-provenance.json').read_text())
        for row in record['files']:
            if digest(DEST/row['name']) != row['variant_sha256']:
                raise ValueError('Existing overlay changed: '+row['name'])
        print(DEST)
        return
    DEST.mkdir()
    rows=[]
    overrides={'do_image_splitting':False,'do_resize':False,'size':{'longest_edge':512}}
    for src in sorted(SOURCE.iterdir()):
        if not src.is_file():
            continue
        dst=DEST/src.name
        if src.suffix == '.json':
            payload=src.read_bytes()
            if src.name=='preprocessor_config.json':
                config=json.loads(payload)
                config.update(overrides)
                payload=(json.dumps(config,indent=2)+'\n').encode()
            with dst.open('xb') as stream:
                stream.write(payload)
        else:
            dst.symlink_to(src.resolve())
        rows.append({'name':src.name,'source':str(src),'source_sha256':digest(src),
                     'variant_sha256':digest(dst),'symlink':dst.is_symlink()})
    record={'label':'Explicit CPU one-tile processor adaptation, NOT stock SGLang preprocessing',
            'source_revision':SOURCE.name,'overrides':overrides,'files':rows,
            'weights_changed':False,'expected_image_tokens':64,
            'comparison_layouts':{'HF_training':64,'llamacpp':128,'vllm_latest_successful_smoke_003':320,'SGLang_stock_smoke':1088,'SGLang_variant':64}}
    with (DEST/'liemapp-provenance.json').open('x') as stream:
        json.dump(record,stream,indent=2)
        stream.write('\n')
    print(DEST)


if __name__=='__main__':
    main()
