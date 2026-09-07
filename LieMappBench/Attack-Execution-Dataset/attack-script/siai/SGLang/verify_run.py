"""Independent raw-flow audit; not a replacement for the common AC/DC Analyzer."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import numpy as np


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    events=[json.loads(line) for line in (args.run_dir/'events.jsonl').read_text().splitlines()]
    grouped=defaultdict(list)
    for event in events:
        if rid:=event.get('context',{}).get('request_id'):
            grouped[rid].append(event)
    rows=[]
    stages=['input_received','request_started','processor_output','encoder_input','projected_embedding','decoder_input','generation_output']
    for rid,group in grouped.items():
        mapping={stage:[e for e in group if e['stage']==stage] for stage in stages}
        assert all(len(es)==1 for es in mapping.values()),(rid,{k:len(v) for k,v in mapping.items()})
        mapping={k:v[0] for k,v in mapping.items()}
        context=mapping['generation_output']['context']
        for stage in stages[2:]:
            assert mapping[stage]['raw']['native_request_id']==rid
        def tensor(stage,key='values'):
            artifact=mapping[stage]['artifacts'][key]
            path=args.run_dir/artifact['path']
            assert hashlib.sha256(path.read_bytes()).hexdigest()==artifact['sha256']
            value=np.load(path,allow_pickle=False)
            assert list(value.shape)==artifact['shape'] and np.isfinite(value).all()
            return value
        proc,enc=tensor('processor_output'),tensor('encoder_input')
        proj,dec=tensor('projected_embedding'),tensor('decoder_input')
        logits=tensor('generation_output','logits')
        assert proc.shape==enc.shape==(1,3,512,512) and np.array_equal(proc,enc)
        assert proj.shape==dec.shape==(64,576) and logits.shape==(49280,)
        assert all(v.dtype==np.float32 for v in (proc,enc,proj,dec,logits))
        is_ablation=context['run_kind']=='zero_visual_embeddings'
        assert not np.count_nonzero(dec) if is_ablation else np.array_equal(proj,dec)
        assert mapping['generation_output']['raw']['meta_info']['image_tokens']==64
        rows.append({'request_id':rid,'input_id':context['input_id'],'role':context['role'],
            'transform':context['transform'],'isolated_process':context['isolated_process'],
            'processor_encoder_bitwise_equal':True,'projection_decoder_bitwise_equal':np.array_equal(proj,dec),
            'zero_visual_intervention':is_ablation,'image_tokens':64,'full_logits_count':49280,
            'event_refs':{k:v['event_id'] for k,v in mapping.items()}})
    result={'label':'Separate structural/raw-flow verifier, not AC/DC judgment or attack-success measurement',
            'run_dir':str(args.run_dir),'event_count':len(events),'request_count':len(rows),'verified':True,'requests':rows}
    if args.output:
        with args.output.open('x') as stream:
            json.dump(result,stream,ensure_ascii=False,indent=2)
            stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k!='requests'},ensure_ascii=False))


if __name__=='__main__':
    main()
