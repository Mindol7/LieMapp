"""Compare preserved analysis environments; never edit prior reports."""
import json
from pathlib import Path

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
BASE=ROOT/'.archive/20260907-report-layout/report/siai/SGLang'
RUN='siai-SGLang-native-cpu-one-tile-20260906-001'


def differences(a,b,path='conditions'):
    out=[]
    if isinstance(a,dict):
        assert set(a)==set(b)
        for key in a:
            out.extend(differences(a[key],b[key],path+'.'+key))
    elif isinstance(a,list):
        assert len(a)==len(b)
        for i,(x,y) in enumerate(zip(a,b)):
            out.extend(differences(x,y,f'{path}[{i}]'))
    elif a != b:
        if type(a) is float and type(b) is float:
            out.append({'path':path,'left':a,'right':b,'absolute_difference':abs(a-b)})
        else:
            raise AssertionError(f'Non-floating result changed: {path}: {a!r} != {b!r}')
    return out


def main():
    records=[]
    selected=BASE/(RUN+'-reviewed-common-serial')
    target=json.loads((selected/'analysis.json').read_text())
    for suffix,label in [('reviewed','SGLang venv; OPENBLAS thread count not explicitly set'),
                         ('reviewed-serial','SGLang venv; OPENBLAS_NUM_THREADS=1')]:
        folder=BASE/(RUN+'-'+suffix)
        left=json.loads((folder/'analysis.json').read_text())
        assert left['summary']==target['summary']
        rows=differences(left['conditions'],target['conditions'])
        records.append({'report':str(folder),'environment':label,'judgments_unchanged':True,
                        'floating_difference_count':len(rows),
                        'max_absolute_float_difference':max((r['absolute_difference'] for r in rows),default=0),
                        'differences':rows})
    result={'historical_selected_report':str(selected),
            'selected_environment':'OPENBLAS_NUM_THREADS=1 /tmp/siai-assets-venv/bin/python',
            'raw_and_rules_unchanged':True,'prior_reports_preserved':True,'comparisons':records}
    output=ROOT/'.evidence/audits/siai-SGLang-historical-environment-comparison.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    print(json.dumps({**result,'comparisons':[{k:v for k,v in r.items() if k!='differences'} for r in records]},ensure_ascii=False))


if __name__=='__main__':
    main()
