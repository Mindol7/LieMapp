"""Publish real numeric examples from the sealed canonical run, not a template."""
import json
import os
from pathlib import Path

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
RUN=ROOT/'.evidence/raw/siai/SGLang/siai-SGLang-native-cpu-one-tile-20260906-001'
OUT=ROOT/'LieMappBench/Logging-Dataset/siai/SGLang'


def main():
    assert json.loads((RUN/'seal.json').read_text())['status']=='completed'
    events=[json.loads(s) for s in (RUN/'events.jsonl').read_text().splitlines()]
    selected=[(i+1,e) for i,e in enumerate(events) if e.get('context',{}).get('role')=='attack'
              and e['context']['transform']=='original' and e['context']['run_kind']=='normal']
    rows=[]
    lines=['# SGLang — 실제 로깅 값 예시','',
        '템플릿이나 shape 설명이 아니라, 완료·봉인한 canonical run의 **공격 원본 1개 실제 요청**에서 추출한 값이다. 8개 preview는 전체 raw 값의 일부이고, 전체 값은 각각 링크한 `.npy` 파일에 있다.',
        '',f'- Run: `{RUN.name}`',f'- [전체 JSONL]({os.path.relpath(RUN/"events.jsonl",OUT)})',
        f'- [가독성 pretty JSON]({os.path.relpath(RUN/"events.pretty.json",OUT)})',
        f'- [공통 Analyzer 최종 보고서]({os.path.relpath(ROOT/"report/siai/SGLang/SIAI-SGLang-Report.md",OUT)})',
        '', '실제 CPU Engine seed는 runner의 고정 `random_seed=20260906`, temperature=0이다. `context.seed`는 데이터셋 이미지/증강 생성 seed를 보존한 값으로 Engine seed와 구분한다. 공격 원본과 zero-ablation은 같은 실제 Engine seed를 사용했다.',
        '', '교차 엔진 참고표에 남은 vLLM128은 overlay 생성 당시 예상값이고 실행 인자가 아니다. 최신 실제 vLLM smoke003은320tokens이며 SGLang은64tokens다. 원본 overlay/config/weights를 실행 중 바꾸지 않았다.']
    for number,event in selected:
        if event['stage'] not in ('input_received','processor_output','encoder_input','projected_embedding','decoder_input','generation_output'):
            continue
        src=event['source']
        lines.extend(['',f'## {event["stage"]}','',
            f'- Event ID: `{event["event_id"]}` / sequence `{event["sequence"]}` / JSONL line `{number}`',
            f'- Request ID: `{event["context"]["request_id"]}`',
            f'- 실제 source: `{src["path"]}:{src["line"]}` / function `{src["function"]}`',
            f'- Source SHA-256: `{src["sha256"]}`',
            f'- 실제 반환/상태: `returncode={event["raw"].get("returncode")}`, `status={event["raw"].get("status")}`'])
        for name,item in event.get('artifacts',{}).items():
            link=os.path.relpath(RUN/item['path'],OUT)
            lines.extend(['',f'**{name}** — dtype `{item["dtype"]}`, shape `{item["shape"]}`, raw bytes `{item["raw_nbytes"]}`',
                '', '실제로 기록된 첫 8개 수치:', '', '```json', json.dumps(item['preview'],ensure_ascii=False),'```',
                '',f'전체 raw: [{Path(item["path"]).name}]({link})',
                '',f'SHA-256: `{item["sha256"]}`; min `{item["min"]}`, max `{item["max"]}`'])
        if event['stage']=='generation_output':
            lines.extend(['','실제 생성 원문(JSON string; 선행 공백·개행 보존):','','```json',
                json.dumps(event['raw']['generated_text'],ensure_ascii=False),'```','',
                '실제 생성 token IDs:','','```json',json.dumps(event['raw']['token_ids']),'```'])
        rows.append({'jsonl_line':number,'event':event})
    with (OUT/'evidence-examples.md').open('x') as stream:
        stream.write('\n'.join(lines)+'\n')
    with (OUT/'evidence-examples.json').open('x') as stream:
        json.dump({'run':RUN.name,'description':'Actual canonical attack-original LP values, not synthetic examples','events':rows},stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    print(OUT/'evidence-examples.md')


if __name__=='__main__':
    main()
