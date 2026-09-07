"""Publish actual applied SGLang source hooks, separately from static candidates."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
ENGINE=ROOT/'Instrumented-LIE/siai/SGLang'
OUT=ROOT/'LieMappBench/Logging-Dataset/siai/SGLang'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def location(relative,function,needle=None):
    path=ENGINE/relative
    text=path.read_text()
    if needle:
        line=next(i+1 for i,s in enumerate(text.splitlines()) if needle in s)
    else:
        line=next(n.lineno for n in ast.walk(ast.parse(text)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==function)
    return {'path':str(path),'relative_path':relative,'function':function,'line':line,'sha256':digest(path)}


def main():
    obs='python/sglang/liemapp_observer.py'
    rows=[
        ('processor_output','processor_output',['AC2','DC1'],
         '실제 request_obj.rid가 활성 요청과 일치할 때 HF processor의 최종 FP32 pixel_values 전체를 기록한다. encoder_input과 bitwise 비교하여 같은 입력이 실제 vision encoder로 전달됐는지 확인한다.',
         '[1,3,512,512] FP32 normalized pixels',
         location('python/sglang/srt/multimodal/processors/transformers_auto.py','process_mm_data_async','liemapp_observer.processor_output(processor_output)')),
        ('encoder_input','vision_pre',['AC1','AC2','DC1'],
         'Engine가 소유한 실제 SmolVLM vision_model의 forward_pre_hook에서 전처리 후 입력 텐서를 수집한다. callback은 실제 scheduler batch의 rid와 일치한 동안에만 활성화된다.',
         '[1,3,512,512] FP32 actual vision forward input',
         location('python/sglang/srt/models/transformers.py','__init__','liemapp_observer.install_model_hooks(self.model)')),
        ('projected_embedding','connector_post',['AC1','AC3','DC2','DC3'],
         '실제 vision connector의 성공한 forward 직후 투영된 임베딩 전체를 기록한다. 원본·증강 같은 계층의 값으로 cosine을 계산하고 decoder가 실제 소비한 visual rows와 비교한다. Ablation에서도 원래 projection 결과는 보존하고 전달되는 반환값만 0으로 개입한다.',
         '[64,576] FP32 projected visual embeddings',
         location('python/sglang/srt/models/transformers.py','__init__','liemapp_observer.install_model_hooks(self.model)')),
        ('decoder_input','text_post',['AC1','AC3'],
         '실제 image_token_id mask로 language decoder에 들어간 visual rows를 선택하고, 해당 text_model forward가 성공한 후 기록한다. 구조적 호출만으로 인과성을 주장하지 않고 별도 fresh-process zero-visual 실험 및 첫 logits 변화와 결합한다.',
         '[64,576] FP32 visual rows actually consumed by completed decoder',
         location('python/sglang/srt/models/transformers.py','_run_hf_backbone','return self.model(')),
        ('generation_output','capture_logits',['AC1','AC3'],
         '실제 SGLang LogitsProcessor.forward의 첫 전체 next-token logits 벡터를 수집한다. private IPC의 rid를 검증한 후 동일 Engine.generate 응답의 원문·token IDs와 합쳐 common logger가 최종 저장한다. 후속 decode logits 및 warmup은 섞지 않는다.',
         '[49280] FP32 first-step logits + exact Engine-generated text/token IDs',
         location('python/sglang/srt/layers/logits_processor.py','forward','liemapp_observer.capture_logits(sampled_logits)')),
    ]
    records=[]
    for stage,function,conditions,reason,raw,site in rows:
        records.append({'stage':stage,'status':'instrumented_and_native_smoke_verified',
            'conditions':conditions,'reason_ko':reason,'raw_values':raw,
            'actual_hook':location(obs,function),'native_engine_site':site,
            'request_identity':'actual request_obj.rid / batch.reqs[*].rid exact match; warmup inactive'})
    paths=subprocess.check_output(['git','diff','--name-only'],cwd=ENGINE,text=True).splitlines()+[obs]
    data={'schema_version':'1.0.0','attack_id':'siai','engine_id':'SGLang',
        'source_commit':'97c6978369ac1e04c91fcc01c98acc25129a6000',
        'library':{'path':str(ROOT/'LieMappBench/Attack-Library/attack_library.xlsx'),
                   'cells':{'AC':'AI 포렌식!G10','DC':'AI 포렌식!H10','historical_SGLang':'AI 포렌식!M10'}},
        'processor_variant':json.loads((ENGINE/'.model-cpu-one-tile/liemapp-provenance.json').read_text()),
        'smoke_run':'siai-SGLang-native-one-tile-smoke-20260906-003',
        'canonical_run':'siai-SGLang-native-cpu-one-tile-20260906-001',
        'scope':'Actual native SGLang Engine/scheduler, upstream Transformers backend, CPU one-tile adaptation',
        'isolation':'original attack and zero-visual each fresh process; other serial requests share Engine',
        'caches':{'radix_cache':False,'mm_preprocess_cache_size_mb':0,'SGLANG_VLM_CACHE_SIZE_MB':0,
                  'prefix_mm_cache':False,'mm_global_cache':False},
        'instrumented_files':{p:digest(ENGINE/p) for p in paths},'logging_points':records,
        'limitations':['Not stock SGLang preprocessing (stock smoke has 1088 image tokens)',
          'Historical static _encode_modality_items mapping does not prove execution: this backend passes multimodal kwargs into the engine-owned SmolVLM model; actual vision/connector/text hooks above are the executed boundaries.',
          'AC/DC readiness and ablation evidence are not an SIAI success-rate or validated detector claim.']}
    OUT.mkdir(parents=True,exist_ok=True)
    with (OUT/'logging-points.json').open('x') as stream:
        json.dump(data,stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    lines=['# SGLang — 실제 계측 지점 및 로깅 근거','',
           '현재 소스의 실제 native Engine/scheduler 실행 경로다. `source-review.*`의 정적 후보 매핑과 구분한다.',
           '',f'원본 commit: `{data["source_commit"]}`. 원본 LIE 및 HF cached weights는 수정하지 않았다.',
           '', 'CPU 전처리 변형: resize/splitting 비활성, 512×512 단일 이미지, visual tokens 64. 원래 SGLang 기본 전처리(1088 tokens)와 구분하며 stock benchmark로 주장하지 않는다.',
           '', '| 이벤트 | 실제 source hook | 원본 엔진의 연결 지점 | AC/DC | raw 값 |','|---|---|---|---|---|']
    for r in records:
        h,s=r['actual_hook'],r['native_engine_site']
        lines.append(f'| {r["stage"]} | `{h["relative_path"]}:{h["line"]}` ({h["function"]}) | `{s["relative_path"]}:{s["line"]}` | {", ".join(r["conditions"])} | {r["raw_values"]} |')
    for r in records:
        lines.extend(['',f'## {r["stage"]} — 로깅 이유','',r['reason_ko']])
    lines.extend(['','## 요청 격리와 raw 증거','',
        '실제 native rid가 명시한 request_id 한 개와 정확히 일치할 때만 활성화한다. init/warmup 및 다른 요청을 계측 증거에 포함하지 않는다. 공격 원본과 zero-visual ablation은 서로 다른 fresh process이며 나머지는 순차 shared Engine이다. 각 이벤트 context에 실제 isolated_process 값을 기록한다.',
        '', 'processor/encoder/projected/decoder는 전체 FP32 `.npy`, generation은 첫 전체 logits `.npy` 및 원문 text/token IDs다. preview만으로 비교하지 않으며 공통 Analyzer가 hash/shape/finite 값 및 봉인을 확인한다.',
        '', '함수 `_encode_modality_items`는 정적 후보였지만 이 실행의 실제 visual 경로를 대표하지 않는다. 실제 계측은 위 native wrapper가 소유한 vision_model / connector / text_model의 forward callback이다. 단독 HF 모델 실험으로 SGLang을 대체한 것이 아니다.',
        '', '선택적 EAGLE/cache-copy CPU extension import의 호출시점 지연은 `cpu-feasibility-review.md` 및 실제 patch를 참조한다. 존재하지 않는 커널을 흉내 내거나 attention 연산을 바꾸지 않았다.'])
    with (OUT/'logging-points.md').open('x') as stream:
        stream.write('\n'.join(lines)+'\n')
    patch=subprocess.check_output(['git','diff','--no-ext-diff'],cwd=ENGINE)
    with (OUT/'native-instrumentation.patch').open('xb') as stream:
        stream.write(patch)
    print(OUT/'logging-points.md')


if __name__=='__main__':
    main()
