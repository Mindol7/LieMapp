"""Real Engine/scheduler CPU smoke; no HF.generate or CUDA mocking."""
import json
import os
from pathlib import Path

MODEL = '/home/mindol/.cache/huggingface/hub/models--HuggingFaceTB--SmolVLM-256M-Instruct/snapshots/7e3e67edbbed1bf9888184d9df282b700a323964'
ROOT = next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
IMAGE = ROOT/'LieMappBench/Attack-Execution-Dataset/attack-source/siai/shared/training-cpu-128/clean.png'


def main():
    import torch
    from sglang import Engine
    from transformers import AutoProcessor
    torch.set_num_threads(2)
    processor = AutoProcessor.from_pretrained(MODEL, local_files_only=True)
    prompt = processor.apply_chat_template([{'role':'user','content':[
        {'type':'image'}, {'type':'text','text':'Describe the main object in this image.'}]}],
        tokenize=False, add_generation_prompt=True)
    engine = Engine(model_path=MODEL, device='cpu', dtype='float32',
                    model_impl='transformers', attention_backend='torch_native',
                    tp_size=1, disable_overlap_schedule=True,
                    disable_cuda_graph=True, max_total_tokens=2048,
                    context_length=2048, mem_fraction_static=0.2,
                    max_running_requests=1, chunked_prefill_size=-1,
                    disable_radix_cache=True, log_level='info')
    try:
        output = engine.generate(prompt=prompt,
                                 image_data=str(IMAGE),
                                 rid='liemapp-native-smoke-only-001',
                                 sampling_params={'temperature':0,'max_new_tokens':32})
        print(json.dumps({'native_engine_output':output},ensure_ascii=False,default=str))
    finally:
        engine.shutdown()


if __name__ == '__main__':
    main()
