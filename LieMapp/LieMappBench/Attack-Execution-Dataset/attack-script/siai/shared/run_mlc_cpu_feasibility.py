"""Record precise cached-MLC CPU feasibility, not substitute model inference."""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import platform

from run_preflight import ROOT, LOGGING, command, module


def main():
    logger_module = module("mlc_feasibility_logger", LOGGING / "logger.py")
    analyzer = module("mlc_feasibility_analyzer", ROOT / "LieMappAnalyzer/analyzer.py")
    profile = next(p for p in json.loads((LOGGING / "siai/runtime-profiles.json").read_text())["engines"] if p["id"] == "mlc-llm")
    repo = ROOT / "LIE/mlc-llm"
    run_id = "siai-mlc-llm-cpu-feasibility-20260906-002"
    revision = command(["git", "-C", str(repo), "rev-parse", "HEAD"])
    metadata = {"run_id": run_id, "attack_id": "siai", "execution_scope": "preflight",
                "engine": {"id": "mlc-llm", "name": "MLC-LLM", "revision": revision["stdout"].strip(), "source_root": str(repo)},
                "runtime": {"device": "cpu", "platform": platform.platform()},
                "native_inference_executed": False, "original_source_modified": False,
                "reason": profile["reason"], "profile_sha256": logger_module.sha256_file(LOGGING / "siai/runtime-profiles.json"),
                "logger_sha256": logger_module.sha256_file(LOGGING / "logger.py"),
                "runner_sha256": logger_module.sha256_file(Path(__file__))}
    directory = ROOT / ".evidence/raw/siai/mlc-llm" / run_id
    writer = logger_module.Logger(directory, metadata, source_root=ROOT.parent)

    def emit(stage, raw, summary):
        writer.emit(stage, raw, context={"request_id": "cpu-feasibility-review", "evaluation": "preflight"},
                    readable={"summary": summary},
                    source={"path": str(Path(__file__).resolve()), "function": "main.emit",
                            "line": inspect.currentframe().f_lineno, "logging_point_id": f"preflight.mlc.{stage}"})

    try:
        emit("source_preflight", {"revision": revision,
             "submodules": command(["git", "-C", str(repo), "submodule", "status"]),
             "tvm_gitlink": command(["git", "-C", str(repo), "ls-tree", "HEAD", "3rdparty/tvm"])},
             "원본 9fa644와 TVM gitlink 837cb9를 확인. 서브모듈 미초기화만으로 CPU 불가를 뜻하지 않는다.")
        probe = '''import ctypes,json,sys
sys.path.insert(0,"/tmp/mlc-exact-python")
import tvm_ffi
compiler=ctypes.CDLL("/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so",mode=ctypes.RTLD_GLOBAL)
version=tvm_ffi.get_global_func("target.llvm_version_major")()
available=tvm_ffi.get_global_func("target.build.llvm",allow_missing=True) is not None
print(json.dumps({"ffi_origin":tvm_ffi.__file__,"compiler_loaded":True,"llvm_major":version,"llvm_codegen_registered":available}))
'''
        compiler_probe = command(["/tmp/mlc-exact-venv/bin/python", "-c", probe])
        emit("compiler_preflight", {"probe": compiler_probe,
             "ldd": command(["ldd", "/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so"]),
             "compiler_sha256": logger_module.sha256_file(Path("/tmp/mlc-tvm-837c-build/lib/libtvm_compiler.so")),
             "runtime_sha256": logger_module.sha256_file(Path("/tmp/mlc-tvm-837c-build/lib/libtvm_runtime.so")),
             "build_options": Path("/tmp/mlc-tvm-837c-build/TVMBuildOptions.txt").read_text()},
             "cached CPU compiler의 실제 로드와 LLVM 17 codegen 등록을 확인했다. 모델 추론을 실행한 것은 아니다.")
        registry_probe = '''import ast,json,sys
from pathlib import Path
p=Path(sys.argv[1]);t=ast.parse(p.read_text());keys=set()
for n in ast.walk(t):
 if isinstance(n,ast.Dict):
  keys.update(k.value for k in n.keys if isinstance(k,ast.Constant) and isinstance(k.value,str))
print(json.dumps({"phi3_v_registered":"phi3_v" in keys,"llava_registered":"llava" in keys,"smolvlm_registered":"smolvlm" in keys,"idefics3_registered":"idefics3" in keys}))
'''
        registry = repo / "python/mlc_llm/model/model.py"
        emit("model_support_preflight", {"registry_path": str(registry), "registry_sha256": logger_module.sha256_file(registry),
             "probe": command(["/tmp/mlc-exact-venv/bin/python", "-c", registry_probe, str(registry)]),
             "source_search": command(["rg", "-n", "smolvlm|idefics3|SmolVLM|Idefics", str(repo / "python"), str(repo / "cpp")]),
             "note": "rg exit 1 means no matching implementation text; no random-weight or HF-forward substitute was used."},
             "fresh MLC에서 Phi3V/LLaVA는 등록되어 있고 캐시 SmolVLM/Idefics3는 등록·구현을 찾지 못했다.")
        inventory = {}
        for path in [Path("/home/mindol/.cache/mlc_llm/model_weights"), Path("/home/mindol/.cache/mlc_llm/model_lib")]:
            inventory[str(path)] = [{"path": str(p.relative_to(path)), "bytes": p.stat().st_size}
                                    for p in path.rglob("*") if p.is_file()]
        emit("weights_preflight", {"mlc_cache_inventory": inventory,
             "candidate_search": command(["rg", "--files", "/tmp", "/home/mindol/.cache", "-g", "ndarray-cache.json", "-g", "mlc-chat-config.json", "-g", "*params_shard*"]),
             "available_hf_cache_directories": sorted(p.name for p in Path("/home/mindol/.cache/huggingface/hub").glob("models--*")),
             "llava_config_only": {"path": "/tmp/mlc-llava-config.json", "bytes": Path("/tmp/mlc-llava-config.json").stat().st_size,
                                   "sha256": logger_module.sha256_file(Path("/tmp/mlc-llava-config.json")), "is_model_weights": False}},
             "確認した MLC model_weights/model_lib 캐시가 비어 있다. LLaVA config 파일만으로 실제 VLM 추론을 할 수 없다.")
        compare_probe = '''import json,sys
from pathlib import Path
src=Path(sys.argv[1]);installed=Path("/tmp/mlc-siai-venv/lib/python3.12/site-packages/mlc_llm")
same=[];different=[];missing=[]
for p in src.rglob("*.py"):
 q=installed/p.relative_to(src)
 if not q.exists():missing.append(str(p.relative_to(src)))
 elif p.read_bytes()==q.read_bytes():same.append(str(p.relative_to(src)))
 else:different.append(str(p.relative_to(src)))
print(json.dumps({"same_count":len(same),"different":different,"missing":missing,"phi3v_identical":"model/phi3v/phi3v_model.py" in same,"llava_identical":"model/llava/llava_model.py" in same}))
'''
        emit("version_preflight", {"python_comparison": command(["/tmp/mlc-exact-venv/bin/python", "-c", compare_probe, str(repo / "python/mlc_llm")]),
             "installed_distribution_versions": command(["/tmp/mlc-siai-venv/bin/python", "-c",
                  'import importlib.metadata as m,json;print(json.dumps({n:m.version(n) for n in ["mlc-llm-nightly-cpu","mlc-ai-nightly-cpu","apache-tvm-ffi"]}))']),
             "exact_venv_module_probe": command(["/tmp/mlc-exact-venv/bin/python", "-c",
                  'import importlib.util,json;print(json.dumps({n:importlib.util.find_spec(n) is not None for n in ["tvm","tvm_ffi","mlc_llm"]}))'])},
             "설치 wheel의 Python 319개는 fresh와 같지만 compiler pass 3개가 다르다. 모델 구현 전체가 다른 것으로 과장하지 않는다.")
        emit("execution_unavailable", {"native_inference_executed": False,
             "compiler_available": compiler_probe.get("returncode") == 0,
             "reason": profile["reason"], "next_step": profile["next_step"],
             "scope_boundary": "Choosing a different supported VLM or porting SmolVLM changes the experiment; explicit user model choice is required."},
             "실제 모델 요청은 미실행. 지원 모델 선택·가중치 및 모델 라이브러리 준비가 필요하며 AC/DC는 판정불가다.")
        writer.close(status="blocked", reason=profile["reason"])
    except BaseException as exc:
        writer.close(status="failed", reason=str(exc))
        raise
    report = ROOT / ".evidence/analyses/siai/mlc-llm" / (run_id + "-reviewed")
    result = analyzer.analyze(directory / "events.jsonl", LOGGING / "siai/conditions.json", report)
    print(json.dumps({"log": str(directory), "report": str(report), "summary": result["summary"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
