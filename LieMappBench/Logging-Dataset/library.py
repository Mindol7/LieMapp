"""Read the authoritative workbook; export versioned, non-executed source reviews.

No dependency on an engine or a spreadsheet application. The workbook is never
modified, and formatting-only rows and hidden conference-list sheets are ignored.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import posixpath
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
ROOT = Path(__file__).resolve().parents[2]
WORKBOOK = ROOT / "LieMappBench/Attack-Library/attack_library.xlsx"
ENGINES = {
    "llamacpp": ("llama.cpp", "I"),
    "mlc-llm": ("mlc-llm", "J"),
    "vllm": ("vllm", "K"),
    "tensorRT-llm": ("TensorRT-LLM", "L"),
    "SGLang": ("sglang", "M"),
}
KNOWN_ATTACKS = {
    "Self-interpreting Adversarial Images": "siai",
    "I Know What You Asked: Prompt Leakage via KV-Cache Sharing in Multi-Tenant LLM Serving": "ikwa",
    "I Know What You Said: Unveiling Hardware Cache Side-Channels in Local Large Language Model Inference": "ikws",
    "Mind the Gap: A Practical Attack on GGUF Quantization": "mindthegap",
    "Universal and Transferable Adversarial Attacks on Aligned Language Models": "gcg",
    "Attractive Metadata Attack: Inducing LLM Agents to Invoke Malicious Tools": "ama",
    # Preserve the authoritative workbook text, including its current spelling.
    "Attractive Metadata Attck: Inducing LLM Agents to Invoke Malicious Tools": "ama",
}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_cells(workbook: Path = WORKBOOK, sheet_name: str = "AI 포렌식") -> dict[str, str]:
    """Read cell values by the sheet's relationship, not a guessed sheet number."""
    with zipfile.ZipFile(workbook) as archive:
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            shared = ["".join(t.text or "" for t in x.iter(f"{{{NS['s']}}}t"))
                      for x in ET.fromstring(archive.read("xl/sharedStrings.xml"))]
        book = ET.fromstring(archive.read("xl/workbook.xml"))
        matches = [s for s in book.findall("s:sheets/s:sheet", NS) if s.get("name") == sheet_name]
        if len(matches) != 1:
            raise ValueError(f"Expected one sheet named {sheet_name!r}")
        rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        target = next(r.get("Target") for r in rels if r.get("Id") == matches[0].get(f"{{{REL}}}id"))
        sheet_path = target.lstrip("/") if target.startswith("/") else posixpath.normpath("xl/" + target)
        cells = {}
        for cell in ET.fromstring(archive.read(sheet_path)).findall(".//s:sheetData/s:row/s:c", NS):
            value = cell.find("s:v", NS)
            if cell.get("t") == "s" and value is not None:
                text = shared[int(value.text)]
            elif cell.get("t") == "inlineStr":
                text = "".join(t.text or "" for t in cell.findall(".//s:t", NS))
            else:
                text = value.text if value is not None else ""
            if text:
                cells[cell.get("r")] = text
        return cells


def split_conditions(text: str) -> list[dict]:
    """Keep each original condition text (including explanatory continuation lines)."""
    markers = list(re.finditer(r"(?m)^(AC|DC)(\d+)[.:]\s*", text))
    return [{"condition_id": m.group(1) + m.group(2),
             "type": m.group(1),
             "text": text[m.end():markers[i + 1].start() if i + 1 < len(markers) else len(text)].strip()}
            for i, m in enumerate(markers)]


def load_library(workbook: Path = WORKBOOK) -> dict:
    cells = read_cells(workbook)
    attacks = []
    for cell, title in cells.items():
        if not re.fullmatch(r"D\d+", cell) or int(cell[1:]) < 6:
            continue
        row = int(cell[1:])
        normalized_title = " ".join(title.split())
        conditions = []
        for column in ("G", "H"):
            for condition in split_conditions(cells.get(f"{column}{row}", "")):
                condition["source"] = {"sheet": "AI 포렌식", "cell": f"{column}{row}"}
                conditions.append(condition)
        attacks.append({
            "attack_id": KNOWN_ATTACKS.get(normalized_title, "paper-" + hashlib.sha256(normalized_title.encode()).hexdigest()[:12]), "title": normalized_title,
            "row": row, "venue": cells.get(f"C{row}", ""),
            "category": cells.get(f"E{row}", ""), "technique": cells.get(f"F{row}", ""),
            "raw_cells": {f"{col}{row}": cells.get(f"{col}{row}", "") for col in "DEFGHIJKLM"},
            "conditions": conditions,
            "historical_source_mapping": {
                key: {"engine": name, "sheet": "AI 포렌식", "cell": f"{col}{row}",
                      "text": cells.get(f"{col}{row}", ""), "status": "historical_unversioned_reference"}
                for key, (name, col) in ENGINES.items()},
        })
    return {"schema_version": "1.0.0", "source": {"path": str(workbook.relative_to(ROOT)) if workbook.is_relative_to(ROOT) else str(workbook),
             "sha256": sha256(workbook), "sheet": "AI 포렌식"},
            "attack_count": len(attacks), "attacks": sorted(attacks, key=lambda a: a["row"])}


# These are static candidate mappings. Runtime instrumentation belongs to a
# per-attack Instrumented-LIE tree and is intentionally not implied by this file.
SPECS = {
    "llamacpp": [
        ("tools/mtmd/mtmd.cpp", "add_media", None, "preprocess", ["AC2", "DC1"]),
        ("tools/mtmd/mtmd.cpp", "mtmd_encode_impl", None, "encode", ["AC1", "AC2", "DC1", "DC2", "DC3"]),
        ("tools/mtmd/mtmd-helper.cpp", "mtmd_helper_decode_image_chunk", None, "fusion_decode", ["AC1", "AC3"]),
    ],
    "mlc-llm": [
        ("python/mlc_llm/model/phi3v/phi3v_model.py", "image_preprocess", None, "preprocess", ["AC2", "DC1"]),
        ("python/mlc_llm/model/phi3v/phi3v_model.py", "image_embed", None, "encode", ["AC1", "AC2", "DC1", "DC2", "DC3"]),
        ("python/mlc_llm/model/phi3v/phi3v_model.py", "prefill", None, "fusion_decode", ["AC1", "AC3"]),
    ],
    "vllm": [
        ("vllm/model_executor/models/idefics3.py", "_apply_hf_processor_main", "Idefics3MultiModalProcessor", "preprocess", ["AC2", "DC1"]),
        ("vllm/model_executor/models/idefics3.py", "image_pixels_to_features", None, "encoder_input", ["AC2", "DC1"]),
        ("vllm/model_executor/models/idefics3.py", "_process_image_input", None, "encode", ["AC1", "DC2", "DC3"]),
        ("vllm/model_executor/models/utils.py", "_merge_multimodal_embeddings", None, "fusion", ["AC1", "AC3"]),
    ],
    "tensorRT-llm": [
        ("tensorrt_llm/_torch/models/modeling_qwen2vl.py", "call_with_text_prompt", "Qwen2VLInputProcessorBase", "preprocess", ["AC2", "DC1"]),
        ("tensorrt_llm/_torch/models/modeling_qwen2vl.py", "forward", "Qwen2VisionModelBase", "encode", ["AC1", "AC2", "DC1", "DC2", "DC3"]),
        ("tensorrt_llm/_torch/models/modeling_multimodal_utils.py", "fuse_input_embeds", None, "fusion", ["AC1", "AC3"]),
    ],
    "SGLang": [
        ("python/sglang/srt/multimodal/processors/transformers_auto.py", "process_mm_data_async", None, "preprocess", ["AC2", "DC1"]),
        ("python/sglang/srt/models/transformers.py", "_encode_modality_items", "MultiModalMixin", "encode", ["AC1", "AC2", "DC1", "DC2", "DC3"]),
        ("python/sglang/srt/models/transformers.py", "_forward_hidden_states", "MultiModalMixin", "fusion_decode", ["AC1", "AC3"]),
    ],
}
REASONS = {
    "preprocess": ("전처리 전후 및 이미지-증강 계보를 확보하는 경계", ["input bytes/tensor", "output tensor", "processor parameters", "parent/input ID"]),
    "encoder_input": ("전처리 결과가 실제 인코더 입력으로 전달되는 경계", ["encoder input tensor", "request/input ID", "processor fingerprint"]),
    "encode": ("이미지 인코딩 성공 여부와 같은 계층의 원시 임베딩을 확보하는 경계", ["encoder input tensor", "embedding tensor", "return status", "layer/stage ID"]),
    "fusion": ("이미지 임베딩이 언어 입력에 결합되는 경계; 후속 디코더 증거도 필요", ["visual embedding hash", "image-token positions", "fused embeddings", "request ID"]),
    "fusion_decode": ("이미지 임베딩을 이용한 언어 디코더 실행 경계", ["embedding identity", "decoder return status", "logits", "sequence/request ID"]),
}


def resolve_symbol(path: Path, name: str, class_name: str | None) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        tree = ast.parse(text)
        scope = tree
        if class_name:
            scope = next(x for x in ast.walk(tree) if isinstance(x, ast.ClassDef) and x.name == class_name)
        candidates = [x for x in ast.walk(scope) if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == name]
        if len(candidates) != 1:
            raise ValueError(f"Ambiguous or missing symbol: {path}:{class_name}.{name}")
        return candidates[0].lineno, candidates[0].end_lineno
    matches = list(re.finditer(r"(?m)^\s*(?:static\s+)?int32_t\s+" + re.escape(name) + r"\s*\(", text))
    if len(matches) != 1:
        raise ValueError(f"Ambiguous or missing C++ symbol: {path}:{name}")
    start = text.count("\n", 0, matches[0].start()) + 1
    # Function start is the stable anchor; do not pretend regex parses C++ bodies.
    while not text.splitlines()[start - 1].strip():
        start += 1
    return start, start


def export(destination: Path | None = None) -> None:
    dest = destination or Path(__file__).resolve().parent
    library = load_library()
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "library.json").write_text(json.dumps(library, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    siai = next(a for a in library["attacks"] if a["attack_id"] == "siai")
    for key, specs in SPECS.items():
        name, _ = ENGINES[key]
        source_root = ROOT / "LIE" / name
        commit = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
        entries = []
        for i, (relative, symbol, owner, stage, conditions) in enumerate(specs, 1):
            path = source_root / relative
            line, end = resolve_symbol(path, symbol, owner)
            reason, raw = REASONS[stage]
            entries.append({"mapping_id": f"siai-{key}-candidate-{i:02d}", "status": "static_candidate",
                            "condition_ids": conditions, "source": {"file": relative, "symbol": symbol,
                            "class": owner, "line": line, "end_line": end, "sha256": sha256(path)},
                            "stage": stage, "reason": reason, "required_raw_evidence": raw,
                            "executed": False, "instrumented": False})
        review = {"schema_version": "1.0.0", "attack_id": "siai", "engine": name,
                  "engine_id": key, "source_root": f"LIE/{name}", "source_commit": commit,
                  "status": "static_candidate_review_only", "library_source": library["source"],
                  "conditions": siai["conditions"], "historical_mapping": siai["historical_source_mapping"][key],
                  "logging_points": entries,
                  "limitations": ["함수 존재·매핑만 확인함. 계측 적용·실행·T/F 판정을 뜻하지 않음.",
                                   "AC2에는 clean/attack 쌍의 encoder-input 차이와 공격 provenance가 필요함.",
                                   "AC3 직접 영향 주장은 같은 요청 추적과 통제된 visual ablation이 필요함.",
                                   "DC1~3은 탐지 준비도이며 공격 탐지 성능이나 사건 발생 입증과 다름."]}
        if key == "mlc-llm":
            review["limitations"].append("TVM graph-building Python 함수의 호출은 runtime 수치 증거가 아님. VM runtime tensor/callback 필요.")
        folder = dest / "siai" / key
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "source-review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        lines = [f"# SIAI / {name} — 소스 매핑 사전 검토", "", f"기준 커밋: `{commit}`", "",
                 "상태: **정적 후보**. 실제 계측·실행 증거는 별도의 logging-points 및 실행 로그를 확인한다.", "",
                 "## AC / DC 원문", ""]
        for c in siai["conditions"]:
            lines.extend([f"- **{c['condition_id']}** ({c['source']['cell']}): {c['text'].replace(chr(10), ' ')}"])
        lines.extend(["", "## 매핑 위치와 로깅 근거", "", "|조건|현재 소스 지점|로깅 이유|필요한 raw 값|", "|---|---|---|---|"])
        for e in entries:
            s = e["source"]
            lines.append(f"|{', '.join(e['condition_ids'])}|`{s['file']}:{s['line']}`<br>`{s['symbol']}`|{e['reason']}|{', '.join(e['required_raw_evidence'])}|")
        lines.extend(["", "## 판정 한계", ""] + [f"- {v}" for v in review["limitations"]])
        lines.extend(["", "## 엑셀의 기존 위치 (이력 보존; 현재 행번호와 다름)", "", "```text", review["historical_mapping"]["text"], "```", ""])
        (folder / "source-review.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Export folder (default: this Logging-Dataset)")
    args = parser.parse_args()
    export(args.output)
