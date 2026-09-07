# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
"""Single-request native audit transport; final evidence is written by logger.py."""

import importlib.util
import inspect
import os
from pathlib import Path

_active = False
_owner = None
_context = None
_client = None
_zero_visual = False
_pending_mask = None
_pending_consumed = None
_consumed_source = None
_first_logits = None
_logits_source = None


def active() -> bool:
    if _active and _owner != os.getpid():
        raise RuntimeError("Audit context crossed a process boundary")
    return _active


def activate(context: dict, *, zero_visual: bool = False) -> None:
    """Activate after native initialization, excluding profile and dummy inputs."""
    global _active, _owner, _context, _client, _zero_visual
    global _pending_mask, _first_logits, _logits_source
    global _pending_consumed, _consumed_source
    if _active:
        raise RuntimeError("One audit request may be active at a time")
    path = Path(os.environ["LIEMAPP_LOGGER_PATH"]).resolve(strict=True)
    spec = importlib.util.spec_from_file_location("liemapp_shared_writer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _client = module.Client()
    _owner = os.getpid()
    _context = dict(context)
    _zero_visual = zero_visual
    _pending_mask = _first_logits = _logits_source = None
    _pending_consumed = _consumed_source = None
    _active = True


def deactivate() -> None:
    global _active
    _active = False


def _source(frame, point: str) -> dict:
    return {
        "path": str(Path(frame.f_code.co_filename).resolve()),
        "function": frame.f_code.co_name,
        "line": frame.f_lineno,
        "logging_point_id": point,
    }


def _array(tensor):
    import torch

    if tensor.dtype not in (torch.float32, torch.float64):
        raise RuntimeError("Audit requires losslessly representable float tensors")
    return tensor.detach().cpu().contiguous().numpy().copy()


def emit_tensor(stage: str, tensor, point: str, **raw) -> None:
    if not active():
        return
    _client.emit(
        stage,
        {"status": "success", "returncode": 0, **raw},
        context=_context,
        source=_source(inspect.currentframe().f_back, point),
        tensors={"values": _array(tensor)},
        readable={"summary": "Exact native tensor at the recorded source boundary"},
    )


def before_merge(multimodal_embeddings, is_multimodal):
    """Intervene only in the native merge input, leaving projection intact."""
    global _pending_mask
    if not active() or multimodal_embeddings is None:
        return multimodal_embeddings
    if len(multimodal_embeddings) == 0:
        return multimodal_embeddings
    if _pending_mask is not None:
        raise RuntimeError("Previous visual merge was not consumed by forward")
    if is_multimodal is None or len(multimodal_embeddings) != 1:
        raise RuntimeError("Audit requires one image and an explicit visual mask")
    _pending_mask = is_multimodal.detach().clone()
    if not _zero_visual:
        return multimodal_embeddings
    import torch

    return [torch.zeros_like(value) for value in multimodal_embeddings]


def before_forward(inputs_embeds) -> None:
    global _pending_consumed, _consumed_source
    if not active() or _pending_mask is None:
        return
    if inputs_embeds is None or inputs_embeds.shape[0] != _pending_mask.numel():
        raise RuntimeError("Native decoder shape differs from the merge mask")
    _pending_consumed = _array(inputs_embeds[_pending_mask])
    _consumed_source = _source(
        inspect.currentframe().f_back, "siai.vllm.decoder-entry-snapshot"
    )


def after_forward(inputs_embeds) -> None:
    global _pending_mask, _pending_consumed, _consumed_source
    if not active() or _pending_mask is None:
        return
    if _pending_consumed is None:
        raise RuntimeError("Decoder success has no corresponding entry snapshot")
    _client.emit(
        "decoder_input",
        {
            "status": "success",
            "returncode": 0,
            "intervention": _zero_visual,
            "visual_token_count": int(_pending_mask.sum().item()),
            "decoder_completed": True,
            "entry_snapshot_source": dict(_consumed_source),
        },
        context=_context,
        source=_source(inspect.currentframe().f_back, "siai.vllm.decoder-consumed"),
        tensors={"values": _pending_consumed},
        readable={"summary": "Actual visual rows consumed by successful forward"},
    )
    _pending_mask = None
    _pending_consumed = _consumed_source = None


def capture_logits(logits) -> None:
    global _first_logits, _logits_source
    if not active() or _first_logits is not None:
        return
    if logits is None or logits.ndim != 2 or logits.shape[0] != 1:
        raise RuntimeError("Audit requires one full first-token logits vector")
    _first_logits = _array(logits[0])
    _logits_source = _source(
        inspect.currentframe().f_back, "siai.vllm.first-token-logits"
    )


def finish_generation(result) -> None:
    if not active() or _first_logits is None or _pending_mask is not None:
        raise RuntimeError("Incomplete native decoder/logits evidence")
    if len(result.outputs) != 1:
        raise RuntimeError("Audit requires one completion per request")
    output = result.outputs[0]
    _client.emit(
        "generation_output",
        {
            "status": "success",
            "returncode": 0,
            "engine_request_id": result.request_id,
            "generated_text": output.text,
            "token_ids": list(output.token_ids),
            "generated_token_count": len(output.token_ids),
            "finish_reason": output.finish_reason,
            "stop_reason": output.stop_reason,
            "prompt_token_ids": result.prompt_token_ids,
            "first_step_logits_count": int(_first_logits.size),
            "first_logits_source": dict(_logits_source),
            "generation_output_source": _source(
                inspect.currentframe().f_back,
                "siai.vllm.public-generate-result",
            ),
            "event_composition": (
                "First native logits joined with the public generate result "
                "within one active audit request; source identifies logits capture"
            ),
        },
        context=_context,
        source=_logits_source,
        tensors={"logits": _first_logits},
        readable={"summary": "Native first-token logits joined to LLM.generate output"},
    )
