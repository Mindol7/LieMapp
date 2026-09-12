"""Request-scoped, observation-only bridge to the common LieMapp logger.

The stock MLC model, Conversation renderer, sampler, and Python-call parser
remain responsible for inference. This module never changes any model value.
"""

from contextlib import contextmanager
from contextvars import ContextVar
import copy
from functools import lru_cache
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys

_ACTIVE = ContextVar("liemapp_ama_request", default=None)


def enabled():
    return bool(os.environ.get("LIEMAPP_SOCKET")) and _ACTIVE.get() is not None


def observing():
    return _ACTIVE.get() is not None and (
        bool(os.environ.get("LIEMAPP_SOCKET")) or os.environ.get("LIEMAPP_DIAGNOSTICS") == "1"
    )


@contextmanager
def request_scope(submitted, effective, adaptations):
    request_id = submitted.get("liemapp_request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 256:
        raise ValueError("Invalid experiment request ID")
    context = submitted.get("liemapp_context", {})
    if not isinstance(context, dict):
        raise ValueError("Experiment context must be an object")
    if len(json.dumps(context).encode()) > 16384:
        raise ValueError("Experiment context exceeds 16 KiB")
    state = {"request_id": request_id, "context": copy.deepcopy(context),
             "submitted_request": copy.deepcopy(submitted),
             "effective_request": copy.deepcopy(effective),
             "adaptations": copy.deepcopy(adaptations), "output_token_ids": [[]],
             "native_finish_reasons": [], "extra_prefix_strings": [], "observations": []}
    token = _ACTIVE.set(state)
    try:
        yield state
    finally:
        _ACTIVE.reset(token)


def state():
    return _ACTIVE.get()


def capture_tokens(request_id, stream_outputs):
    if not observing():
        return
    item = state()
    if request_id != item["request_id"]:
        raise ValueError("MLC callback request correlation mismatch")
    while len(item["output_token_ids"]) < len(stream_outputs):
        item["output_token_ids"].append([])
    for index, output in enumerate(stream_outputs):
        item["output_token_ids"][index].extend(int(value) for value in output.delta_token_ids)
        item["extra_prefix_strings"].append(output.extra_prefix_string)
        if output.finish_reason is not None:
            item["native_finish_reasons"].append({"choice": index, "finish_reason": output.finish_reason})


def capture_before_parser(output_texts, finish_reasons):
    if observing():
        state()["generated_texts_before_parser"] = list(output_texts)
        state()["finish_reasons_before_parser"] = list(finish_reasons)


def capture_native_request(request_id, request):
    if not observing():
        return
    if state()["request_id"] != request_id:
        raise ValueError("MLC native request correlation mismatch")
    from mlc_llm.serve import _ffi_api
    serialized = str(_ffi_api.RequestGetGenerationConfigJSON(request))
    state()["native_generation_config_json"] = serialized
    state()["native_generation_config"] = json.loads(serialized)


@lru_cache(maxsize=1)
def _logger_module():
    path = Path(os.environ["LIEMAPP_LOGGER_PATH"]).resolve(strict=True)
    name = "liemapp_ama_mlc_common_logger"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot import the common logger")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(stage, point, raw, summary):
    if not observing():
        return
    item = state()
    frame = inspect.currentframe()
    caller = frame.f_back
    source = {"path": str(Path(caller.f_code.co_filename).resolve()),
              "function": caller.f_code.co_name, "line": caller.f_lineno,
              "logging_point_id": point}
    del frame, caller
    if os.environ.get("LIEMAPP_DIAGNOSTICS") == "1":
        item["observations"].append(copy.deepcopy({"stage": stage, "raw": {**raw, "request_id": item["request_id"]},
                                                   "source": source}))
    if not enabled():
        return
    _logger_module().Client().emit(
        stage, {**raw, "request_id": item["request_id"]},
        readable={"summary": summary, "scope": "native MLC Python serving observation"},
        context={**item["context"], "request_id": item["request_id"], "layer": "inference_engine"},
        source=source,
    )
