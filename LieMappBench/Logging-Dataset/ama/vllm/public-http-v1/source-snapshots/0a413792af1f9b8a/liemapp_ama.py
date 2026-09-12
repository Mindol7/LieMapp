# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
"""Observation-only transport for the private LieMapp AMA experiment.

Request labels never enter generation parameters or chat-template inputs. All
storage, evidence hashes, and event sequencing belong to the common logger.
"""

import importlib.util
import inspect
import json
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any


def enabled(request: Any) -> bool:
    """Observe only explicitly correlated, nonstreaming experiment requests."""
    return bool(os.environ.get("LIEMAPP_SOCKET")) and bool(
        getattr(request, "liemapp_request_id", None)
    )


def tool_calls(payload: dict) -> list:
    """Normalize only absent/null no-call fields; retain the original response."""
    result = []
    for choice in payload["choices"]:
        calls = choice["message"].get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list):
            raise ValueError("Native response tool_calls must be a list or null")
        result.extend(calls)
    return result


@lru_cache(maxsize=1)
def _logger_module():
    path = Path(os.environ["LIEMAPP_LOGGER_PATH"]).resolve(strict=True)
    name = "liemapp_ama_common_logger"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load common LieMapp logger")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(request: Any, stage: str, point: str, raw: dict, summary: str) -> None:
    """Emit exact request-scoped observations; fail if collection is incomplete."""
    if not enabled(request):
        return
    request_id = getattr(request, "liemapp_request_id", None)
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 256:
        raise ValueError("Invalid LieMapp request correlation ID")
    labels = getattr(request, "liemapp_context", {})
    if not isinstance(labels, dict):
        raise ValueError("LieMapp request context must be an object")
    encoded = json.dumps(labels, ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > 16384:
        raise ValueError("LieMapp request context exceeds 16 KiB")
    context = json.loads(encoded)
    context["request_id"] = request_id
    frame = inspect.currentframe()
    assert frame is not None and frame.f_back is not None
    caller = frame.f_back
    source = {
        "path": str(Path(caller.f_code.co_filename).resolve()),
        "function": caller.f_code.co_name,
        "line": caller.f_lineno,
        "logging_point_id": point,
    }
    del frame, caller
    _logger_module().Client().emit(
        stage,
        {**raw, "request_id": request_id},
        readable={"summary": summary, "scope": "native inference observation"},
        context=context,
        source=source,
    )
