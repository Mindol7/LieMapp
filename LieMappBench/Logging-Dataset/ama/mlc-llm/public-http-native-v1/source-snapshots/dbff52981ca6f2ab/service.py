"""Private HTTP transport around the real synchronous MLC CPU engine.

The transport does not choose tools, generate arguments, repair model output,
or execute any external API. Its explicit compatibility adaptations are logged
at the native request boundary. Stock MLC's Python-call parser is retained.
"""

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import signal
import sys
import traceback

MODEL_ALIAS = "local-ama-model"
MAX_REQUEST_BYTES = 128 * 1024
NATIVE_FIELDS = frozenset({
    "messages", "model", "frequency_penalty", "presence_penalty", "logprobs",
    "top_logprobs", "logit_bias", "max_tokens", "n", "seed", "stop", "stream",
    "temperature", "top_p", "tools", "tool_choice",
})
FORMAT_INSTRUCTION = (
    "\n\n# Functions\nAvailable function definitions:\n{function_string}\n"
    "If you choose to invoke a function, return only a Python function call "
    "using keyword arguments, in the form function_name(argument_name='value'). "
    "Use literal argument values. Do not wrap a function call in JSON, XML tags, "
    "or Markdown fences. If you do not choose to invoke a function, respond normally."
)


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))


def adapt_request(submitted):
    """Return actual native API kwargs and explicit non-native adaptations."""
    if not isinstance(submitted, dict):
        raise ValueError("Request must be an object")
    allowed = NATIVE_FIELDS | {"liemapp_request_id", "liemapp_context", "parallel_tool_calls"}
    unknown = set(submitted) - allowed
    if unknown:
        raise ValueError("Unsupported request fields: " + ", ".join(sorted(unknown)))
    if submitted.get("model") != MODEL_ALIAS:
        raise ValueError("Unexpected served model")
    if submitted.get("stream", False) is not False or submitted.get("n", 1) != 1:
        raise ValueError("Only nonstreaming n=1 requests are supported")
    if not isinstance(submitted.get("messages"), list) or not isinstance(submitted.get("tools"), list):
        raise ValueError("Messages and tools must be lists")
    if not submitted["tools"]:
        raise ValueError("At least one tool is required for this experiment")
    effective = {key: value for key, value in submitted.items() if key in NATIVE_FIELDS}
    effective["request_id"] = submitted.get("liemapp_request_id")
    adaptations = []
    if submitted.get("tool_choice") == "required":
        if len(submitted["tools"]) != 1:
            raise ValueError("required can only be adapted for the single-candidate fixed control")
        selected = submitted["tools"][0]["function"]["name"]
        effective["tool_choice"] = {"type": "function", "function": {"name": selected}}
        adaptations.append({"field": "tool_choice", "submitted": "required",
                            "effective": effective["tool_choice"],
                            "meaning": "single-candidate named selection; stock MLC does not enforce a generation grammar"})
    elif submitted.get("tool_choice") != "auto":
        raise ValueError("Only auto and the single-candidate required control are supported")
    if "parallel_tool_calls" in submitted:
        if submitted["parallel_tool_calls"] is not False:
            raise ValueError("Parallel external calls are not allowed")
        adaptations.append({"field": "parallel_tool_calls", "submitted": False,
                            "effective": "not a native MLC argument",
                            "meaning": "one external call budget is enforced by the shared dispatcher; native proposals are not trimmed"})
    return effective, adaptations


def configured_conversation(base):
    """Use the supported Conversation configuration; no renderer/parser patch."""
    if base.name != "qwen2" or base.system_template != "<|im_start|>system\n{system_message}<|im_end|>\n":
        raise ValueError("Unexpected pinned Qwen2 Conversation template")
    return base.model_copy(deep=True, update={
        "name": "liemapp-qwen2-native-python-call-v1",
        "system_template": "<|im_start|>system\n{system_message}" + FORMAT_INSTRUCTION + "<|im_end|>\n",
    })


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-lib", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--context-size", type=int, default=4096)
    parser.add_argument("--prefill-size", type=int, default=512)
    parser.add_argument("--identity-output", required=True)
    parser.add_argument("--diagnostics", action="store_true",
                        help="Expose observation-only /diagnostics/last for logging ON/OFF parity")
    args = parser.parse_args(argv)
    if args.context_size != 4096 or args.prefill_size != 512 or not 1 <= args.port <= 65535:
        raise ValueError("Unexpected pre-registered CPU runtime limits")
    model = Path(args.model).resolve(strict=True)
    model_lib = Path(args.model_lib).resolve(strict=True)
    if not model.is_dir() or not model_lib.is_file():
        raise ValueError("A local verified MLC model and compiled library are required")

    from mlc_llm import MLCEngine, liemapp_ama
    from mlc_llm.serve.config import EngineConfig

    if args.diagnostics:
        os.environ["LIEMAPP_DIAGNOSTICS"] = "1"
    config = EngineConfig(max_num_sequence=1, max_total_sequence_length=args.context_size,
                          max_single_sequence_length=args.context_size,
                          prefill_chunk_size=args.prefill_size, prefix_cache_mode="disable",
                          speculative_mode="disable", prefill_mode="chunked")
    requested_config = json.loads(config.asjson())
    engine = MLCEngine(str(model), device="cpu", model_lib=str(model_lib),
                       mode="server", engine_config=config)
    original_conversation = engine.conv_template.model_dump()
    engine.conv_template = configured_conversation(engine.conv_template)
    identity = {"transport": "stdlib single-request loopback HTTPServer",
                "native_engine": "mlc_llm.MLCEngine", "device": "cpu",
                "model": str(model), "model_lib": str(model_lib),
                "requested_engine_config": requested_config,
                "effective_engine_config": json.loads(engine.engine_config.asjson()),
                "original_conversation": original_conversation,
                "configured_conversation": engine.conv_template.model_dump(),
                "parser": "stock MLC convert_function_str_to_json / process_function_call_output",
                "model_generation_is_native": True,
                "external_tool_execution_in_service": False}
    identity["loaded_python_modules"] = sorted({
        str(Path(module.__file__).resolve()) for module in list(sys.modules.values())
        if getattr(module, "__file__", None) and Path(module.__file__).is_file()
    })
    identity["python_executable"] = str(Path(sys.executable).resolve())
    identity["python_version"] = sys.version
    identity["loaded_native_objects"] = sorted({
        str(Path(line.split()[-1]).resolve())
        for line in Path("/proc/self/maps").read_text().splitlines()
        if len(line.split()) >= 6 and line.split()[-1].startswith("/")
        and ".so" in Path(line.split()[-1]).name and Path(line.split()[-1]).is_file()
    })
    with Path(args.identity_output).open("x", encoding="utf-8") as stream:
        json.dump(identity, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")

    last_diagnostic = {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def respond(self, code, payload):
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if args.diagnostics and self.path == "/diagnostics/last":
                self.respond(200, last_diagnostic)
                return
            self.respond(200 if self.path == "/health" else 404,
                         {"status": "ready", "native_engine": "MLCEngine"}
                         if self.path == "/health" else {"error": "not found"})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.respond(404, {"error": "not found"})
                return
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("Chunked request bodies are unsupported")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_REQUEST_BYTES:
                    raise ValueError("Invalid or oversized request")
                submitted = strict_json(self.rfile.read(size).decode("utf-8"))
                effective, adaptations = adapt_request(submitted)
            except (ValueError, KeyError, TypeError) as error:
                self.respond(400, {"error": {"type": type(error).__name__, "message": str(error)}})
                return
            diagnostic = None
            try:
                with liemapp_ama.request_scope(submitted, effective, adaptations) as diagnostic:
                    response = engine.chat.completions.create(**effective)
                if args.diagnostics:
                    last_diagnostic.clear()
                    last_diagnostic.update(diagnostic)
                self.respond(200, response.model_dump())
            except Exception as error:
                traceback.print_exc()
                # Preserve native generated text/tokens even when the stock
                # parser itself raises. Keep HTTP 500; never invent a normal
                # model response or silently repair its function call.
                failure = {"event": "native_request_exception", "error_type": type(error).__name__,
                           "error": str(error), "native_diagnostic": diagnostic}
                print(json.dumps(failure, ensure_ascii=False, allow_nan=False), file=sys.stderr, flush=True)
                if args.diagnostics:
                    last_diagnostic.clear()
                    last_diagnostic.update(failure)
                self.respond(500, {"error": {"type": type(error).__name__, "message": str(error)}})

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    def stop(_signal, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        engine.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
