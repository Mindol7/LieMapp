"""Read-only pinned llama.cpp native binary for the shared public AMA protocol."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[5]
ENGINE = ROOT / "Instrumented-LIE/ama/llamacpp"
BINARY = ENGINE / "build-liemapp/bin/llama-server"
MANIFEST = ROOT / "LieMappBench/Logging-Dataset/ama/llamacpp/public-http-v1/native-build-manifest.json"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_runtime():
    manifest = json.loads(MANIFEST.read_text())
    head = subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip()
    if head != manifest["upstream_commit"]:
        raise ValueError("Native llama.cpp revision changed")
    for item in manifest["validated_files"]:
        path = ROOT / item["path"]
        if not path.is_file() or sha256(path) != item["sha256"]:
            raise ValueError("Pinned native source/binary changed: " + item["path"])
    modified = set(subprocess.check_output(["git", "-C", str(ENGINE), "diff", "HEAD", "--name-only"], text=True).splitlines())
    if modified != set(manifest["expected_modified_paths"]):
        raise ValueError("Native source patch set differs from frozen build")
    return manifest


def environment(output_dir, socket_path=None, threads=6):
    if not 1 <= threads <= 6:
        raise ValueError("Threads must be 1..6")
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("LLAMA_", "LIEMAPP_", "GGML_", "HF_", "SGLANG_", "VLLM_")) or key in {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
        }:
            env.pop(key, None)
    env.update(OMP_NUM_THREADS=str(threads), OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS=str(threads))
    if socket_path is not None:
        env["LIEMAPP_SOCKET"] = str(socket_path)
    return env


def checked_generation(response, payload):
    """Validate upstream per-request effective settings from actual native response."""
    verbose = response.get("__verbose")
    if not isinstance(verbose, dict) or not isinstance(verbose.get("content"), str):
        raise ValueError("Actual native generation diagnostics unavailable")
    actual = verbose["generation_settings"]
    expected = {"seed": payload["seed"], "temperature": payload["temperature"], "top_p": 1.0,
                "top_k": 0, "min_p": 0.0, "repeat_penalty": 1.0, "presence_penalty": 0.0,
                "frequency_penalty": 0.0, "dynatemp_range": 0.0, "mirostat": 0,
                "max_tokens": payload["max_tokens"], "samplers": ["temperature"]}
    for key, value in expected.items():
        observed = actual.get(key)
        if isinstance(value, float):
            valid = isinstance(observed, (int, float)) and not isinstance(observed, bool) and math.isclose(observed, value, abs_tol=1e-7)
        else:
            valid = observed == value and (type(observed) is type(value) or isinstance(value, list))
        if not valid:
            raise ValueError(f"Effective native setting differs: {key}: {observed!r} != {value!r}")
    if verbose.get("truncated") is not False:
        raise ValueError("Prompt was truncated")
    cached = response.get("usage", {}).get("prompt_tokens_details", {}).get("cached_tokens")
    if cached != 0:
        raise ValueError("Unexpected cached prompt tokens")
    return actual


def _process_tree(pid):
    parents = {}
    for status in Path("/proc").glob("[0-9]*/status"):
        try:
            lines = status.read_text().splitlines()
            parents[int(status.parent.name)] = int(next(
                line.split()[1] for line in lines if line.startswith("PPid:")
            ))
        except (OSError, StopIteration, ValueError):
            continue
    result = {pid}
    while True:
        expanded = result | {child for child, parent in parents.items() if parent in result}
        if expanded == result:
            return result
        result = expanded


def assert_loopback_listeners(pid):
    """Audit all current listening TCP sockets owned by the native process tree."""
    owners = {}
    for child in _process_tree(pid):
        for fd in Path(f"/proc/{child}/fd").glob("*"):
            try:
                link = os.readlink(fd)
            except OSError:
                continue
            if link.startswith("socket:["):
                owners.setdefault(link[8:-1], set()).add(child)
    listeners = []
    for network in ("tcp", "tcp6"):
        for line in Path(f"/proc/net/{network}").read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] != "0A" or fields[9] not in owners:
                continue
            address, port = fields[1].split(":")
            packed = bytes.fromhex(address)
            packed = b"".join(packed[i:i + 4][::-1] for i in range(0, len(packed), 4))
            ip = ipaddress.ip_address(packed)
            record = {"address": str(ip), "port": int(port, 16),
                      "pids": sorted(owners[fields[9]]), "loopback": ip.is_loopback}
            listeners.append(record)
            if not ip.is_loopback:
                raise RuntimeError(f"Non-loopback native TCP listener: {record}")
    return listeners


@contextmanager
def server(args, model_path, output_dir, socket_path=None):
    """No rebuild/download; private CPU native server and read-only model."""
    validate_runtime()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = Path(model_path).resolve(strict=True)
    if not model_path.is_file() or model_path.suffix != ".gguf" or not model_path.is_relative_to(ROOT / ".evidence/models/ama"):
        raise ValueError("Expected verified local GGUF model")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [str(BINARY), "-m", str(model_path), "--alias", "local-ama-model",
               "--host", "127.0.0.1", "--port", str(port), "-ngl", "0",
               "-t", str(args.threads), "-tb", str(args.threads), "-c", str(args.context_size),
               "-b", "512", "-ub", "512", "-np", "1", "--jinja", "--no-webui", "--no-agent",
               "--cache-ram", "0", "--no-cache-prompt", "--samplers", "temperature",
               "--repeat-penalty", "1", "--top-p", "1", "--top-k", "0", "--min-p", "0",
               "--temp", str(getattr(args, "temperature", 0.0)), "--log-verbosity", "10", "--log-colors", "off"]
    env = environment(output_dir, socket_path, args.threads)
    stdout_path, stderr_path = output_dir / "server.stdout.log", output_dir / "server.stderr.log"
    process = None
    observations = []
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError("Native server redirects forbidden")
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=ENGINE, env=env, stdout=out, stderr=err, start_new_session=True)
            base = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            deadline = time.monotonic() + args.startup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Native llama-server exited {process.returncode}: {stderr_path}")
                listeners = assert_loopback_listeners(process.pid)
                try:
                    with opener.open(base + "/health", timeout=2) as response:
                        health = json.loads(response.read())
                        if response.status == 200 and health.get("status") == "ok":
                            observations.append({"phase": "healthy", "listeners": listeners})
                            break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.25)
            else:
                raise TimeoutError("Native llama-server did not become healthy")
            with opener.open(base + "/props", timeout=5) as response:
                properties = json.loads(response.read())
            observations.append({"phase": "native_properties", "properties": properties})
            yield base, command
            observations.append({"phase": "after_requests", "listeners": assert_loopback_listeners(process.pid)})
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                audit = {"pid": process.pid, "observations": observations, "server_exit_code": process.returncode,
                         "shutdown_requested_by_harness": True,
                         "scope": "Owned TCP listeners observed at startup/after requests, plus native GET /props; not packet capture"}
                with (output_dir / "native-network-audit.json").open("x", encoding="utf-8") as stream:
                    json.dump(audit, stream, indent=2, ensure_ascii=False)
                    stream.write("\n")
