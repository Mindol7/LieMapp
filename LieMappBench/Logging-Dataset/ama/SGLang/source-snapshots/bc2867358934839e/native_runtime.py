"""Pinned, loopback-only native SGLang CPU runtime for the AMA experiment."""

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[5]
ENGINE = ROOT / "Instrumented-LIE/ama/SGLang"
PRIOR = ROOT / "Instrumented-LIE/siai/SGLang"
PYTHON = PRIOR / ".venv/bin/python"
MANIFEST = ROOT / "LieMappBench/Logging-Dataset/ama/SGLang/native-build-manifest.json"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_identity():
    """Return the frozen source/kernel/dependency manifest, not a new claim."""
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def validate_runtime():
    """Refuse changed native sources, kernels, or pinned runtime dependencies."""
    manifest = runtime_identity()
    head = subprocess.check_output(
        ["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != manifest["upstream_commit"]:
        raise ValueError("Native SGLang commit differs from its manifest")
    for item in manifest["validated_files"]:
        path = ROOT / item["path"]
        if not path.is_file() or sha256(path) != item["sha256"]:
            raise ValueError(f"Pinned runtime file changed: {item['path']}")
    return manifest


def environment(output_dir, socket_path=None, threads=6):
    """Read-only prior venv, independent AMA source and private run caches."""
    if not 1 <= threads <= 6:
        raise ValueError("CPU experiment threads must be between 1 and 6")
    cache = Path(output_dir).resolve() / "runtime-cache"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("SGLANG_", "VLLM_", "LIEMAPP_")) or key in {
            "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
            "RANK", "LOCAL_RANK", "WORLD_SIZE", "MASTER_ADDR", "MASTER_PORT",
        }:
            env.pop(key, None)
    env.update({
        "PYTHONPATH": str(ENGINE / "python"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "SGLANG_USE_CPU_ENGINE": "1",
        "SGLANG_CACHE_DIR": str(cache / "sglang"),
        "SGLANG_VLM_CACHE_SIZE_MB": "0",
        "GLOO_SOCKET_IFNAME": "lo",
        "DO_NOT_TRACK": "1",
        "DISABLE_OPENAPI_DOC": "1",
        "HF_HUB_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HOME": str(cache / "huggingface"),
        "XDG_CACHE_HOME": str(cache),
        "TORCHINDUCTOR_CACHE_DIR": str(cache / "torchinductor"),
        "TRITON_CACHE_DIR": str(cache / "triton"),
        "TOKENIZERS_PARALLELISM": "false",
        "OMP_NUM_THREADS": str(threads),
        "MKL_NUM_THREADS": str(threads),
        "OPENBLAS_NUM_THREADS": "1",
        "LIEMAPP_LOGGER_PATH": str(ROOT / "LieMappBench/Logging-Dataset/logger.py"),
    })
    if socket_path is not None:
        env["LIEMAPP_SOCKET"] = str(socket_path)
    return env


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
    """Run the real SGLang OpenAI server; no model download or tool dispatch."""
    validate_runtime()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = Path(model_path).resolve(strict=True)
    if not model_path.is_dir() or not (model_path / "config.json").is_file():
        raise ValueError("Expected a verified local Hugging Face model directory")
    runtime_python = Path(getattr(args, "runtime_python", None) or PYTHON).absolute()
    if runtime_python != PYTHON.absolute():
        raise ValueError("A different Python environment requires a new runtime manifest")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [
        str(runtime_python), "-B", "-m", "sglang.launch_server",
        "--model-path", str(model_path), "--served-model-name", "local-ama-model",
        "--host", "127.0.0.1", "--port", str(port),
        "--device", "cpu", "--dtype", "float32", "--model-impl", "sglang",
        "--attention-backend", "torch_native", "--tp-size", "1",
        "--context-length", str(args.context_size),
        "--max-total-tokens", str(args.context_size),
        "--max-running-requests", "1", "--mem-fraction-static", "0.6",
        "--chunked-prefill-size", "-1", "--disable-radix-cache",
        "--disable-overlap-schedule", "--disable-custom-all-reduce",
        "--cuda-graph-backend-decode", "disabled",
        "--cuda-graph-backend-prefill", "disabled",
        "--tool-call-parser", "hermes", "--sampling-defaults", "openai",
        "--random-seed", "20260911", "--log-level", "info",
    ]
    env = environment(output_dir, socket_path, args.threads)
    stdout_path = output_dir / "server.stdout.log"
    stderr_path = output_dir / "server.stderr.log"
    process = None
    observations = []
    with tempfile.TemporaryDirectory(prefix="ama-sglang-ipc-") as ipc_dir, \
            stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        env["TMPDIR"] = ipc_dir
        env["SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE"] = "file://" + ipc_dir + "/dist-store"
        try:
            process = subprocess.Popen(command, cwd=ENGINE, env=env, stdout=out,
                                       stderr=err, start_new_session=True)
            base = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + args.startup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Native SGLang exited {process.returncode}: {stderr_path}")
                listeners = assert_loopback_listeners(process.pid)
                try:
                    with opener.open(base + "/health", timeout=2) as response:
                        if response.status == 200:
                            observations.append({"phase": "healthy", "listeners": listeners})
                            break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.5)
            else:
                raise TimeoutError(f"Native SGLang startup timed out: {stderr_path}")
            yield base, command
            observations.append({"phase": "after_requests",
                                 "listeners": assert_loopback_listeners(process.pid)})
        finally:
            if process is not None:
                if process.poll() is None:
                    # Let SGLang drain and stop its workers before force cleanup.
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                # Popen created this private session; stop only surviving members.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                audit = {"pid": process.pid, "observations": observations,
                         "server_exit_code": process.returncode,
                         "shutdown_requested_by_harness": True,
                         "scope": "TCP listener snapshots during startup and after requests; not packet capture"}
                (output_dir / "native-network-audit.json").write_text(
                    json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
