"""Pinned loopback-only CPU MLC runtime; no inference or HTTP substitution."""

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
ENGINE = ROOT / "Instrumented-LIE/ama/mlc-llm/engine"
PRIOR = ROOT / "Instrumented-LIE/siai/mlc-llm"
PYTHON = PRIOR / ".venv/bin/python"
MANIFEST = ROOT / "LieMappBench/Logging-Dataset/ama/mlc-llm/native-build-manifest.json"
MODEL_LIBRARY_NAME = "qwen2.5-3b-instruct-q4f32_1-cpu.so"
DEPS = ROOT / "Instrumented-LIE/ama/mlc-llm/runtime-deps"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_identity():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def snapshot_runtime_dependencies():
    """Copy the proven CPU runtime bytes out of temporary compiler caches.

    Never overwrite a snapshot, modify the original environments, or create
    hardlinks/symlinks. The later initialized-process manifest checks which
    copied libraries actually load; copying alone is not compatibility proof.
    """
    if DEPS.exists():
        raise FileExistsError(DEPS)
    DEPS.mkdir(parents=True)
    python_dir, library_dir = DEPS / "python", DEPS / "lib"
    python_dir.mkdir()
    library_dir.mkdir()
    sources = [(Path("/tmp/mlc-exact-python/tvm_ffi"), python_dir / "tvm_ffi"),
               (PRIOR / "engine/3rdparty/tvm/python/tvm", python_dir / "tvm")]
    for source, target in sources:
        shutil.copytree(source, target, symlinks=False,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    records = []
    for name in ("libtvm_runtime.so", "libtvm_runtime_extra.so", "libtvm_compiler.so"):
        source = Path("/tmp/mlc-tvm-837c-build/lib") / name
        target = library_dir / name
        shutil.copy2(source, target, follow_symlinks=True)
        records.append({"source": str(source), "target": str(target.relative_to(ROOT)), "sha256": sha256(target)})
    for name in ("libmlc_llm_module.so", "libmlc_llm.so"):
        source, target = PRIOR / "engine/build" / name, library_dir / name
        shutil.copy2(source, target, follow_symlinks=True)
        records.append({"source": str(source.relative_to(ROOT)), "target": str(target.relative_to(ROOT)), "sha256": sha256(target)})
    for source, target in sources:
        for item in sorted(target.rglob("*")):
            if item.is_file():
                original = source / item.relative_to(target)
                if item.is_symlink() or item.stat().st_ino == original.stat().st_ino or sha256(item) != sha256(original):
                    raise ValueError("Runtime snapshot is not an independent exact copy")
                records.append({"source": str(original), "target": str(item.relative_to(ROOT)), "sha256": sha256(item)})
    with (DEPS / "copy-manifest.json").open("x", encoding="utf-8") as stream:
        json.dump({"independent_copies": True, "files": records}, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return records


def validate_runtime():
    manifest = runtime_identity()
    head = subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip()
    if head != manifest["upstream_commit"]:
        raise ValueError("MLC source commit differs from manifest")
    for item in manifest["validated_files"]:
        path = Path(item["path"])
        path = path if path.is_absolute() else ROOT / path
        if not path.is_file() or sha256(path) != item["sha256"]:
            raise ValueError("Pinned native runtime changed: " + item["path"])
    return manifest


def resolve_model_library(requested, manifest):
    """Bind the actually selected CPU library to the frozen runtime identity."""
    descriptor = manifest["build"]["native_model_library"]
    recorded = (ROOT / descriptor["path"]).resolve(strict=True)
    selected = Path(requested).resolve(strict=True) if requested is not None else recorded
    if selected != recorded:
        raise ValueError("Selected model library differs from the frozen native build")
    if (not selected.is_file() or selected.stat().st_size != descriptor["bytes"]
            or sha256(selected) != descriptor["sha256"]):
        raise ValueError("Selected model library bytes differ from the frozen native build")
    return selected


def proof_files(document):
    """Verify and collect every content-addressed file referenced by a proof."""
    files = set()
    def walk(value):
        if isinstance(value, dict):
            if {"path", "sha256"} <= value.keys():
                path = Path(value["path"])
                path = (path if path.is_absolute() else ROOT / path).resolve(strict=True)
                if (not path.is_file() or sha256(path) != value["sha256"]
                        or ("bytes" in value and path.stat().st_size != value["bytes"])):
                    raise ValueError("CPU proof artifact changed: " + str(path))
                files.add(path)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(document)
    return files


def cpu_proofs(library, compiler_identity, numerical_validation):
    """Require independent observed checks for this exact selected CPU variant."""
    documents, files = {}, set()
    for key, source in (("compiler_identity", compiler_identity), ("numerical_validation", numerical_validation)):
        path = Path(source).resolve(strict=True)
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("status") not in {"pass", "passed"}:
            raise ValueError("CPU validation did not pass: " + key)
        candidate = document["candidate_library"]
        if (Path(candidate["path"]).resolve(strict=True) != Path(library).resolve(strict=True)
                or candidate["sha256"] != sha256(library)):
            raise ValueError("CPU proof is for another model library: " + key)
        files.update(proof_files(document))
        files.add(path)
        documents[key] = {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size,
                          "sha256": sha256(path), "status": document["status"]}
    return documents, files


def freeze_runtime(identity_path, *, compiler_identity, numerical_validation, output=MANIFEST):
    """Freeze an actually initialized service plus all native MLC Python sources.

    This is not proof of model output correctness: the separate logging ON/OFF
    parity and full experiment establish the applicable execution observations.
    External read-only dependency paths are retained explicitly when necessary.
    """
    identity_path = Path(identity_path).resolve(strict=True)
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    if identity.get("native_engine") != "mlc_llm.MLCEngine" or not identity.get("model_generation_is_native"):
        raise ValueError("Expected actual service initialization identity")
    proofs, proof_paths = cpu_proofs(identity["model_lib"], compiler_identity, numerical_validation)
    files = {Path(path).resolve(strict=True) for key in ("loaded_python_modules", "loaded_native_objects")
             for path in identity[key]}
    files.update(proof_paths)
    files.add(identity_path)
    files.add((HERE / "prepare_evaluation.py").resolve(strict=True))
    files.update(path.resolve() for name in ("bootstrap.json", "stdout.log", "stderr.log")
                 if (path := identity_path.parent / name).is_file())
    files.add(Path(identity["python_executable"]).resolve(strict=True))
    files.update(path.resolve() for path in (ENGINE / "python/mlc_llm").rglob("*.py"))
    files.update(path.resolve() for path in DEPS.rglob("*") if path.is_file()
                 and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"})
    files.update({(HERE / "service.py").resolve(), Path(__file__).resolve(),
                  Path(identity["model_lib"]).resolve(strict=True)})
    def record(path):
        return {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                "sha256": sha256(path), "bytes": path.stat().st_size}
    changes = []
    original = ROOT / "LIE/mlc-llm"
    for relative in ("python/mlc_llm/serve/engine.py", "python/mlc_llm/serve/engine_base.py",
                     "python/mlc_llm/liemapp_ama.py"):
        baseline = original / relative
        changes.append({"path": relative, "original_sha256": sha256(baseline) if baseline.exists() else None,
                        "instrumented_sha256": sha256(ENGINE / relative)})
    manifest = {"schema_version": "1.0.0", "attack_id": "ama", "engine_id": "mlc-llm",
                "upstream_commit": subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip(),
                "original_repository": "LIE/mlc-llm",
                "instrumented_repository": str(ENGINE.relative_to(ROOT)),
                "source_changes": changes, "validated_files": [record(path) for path in sorted(files)],
                "build": {"backend": "CPU", "runtime_python": str(PYTHON.relative_to(ROOT)),
                          "native_model_library": record(Path(identity["model_lib"])),
                          "compiler_variant": "approved independent-output-channel CPU scheduling; not stock upstream scheduling",
                          "validation_proofs": proofs,
                          "runtime_initialization_observed": True,
                          "original_model_parser_unchanged": True,
                          "conversation_configuration": "explicit Qwen2 native Python-call format variant",
                          "dependency_scope": "loaded Python modules/shared objects at initialization, all MLC Python sources, and every copied runtime dependency; not a complete OS reproducibility guarantee"},
                "initialization_identity": {"path": str(identity_path.relative_to(ROOT)) if identity_path.is_relative_to(ROOT) else str(identity_path),
                                            "sha256": sha256(identity_path)},
                "limitations": ["Sampling and format are not numerically identical to other inference engines.",
                                "Function-call proposal is not proof of external API execution.",
                                "Logger ON/OFF parity is separate from stock-versus-instrumented binary equivalence."]}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")
    return manifest


def environment(output_dir, socket_path=None, threads=6):
    if not 1 <= threads <= 6:
        raise ValueError("CPU thread count must be between 1 and 6")
    cache = Path(output_dir).resolve() / "runtime-cache"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("LIEMAPP_", "TVM_", "MLC_")) or key in {
            "PYTHONPATH", "PYTHONHOME", "LD_LIBRARY_PATH", "LD_PRELOAD",
            "RANK", "LOCAL_RANK", "WORLD_SIZE", "MASTER_ADDR", "MASTER_PORT",
        }:
            env.pop(key, None)
    env.update({
        "PYTHONPATH": ":".join([str(DEPS / "python"), str(ENGINE / "python")]),
        "TVM_LIBRARY_PATH": str(DEPS / "lib"),
        "MLC_LIBRARY_PATH": str(DEPS / "lib"),
        "LD_LIBRARY_PATH": ":".join([str(DEPS / "python/tvm_ffi/lib"), str(DEPS / "lib")]),
        "PYTHONDONTWRITEBYTECODE": "1", "TVM_NUM_THREADS": str(threads),
        "OMP_NUM_THREADS": str(threads), "MKL_NUM_THREADS": str(threads),
        "OPENBLAS_NUM_THREADS": "1", "TOKENIZERS_PARALLELISM": "false",
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
        "HF_HOME": str(cache / "huggingface"), "XDG_CACHE_HOME": str(cache),
        "MLC_LLM_HOME": str(cache / "mlc"),
        "LIEMAPP_LOGGER_PATH": str(ROOT / "LieMappBench/Logging-Dataset/logger.py"),
    })
    if socket_path is not None:
        env["LIEMAPP_SOCKET"] = str(socket_path)
    return env


def _process_tree(pid):
    parents = {}
    for path in Path("/proc").glob("[0-9]*/status"):
        try:
            parents[int(path.parent.name)] = int(next(line.split()[1] for line in path.read_text().splitlines()
                                                      if line.startswith("PPid:")))
        except (OSError, StopIteration, ValueError):
            continue
    result = {pid}
    while True:
        expanded = result | {child for child, parent in parents.items() if parent in result}
        if expanded == result:
            return result
        result = expanded


def assert_loopback_listeners(pid):
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
    manifest = validate_runtime()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = Path(model_path).resolve(strict=True)
    model_lib = resolve_model_library(getattr(args, "model_lib", None), manifest)
    runtime_python = Path(getattr(args, "runtime_python", None) or PYTHON).absolute()
    if runtime_python != PYTHON.absolute():
        raise ValueError("Different runtime Python requires a new manifest")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [str(runtime_python), "-B", str(HERE / "service.py"),
               "--model", str(model_path), "--model-lib", str(model_lib),
               "--port", str(port), "--context-size", str(args.context_size),
               "--prefill-size", "512", "--identity-output", str(output_dir / "native-service-identity.json")]
    if getattr(args, "diagnostics", False):
        command.append("--diagnostics")
    env = environment(output_dir, socket_path, args.threads)
    stdout_path, stderr_path = output_dir / "server.stdout.log", output_dir / "server.stderr.log"
    process = None
    observations = []
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=ENGINE, env=env, stdout=out, stderr=err,
                                       start_new_session=True)
            base = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + args.startup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Native MLC exited {process.returncode}: {stderr_path}")
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
                raise TimeoutError(f"Native MLC startup timed out: {stderr_path}")
            yield base, command
            observations.append({"phase": "after_requests", "listeners": assert_loopback_listeners(process.pid)})
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                with (output_dir / "native-network-audit.json").open("x", encoding="utf-8") as stream:
                    json.dump({"pid": process.pid, "observations": observations,
                               "server_exit_code": process.returncode,
                               "shutdown_requested_by_harness": True,
                               "scope": "TCP listener snapshots; not packet capture"},
                              stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
