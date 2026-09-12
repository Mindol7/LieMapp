"""Create-only native initialization and readiness bindings; never fabricate results."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

import native_runtime as N
import run_public as R

P = R.load(R.HERE / "mlc_protocol.py", "mlc_preparation_protocol")


def descriptor(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path.relative_to(R.ROOT)), "sha256": R.digest(path), "bytes": path.stat().st_size}


def freeze(args):
    if N.MANIFEST.exists():
        raise FileExistsError(N.MANIFEST)
    N.cpu_proofs(args.model_lib, args.compiler_identity, args.numerical_validation)
    _, model = R.checked_model()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    identity = output / "native-service-identity.json"
    command = [str(N.PYTHON), "-B", str(R.HERE / "service.py"), "--model", str(model),
               "--model-lib", str(args.model_lib.resolve()), "--port", str(port),
               "--identity-output", str(identity)]
    audit = {"command": command, "purpose": "initialization_only_no_model_requests_no_external_API", "healthy": False}
    with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
        process = subprocess.Popen(command, cwd=R.ROOT, env=N.environment(output), stdout=stdout, stderr=stderr)
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Native initialization failed; inspect preserved stderr")
                audit["listeners"] = N.assert_loopback_listeners(process.pid)
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                        audit["healthy"] = response.status == 200
                    if audit["healthy"]:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.5)
            if not audit["healthy"]:
                raise TimeoutError("Native initialization timed out")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            audit["exit_code"] = process.returncode
            P.write_new(output / "bootstrap.json", audit)
    if process.returncode != 0:
        raise RuntimeError("Native service did not shut down cleanly")
    manifest = N.freeze_runtime(identity, compiler_identity=args.compiler_identity,
                                numerical_validation=args.numerical_validation)
    print(P.canonical({"status": "frozen", "manifest": str(N.MANIFEST),
                       "validated_files": len(manifest["validated_files"])}), flush=True)


def readiness(args):
    N.validate_runtime()
    parity = P.strict_json(args.parity.read_text())
    if (parity["status"] != "passed" or parity["native_responses_received"] != 4
            or parity["external_api_calls"] != 0 or parity["runtime"] != N.runtime_identity()):
        raise ValueError("Actual logging parity did not pass for the frozen runtime")
    N.proof_files([parity["sources"], parity["runtime"]["validated_files"],
                   *[mode["artifacts"] for mode in parity["modes"].values()]])
    package, finished = P.verify_run(args.development_run)
    if package.metadata["protocol"]["split"] != "development":
        raise ValueError("Readiness must reference a development-only run")
    groups = {(event["context"]["variant"], event["context"]["control"]) for event in finished}
    if groups != set(P.CONDITIONS) or not any(event["raw"]["public_calls_confirmed"] for event in finished):
        raise ValueError("Development must exercise all four groups and confirm a real HTTPS response")
    document = {"status": "passed", "protocol_id": P.PROTOCOL_ID,
                "runtime_manifest": descriptor(N.MANIFEST),
                "evaluation_plan": descriptor(R.HERE / "evaluation-plan.json"),
                "parity": descriptor(args.parity),
                "development_run": {"directory": str(args.development_run.resolve().relative_to(R.ROOT)),
                                    "artifacts": [descriptor(args.development_run / name) for name in
                                                  ("events.jsonl", "run.json", "seal.json", "observations.json")]},
                "execution_sources": [descriptor(R.HERE / name) for name in
                                      ("run_public.py", "mlc_protocol.py", "native_runtime.py", "service.py")],
                "claim_limit": "Development gates passed; this is not a completed held-out evaluation."}
    P.write_new(R.HERE / "evaluation-readiness.json", document)
    print(P.canonical({"status": "ready", "development_requests": len(finished)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("freeze")
    for name in ("model-lib", "compiler-identity", "numerical-validation", "output-dir"):
        start.add_argument("--" + name, type=Path, required=True)
    ready = sub.add_parser("readiness")
    ready.add_argument("--parity", type=Path, required=True)
    ready.add_argument("--development-run", type=Path, required=True)
    args = parser.parse_args()
    (freeze if args.action == "freeze" else readiness)(args)


if __name__ == "__main__":
    main()
