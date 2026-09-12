"""Verify a sealed public run and archive immutable reproduction source bytes."""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    protocol_path = HERE.parent / "shared/public_http_protocol.py"
    spec = importlib.util.spec_from_file_location("audit_public_protocol", protocol_path)
    protocol = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(protocol)
    package, finished = protocol.verify_run(args.run_dir)
    target = ROOT / ".evidence/audits" / (package.metadata["run_id"] + "-verified")
    target.mkdir(parents=True, exist_ok=False)
    archive = target / "source-snapshots"
    archive.mkdir()
    files = {}
    for record in package.metadata["code_dependencies"]:
        files[record["path"]] = record["sha256"]
    for event in package.events:
        source = event.get("source")
        if source:
            files[str(Path(source["path"]).relative_to(ROOT))] = source["sha256"]
    for path, expected in files.items():
        original = ROOT / path
        if protocol.digest(original) != expected:
            raise ValueError("Cannot snapshot changed source: " + path)
        destination = archive / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(original.read_bytes())
    originals = []
    for engine in ("llama.cpp", "vllm", "sglang", "mlc-llm", "TensorRT-LLM"):
        repo = ROOT / "LIE" / engine
        status = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"], text=True)
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        if status:
            raise ValueError("Original source tree has modifications: " + engine)
        originals.append({"engine": engine, "commit": revision, "tracked_source_clean": True})
    groups = defaultdict(list)
    for event in finished:
        c = event["context"]
        groups[c["variant"] + "/" + c["control"]].append(event)
    summary = {}
    for key, events in groups.items():
        summary[key] = {"requests": len(events), **{field: sum(e["raw"][field] for e in events) for field in
                       ("attacker_selected", "attacker_executed", "synthetic_canary_transferred", "normal_executed", "public_calls_confirmed", "blocked_calls", "unconfirmed_calls")}}
    report = {"status": "verified", "run_id": package.metadata["run_id"], "events_sha256": package.seal["events_sha256"],
              "request_count": len(finished), "event_counts": dict(Counter(e["stage"] for e in package.events)),
              "groups": summary, "original_engines": originals,
              "source_snapshots": [{"path": p, "sha256": h} for p, h in sorted(files.items())],
              "verifier_sha256": protocol.digest(protocol_path), "audit_script_sha256": protocol.digest(__file__),
              "scope": "Sealed evidence replay and source-byte preservation. Hashes are integrity checks, not external trusted timestamps or legal admissibility guarantees."}
    protocol.write_new(target / "audit.json", report)
    print(json.dumps({"audit": str(target / "audit.json"), "requests": len(finished), "groups": summary}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
