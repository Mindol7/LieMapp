"""Download immutable official MLC weights, verify Git/LFS hashes, never execute remote code."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parents[5]
REPOSITORY = "mlc-ai/Qwen2.5-3B-Instruct-q4f32_1-MLC"
REVISION = "dfa91e859b714acfa489a1464297080656c3460d"
OUTPUT = ROOT / ".evidence/models/ama/mlc-official-qwen2.5-3b-instruct-q4f32_1-dfa91e8"
PROVENANCE = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-source/ama/mlc-llm/model-provenance/dfa91e8"


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def main():
    OUTPUT.mkdir(parents=True, exist_ok=False)
    PROVENANCE.mkdir(parents=True, exist_ok=False)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"https://huggingface.co/api/models/{REPOSITORY}/revision/{REVISION}?blobs=true"
    with opener.open(url, timeout=45) as response:
        api_bytes = response.read(1024 * 1024)
    metadata = json.loads(api_bytes)
    if metadata["sha"] != REVISION or metadata["id"] != REPOSITORY:
        raise ValueError("Unexpected official model identity")
    with (PROVENANCE / "huggingface-api.json").open("xb") as stream:
        stream.write(api_bytes)
    records = metadata["siblings"]
    names = [row["rfilename"] for row in records]
    if len(names) != len(set(names)) or any(Path(n).name != n or n in {".", ".."} for n in names):
        raise ValueError("Unsafe or duplicate upstream filename")

    def download(row):
        name = row["rfilename"]
        target = OUTPUT / name
        attempts = []
        for attempt in range(1, 4):
            partial = OUTPUT / (name + f".download-attempt-{attempt}")
            remote = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{name}?download=true"
            try:
                with opener.open(remote, timeout=120) as response, partial.open("xb") as stream:
                    shutil.copyfileobj(response, stream, length=1024 * 1024)
                if partial.stat().st_size != row["size"]:
                    raise ValueError("Upstream byte size mismatch")
                with partial.open("rb") as stream:
                    sha = hashlib.file_digest(stream, "sha256").hexdigest()
                if "lfs" in row:
                    if sha != row["lfs"]["sha256"]:
                        raise ValueError("Upstream LFS SHA256 mismatch")
                    kind, expected = "lfs_sha256", row["lfs"]["sha256"]
                else:
                    blob = hashlib.sha1(b"blob " + str(row["size"]).encode() + b"\0")
                    with partial.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            blob.update(chunk)
                    if blob.hexdigest() != row["blobId"]:
                        raise ValueError("Upstream Git blob identity mismatch")
                    kind, expected = "git_blob_sha1", row["blobId"]
                if target.exists():
                    raise FileExistsError(target)
                partial.rename(target)
                result = {"path": name, "bytes": row["size"], "sha256": sha,
                          "upstream_hash_kind": kind, "upstream_hash": expected,
                          "url": remote, "failed_attempts": attempts}
                print(json.dumps({"verified": name, "bytes": row["size"]}), flush=True)
                return result
            except Exception as error:
                attempts.append({"attempt": attempt, "type": type(error).__name__, "error": str(error)})
                if attempt == 3:
                    write_new(PROVENANCE / (name + ".failure.json"), attempts)
                    raise

    with ThreadPoolExecutor(max_workers=4) as pool:
        files = list(pool.map(download, records))
    manifest = {"repository": REPOSITORY, "revision": REVISION,
                "fetched_utc": datetime.now(timezone.utc).isoformat(), "api_url": url,
                "api_sha256": hashlib.sha256(api_bytes).hexdigest(),
                "source_base": "Qwen/Qwen2.5-3B-Instruct",
                "source_base_exact_revision_disclosed_by_provider": False,
                "same_bytes_as_local_HF_quantization_claimed": False,
                "cache_path": str(OUTPUT.relative_to(ROOT)), "files": files,
                "download_helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write_new(PROVENANCE / "manifest.json", manifest)
    print(json.dumps({"status": "verified", "files": len(files), "bytes": sum(r["bytes"] for r in files),
                      "model": str(OUTPUT), "manifest": str(PROVENANCE / "manifest.json")}), flush=True)


if __name__ == "__main__":
    main()
