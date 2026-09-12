"""Fetch a pinned official safetensors model and verify every file's SHA-256."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(path, record):
    return path.is_file() and path.stat().st_size == record["bytes"] and digest(path) == record["sha256"]


def fetch(spec, directory, record):
    name = record["path"]
    if Path(name).name != name or name in {"", ".", ".."}:
        raise ValueError("Only explicit single-component model filenames are allowed")
    target = directory / name
    partial = target.with_name(name + ".download")
    if target.is_symlink() or partial.is_symlink():
        raise ValueError("Refusing model file symlinks")
    if target.exists():
        if not verify(target, record):
            raise ValueError("Existing model file differs from the pinned bytes; retained: " + str(target))
        print("Verified existing: " + name, flush=True)
        return
    if partial.exists() and partial.stat().st_size > record["bytes"]:
        raise ValueError("Oversized partial file retained: " + str(partial))
    if partial.exists() and partial.stat().st_size == record["bytes"]:
        if not verify(partial, record):
            raise ValueError("Complete partial file has an invalid hash; retained: " + str(partial))
        partial.rename(target)
        print("Verified completed partial: " + name, flush=True)
        return
    url = f'https://huggingface.co/{spec["repository"]}/resolve/{spec["revision"]}/{name}'
    print(f'Downloading {name} ({record["bytes"]:,} bytes)', flush=True)
    subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                    "--retry", "3", "--retry-delay", "2", "--connect-timeout", "30",
                    "--max-time", "3600", "--continue-at", "-", "--output", str(partial), url], check=True)
    if not verify(partial, record):
        raise ValueError("Downloaded file failed size/SHA-256 verification; retained: " + str(partial))
    if target.exists():
        raise FileExistsError("Model destination appeared during download; refusing overwrite")
    partial.rename(target)
    print("Verified downloaded: " + name + " / " + record["sha256"], flush=True)


def main():
    spec = json.loads((HERE / "model.json").read_text(encoding="utf-8"))
    directory = (ROOT / spec["cache_path"]).resolve()
    if not directory.is_relative_to(ROOT / ".evidence/models/ama"):
        raise ValueError("Model directory must remain inside the AMA model cache")
    directory.mkdir(parents=True, exist_ok=True)
    names = [record["path"] for record in spec["files"]]
    if not names or len(names) != len(set(names)):
        raise ValueError("Empty or duplicate model filenames")
    with (directory / ".prepare.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in [pool.submit(fetch, spec, directory, record) for record in spec["files"]]:
                future.result()
    print("All pinned model files verified: " + str(directory), flush=True)


if __name__ == "__main__":
    main()
