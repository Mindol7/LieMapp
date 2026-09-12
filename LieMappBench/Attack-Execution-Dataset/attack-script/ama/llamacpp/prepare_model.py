"""Download one pinned official GGUF and verify its published LFS SHA-256."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "LieMappBench").is_dir())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    spec = json.loads((HERE / "model.json").read_text(encoding="utf-8"))
    target = ROOT / spec["cache_path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.stat().st_size != spec["bytes"] or digest(target) != spec["sha256"]:
            raise ValueError("Existing model differs from the pinned model; refusing to overwrite")
        print("Verified existing model:", target, flush=True)
        return
    temporary = target.with_suffix(".gguf.download")
    url = f'https://huggingface.co/{spec["repository"]}/resolve/{spec["revision"]}/{spec["filename"]}'
    print("Downloading pinned official model:", url, flush=True)
    subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--connect-timeout", "30",
                    "--output", str(temporary), url], check=True)
    if temporary.stat().st_size != spec["bytes"] or digest(temporary) != spec["sha256"]:
        raise ValueError("Downloaded file failed size/SHA-256 validation; retained for inspection")
    temporary.rename(target)
    print("Verified SHA-256:", spec["sha256"], flush=True)
    print("Model:", target, flush=True)


if __name__ == "__main__":
    main()
