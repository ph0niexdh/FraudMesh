"""Download and verify pretrained weights listed in ml/weights/manifest.json."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

WEIGHTS = Path(__file__).resolve().parents[1] / "weights"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    manifest = json.loads((WEIGHTS / "manifest.json").read_text())
    failed = 0
    for name, meta in manifest.items():
        dest = WEIGHTS / name
        if dest.exists() and sha256(dest) == meta["sha256"]:
            print(f"ok       {name}")
            continue
        print(f"download {name} <- {meta['url']}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        urllib.request.urlretrieve(meta["url"], tmp)  # noqa: S310 (fixed https URLs from the manifest)
        digest = sha256(tmp)
        if digest != meta["sha256"]:
            tmp.unlink(missing_ok=True)
            print(f"FAILED   {name}: sha256 {digest} != {meta['sha256']}", file=sys.stderr)
            failed += 1
            continue
        tmp.rename(dest)
        print(f"verified {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
