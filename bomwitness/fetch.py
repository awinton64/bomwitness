"""Download official OpenWrt artifacts and refuse anything whose SHA-256 differs."""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

UA = "bomwitness-fetch/0.0.1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, expect_sha256: str | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        tmp.replace(dest)
    if expect_sha256 is not None:
        got = sha256_file(dest)
        if got != expect_sha256:
            dest.unlink()
            raise SystemExit(f"sha256 mismatch for {url}: got {got}, expected {expect_sha256}")
    return dest


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    spec = json.loads((root / "images.json").read_text())
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "work" / "dl"
    for im in spec["images"]:
        tbase = f"{spec['base']}/targets/{im['target']}"
        for key in ("image", "bom", "manifest"):
            p = download(f"{tbase}/{im[key]}", out / im["id"] / im[key], im[f"{key}_sha256"])
            print(f"ok {im['id']:22s} {key:8s} {p.stat().st_size:>9d} bytes  sha256 verified")


if __name__ == "__main__":
    main()
