"""Download official OpenWrt images and refuse anything whose SHA-256 differs from the signed release metadata."""
from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path

from .reference import UA, Reference


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, expect_sha256: str) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(req, timeout=180) as r, tmp.open("wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        tmp.replace(dest)
    got = sha256_file(dest)
    if got != expect_sha256:
        dest.unlink()
        raise SystemExit(f"sha256 mismatch for {url}: got {got}, expected {expect_sha256}")
    return dest


def image(ref: Reference, filename: str, dest_dir: Path) -> Path:
    """Fetch one image of `ref`'s target. Its hash must be in profiles.json, which the signed sha256sums pins."""
    want = ref.meta()["images"].get(filename)
    if not want:
        raise SystemExit(f"{filename} is not listed in the signed metadata of {ref.release} {ref.target}")
    return download(f"{ref.target_url}/{filename}", Path(dest_dir) / filename, want)
