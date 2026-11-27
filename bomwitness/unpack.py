"""Carve the SquashFS root filesystem out of a firmware image and extract it.

Pure Python (PySquashfsImage). Nothing from the firmware is executed. Device
nodes are skipped, symlinks are recreated as symlinks and never followed.
Gzip-compressed images (x86 and SD-card images) are decompressed first.
"""
from __future__ import annotations

import gzip
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

SQFS_MAGIC = b"hsqs"
MAX_IMAGE = 1 << 30


def find_squashfs(blob: bytes) -> list[dict]:
    """Return every plausible SquashFS 4.0 superblock in the blob."""
    hits = []
    pos = blob.find(SQFS_MAGIC)
    while pos != -1:
        sb = blob[pos:pos + 96]
        if len(sb) == 96:
            (_, inodes, mkfs_time, block_size, _frags, comp, block_log, _flags, _ids,
             major, minor, _root, bytes_used) = struct.unpack("<4sIIIIHHHHHHQQ", sb[:48])
            if major == 4 and minor == 0 and 12 <= block_log <= 20 and block_size == 1 << block_log \
                    and 0 < bytes_used <= len(blob) - pos and inodes > 0:
                hits.append({"offset": pos, "bytes_used": bytes_used, "inodes": inodes, "mkfs_time": mkfs_time,
                             "block_size": block_size, "compressor_id": comp})
        pos = blob.find(SQFS_MAGIC, pos + 1)
    return hits


def read_image(image: Path) -> bytes:
    blob = Path(image).read_bytes()
    if blob[:2] == b"\x1f\x8b":
        # OpenWrt pads some .img.gz files after the gzip stream; decompress the first member only.
        import zlib
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        blob = d.decompress(blob, MAX_IMAGE)
    return blob


def extract(image: Path, dest: Path) -> dict:
    from PySquashfsImage import SquashFsImage

    blob = read_image(image)
    hits = find_squashfs(blob)
    if not hits:
        raise SystemExit(f"no SquashFS 4.0 superblock found in {image}")
    sb = max(hits, key=lambda h: h["inodes"])
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    counts = {"files": 0, "dirs": 0, "symlinks": 0, "skipped": 0}
    with tempfile.NamedTemporaryFile(suffix=".sqfs") as tmp:
        tmp.write(blob[sb["offset"]: sb["offset"] + sb["bytes_used"]])
        tmp.flush()
        with SquashFsImage.from_file(tmp.name) as img:
            for item in img:
                rel = item.path.lstrip("/")
                if not rel:
                    continue
                target = root / rel
                if not str(target.parent.resolve()).startswith(str(root)):
                    counts["skipped"] += 1
                    continue
                if item.is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                    counts["dirs"] += 1
                elif item.is_symlink:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_symlink() or target.exists():
                        target.unlink()
                    os.symlink(item.readlink(), target)
                    counts["symlinks"] += 1
                elif item.is_file:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(item.read_bytes())
                    os.chmod(target, 0o755 if item.mode & 0o111 else 0o644)
                    counts["files"] += 1
                else:
                    counts["skipped"] += 1
    return {"image": Path(image).name, "superblock": sb, "candidates": len(hits), **counts}


def release_hint(rootfs: Path) -> dict:
    """What the firmware says about itself in /etc/openwrt_release. A hint for choosing the reference, not evidence."""
    out = {}
    p = Path(rootfs) / "etc/openwrt_release"
    if p.is_file():
        for line in p.read_text(errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
    return {"release": out.get("DISTRIB_RELEASE"), "target": out.get("DISTRIB_TARGET"), "arch": out.get("DISTRIB_ARCH")}


if __name__ == "__main__":
    print(json.dumps(extract(Path(sys.argv[1]), Path(sys.argv[2])), indent=1))
