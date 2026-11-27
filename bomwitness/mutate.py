"""Seed labelled errors into (BOM, firmware tree, device database) triples.

Every case is one mutation with one ground-truth label. `db` says what
happened to the device's own package database:
  honest     untouched, so it still tells the truth
  colluding  edited to agree with the wrong BOM
  stripped   removed, as in much vendor firmware
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from . import opkgdb


def clone(src: Path, dst: Path) -> Path:
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # APFS clone where available; plain copy otherwise. Symlinks are kept as symlinks.
    if subprocess.run(["cp", "-Rc", str(src), str(dst)], capture_output=True).returncode != 0:
        shutil.copytree(src, dst, symlinks=True)
    return dst


def _blocks(rootfs: Path) -> list[str]:
    return re.split(r"\n\s*\n", (rootfs / opkgdb.STATUS).read_text().strip())


def _write(rootfs: Path, blocks: list[str]) -> None:
    (rootfs / opkgdb.STATUS).write_text("\n\n".join(blocks) + "\n")


def db_remove(rootfs: Path, name: str) -> None:
    _write(rootfs, [b for b in _blocks(rootfs) if not re.search(rf"^Package: {re.escape(name)}$", b, re.M)])
    for f in (rootfs / opkgdb.INFO).glob(f"{name}.*"):
        f.unlink()


def db_set_version(rootfs: Path, name: str, version: str) -> None:
    out = []
    for b in _blocks(rootfs):
        if re.search(rf"^Package: {re.escape(name)}$", b, re.M):
            b = re.sub(r"^Version: .*$", f"Version: {version}", b, flags=re.M)
        out.append(b)
    _write(rootfs, out)
    ctl = rootfs / opkgdb.INFO / f"{name}.control"
    if ctl.is_file():
        ctl.write_text(re.sub(r"^Version: .*$", f"Version: {version}", ctl.read_text(), flags=re.M))


def db_add(rootfs: Path, name: str, version: str, arch: str, paths: list[str]) -> None:
    block = f"Package: {name}\nVersion: {version}\nDepends: libc\nStatus: install user installed\nArchitecture: {arch}\nInstalled-Time: 1784877710"
    _write(rootfs, _blocks(rootfs) + [block])
    (rootfs / opkgdb.INFO / f"{name}.list").write_text("".join(f"/{p}\n" for p in paths))
    (rootfs / opkgdb.INFO / f"{name}.control").write_text(f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n")


def db_strip(rootfs: Path) -> None:
    shutil.rmtree(rootfs / "usr/lib/opkg", ignore_errors=True)


def implant(rootfs: Path, members) -> list[str]:
    """Write a reference package's payload into the tree without telling the BOM or the database."""
    written = []
    root = rootfs.resolve()
    for path, m, blob in members:
        target = root / path
        if blob is None or not str(target.parent.resolve()).startswith(str(root)) or target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        written.append(path)
    return written
