"""A tiny synthetic OpenWrt-style release tree on disk, signed with a throwaway key, for offline tests.

Nothing here comes from OpenWrt. Package contents are made-up bytes.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bomwitness.reference import Reference

KEY_ID = bytes.fromhex("0011223344556677")
ELF = b"\x7fELF\x01\x01\x01" + b"\x00" * 9


def elf(body: bytes) -> bytes:
    return ELF + body


class Signer:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.keys = {KEY_ID.hex(): (base64.b64encode(b"Ed" + KEY_ID + pub).decode(), "test key")}

    def sign(self, message: bytes) -> str:
        return "untrusted comment: test\n" + base64.b64encode(b"Ed" + KEY_ID + self.key.sign(message)).decode() + "\n"


def _tar(members: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo("./" + name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo("./" + name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buf.getvalue()


def ipk(name: str, version: str, files: dict[str, bytes], conffiles: list[str] = (), extra_control: str = "") -> bytes:
    control = f"Package: {name}\nVersion: {version}\nSourceName: {name.split('-')[0]}\nSourceDateEpoch: 1700000000\n{extra_control}"
    ctl = {"control": control.encode()}
    if conffiles:
        ctl["conffiles"] = "".join(f"/{c}\n" for c in conffiles).encode()
    return _tar({"debian-binary": b"2.0\n", "data.tar.gz": _tar(files), "control.tar.gz": _tar(ctl)})


# name: (feed, version, files, extra index fields)
DEFAULT_PACKAGES = {
    "base-files": ("target", "1-r1", {"etc/banner": b"hello\n", "etc/config/system": b"config system\n"}, ""),
    "kmod-foo": ("kmods", "6.6.1-r1", {"lib/modules/6.6.1/foo.ko": elf(b"vermagic=6.6.1 SMP mod_unload")}, ""),
    "alpha": ("base", "1.2.3-r1", {"usr/bin/alpha": elf(b"alpha version 1.2.3 ok")}, ""),
    "alpha-variant": ("base", "1.2.3-r1", {"usr/bin/alpha": elf(b"alpha VARIANT 1.2.3 ok")}, ""),
    "libbeta5": ("base", "2.0.1-r2", {"usr/lib/libbeta.so.2.0.1": elf(b"libbeta 2.0.1 aes256-ctr hmac-sha1")},
                 "ABIVersion: 5\nProvides: libbeta\n"),
    "gamma": ("base", "2024.01.01~abc-r1", {"usr/bin/gamma": elf(b"gamma tool no marker")}, ""),
    "delta": ("base", "3.0-r1", {"usr/bin/delta": elf(b"delta 3.0")}, ""),
    "meta": ("base", "1-r1", {}, ""),
    "stamp": ("base", "1.0-r1", {"usr/bin/stamp": elf(b"stamp 1.0 built (2026-10-29 20:36:30 UTC) end")}, ""),
    "extra-tool": ("packages", "0.9-r1", {"usr/bin/extra-tool": elf(b"extra tool 0.9")}, ""),
}


def make_release(root: Path, signer: Signer, release: str = "99.01.0", target: str = "fake/generic",
                 packages: dict | None = None, manifest: dict | None = None, kver: str = "6.6.1-1-abc") -> None:
    """Write releases/<release>/... under `root`."""
    packages = DEFAULT_PACKAGES if packages is None else packages
    tdir = root / release / "targets" / target
    feeds = {"target": tdir / "packages", "kmods": tdir / "kmods" / kver}
    for f in ("base", "luci", "packages", "routing", "telephony"):
        feeds[f] = root / release / "packages" / "testarch" / f
    index = {f: [] for f in feeds}
    for name, (feed, version, files, extra) in packages.items():
        blob = ipk(name, version, files, conffiles=[p for p in files if p.startswith("etc/config/")])
        fn = f"{name}_{version}_testarch.ipk"
        feeds[feed].mkdir(parents=True, exist_ok=True)
        (feeds[feed] / fn).write_bytes(blob)
        index[feed].append(f"Package: {name}\nVersion: {version}\n{extra}Filename: {fn}\nSize: {len(blob)}\n"
                           f"SHA256sum: {hashlib.sha256(blob).hexdigest()}\n")
    sums = {}
    for f, d in feeds.items():
        d.mkdir(parents=True, exist_ok=True)
        text = "\n".join(index[f]).encode()
        (d / "Packages").write_bytes(text)
        (d / "Packages.gz").write_bytes(gzip.compress(text))
        (d / "Packages.sig").write_text(signer.sign(text))
        if f == "target":
            sums["packages/Packages"] = hashlib.sha256(text).hexdigest()
        elif f == "kmods":
            sums[f"kmods/{kver}/Packages"] = hashlib.sha256(text).hexdigest()
    prof = {"arch_packages": "testarch", "source_date_epoch": 1700000000, "version_code": "r1", "target": target,
            "linux_kernel": {"version": "6.6.1"}, "default_packages": ["base-files", "alpha"],
            "profiles": {"dev-a": {"device_packages": ["kmod-foo"], "images": []},
                         "dev-b": {"device_packages": ["kmod-foo"], "images": []}}}
    pj = json.dumps(prof).encode()
    (tdir / "profiles.json").write_bytes(pj)
    sums["profiles.json"] = hashlib.sha256(pj).hexdigest()
    man = {n: v for n, (_f, v, _files, _e) in packages.items()} if manifest is None else manifest
    mname = f"openwrt-{release}-{target.replace('/', '-')}.manifest"
    mt = "".join(f"{n} - {v}\n" for n, v in man.items()).encode()
    (tdir / mname).write_bytes(mt)
    sums[mname] = hashlib.sha256(mt).hexdigest()
    st = "".join(f"{h} *{n}\n" for n, h in sums.items()).encode()
    (tdir / "sha256sums").write_bytes(st)
    (tdir / "sha256sums.sig").write_text(signer.sign(st))


def reference(root: Path, signer: Signer, cache: Path, release: str = "99.01.0", target: str = "fake/generic", index: bool = True) -> Reference:
    ref = Reference(release, target, cache, base=root.as_uri(), keys=signer.keys)
    if index:
        ref.build_path_index()
    return ref


def make_rootfs(dest: Path, names: list[str], packages: dict | None = None, db: bool = True) -> Path:
    """An unpacked firmware tree holding the given packages' files, with an opkg database unless db is False."""
    packages = DEFAULT_PACKAGES if packages is None else packages
    status = []
    for n in names:
        _feed, version, files, extra = packages[n]
        for path, data in files.items():
            q = dest / path
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_bytes(data)
        if db:
            info = dest / "usr/lib/opkg/info"
            info.mkdir(parents=True, exist_ok=True)
            (info / f"{n}.list").write_text("".join(f"/{p}\n" for p in files))
            (info / f"{n}.control").write_text(f"Package: {n}\nVersion: {version}\n")
            conf = [p for p in files if p.startswith("etc/config/")]
            if conf:
                (info / f"{n}.conffiles").write_text("".join(f"/{p}\n" for p in conf))
            status.append(f"Package: {n}\nVersion: {version}\n{extra}Status: install user installed\nArchitecture: testarch")
    if db:
        (dest / "usr/lib/opkg/status").write_text("\n\n".join(status) + "\n")
    (dest / "etc").mkdir(parents=True, exist_ok=True)
    (dest / "etc/openwrt_release").write_text("DISTRIB_RELEASE='99.01.0'\nDISTRIB_TARGET='fake/generic'\nDISTRIB_ARCH='testarch'\n")
    return dest


def claims(names: list[str], packages: dict | None = None) -> list[dict]:
    packages = DEFAULT_PACKAGES if packages is None else packages
    return [{"name": n, "version": packages[n][1]} for n in names]
