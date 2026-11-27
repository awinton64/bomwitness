"""Reference evidence: the official OpenWrt package feeds for one release.

For a (release, target, arch) the feed indexes list every package with the
SHA-256 of its .ipk. A package payload is downloaded only when a claim or an
orphan file needs it, checked against the index hash, and reduced to a
per-file SHA-256 manifest. Nothing from a package is executed or written into
the analysis tree.

Round 1 limit: the usign signature on each index is not yet checked, so the
trust anchor is TLS to downloads.openwrt.org. opkg (.ipk) releases only.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .opkgdb import depends, parse_control

BASE = "https://downloads.openwrt.org/releases"
UA = "bomwitness-feed/0.0.1"
MAX_IPK = 64 << 20
ARCH_FEEDS = ("base", "luci", "packages", "routing", "telephony")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read(MAX_IPK + 1)


def soname(blob: bytes) -> str | None:
    """DT_SONAME of an ELF shared object, or None.

    Read from the PT_DYNAMIC segment, because OpenWrt strips section headers.
    """
    if blob[:4] != b"\x7fELF":
        return None
    try:
        from elftools.elf.dynamic import DynamicSegment
        from elftools.elf.elffile import ELFFile
        for seg in ELFFile(io.BytesIO(blob)).iter_segments():
            if isinstance(seg, DynamicSegment):
                for tag in seg.iter_tags():
                    if tag.entry.d_tag == "DT_SONAME":
                        return tag.soname
    except Exception:
        return None
    return None


class Feed:
    def __init__(self, release: str, target: str, arch: str, kmods: str | None, cache: Path):
        self.release, self.target, self.arch, self.kmods = release, target, arch, kmods
        self.cache = cache / release / arch
        self.cache.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, dict] | None = None
        self.fetched: list[dict] = []

    def feed_urls(self) -> list[str]:
        t = f"{BASE}/{self.release}/targets/{self.target}"
        urls = [f"{t}/packages"]
        if self.kmods:
            urls.append(f"{t}/kmods/{self.kmods}")
        urls += [f"{BASE}/{self.release}/packages/{self.arch}/{f}" for f in ARCH_FEEDS]
        return urls

    def index(self) -> dict[str, dict]:
        if self._index is None:
            p = self.cache / f"index-{self.target.replace('/', '_')}.json"
            if p.exists():
                self._index = json.loads(p.read_text())
            else:
                idx: dict[str, dict] = {}
                for url in self.feed_urls():
                    text = gzip.decompress(_get(f"{url}/Packages.gz")).decode("utf-8", "replace")
                    for rec in parse_control(text):
                        idx.setdefault(rec["Package"], {
                            "name": rec["Package"], "version": rec.get("Version", ""),
                            "url": f"{url}/{rec.get('Filename', '')}", "sha256": rec.get("SHA256sum", ""),
                            "depends": depends(rec),
                            "provides": [x.strip() for x in rec.get("Provides", "").split(",") if x.strip()],
                            "cpe": rec.get("CPE-ID", ""), "license": rec.get("License", ""),
                        })
                p.write_text(json.dumps(idx))
                self._index = idx
        return self._index

    def ipk_bytes(self, name: str) -> bytes:
        rec = self.index()[name]
        p = self.cache / "ipk" / rec["url"].rsplit("/", 1)[1]
        if p.exists():
            blob = p.read_bytes()
        else:
            blob = _get(rec["url"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(blob)
        if hashlib.sha256(blob).hexdigest() != rec["sha256"]:
            p.unlink(missing_ok=True)
            raise ValueError(f"index hash mismatch for {rec['url']}")
        return blob

    def payload_members(self, name: str):
        """Yield (path, tarinfo, bytes-or-None) for every entry in the package payload."""
        outer = tarfile.open(fileobj=io.BytesIO(self.ipk_bytes(name)), mode="r:gz")
        data = outer.extractfile("./data.tar.gz").read()
        inner = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        for m in inner:
            path = m.name.lstrip("./")
            if not path:
                continue
            yield path, m, (inner.extractfile(m).read() if m.isfile() else None)

    def file_bytes(self, name: str, path: str) -> bytes | None:
        for p, _m, blob in self.payload_members(name):
            if p == path:
                return blob
        return None

    def payload(self, name: str) -> dict:
        """Per-file SHA-256 manifest of the reference package called `name`."""
        rec = self.index()[name]
        p = self.cache / "payload" / f"{name}_{rec['version']}.json"
        if p.exists():
            return json.loads(p.read_text())
        files, links = {}, {}
        for path, m, blob in self.payload_members(name):
            if blob is not None:
                files[path] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob),
                               "elf": blob[:4] == b"\x7fELF", "soname": soname(blob)}
            elif m.issym():
                links[path] = m.linkname
        outer = tarfile.open(fileobj=io.BytesIO(self.ipk_bytes(name)), mode="r:gz")
        ctl = tarfile.open(fileobj=io.BytesIO(outer.extractfile("./control.tar.gz").read()), mode="r:gz")
        conffiles = []
        for m in ctl:
            if m.name.lstrip("./") == "conffiles":
                conffiles = [l.strip().lstrip("/") for l in ctl.extractfile(m).read().decode().splitlines() if l.strip()]
        out = {"name": name, "version": rec["version"], "url": rec["url"], "ipk_sha256": rec["sha256"],
               "files": files, "symlinks": links, "conffiles": conffiles}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out))
        self.fetched.append({"url": rec["url"], "sha256": rec["sha256"]})
        return out

    def payloads(self, names: list[str]) -> dict[str, dict]:
        names = [n for n in dict.fromkeys(names) if n in self.index()]
        with ThreadPoolExecutor(max_workers=6) as ex:
            return dict(zip(names, ex.map(self.payload, names)))
