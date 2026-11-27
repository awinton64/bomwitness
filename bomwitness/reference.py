"""Reference evidence: what the publisher shipped for one OpenWrt release and target.

Everything here comes from the publisher's download tree and is checked
before use:

  sha256sums          usign signature (pinned release keys, see usign.py)
  profiles.json,
  release manifest    SHA-256 listed in the signed sha256sums
  target and kmods
  package indexes     SHA-256 listed in the signed sha256sums ("frozen" feeds:
                      they never change after the release)
  shared arch feeds   usign signature on each Packages index ("shared" feeds:
                      one directory serves every point release of a series and
                      is rebuilt after the release, so labels and bytes drift)
  packages (.ipk)     SHA-256 from the index that lists them

A package is reduced to a per-file SHA-256 manifest. Nothing from a package
is executed or written into the analysis tree. opkg (.ipk) releases only.
"""
from __future__ import annotations

import calendar
import gzip
import hashlib
import io
import json
import re
import tarfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import usign
from .elfinfo import has_token, is_elf, soname, upstream_token

BASE = "https://downloads.openwrt.org/releases"
UA = "bomwitness/0.2 (firmware BOM verification research)"
MAX_IPK = 96 << 20
ARCH_FEEDS = ("base", "luci", "packages", "routing", "telephony")
DEFAULT_INDEX_FEEDS = ("target", "kmods", "base", "luci")
DEFAULT_INDEX_MAX_SIZE = 4 << 20


class ReferenceError(RuntimeError):
    pass


def parse_control(text: str) -> list[dict]:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        rec, key = {}, None
        for line in block.splitlines():
            if line[:1] in " \t" and key:
                rec[key] += "\n" + line.strip()
            elif ":" in line:
                key, val = line.split(":", 1)
                rec[key] = val.strip()
        if rec.get("Package"):
            out.append(rec)
    return out


def split_list(raw: str) -> list[str]:
    return [re.sub(r"\s*\(.*?\)", "", d).strip() for d in (raw or "").split(",") if d.strip()]


def parse_ipk(blob: bytes) -> dict:
    """Per-file manifest and control facts of one .ipk (gzip tar holding data.tar.gz and control.tar.gz)."""
    outer = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    parts = {m.name.lstrip("./"): outer.extractfile(m).read() for m in outer if m.isfile()}
    control, conffiles = {}, []
    ctl = tarfile.open(fileobj=io.BytesIO(parts["control.tar.gz"]), mode="r:gz")
    for m in ctl:
        base = m.name.lstrip("./")
        if base == "control":
            recs = parse_control(ctl.extractfile(m).read().decode("utf-8", "replace"))
            control = recs[0] if recs else {}
        elif base == "conffiles":
            conffiles = [l.strip().lstrip("/") for l in ctl.extractfile(m).read().decode().splitlines() if l.strip()]
    token = upstream_token(control.get("Version", ""))
    files, links = {}, {}
    data = tarfile.open(fileobj=io.BytesIO(parts["data.tar.gz"]), mode="r:gz")
    for m in data:
        path = m.name.lstrip("./")
        if not path:
            continue
        if m.isfile():
            b = data.extractfile(m).read()
            files[path] = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "elf": is_elf(b),
                           "soname": soname(b) if ".so" in path.rsplit("/", 1)[-1] else None,
                           "marker": bool(token) and (has_token(path.encode(), token) or has_token(b, token))}
        elif m.issym():
            links[path] = m.linkname
    return {"name": control.get("Package"), "version": control.get("Version", ""),
            "source_name": control.get("SourceName"), "source": control.get("Source"),
            "sde": int(control["SourceDateEpoch"]) if control.get("SourceDateEpoch", "").isdigit() else None,
            "files": files, "symlinks": links, "conffiles": conffiles}


def ipk_members(blob: bytes):
    """Yield (path, tarinfo, bytes-or-None) for every entry in the package payload."""
    outer = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    data = next(outer.extractfile(m).read() for m in outer if m.name.lstrip("./") == "data.tar.gz")
    inner = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    for m in inner:
        path = m.name.lstrip("./")
        if path:
            yield path, m, (inner.extractfile(m).read() if m.isfile() else None)


class Reference:
    def __init__(self, release: str, target: str, cache: Path, *, base: str = BASE, offline: bool = False,
                 keys: dict | None = None):
        self.release, self.target, self.base, self.offline, self.keys = release, target, base.rstrip("/"), offline, keys
        self.cache = Path(cache)
        self.dir = self.cache / release / target.replace("/", "_")
        self.dir.mkdir(parents=True, exist_ok=True)
        self._meta = self._index = self._manifest = None
        self._payloads: dict[str, dict] = {}
        self._paths: dict[str, list[str]] | None = None
        self._sonames: dict[str, list[str]] | None = None
        self._listing: dict[str, dict] = {}
        self._file_cache: dict[tuple[str, str], bytes | None] = {}
        self.downloads: list[dict] = []          # every package fetched in this process: url, sha256, bytes
        self._load_path_index()

    # ---- transport -------------------------------------------------------------------------------------
    def _get(self, url: str, limit: int = MAX_IPK) -> bytes:
        if self.offline:
            raise ReferenceError(f"offline mode, but {url} is not cached")
        err = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=120) as r:
                    blob = r.read(limit + 1)
                if len(blob) > limit:
                    raise ReferenceError(f"{url} is larger than {limit} bytes")
                return blob
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                err = e
                if (isinstance(e, urllib.error.HTTPError) and e.code in (403, 404)) or url.startswith("file:"):
                    break
                time.sleep(1.5 * (attempt + 1))
        raise ReferenceError(f"cannot fetch {url}: {err}")

    @property
    def target_url(self) -> str:
        return f"{self.base}/{self.release}/targets/{self.target}"

    # ---- signed target metadata ------------------------------------------------------------------------
    def meta(self) -> dict:
        if self._meta is None:
            p = self.dir / "meta.json"
            if p.exists() and "profile_images" in (cached := json.loads(p.read_text())):
                self._meta = cached
            else:
                sums_raw = self._get(f"{self.target_url}/sha256sums")
                signed_by = usign.verify(sums_raw, self._get(f"{self.target_url}/sha256sums.sig").decode(), self.keys)
                sums = {}
                for line in sums_raw.decode().splitlines():
                    m = re.match(r"([0-9a-f]{64}) [ *](.+)$", line.strip())
                    if m:
                        sums[m.group(2)] = m.group(1)
                prof = self._checked(f"{self.target_url}/profiles.json", sums.get("profiles.json"))
                prof = json.loads(prof)
                kmods = sorted({k.split("/")[1] for k in sums if k.startswith("kmods/") and k.endswith("/Packages")})
                manifest = next((k for k in sums if k.endswith(".manifest") and "/" not in k), None)
                bom = next((k for k in sums if k.endswith(".bom.cdx.json") and "/" not in k), None)
                self._meta = {
                    "release": self.release, "target": self.target, "arch": prof["arch_packages"],
                    "source_date_epoch": prof.get("source_date_epoch"), "version_code": prof.get("version_code"),
                    "kernel": prof.get("linux_kernel"), "default_packages": prof.get("default_packages", []),
                    "device_packages": {k: v.get("device_packages", []) for k, v in prof.get("profiles", {}).items()},
                    "images": {i["name"]: i["sha256"] for v in prof.get("profiles", {}).values() for i in v.get("images", [])},
                    "profile_images": {k: [i["name"] for i in v.get("images", [])] for k, v in prof.get("profiles", {}).items()},
                    "kmods": kmods[-1] if kmods else None, "manifest": manifest, "official_bom": bom,
                    "sha256sums_signed_by": signed_by, "sha256sums_sha256": hashlib.sha256(sums_raw).hexdigest(),
                    "sums": {k: v for k, v in sums.items() if k.endswith(("Packages", ".manifest", ".bom.cdx.json"))
                             or k == "profiles.json"},
                }
                p.write_text(json.dumps(self._meta))
        return self._meta

    def _checked(self, url: str, expect: str | None) -> bytes:
        blob = self._get(url)
        if expect is None:
            raise ReferenceError(f"{url} is not listed in the signed sha256sums")
        if hashlib.sha256(blob).hexdigest() != expect:
            raise ReferenceError(f"sha256 mismatch for {url}")
        return blob

    @property
    def arch(self) -> str:
        return self.meta()["arch"]

    def feeds(self) -> list[dict]:
        m = self.meta()
        out = [{"name": "target", "url": f"{self.target_url}/packages", "frozen": True, "sums_key": "packages/Packages"}]
        if m["kmods"]:
            out.append({"name": "kmods", "url": f"{self.target_url}/kmods/{m['kmods']}", "frozen": True,
                        "sums_key": f"kmods/{m['kmods']}/Packages"})
        out += [{"name": f, "url": f"{self.base}/{self.release}/packages/{m['arch']}/{f}", "frozen": False}
                for f in ARCH_FEEDS]
        return out

    def manifest(self) -> dict[str, str]:
        """The publisher's release manifest for this target: package name to version at release time."""
        if self._manifest is None:
            p = self.dir / "manifest.json"
            if p.exists():
                self._manifest = json.loads(p.read_text())
            else:
                m = self.meta()
                self._manifest = {}
                if m["manifest"]:
                    text = self._checked(f"{self.target_url}/{m['manifest']}", m["sums"][m["manifest"]]).decode()
                    for line in text.splitlines():
                        if " - " in line:
                            n, v = line.strip().split(" - ", 1)
                            self._manifest[n] = v
                p.write_text(json.dumps(self._manifest))
        return self._manifest

    def official_bom(self) -> dict | None:
        m = self.meta()
        if not m["official_bom"]:
            return None
        p = self.dir / "official-bom.json"
        if not p.exists():
            p.write_bytes(self._checked(f"{self.target_url}/{m['official_bom']}", m["sums"][m["official_bom"]]))
        return json.loads(p.read_text())

    # ---- package indexes -------------------------------------------------------------------------------
    def index(self) -> dict[str, dict]:
        if self._index is None:
            p = self.dir / "index.json"
            if p.exists():
                self._index = json.loads(p.read_text())
            else:
                idx: dict[str, dict] = {}
                trust = {}
                for feed in self.feeds():
                    try:
                        raw = gzip.decompress(self._get(f"{feed['url']}/Packages.gz"))
                    except ReferenceError:
                        if feed["frozen"]:
                            raise
                        continue          # an optional shared feed that this release does not have
                    if feed["frozen"]:
                        want = self.meta()["sums"].get(feed["sums_key"])
                        if hashlib.sha256(raw).hexdigest() != want:
                            raise ReferenceError(f"{feed['url']}/Packages does not match the signed sha256sums")
                        trust[feed["name"]] = "sha256 in signed sha256sums"
                    else:
                        key = usign.verify(raw, self._get(f"{feed['url']}/Packages.sig").decode(), self.keys)
                        trust[feed["name"]] = f"usign {key}"
                    for rec in parse_control(raw.decode("utf-8", "replace")):
                        idx.setdefault(rec["Package"], {
                            "name": rec["Package"], "version": rec.get("Version", ""), "feed": feed["name"],
                            "frozen": feed["frozen"], "url": f"{feed['url']}/{rec.get('Filename', '')}",
                            "sha256": rec.get("SHA256sum", ""), "size": int(rec.get("Size", "0") or 0),
                            "depends": split_list(rec.get("Depends", "")), "provides": split_list(rec.get("Provides", "")),
                            "abi": rec.get("ABIVersion", ""), "cpe": rec.get("CPE-ID", ""), "license": rec.get("License", ""),
                        })
                (self.dir / "index-trust.json").write_text(json.dumps(trust))
                p.write_text(json.dumps(idx))
                self._index = idx
        return self._index

    def index_trust(self) -> dict:
        self.index()
        p = self.dir / "index-trust.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def published(self, name: str) -> int | None:
        """Unix time the reference package file was last published, from the feed's directory listing."""
        rec = self.index().get(name)
        if not rec:
            return None
        feed = rec["feed"]
        if feed not in self._listing:
            p = self.dir / f"listing-{feed}.json"
            if p.exists():
                self._listing[feed] = json.loads(p.read_text())
            else:
                rows = {}
                try:
                    html = self._get(rec["url"].rsplit("/", 1)[0] + "/").decode("utf-8", "replace")
                    for fn, date in re.findall(r'href="([^"]+\.ipk)".*?class="d">([^<]+)<', html):
                        try:
                            rows[fn] = calendar.timegm(time.strptime(date.strip(), "%a %b %d %H:%M:%S %Y"))
                        except ValueError:
                            pass
                except ReferenceError:
                    pass
                p.write_text(json.dumps(rows))
                self._listing[feed] = rows
        return self._listing[feed].get(rec["url"].rsplit("/", 1)[1])

    # ---- packages --------------------------------------------------------------------------------------
    def ipk_bytes(self, name: str, keep: bool = True) -> bytes:
        rec = self.index()[name]
        p = self.cache / "ipk" / f"{rec['sha256']}.ipk"
        if p.exists():
            return p.read_bytes()
        blob = self._get(rec["url"])
        if hashlib.sha256(blob).hexdigest() != rec["sha256"]:
            raise ReferenceError(f"index hash mismatch for {rec['url']}")
        self.downloads.append({"url": rec["url"], "sha256": rec["sha256"], "bytes": len(blob)})
        if keep:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(blob)
        return blob

    def payload(self, name: str) -> dict:
        """Per-file SHA-256 manifest of the reference package called `name`."""
        if name in self._payloads:
            return self._payloads[name]
        rec = self.index()[name]
        p = self.cache / "payload" / rec["sha256"][:2] / f"{rec['sha256']}.json"
        if p.exists():
            out = json.loads(p.read_text())
        else:
            out = parse_ipk(self.ipk_bytes(name, keep=False))
            out.update(name=name, version=rec["version"], ipk_sha256=rec["sha256"], url=rec["url"])
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(f".{id(out)}.tmp")
            tmp.write_text(json.dumps(out))
            tmp.replace(p)
        self._payloads[name] = out
        return out

    def payloads(self, names: list[str], workers: int = 12) -> dict[str, dict]:
        names = [n for n in dict.fromkeys(names) if n in self.index()]
        todo = [n for n in names if n not in self._payloads]
        if todo:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(self.payload, todo))
        return {n: self._payloads[n] for n in names}

    def members(self, name: str):
        return ipk_members(self.ipk_bytes(name))

    def file_bytes(self, name: str, path: str) -> bytes | None:
        key = (name, path)
        if key not in self._file_cache:
            self._file_cache[key] = next((blob for p, _m, blob in self.members(name) if p == path), None)
        return self._file_cache[key]

    # ---- path index ------------------------------------------------------------------------------------
    def index_selection(self, feeds=DEFAULT_INDEX_FEEDS, max_size=DEFAULT_INDEX_MAX_SIZE) -> list[str]:
        return sorted(n for n, r in self.index().items()
                      if r["feed"] in feeds and r["size"] <= max_size and not n.startswith("luci-i18n-"))

    def build_path_index(self, feeds=DEFAULT_INDEX_FEEDS, max_size=DEFAULT_INDEX_MAX_SIZE, workers: int = 16) -> dict:
        """Fetch every package of the selected feeds once and store a file-path index for this release and target.

        The index lets an unaccounted file be attributed to the package that
        ships it, instead of guessing package names from file names. Packages
        larger than `max_size` (mostly firmware blobs for other hardware) and
        translation packages are left out; they are still fetched by name when
        a BOM declares them.
        """
        names = self.index_selection(feeds, max_size)
        t0 = time.time()
        got = self.payloads(names, workers=workers)
        doc = {"release": self.release, "target": self.target, "arch": self.arch, "feeds": list(feeds),
               "max_package_size": max_size, "packages": got}
        with gzip.open(self.dir / "pathindex.json.gz", "wt") as f:
            json.dump(doc, f)
        self._paths = self._sonames = None
        self._indexed = set(got)
        return {"packages": len(got), "files": sum(len(p["files"]) for p in got.values()),
                "seconds": round(time.time() - t0, 1), "downloaded": len(self.downloads),
                "downloaded_bytes": sum(d["bytes"] for d in self.downloads)}

    def _load_path_index(self) -> None:
        p = self.dir / "pathindex.json.gz"
        self._indexed: set[str] = set()
        if p.exists():
            with gzip.open(p, "rt") as f:
                doc = json.load(f)
            self._payloads.update(doc["packages"])
            self._indexed = set(doc["packages"])

    @property
    def has_path_index(self) -> bool:
        return bool(self._indexed)

    def indexed(self, name: str) -> bool:
        return name in self._indexed

    def _maps(self) -> None:
        if self._paths is None:
            paths: dict[str, list[str]] = {}
            sonames: dict[str, list[str]] = {}
            for n in sorted(self._indexed):
                for path, meta in self._payloads[n]["files"].items():
                    paths.setdefault(path, []).append(n)
                    if meta.get("soname"):
                        sonames.setdefault(meta["soname"], []).append(n)
            self._paths, self._sonames = paths, sonames

    def path_owners(self, path: str) -> list[str]:
        self._maps()
        return self._paths.get(path, [])

    def soname_owners(self, so: str) -> list[str]:
        self._maps()
        return self._sonames.get(so, [])

    def source_packages(self, source_name: str) -> list[str]:
        return sorted(n for n in self._indexed if self._payloads[n].get("source_name") == source_name)

    def provenance(self) -> dict:
        m = self.meta()
        return {"release": self.release, "target": self.target, "arch": m["arch"], "base": self.base,
                "sha256sums_sha256": m["sha256sums_sha256"], "sha256sums_signed_by": m["sha256sums_signed_by"],
                "feed_index_trust": self.index_trust(), "image_source_date_epoch": m["source_date_epoch"],
                "path_index_packages": len(self._indexed)}
