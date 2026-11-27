"""Baselines, each run as published and wrapped only as far as needed to compare with a declared BOM.

syft_diff     Syft (an SBOM generator) inventories the tree; our script diffs that inventory against the
              declared BOM by name and version. The diff is ours, not Syft's.
cvebin_diff   cve-bin-tool's version scanner (signature checkers over file contents, no CVE database)
              identifies products; our script diffs them against the declared BOM. The diff is ours.
bomtrace      BomTrace's verify_openwrt_bom.py at a pinned commit, unmodified, run through its own CLI.
              It needs a CycloneDX 1.4 BOM and a rootfs tar; our adapter writes both and maps its rule ids.

Every finding is normalised to (class, component) with class in absent, wrong_version, undeclared_component.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYFT = ROOT / "tools/syft/syft"
BOMTRACE_DIR = ROOT / "work/baselines/bomtrace"
BOMTRACE_COMMIT = "64e52644b3c4f8244ac952557644f50324e58136"
CVEBIN_PY = ROOT / "work/baselines/cvebin-venv/bin/python"


# ---- Syft ------------------------------------------------------------------------------------------------
def syft_components(rootfs: Path) -> dict[str, set[str]]:
    out = subprocess.run([str(SYFT), f"dir:{rootfs}", "-o", "cyclonedx-json", "-q"],
                         capture_output=True, text=True, timeout=600)
    comps: dict[str, set[str]] = {}
    for c in json.loads(out.stdout).get("components", []):
        if c.get("type") in ("library", "application") and c.get("name"):
            comps.setdefault(c["name"], set()).add(str(c.get("version", "")))
    return comps


def syft_diff(declared: list[dict], seen: dict[str, set[str]]) -> set[tuple[str, str]]:
    f = set()
    dn = {c["name"]: c["version"] for c in declared}
    for n, v in dn.items():
        if n not in seen:
            f.add(("absent", n))
        elif v not in seen[n]:
            f.add(("wrong_version", n))
    for n in seen:
        if n not in dn:
            f.add(("undeclared_component", n))
    return f


# ---- cve-bin-tool ----------------------------------------------------------------------------------------
_CVEBIN_SCRIPT = r'''
import json, sys
from cve_bin_tool.version_scanner import VersionScanner
s = VersionScanner(should_extract=False)
out = {}
for path in json.load(open(sys.argv[1])):
    hits = []
    try:
        for info, _p in s.scan_file(path):
            hits.append([info.product, info.version])
    except Exception as e:
        hits.append(["__error__", str(e)[:80]])
    out[path] = hits
json.dump(out, open(sys.argv[2], "w"))
'''


class CveBin:
    """cve-bin-tool's per-file checkers with a cache keyed by (file name, SHA-256).

    A checker looks only at a file's name and contents, so caching by those two
    keeps the output identical to a full scan while skipping unchanged files.
    """

    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
        self.home = cache_path.with_suffix(".home")       # cve-bin-tool keeps a small sqlite cache under $HOME
        (self.home / ".cache/cve-bin-tool").mkdir(parents=True, exist_ok=True)

    def scan(self, rootfs: Path) -> dict[str, set[str]]:
        keys, todo = {}, {}
        for dp, _dn, fn in os.walk(rootfs):
            for f in fn:
                q = Path(dp) / f
                if q.is_symlink() or not q.is_file():
                    continue
                key = f + ":" + hashlib.sha256(q.read_bytes()).hexdigest()
                keys[str(q)] = key
                if key not in self.cache:
                    todo[str(q)] = key
        if todo:
            with tempfile.TemporaryDirectory() as td:
                (Path(td) / "in.json").write_text(json.dumps(sorted(todo)))
                (Path(td) / "s.py").write_text(_CVEBIN_SCRIPT)
                env = dict(os.environ, HOME=str(self.home))
                r = subprocess.run([str(CVEBIN_PY), str(Path(td) / "s.py"), str(Path(td) / "in.json"), str(Path(td) / "out.json")],
                                   capture_output=True, text=True, timeout=1800, env=env)
                if r.returncode != 0:
                    raise RuntimeError("cve-bin-tool scan failed: " + r.stderr[-400:])
                res = json.loads((Path(td) / "out.json").read_text())
            for path, hits in res.items():
                self.cache[todo[path]] = hits
            self.cache_path.write_text(json.dumps(self.cache))
        products: dict[str, set[str]] = {}
        for key in keys.values():
            for product, version in self.cache[key]:
                if product != "__error__":
                    products.setdefault(product, set()).add(version)
        return products


# product name as cve-bin-tool reports it -> prefixes of OpenWrt package names it stands for
CVEBIN_ALIASES = {"hostapd": ("hostapd", "wpad"), "wpa_supplicant": ("wpa-supplicant", "wpad"), "linux_kernel": ("kernel",),
                  "mbed_tls": ("libmbedtls",), "openssl": ("libopenssl",), "wolfssl": ("libwolfssl",), "zlib": ("zlib",),
                  "curl": ("curl", "libcurl"), "libcurl": ("libcurl",), "ppp": ("ppp",), "iptables": ("iptables", "ip6tables", "xtables"),
                  "u-boot": ("uboot",), "busybox": ("busybox",), "dnsmasq": ("dnsmasq",), "dropbear_ssh": ("dropbear",),
                  "dropbear": ("dropbear",), "e2fsprogs": ("e2fsprogs", "libext2fs", "libcomerr", "libss"), "f2fs-tools": ("f2fs", "mkf2fs", "libf2fs"),
                  "lua": ("lua", "liblua"), "json-c": ("libjson-c",), "libnl": ("libnl",), "nftables": ("nftables",)}


def cvebin_names(product: str) -> tuple[str, ...]:
    return CVEBIN_ALIASES.get(product, (product.replace("_", "-"),))


def cvebin_diff(declared: list[dict], products: dict[str, set[str]]) -> set[tuple[str, str]]:
    f = set()
    for product, versions in products.items():
        prefixes = cvebin_names(product)
        matched = [c for c in declared if any(c["name"] == p or c["name"].startswith(p) for p in prefixes)]
        if not matched:
            f.add(("undeclared_component", product))
            continue
        for c in matched:
            tok = re.match(r"\d+(\.\d+)+", c["version"])
            if tok and not any(v == tok.group(0) or v.startswith(tok.group(0)) or tok.group(0).startswith(v) for v in versions if v and v != "UNKNOWN"):
                if any(v and v != "UNKNOWN" for v in versions):
                    f.add(("wrong_version", c["name"]))
    return f


def cvebin_label_match(found: set, label: tuple[str, str]) -> bool:
    """A cve-bin-tool finding names a product; count it for a label that names a package of that product."""
    if label in found:
        return True
    kind, name = label
    return any(k == kind == "undeclared_component" and any(name == p or name.startswith(p) for p in cvebin_names(prod))
               for k, prod in found)


# ---- BomTrace --------------------------------------------------------------------------------------------
BOMTRACE_RULES = {"DECLARED_PACKAGE_ABSENT": "absent", "PACKAGE_VERSION_MISMATCH": "wrong_version",
                  "INSTALLED_PACKAGE_UNDECLARED": "undeclared_component"}


def bomtrace_commit() -> str:
    return subprocess.run(["git", "-C", str(BOMTRACE_DIR), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def bomtrace(declared: list[dict], rootfs: Path) -> dict:
    """Run BomTrace's published OpenWrt verifier on (declared BOM, the tree's package database)."""
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
           "components": [{"type": "application", "name": c["name"], "version": c["version"]} for c in declared]}
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "bom.json").write_text(json.dumps(bom))
        with tarfile.open(td / "rootfs.tar.gz", "w:gz") as tar:
            status = rootfs / "usr/lib/opkg/status"
            if status.is_file():
                tar.add(status, arcname="./usr/lib/opkg/status")
            else:
                info = tarfile.TarInfo("./etc/placeholder")
                tar.addfile(info, io.BytesIO(b""))
        r = subprocess.run([sys.executable, str(BOMTRACE_DIR / "verify_openwrt_bom.py"), "--bom", str(td / "bom.json"),
                            "--rootfs-tar", str(td / "rootfs.tar.gz"), "--out", str(td / "out.json")],
                           capture_output=True, text=True, timeout=120, cwd=str(BOMTRACE_DIR))
        if r.returncode != 0 or not (td / "out.json").exists():
            err = (r.stderr.strip().splitlines() or ["no output"])[-1]
            return {"ran": False, "error": err[:200], "findings": set(), "unresolved": 0}
        rep = json.loads((td / "out.json").read_text())
    found = {(BOMTRACE_RULES.get(f["rule_id"], f["rule_id"].lower()), f["package"]) for f in rep["findings"]}
    return {"ran": True, "error": None, "findings": found, "unresolved": len(rep.get("unresolved", []))}
