"""Read declared BOMs (CycloneDX 1.4 to 1.6 JSON, SPDX 2.3 JSON) and write CycloneDX.

A software claim is {"name", "version", "ref"}. Cryptographic assets and
machine-learning models are returned separately so the SBOM, CBOM and AI-BOM
checks can share one input file or use three.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

NON_SOFTWARE = {"cryptographic-asset", "machine-learning-model", "data"}


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def _walk(components):
    for c in components or []:
        yield c
        yield from _walk(c.get("components"))


def _purl_version(purl: str | None) -> str:
    m = re.search(r"@([^?#]+)", purl or "")
    return m.group(1) if m else ""


def detect(doc: dict) -> str:
    if doc.get("bomFormat") == "CycloneDX":
        return f"CycloneDX {doc.get('specVersion', '?')}"
    if str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        return doc["spdxVersion"]
    raise ValueError("not a CycloneDX or SPDX JSON document")


def software_claims(doc: dict) -> list[dict]:
    kind = detect(doc)
    out = []
    if kind.startswith("CycloneDX"):
        for c in _walk(doc.get("components")):
            if c.get("type") in NON_SOFTWARE or not c.get("name"):
                continue
            out.append({"name": c["name"], "version": str(c.get("version") or _purl_version(c.get("purl"))),
                        "ref": c.get("bom-ref") or c["name"]})
    else:
        described = set(doc.get("documentDescribes") or [])
        for p in doc.get("packages", []):
            if p.get("SPDXID") in described or not p.get("name"):
                continue
            ver = p.get("versionInfo") or next((_purl_version(r.get("referenceLocator")) for r in p.get("externalRefs", [])
                                                if r.get("referenceType") == "purl"), "")
            out.append({"name": p["name"], "version": str(ver), "ref": p.get("SPDXID") or p["name"]})
    return out


def crypto_assets(doc: dict) -> list[dict]:
    if not detect(doc).startswith("CycloneDX"):
        return []
    return [c for c in _walk(doc.get("components")) if c.get("type") == "cryptographic-asset"]


def models(doc: dict) -> list[dict]:
    if not detect(doc).startswith("CycloneDX"):
        return []
    return [c for c in _walk(doc.get("components")) if c.get("type") == "machine-learning-model"]


def provides_map(doc: dict) -> dict[str, list[str]]:
    """CycloneDX 1.6 dependency "provides": crypto asset bom-ref to the software bom-refs that implement it."""
    out: dict[str, list[str]] = {}
    for d in doc.get("dependencies", []) or []:
        for asset in d.get("provides", []) or []:
            out.setdefault(asset, []).append(d.get("ref"))
    return out


def sbom(components: list[dict], subject: str, spec: str = "1.6") -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
        "metadata": {"component": {"type": "firmware", "name": subject}},
        "components": [
            {"type": "library", "bom-ref": f"pkg:{c['name']}", "name": c["name"], "version": c["version"],
             "purl": f"pkg:opkg/openwrt/{c['name']}@{c['version']}"}
            for c in components
        ],
    }
