"""Minimal CycloneDX 1.6 reading and writing for declared SBOMs and CBOMs."""
from __future__ import annotations

import json
from pathlib import Path


def sbom(components: list[dict], subject: str) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "firmware", "name": subject}},
        "components": [
            {"type": "library", "bom-ref": f"pkg:{c['name']}", "name": c["name"], "version": c["version"],
             "purl": f"pkg:opkg/openwrt/{c['name']}@{c['version']}"}
            for c in components
        ],
    }


def components(doc: dict) -> list[dict]:
    return [{"name": c["name"], "version": str(c.get("version", ""))}
            for c in doc.get("components", []) if c.get("type") != "cryptographic-asset"]


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text())
