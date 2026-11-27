"""Verify the publisher's own per-target CycloneDX BOM against each device image, from bytes.

OpenWrt publishes one BOM per target (openwrt-<release>-<target>.bom.cdx.json, CycloneDX 1.4, upstream
versions without the package release, library names without the ABI suffix). A device image of that target
also contains device-specific packages. This script feeds the published BOM, unchanged, to the verifier and
records how many of its claims the bytes confirm and what the image contains beyond it.

Wording matters: the BOM is published per target, and we have not found a statement that it is meant to
cover every device image. The result is a coverage observation, not an accusation of an error.

Usage: official_bom.py [--out results/r2/official-bom.json]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from bomwitness import bomio, devicedb
from bomwitness.reference import Reference
from bomwitness.verify import verify

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="results/r2/official-bom.json"); a = ap.parse_args()
    spec = json.loads((ROOT / "bench/images.json").read_text())
    out = {}
    for im in spec["images"]:
        ref = Reference(im["release"], im["target"], ROOT / "work/cache")
        doc = ref.official_bom()
        if doc is None:
            out[im["id"]] = {"official_bom": None}
            continue
        claims = bomio.software_claims(doc)
        snap_path = ROOT / "work/snapshots" / f"{im['id']}.json"
        snaps = [json.loads(snap_path.read_text())] if snap_path.exists() else []
        rootfs = ROOT / "work/rootfs" / im["id"]
        rep = verify(rootfs, claims, ref, manifest=ref.manifest(), snapshots=snaps)
        undeclared = sorted(f["component"] for f in rep["findings"] if f["class"] == "undeclared_component")
        files_undeclared = sum(len(f.get("files", [])) for f in rep["findings"] if f["class"] == "undeclared_component")
        inst = devicedb.installed(rootfs)
        out[im["id"]] = {
            "split": im["split"], "official_bom": ref.meta()["official_bom"], "official_bom_sha256": ref.meta()["sums"][ref.meta()["official_bom"]],
            "format": bomio.detect(doc), "bom_components": len(claims), "verdicts": rep["summary"]["verdicts"],
            "matched_by": {how: sum(1 for c in rep["components"] if c["matched_by"] == how) for how in ("exact", "abi", "provides", "source", "builtin", "none")},
            "not_verified": [{"name": c["name"], "declared_version": c["declared_version"], "verdict": c["verdict"], "reason": c["reason"]}
                             for c in rep["components"] if not c["verdict"].startswith("verified")],
            "components_in_image_not_in_bom": undeclared, "their_files": files_undeclared,
            "executable_files_unaccounted": rep["summary"]["orphan_code_files"],
            "device_database_packages": len(inst),
            "device_database_agrees_those_are_installed": sorted(n for n in undeclared if n in inst),
        }
        o = out[im["id"]]
        print(im["id"], o["bom_components"], o["verdicts"], "beyond the BOM:", len(undeclared), undeclared[:8], flush=True)
    p = ROOT / a.out
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
