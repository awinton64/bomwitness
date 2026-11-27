"""Database-free inventory: what can be said about an image that ships no BOM and no package database?

For each image the device database is used only as ground truth. BOMwitness attributes every file to the
reference package that ships it (bomwitness.verify.inventory). The comparison columns come from the case
files of the main benchmark: Syft on the same tree with the database removed, and cve-bin-tool's products.

Usage: inventory_eval.py [--out results/r2/inventory.json] [--cases results/r2/cases]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from bomwitness import devicedb
from bomwitness.reference import Reference
from bomwitness.verify import inventory

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/r2/inventory.json"); ap.add_argument("--cases", default="results/r2/cases")
    a = ap.parse_args()
    spec = json.loads((ROOT / "bench/images.json").read_text())
    out = {}
    for im in spec["images"]:
        ref = Reference(im["release"], im["target"], ROOT / "work/cache")
        rootfs = ROOT / "work/rootfs" / im["id"]
        snap_path = ROOT / "work/snapshots" / f"{im['id']}.json"
        snaps = [json.loads(snap_path.read_text())] if snap_path.exists() else []
        inst = devicedb.installed(rootfs)
        with_files = {n for n in inst if any((rootfs / p).is_file() and not (rootfs / p).is_symlink() for p in devicedb.owned_files(rootfs, n))}
        t = time.time()
        inv = inventory(rootfs, ref, manifest=ref.manifest(), snapshots=snaps)
        secs = time.time() - t
        got = {c["name"]: c for c in inv["components"]}
        named = set(got) & with_files
        version_ok = sum(1 for n in named if got[n]["version"] == inst[n]["Version"])
        case_file = ROOT / a.cases / f"{im['id']}.json"
        cc = json.loads(case_file.read_text())["clean_control"] if case_file.exists() else {}
        out[im["id"]] = {
            "split": im["split"], "installed_packages": len(inst), "installed_packages_with_files": len(with_files),
            "attributed_components": len(got), "correct_names": len(named), "name_recall": round(len(named) / len(with_files), 4),
            "name_precision": round(len(named) / len(got), 4) if got else None,
            "correct_versions_among_named": version_ok, "grade_A": sum(1 for c in got.values() if c["grade"] == "A"),
            "missed": sorted(with_files - set(got)), "extra": sorted(set(got) - with_files),
            "unattributed_executables": inv["unattributed_code"], "seconds": round(secs, 2),
            "syft_components_database_removed": cc.get("syft_components_db_stripped"), "syft_components_with_database": cc.get("syft_components"),
            "cvebin_products": len(cc.get("cvebin_products") or []),
        }
        o = out[im["id"]]
        print(im["id"], f"{o['correct_names']}/{o['installed_packages_with_files']} named, {o['correct_versions_among_named']} versions right,",
              "extra", o["extra"][:5], "missed", o["missed"][:5], flush=True)
    p = ROOT / a.out
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
