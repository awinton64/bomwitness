"""Observation: how much of a device image does the officially published per-target BOM cover?

Compares each official openwrt-<release>-<target>.bom.cdx.json with the packages in the
device image built for that target. Names are reconciled through opkg Provides aliases and
ABI-version suffixes. Uses the image's package database as the reference inventory, so this
is an observation about published BOMs, not a BOMwitness verification result.
"""
import json
import re
import sys
from pathlib import Path

from bomwitness import opkgdb

ROOT = Path(__file__).resolve().parent.parent
spec = json.loads((ROOT / "images.json").read_text())
out = {}
for im in spec["images"]:
    rootfs = ROOT / "work/rootfs" / im["id"]
    bom = json.loads((ROOT / "work/dl" / im["id"] / im["bom"]).read_text())
    declared = {c["name"]: str(c.get("version", "")) for c in bom["components"]}
    inst = opkgdb.installed(rootfs)
    covered, uncovered = {}, []
    for n, r in inst.items():
        aliases = [n] + [x.strip() for x in r.get("Provides", "").split(",") if x.strip()]
        abi = r.get("ABIVersion")
        if abi and n.endswith(abi):
            aliases.append(n[: -len(abi)])
        hit = next((a for a in aliases if a in declared), None)
        if hit:
            covered[n] = hit
        else:
            uncovered.append(n)
    src = {}
    for n in uncovered:
        ctl = rootfs / opkgdb.INFO / f"{n}.control"
        m = re.search(r"^SourceName: (.+)$", ctl.read_text(), re.M) if ctl.is_file() else None
        src[n] = m.group(1) if m else None
    by_source = sorted(n for n in uncovered if src[n] in declared)
    truly = sorted(n for n in uncovered if src[n] not in declared)
    files = sum(len(opkgdb.owned_files(rootfs, n)) for n in truly)
    unused = sorted(set(declared) - set(covered.values()) - {src[n] for n in by_source})
    out[im["id"]] = {"official_bom": im["bom"], "bom_spec_version": bom.get("specVersion"), "bom_components": len(declared),
                     "installed_packages": len(inst), "covered_by_name_or_alias": len(covered),
                     "covered_only_via_source_package_name": by_source,
                     "installed_but_not_in_official_bom": truly, "their_file_count": files,
                     "bom_components_not_installed_in_this_image": unused}
(ROOT / "results/spike-r1/official-bom-gap.json").write_text(json.dumps(out, indent=1))
for k, v in out.items():
    print(k, {x: (y if not isinstance(y, list) else (len(y), y[:45])) for x, y in v.items()})
