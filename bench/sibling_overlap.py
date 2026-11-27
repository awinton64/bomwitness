"""How independent is each sibling snapshot from the image it helps verify?

The snapshot comes from another device's official image of the same release and target. Devices of one target
share most packages, and some sibling images have exactly the same package set as the tested device. This
script reports the overlap so a reader can judge how much of the snapshot's contribution is "another device
agrees" and how much is close to comparing an image with itself. The no-snapshot ablation in the main
benchmark is the conservative reading.

Usage: sibling_overlap.py [--out results/r2/sibling-overlap.json]
"""
import argparse
import json
from pathlib import Path

from bomwitness import devicedb
from bomwitness.verify import scan_rootfs

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("--out", default="results/r2/sibling-overlap.json"); a = ap.parse_args()
spec = json.loads((ROOT / "bench/images.json").read_text())
lock = json.loads((ROOT / "bench/images.lock.json").read_text())
out = {}
for im in spec["images"]:
    p = ROOT / "work/snapshots" / f"{im['id']}.json"
    if not p.exists():
        out[im["id"]] = {"sibling": None}
        continue
    snap = json.loads(p.read_text())
    rootfs = ROOT / "work/rootfs" / im["id"]
    files = scan_rootfs(rootfs)
    inst = devicedb.installed(rootfs)
    same = sum(1 for path, m in files.items() if snap["files"].get(path) == m["sha256"])
    out[im["id"]] = {
        "sibling": lock[im["id"]]["sibling"]["profile"], "tested_packages": len(inst), "sibling_packages": len(snap["packages"]),
        "packages_in_both": len(set(inst) & set(snap["packages"])), "packages_only_in_tested": sorted(set(inst) - set(snap["packages"])),
        "tested_files": len(files), "files_identical_in_sibling": same, "share_of_files_identical": round(same / len(files), 4),
        "identical_package_set": set(inst) == set(snap["packages"]),
        "identical_root_filesystem_contents": same == len(files) and len(files) == len(snap["files"]),
    }
    o = out[im["id"]]
    print(im["id"], o["sibling"], f"{o['packages_in_both']}/{o['tested_packages']} packages, {same}/{len(files)} files identical,",
          "identical rootfs" if o["identical_root_filesystem_contents"] else "", flush=True)
(ROOT / a.out).parent.mkdir(parents=True, exist_ok=True)
(ROOT / a.out).write_text(json.dumps(out, indent=1))
