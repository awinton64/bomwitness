"""Second sibling choice for a robustness check: the LEAST similar device of the same target.

bench/prepare.py picks the most similar device as sibling, and for most benchmark images that device turned
out to have exactly the same root filesystem as the tested one (results/r2/sibling-overlap.json). This script
picks the device whose package list differs most from the tested device (lowest Jaccard index of
device_packages, ties broken alphabetically), so the snapshot is far from a copy of the image under test.
Snapshots go to work/snapshots-far/, the choices to bench/far-siblings.lock.json.

Usage: prepare_far_sibling.py
"""
import json
import shutil
from pathlib import Path

from bomwitness import devicedb, fetch, unpack
from bomwitness.reference import Reference
from bomwitness.verify import scan_rootfs, snapshot_from_rootfs

ROOT = Path(__file__).resolve().parent.parent


def pick_far(meta: dict, image: str):
    tested = next((p for p, names in meta["profile_images"].items() if image in names), None)
    mine = set(meta["device_packages"].get(tested, []))
    best = None
    for prof, names in sorted(meta["profile_images"].items()):
        img = next((n for n in names if n.endswith("squashfs-sysupgrade.bin")), None)
        if prof == tested or not img:
            continue
        theirs = set(meta["device_packages"].get(prof, []))
        score = len(mine & theirs) / len(mine | theirs) if mine | theirs else 1.0
        if best is None or score < best[0]:
            best = (score, prof, img)
    return best


spec = json.loads((ROOT / "bench/images.json").read_text())
lock = {}
out_dir = ROOT / "work/snapshots-far"
out_dir.mkdir(parents=True, exist_ok=True)
for im in spec["images"]:
    ref = Reference(im["release"], im["target"], ROOT / "work/cache")
    far = pick_far(ref.meta(), im["image"])
    if not far:
        lock[im["id"]] = None
        continue
    score, prof, img = far
    path = fetch.image(ref, img, ROOT / "work/dl" / im["id"])
    tmp = ROOT / "work/rootfs" / f"{im['id']}.far"
    if tmp.exists():
        shutil.rmtree(tmp)
    unpack.extract(path, tmp)
    snap = snapshot_from_rootfs(tmp, f"{im['release']} {im['target']} {prof} ({img})")
    (out_dir / f"{im['id']}.json").write_text(json.dumps(snap))
    shutil.rmtree(tmp)
    rootfs = ROOT / "work/rootfs" / im["id"]
    files = scan_rootfs(rootfs)
    inst = devicedb.installed(rootfs)
    same = sum(1 for p, m in files.items() if snap["files"].get(p) == m["sha256"])
    lock[im["id"]] = {"profile": prof, "image": img, "sha256": ref.meta()["images"][img], "device_package_jaccard": round(score, 3),
                      "tested_packages": len(inst), "packages_in_both": len(set(inst) & set(snap["packages"])),
                      "tested_files": len(files), "files_identical_in_sibling": same}
    print(im["id"], prof, lock[im["id"]]["packages_in_both"], "/", len(inst), "packages;", same, "/", len(files), "files identical", flush=True)
(ROOT / "bench/far-siblings.lock.json").write_text(json.dumps(lock, indent=1, sort_keys=True))
