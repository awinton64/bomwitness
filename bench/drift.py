"""Reference drift over time: how much of an older release image can still be verified at grade A?

The shared package feed of a release series is rebuilt and relabelled after each point release. This script
takes the same device across the point releases of two series, verifies a correct BOM for each image against
today's feeds, and records what each reference source can still confirm:

  feeds only                       frozen target feeds plus the drifting shared feeds
  feeds + release manifest         adds the per-target manifest (pinned by hash in the signed checksum file) for version labels
  feeds + manifest + snapshot      adds a frozen snapshot from one official sibling image of the same release

It also measures drift at the feed level: the share of packages in the shared base feed whose file was
republished after the newest release of the series.

Usage: drift.py [--out results/r2/drift.json]
"""
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from bomwitness import devicedb, fetch, unpack
from bomwitness.reference import Reference
from bomwitness.verify import HARD, snapshot_from_rootfs, verify

from prepare import pick_sibling

ROOT = Path(__file__).resolve().parent.parent
TARGET = "ath79/generic"
DEVICE = "tplink_archer-c7-v2"
RELEASES = ["23.05.0", "23.05.2", "23.05.3", "23.05.4", "23.05.5", "23.05.6",
            "24.10.0", "24.10.1", "24.10.2", "24.10.3", "24.10.4", "24.10.5", "24.10.6", "24.10.7", "24.10.8"]


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="results/r2/drift.json"); a = ap.parse_args()
    now = int(time.time())
    rows = []
    for rel in RELEASES:
        ref = Reference(rel, TARGET, ROOT / "work/cache")
        m = ref.meta()
        image = f"openwrt-{rel}-{TARGET.replace('/', '-')}-{DEVICE}-squashfs-sysupgrade.bin"
        work = ROOT / "work/drift" / rel
        if work.exists():
            shutil.rmtree(work)
        path = fetch.image(ref, image, ROOT / "work/dl/drift")
        unpack.extract(path, work / "rootfs")
        sib = pick_sibling(m, image)
        spath = fetch.image(ref, sib[1], ROOT / "work/dl/drift")
        unpack.extract(spath, work / "sibling")
        snap = snapshot_from_rootfs(work / "sibling", f"{rel} {TARGET} {sib[0]}")
        rootfs = work / "rootfs"
        truth = [{"name": n, "version": r["Version"]} for n, r in devicedb.installed(rootfs).items()]
        row = {"release": rel, "image": image, "image_sha256": m["images"][image], "sibling": sib[1], "sibling_sha256": m["images"][sib[1]],
               "image_source_date_epoch": m["source_date_epoch"], "age_days": round((now - m["source_date_epoch"]) / 86400),
               "declared": len(truth), "configs": {}}
        for name, kw in (("feeds_only", {}), ("feeds_manifest", {"manifest": ref.manifest()}),
                         ("feeds_manifest_snapshot", {"manifest": ref.manifest(), "snapshots": [snap]})):
            rep = verify(rootfs, truth, ref, **kw)
            v = rep["summary"]["verdicts"]
            row["configs"][name] = {"verdicts": v, "verified_A_share": round(v.get("verified_A", 0) / len(truth), 4),
                                    "verified_share": round((v.get("verified_A", 0) + v.get("verified_B", 0)) / len(truth), 4),
                                    "hard_findings": sorted([f["class"], f["component"]] for f in rep["findings"] if f["class"] in HARD)}
        moved = [c["name"] for c in verify(rootfs, truth, ref)["components"]
                 if c.get("reference_version") and c["reference_version"] != c["declared_version"]]
        row["components_whose_feed_label_changed"] = len(moved)
        rows.append(row)
        shutil.rmtree(work)
        print(rel, row["age_days"], "days;", {k: (c["verified_A_share"], c["verified_share"], len(c["hard_findings"])) for k, c in row["configs"].items()},
              "relabelled", len(moved), flush=True)
    feed = {}
    for rel in ("23.05.6", "24.10.8"):
        ref = Reference(rel, TARGET, ROOT / "work/cache")
        epoch = ref.meta()["source_date_epoch"]
        base = [n for n, r in ref.index().items() if r["feed"] == "base"]
        dates = [ref.published(n) for n in base]
        known = [d for d in dates if d]
        feed[rel] = {"arch": ref.arch, "base_feed_packages": len(base), "with_listing_date": len(known),
                     "republished_after_release_build": sum(1 for d in known if d > epoch + 86400),
                     "share_republished": round(sum(1 for d in known if d > epoch + 86400) / len(known), 4) if known else None,
                     "release_build_epoch": epoch, "newest_package_epoch": max(known) if known else None}
    out = ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"device": DEVICE, "target": TARGET, "measured_at_epoch": now, "releases": rows, "shared_base_feed": feed}, indent=1))
    print(json.dumps(feed, indent=1))


if __name__ == "__main__":
    main()
