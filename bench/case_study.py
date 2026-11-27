"""Case study on firmware we did not mutate: a downstream fork of OpenWrt checked against upstream.

ImmortalWrt is an independent fork of OpenWrt with its own build servers, signing key and download tree.
Its 24.10.7 image for the TP-Link Archer C7 v5 is treated here the way an auditor would treat vendor
firmware "based on OpenWrt 24.10.7":

  Part 1  The BOM is the fork's own package list (taken from the image's database, standing in for a
          vendor-supplied BOM). The reference is upstream OpenWrt 24.10.7: its signed feeds, its release
          manifest and its official image for the same device. Question: which declared components are
          really upstream's bytes, which only carry upstream's version marker, and which are the fork's own
          builds under an upstream-looking label?
  Part 2  The same image and BOM checked against the fork's own signed download tree (different key,
          different mirror). Question: does the method carry over to a second publisher unchanged?

Nothing is redistributed. Both images are fetched and checked against their publisher's signed metadata.

Usage: case_study.py [--out results/r2/case-study-immortalwrt.json]
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from bomwitness import devicedb, fetch, unpack
from bomwitness.reference import Reference
from bomwitness.verify import HARD, scan_rootfs, snapshot_from_rootfs, verify

from prepare import pick_sibling

ROOT = Path(__file__).resolve().parent.parent
RELEASE, TARGET, DEVICE = "24.10.7", "ath79/generic", "tplink_archer-c7-v5"
FORK_BASE = "https://downloads.immortalwrt.org/releases"
# https://github.com/immortalwrt/keyring/blob/master/usign/3fd9011f340b50dd  ("Public usign key for 24.10 release builds")
FORK_KEYS = {"3fd9011f340b50dd": ("RWQ/2QEfNAtQ3csOLH+4IytQyH3e+wOAn0rLo0iTGG5f7FTw/hfzfwVM", "ImmortalWrt 24.10 release builds")}


def counts(rep: dict) -> dict:
    return {"verdicts": rep["summary"]["verdicts"],
            "hard_findings": {k: sum(1 for f in rep["findings"] if f["class"] == k) for k in HARD if any(f["class"] == k for f in rep["findings"])},
            "files_accounted": rep["summary"]["files_accounted"], "rootfs_files": rep["summary"]["rootfs_files"],
            "executable_files_unaccounted": rep["summary"]["orphan_code_files"], "code_files": rep["summary"]["code_files"]}


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="results/r2/case-study-immortalwrt.json"); a = ap.parse_args()
    work = ROOT / "work/case-study"
    if work.exists():
        shutil.rmtree(work)
    fork = Reference(RELEASE, TARGET, ROOT / "work/cache-immortalwrt", base=FORK_BASE, keys=FORK_KEYS)
    up = Reference(RELEASE, TARGET, ROOT / "work/cache")
    fimg = f"immortalwrt-{RELEASE}-ath79-generic-{DEVICE}-squashfs-sysupgrade.bin"
    uimg = f"openwrt-{RELEASE}-ath79-generic-{DEVICE}-squashfs-sysupgrade.bin"
    unpack.extract(fetch.image(fork, fimg, work / "dl"), work / "fork")
    unpack.extract(fetch.image(up, uimg, work / "dl"), work / "upstream")
    rootfs = work / "fork"
    inst = devicedb.installed(rootfs)
    bom = [{"name": n, "version": r["Version"]} for n, r in inst.items()]
    up_inst = devicedb.installed(work / "upstream")

    # Part 1: against upstream
    snap_up = snapshot_from_rootfs(work / "upstream", f"official OpenWrt {RELEASE} image for {DEVICE}")
    rep = verify(rootfs, bom, up, manifest=up.manifest(), snapshots=[snap_up])
    files = scan_rootfs(rootfs)
    up_files = snap_up["files"]
    same_path_same_bytes = sum(1 for p, m in files.items() if up_files.get(p) == m["sha256"])
    elf = [p for p, m in files.items() if m["elf"]]
    elf_same = sum(1 for p in elf if up_files.get(p) == files[p]["sha256"])
    by_verdict: dict[str, list[str]] = {}
    for c in rep["components"]:
        by_verdict.setdefault(c["verdict"], []).append(c["name"])
    reasons: dict[str, int] = {}
    for c in rep["components"]:
        if c["verdict"] == "unverifiable":
            reasons[c["reason"]] = reasons.get(c["reason"], 0) + 1
    part1 = {"question": "which declared components are upstream OpenWrt's bytes?", "declared": len(bom), **counts(rep),
             "label_sources": {s: sum(1 for c in rep["components"] if c.get("label_source") == s) for s in {c.get("label_source") for c in rep["components"]} if s},
             "unverifiable_reasons": reasons,
             "examples": {v: sorted(n)[:12] for v, n in by_verdict.items() if v not in ("verified_A",)},
             "same_name_and_version_as_upstream_image": sum(1 for n, r in inst.items() if n in up_inst and up_inst[n]["Version"] == r["Version"]),
             "packages_not_in_upstream_image": sorted(set(inst) - set(up_inst))[:60],
             "files_byte_identical_to_upstream_image": same_path_same_bytes, "files_total": len(files),
             "executables_byte_identical_to_upstream_image": elf_same, "executables_total": len(elf),
             "undeclared_components_found": sorted(f["component"] for f in rep["findings"] if f["class"] == "undeclared_component")[:30]}
    same_label = [c for c in rep["components"] if c["name"] in up_inst and up_inst[c["name"]]["Version"] == c["declared_version"]]
    part1["of_those_with_upstream_label"] = {v: sum(1 for c in same_label if c["verdict"] == v) for v in {c["verdict"] for c in same_label}}

    # Part 2: against the fork's own signed tree
    sib = pick_sibling(fork.meta(), fimg)
    unpack.extract(fetch.image(fork, sib[1], work / "dl"), work / "fork-sibling")
    snap_fork = snapshot_from_rootfs(work / "fork-sibling", f"ImmortalWrt {RELEASE} {sib[0]}")
    rep2 = verify(rootfs, bom, fork, manifest=fork.manifest(), snapshots=[snap_fork])
    part2 = {"question": "does the method work unchanged for a second publisher?", "declared": len(bom), **counts(rep2),
             "reference": fork.provenance(), "sibling": sib[1],
             "not_verified": [{"name": c["name"], "verdict": c["verdict"], "reason": c["reason"]} for c in rep2["components"]
                              if not c["verdict"].startswith("verified")][:40]}
    # the three database conditions on five omitted components, against the fork's reference
    from bomwitness import mutate
    omitted = sorted(n for n in inst if n in fork.index() and fork.payload(n)["files"])[::max(len(inst) // 5, 1)][:5]
    rows = []
    for n in omitted:
        b = [c for c in bom if c["name"] != n]
        found = {}
        for cond in ("honest", "colluding", "stripped"):
            tree = mutate.clone(rootfs, work / "tree")
            if cond == "colluding":
                mutate.db_remove(tree, n)
            elif cond == "stripped":
                mutate.db_strip(tree)
            r = verify(tree, b, fork, manifest=fork.manifest(), snapshots=[snap_fork])
            found[cond] = ("undeclared_component", n) in {(f["class"], f["component"]) for f in r["findings"]}
        rows.append({"omitted": n, **found})
    part2["omitted_component_found_by_database_condition"] = rows

    out = {"subject": {"image": fimg, "sha256": fork.meta()["images"][fimg], "publisher": "ImmortalWrt", "release": RELEASE, "target": TARGET,
                       "sha256sums_signed_by": fork.meta()["sha256sums_signed_by"], "kernel": fork.meta()["kernel"]},
           "upstream": {"image": uimg, "sha256": up.meta()["images"][uimg], "sha256sums_signed_by": up.meta()["sha256sums_signed_by"], "kernel": up.meta()["kernel"]},
           "bom_note": "The declared BOM is the fork image's own package list, standing in for a vendor-supplied BOM. No BOM published by ImmortalWrt was tested.",
           "part1_against_upstream": part1, "part2_against_own_publisher": part2}
    shutil.rmtree(work)
    p = ROOT / a.out
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in part1.items() if k not in ("examples", "packages_not_in_upstream_image")}, indent=1))
    print(json.dumps({k: v for k, v in part2.items() if k not in ("reference", "not_verified")}, indent=1))
    print("part 2 not verified:", [(x["name"], x["verdict"]) for x in part2["not_verified"]][:20])


if __name__ == "__main__":
    main()
