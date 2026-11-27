"""Fetch and unpack the benchmark images. Usage: prepare.py [image-id ...]  (default: all in bench/images.json)

For each image this writes work/rootfs/<id>/ and, where the target has another device, a frozen release
snapshot taken from one official sibling image (work/cache/<release>/<target>/snapshot.json).

Sibling rule (fixed before any result was looked at): among the other device profiles of the same target that
publish a squashfs sysupgrade image, take the one whose device package list is most similar to the tested
device (Jaccard index), ties broken alphabetically. A target with a single device gets no snapshot.

bench/images.lock.json records the SHA-256 of every image and sibling together with the signed metadata they
were checked against.
"""
import json
import shutil
import sys
from pathlib import Path

from bomwitness import fetch, unpack
from bomwitness.reference import Reference
from bomwitness.verify import snapshot_from_rootfs

ROOT = Path(__file__).resolve().parent.parent


def pick_sibling(meta: dict, image: str) -> tuple[str, str] | None:
    tested = next((p for p, names in meta["profile_images"].items() if image in names), None)
    mine = set(meta["device_packages"].get(tested, []))
    best = None
    for prof, names in sorted(meta["profile_images"].items()):
        img = next((n for n in names if n.endswith("squashfs-sysupgrade.bin")), None)
        if prof == tested or not img:
            continue
        theirs = set(meta["device_packages"].get(prof, []))
        score = len(mine & theirs) / len(mine | theirs) if mine | theirs else 1.0
        if best is None or score > best[0]:
            best = (score, prof, img)
    return (best[1], best[2]) if best else None


def main() -> None:
    spec = json.loads((ROOT / "bench/images.json").read_text())
    lock_path = ROOT / "bench/images.lock.json"
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {}
    for im in spec["images"]:
        if len(sys.argv) > 1 and im["id"] not in sys.argv[1:]:
            continue
        ref = Reference(im["release"], im["target"], ROOT / "work/cache")
        m = ref.meta()
        path = fetch.image(ref, im["image"], ROOT / "work/dl" / im["id"])
        dest = ROOT / "work/rootfs" / im["id"]
        if dest.exists():
            shutil.rmtree(dest)
        info = unpack.extract(path, dest)
        entry = {"url": f"{ref.target_url}/{im['image']}", "sha256": m["images"][im["image"]], "bytes": path.stat().st_size,
                 "split": im["split"], "release": im["release"], "target": im["target"], "arch": m["arch"], "kernel": m["kernel"],
                 "image_source_date_epoch": m["source_date_epoch"], "sha256sums_sha256": m["sha256sums_sha256"],
                 "sha256sums_signed_by": m["sha256sums_signed_by"], "squashfs": info["superblock"],
                 "rootfs_files": info["files"], "rootfs_symlinks": info["symlinks"], "self_reported": unpack.release_hint(dest),
                 "sibling": None}
        sib = pick_sibling(m, im["image"])
        snap_path = ROOT / "work/snapshots" / f"{im['id']}.json"
        snap_path.parent.mkdir(parents=True, exist_ok=True)
        if sib:
            spath = fetch.image(ref, sib[1], ROOT / "work/dl" / im["id"])
            sdest = ROOT / "work/rootfs" / f"{im['id']}.sibling"
            if sdest.exists():
                shutil.rmtree(sdest)
            unpack.extract(spath, sdest)
            snap = snapshot_from_rootfs(sdest, f"{im['release']} {im['target']} {sib[0]} ({sib[1]})")
            snap_path.write_text(json.dumps(snap))
            shutil.rmtree(sdest)
            entry["sibling"] = {"profile": sib[0], "image": sib[1], "sha256": m["images"][sib[1]],
                                "packages": len(snap["packages"]), "files": len(snap["files"])}
        elif snap_path.exists():
            snap_path.unlink()
        lock[im["id"]] = entry
        print(im["id"], m["arch"], info["files"], "files; sibling:", entry["sibling"] and entry["sibling"]["profile"], flush=True)
        lock_path.write_text(json.dumps(lock, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
