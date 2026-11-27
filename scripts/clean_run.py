"""Verify a correct BOM (generated from the image's own database) against each unmodified image. Debug aid."""
import json
import sys
from pathlib import Path

from bomwitness import devicedb
from bomwitness.reference import Reference
from bomwitness.verify import HARD, verify

root = Path(__file__).resolve().parent.parent
spec = json.loads((root / "bench/images.json").read_text())
OTHER = {"24.10.8": "23.05.6", "23.05.6": "24.10.8"}
for im in spec["images"]:
    if len(sys.argv) > 1 and im["id"] not in sys.argv[1:]:
        continue
    rootfs = root / "work/rootfs" / im["id"]
    ref = Reference(im["release"], im["target"], root / "work/cache")
    alt = Reference(OTHER[im["release"]], im["target"], root / "work/cache")
    declared = [{"name": n, "version": r["Version"]} for n, r in devicedb.installed(rootfs).items()]
    for label, man in (("with manifest", ref.manifest()), ("no manifest", None)):
        rep = verify(rootfs, declared, ref, [alt], manifest=man)
        print(im["id"], label, json.dumps(rep["summary"]))
    rep = verify(rootfs, declared, ref, [alt], manifest=ref.manifest())
    for f in rep["findings"]:
        if f["class"] in HARD or "-v" in sys.argv:
            print("   ", f["class"], f["component"], f["grade"], "|", f["detail"][:200])
    print("    not verified:", [(r["name"], r["verdict"], r["reason"][:60]) for r in rep["components"] if not r["verdict"].startswith("verified")])
    print("    orphans:", rep["orphans"][:30])
