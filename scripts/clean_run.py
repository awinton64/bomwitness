import json, sys, time
from pathlib import Path
from bomwitness.feed import Feed
from bomwitness import opkgdb
from bomwitness.verify import verify

root = Path(__file__).resolve().parent.parent
spec = json.loads((root / "images.json").read_text())
for im in spec["images"]:
    if len(sys.argv) > 1 and im["id"] not in sys.argv[1:]:
        continue
    rootfs = root / "work/rootfs" / im["id"]
    feed = Feed(spec["release"], im["target"], im["arch"], im["kmods"], root / "work/cache/feed")
    declared = [{"name": n, "version": r["Version"]} for n, r in opkgdb.installed(rootfs).items()]
    t = time.time(); rep = verify(rootfs, declared, feed); dt = time.time() - t
    print(im["id"], round(dt, 1), "s", json.dumps(rep["summary"]))
    for f in rep["findings"]:
        print("   ", f["class"], f["component"], f["grade"], "|", f["detail"])
    print("    unverifiable:", [(r["name"], r["reason"][:40]) for r in rep["components"] if r["verdict"] == "unverifiable"])
    print("    orphans:", rep["orphans"][:30])
