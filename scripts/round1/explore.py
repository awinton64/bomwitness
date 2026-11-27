import hashlib, json, os, sys, time
from pathlib import Path
from bomwitness.feed import Feed
from bomwitness import opkgdb

root = Path(__file__).resolve().parent.parent
spec = json.loads((root / "images.json").read_text())
im = next(i for i in spec["images"] if i["id"] == sys.argv[1])
rootfs = root / "work/rootfs" / im["id"]
feed = Feed(spec["release"], im["target"], im["arch"], im["kmods"], root / "work/cache/feed")
t = time.time(); idx = feed.index(); print("index", len(idx), "pkgs", round(time.time() - t, 1), "s")
inst = opkgdb.installed(rootfs)
missing = [n for n in inst if n not in idx]
print("installed not in feed index:", missing)
print("version differs:", [(n, inst[n]["Version"], idx[n]["version"]) for n in inst if n in idx and idx[n]["version"] != inst[n]["Version"]])
t = time.time(); pl = feed.payloads(list(inst)); print("payloads", len(pl), round(time.time() - t, 1), "s")
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
claimed = set(); tot = same = diff = absent = 0; diffs = []; absents = []
for n, p in pl.items():
    for f, meta in p["files"].items():
        claimed.add(f); tot += 1
        q = rootfs / f
        if q.is_symlink() or not q.is_file(): absent += 1; absents.append((n, f)); continue
        if h(q) == meta["sha256"]: same += 1
        else: diff += 1; diffs.append((n, f, meta["elf"], f in p["conffiles"]))
print("payload files", tot, "same", same, "diff", diff, "absent", absent)
print("DIFF:", diffs)
print("ABSENT:", absents[:40])
orph = []
for dp, dn, fn in os.walk(rootfs):
    for f in fn:
        q = Path(dp) / f
        if q.is_symlink() or not q.is_file(): continue
        rel = str(q.relative_to(rootfs))
        if rel not in claimed: orph.append(rel)
print("rootfs regular files not in any payload:", len(orph))
print([o for o in orph if not o.startswith("usr/lib/opkg/")])
print("payload bytes downloaded:", sum(x.stat().st_size for x in (feed.cache / "ipk").glob("*")))
