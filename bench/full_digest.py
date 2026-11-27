"""A wider check than verdict_check.py that a change to the verifier moved no verdict: old code against new code, directly.

verdict_check.py compares a rerun of the benchmark with the committed case files, so it sees what those files record.
This script records more. For every benchmark image, each of the six BOMwitness configurations of run_cases.py and
three declarations (the correct BOM, the BOM with its first 20 components omitted, the BOM with every version changed)
it stores, without any reason or detail text:
  per declared component   verdict, grade, actual version, actual component, label source, counts of files present and
                           matching, and the list of differing files
  per finding              class, component, grade, attributed files, alternatives
  per run                  the summary (without the timing) and the list of unexplained files

Usage:
  PYTHONPATH=<tree> python full_digest.py digest --tree <tree> --out <digest.json>     once per code tree
  python full_digest.py compare <old digest> <new digest> [--out results/r2/r5-verdict-check/FULL-DIGEST.json]

<tree> is a directory holding the `bomwitness` package and `bench/` of the code under test (for example
`git archive <commit> bomwitness bench | tar -x -C <tree>`), with `work/` linked into it. The three declarations are
not benchmark cases and are scored against nothing; they only make the verifier take its attribution and
wrong-label branches on real images.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DECLARATIONS = ("correct", "first 20 omitted", "every version changed")


def digest(tree: Path, out_path: Path) -> None:
    sys.path.insert(0, str(tree / "bench"))
    import bomwitness
    import run_cases
    from bomwitness import devicedb
    from bomwitness.reference import Reference
    from bomwitness.verify import scan_rootfs, verify
    assert Path(bomwitness.__file__).resolve().is_relative_to(tree.resolve()), "PYTHONPATH does not point at the tree"
    root = run_cases.ROOT
    out = {"images": {}}
    for im in json.loads((root / "bench/images.json").read_text())["images"]:
        clean, cache = root / "work/rootfs" / im["id"], root / "work/cache"
        ref = Reference(im["release"], im["target"], cache)
        alt = Reference(run_cases.OTHER[im["release"]], im["target"], cache)
        snap_path = root / "work/snapshots" / f"{im['id']}.json"
        snaps = [json.loads(snap_path.read_text())] if snap_path.exists() else []
        truth = [{"name": n, "version": r["Version"]} for n, r in devicedb.installed(clean).items()]
        boms = dict(zip(DECLARATIONS, (truth, truth[20:], [dict(c, version=c["version"] + "9") for c in truth])))
        files = scan_rootfs(clean)
        per = {}
        for name, kw in run_cases.bw_configs(ref.manifest(), snaps).items():
            for label, bom in boms.items():
                rep = verify(clean, bom, ref, [alt], files=files, **kw)
                summary = dict(rep["summary"])
                summary.pop("seconds", None)
                per[f"{name} / {label}"] = {
                    "components": [[c["name"], c["verdict"], c.get("grade"), c.get("actual_version"), c.get("actual_component"),
                                    c.get("label_source"), c.get("identical"), c.get("present"), sorted(c.get("differing") or [])]
                                   for c in rep["components"]],
                    "findings": sorted([f["class"], f["component"], f["grade"], sorted(f.get("files") or []),
                                        sorted(f.get("alternatives") or [])] for f in rep["findings"]),
                    "summary": summary, "orphans": rep["orphans"]}
        out["images"][im["id"]] = per
        print(im["id"], len(truth), flush=True)
    out_path.write_text(json.dumps(out, sort_keys=True))


def compare(old_path: Path, new_path: Path, out_path: Path, old_commit: str | None) -> int:
    old, new = json.loads(old_path.read_text()), json.loads(new_path.read_text())
    diffs, runs, comps, finds = [], 0, 0, 0
    assert list(old["images"]) == list(new["images"])
    for im, per in old["images"].items():
        assert list(per) == list(new["images"][im])
        for cfg, x in per.items():
            y = new["images"][im][cfg]
            runs += 1
            comps += len(x["components"])
            finds += len(x["findings"])
            diffs += [f"{im} / {cfg}: {k}" for k in x if x[k] != y[k]]

    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=HERE.parent, capture_output=True, text=True).stdout.strip()
    res = {"note": "Old verifier code against new verifier code on every benchmark image; see the docstring of bench/full_digest.py. "
                   "Reason and detail text is not part of a digest.",
           "old_code_commit": old_commit, "declarations": list(DECLARATIONS),
           "new_code_blobs": {f: git("hash-object", f) for f in ("bomwitness/verify.py", "bomwitness/reference.py", "bench/run_cases.py")},
           "images": len(old["images"]), "verify_runs": runs, "component_records": comps, "findings": finds,
           "differences": diffs, "digest_sha256": {"old": hashlib.sha256(old_path.read_bytes()).hexdigest(),
                                                   "new": hashlib.sha256(new_path.read_bytes()).hexdigest()}}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    print(f"full digest: {res['images']} images, {runs} verify() runs, {comps} component records, {finds} findings; differences: {len(diffs)}")
    for d in diffs[:40]:
        print("  DIFF", d)
    return 1 if diffs else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("digest")
    d.add_argument("--tree", required=True)
    d.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("old")
    c.add_argument("new")
    c.add_argument("--old-commit")
    c.add_argument("--out", default=str(HERE.parent / "results/r2/r5-verdict-check/FULL-DIGEST.json"))
    a = ap.parse_args()
    if a.cmd == "digest":
        digest(Path(a.tree), Path(a.out))
    else:
        sys.exit(compare(Path(a.old), Path(a.new), Path(a.out), a.old_commit))
