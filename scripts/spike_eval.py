"""Round 1 spike: seeded BOM errors on official OpenWrt images, BOMwitness vs a Syft-based diff.

Usage: spike_eval.py <image-id> [...]   Writes results/spike-r1/<image-id>.json
"""
from __future__ import annotations

import json
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

from bomwitness import mutate, opkgdb
from bomwitness.feed import Feed
from bomwitness.verify import upstream_token, verify

ROOT = Path(__file__).resolve().parent.parent
SYFT = ROOT / "tools/syft/syft"
HARD = {"undeclared_component", "wrong_version", "absent", "bytes_differ"}
K = 12
OLD_RELEASE = "23.05.5"


def syft_components(rootfs: Path) -> dict[str, set[str]]:
    out = subprocess.run([str(SYFT), f"dir:{rootfs}", "-o", "cyclonedx-json", "-q"],
                         capture_output=True, text=True, timeout=300)
    comps: dict[str, set[str]] = {}
    for c in json.loads(out.stdout).get("components", []):
        if c.get("type") in ("library", "application") and c.get("name"):
            comps.setdefault(c["name"], set()).add(str(c.get("version", "")))
    return comps


def syft_diff(declared: list[dict], seen: dict[str, set[str]]) -> set[tuple[str, str]]:
    """What a verifier built on Syft's inventory concludes about the declared BOM."""
    f = set()
    dn = {c["name"]: c["version"] for c in declared}
    for n, v in dn.items():
        if n not in seen:
            f.add(("absent", n))
        elif v not in seen[n]:
            f.add(("wrong_version", n))
    for n in seen:
        if n not in dn:
            f.add(("undeclared_component", n))
    return f


def bw_findings(rep: dict) -> set[tuple[str, str]]:
    return {(f["class"], f["component"]) for f in rep["findings"] if f["class"] in HARD}


def score(found: set, truth: set, noise: set) -> dict:
    """Findings already present on the unmodified image with a correct BOM are subtracted for both tools."""
    found = found - noise
    tp = len(found & truth)
    return {"tp": tp, "fp": len(found - truth), "fn": len(truth - found), "extra": sorted(found - truth)[:6]}


def run(image_id: str) -> dict:
    spec = json.loads((ROOT / "images.json").read_text())
    im = next(i for i in spec["images"] if i["id"] == image_id)
    clean = ROOT / "work/rootfs" / image_id
    cases_dir = ROOT / "work/cases" / image_id
    feed = Feed(spec["release"], im["target"], im["arch"], im["kmods"], ROOT / "work/cache/feed")
    old = Feed(OLD_RELEASE, im["target"], im["arch"], None, ROOT / "work/cache/feed")
    index, old_index = feed.index(), old.index()
    inst = opkgdb.installed(clean)
    truth_bom = [{"name": n, "version": r["Version"]} for n, r in inst.items()]
    rng = random.Random(20261127)

    t0 = time.time()
    clean_rep = verify(clean, truth_bom, feed, [old])
    clean_time = time.time() - t0
    bw_noise = bw_findings(clean_rep)          # hard findings on the unmodified image with a correct BOM
    t0 = time.time()
    syft_clean = syft_components(clean)
    syft_time = time.time() - t0
    syft_noise = syft_diff(truth_bom, syft_clean)
    stripped = mutate.clone(clean, cases_dir / "stripped"); mutate.db_strip(stripped)
    syft_stripped = syft_components(stripped)
    syft_noise_stripped = syft_diff(truth_bom, syft_stripped)

    with_files = sorted(n for n in inst if n in index and feed.payload(n)["files"])
    cases = []

    def case(kind, target, db, label, declared, rootfs, syft_seen):
        rep = verify(rootfs, declared, feed, [old])
        flagged = any(f["class"] in ("undeclared_component", "undeclared_file") for f in rep["findings"]
                      if (f["class"], f["component"]) not in bw_noise)
        cases.append({"kind": kind, "target": target, "db": db, "label": list(label),
                      "bomwitness": score(bw_findings(rep), {label}, bw_noise),
                      "bomwitness_flagged_undeclared_code": flagged,
                      "syft_diff": score(syft_diff(declared, syft_seen), {label},
                                         syft_noise_stripped if db == "stripped" else syft_noise)})

    # M1 omitted component: delete one entry from the BOM.
    for n in rng.sample(with_files, K):
        bom = [c for c in truth_bom if c["name"] != n]
        label = ("undeclared_component", n)
        case("M1_omitted", n, "honest", label, bom, clean, syft_clean)
        r = mutate.clone(clean, cases_dir / "case"); mutate.db_remove(r, n)
        case("M1_omitted", n, "colluding", label, bom, r, syft_components(r))
        case("M1_omitted", n, "stripped", label, bom, stripped, syft_stripped)

    # M2 wrong version: the BOM carries the previous major release's version of the package (a stale BOM).
    pool = sorted(n for n in inst if n in old_index and n in index
                  and upstream_token(old_index[n]["version"]) != upstream_token(inst[n]["Version"]))
    for n in rng.sample(pool, K):
        wrong = old_index[n]["version"]
        bom = [dict(c, version=wrong) if c["name"] == n else c for c in truth_bom]
        label = ("wrong_version", n)
        case("M2_wrong_version", n, "honest", label, bom, clean, syft_clean)
        r = mutate.clone(clean, cases_dir / "case"); mutate.db_set_version(r, n, wrong)
        case("M2_wrong_version", n, "colluding", label, bom, r, syft_components(r))
        case("M2_wrong_version", n, "stripped", label, bom, stripped, syft_stripped)

    # M2b wrong version, fabricated: last number of the version bumped by one (a version no feed ever shipped).
    def bump(v):
        import re
        m = list(re.finditer(r"\d+", v.split("~")[0].split("-r")[0]))
        if not m:
            return None
        e = m[-1]
        return v[:e.start()] + str(int(e.group()) + 1) + v[e.end():]
    for n in rng.sample(with_files, K):
        wrong = bump(inst[n]["Version"])
        if not wrong:
            continue
        bom = [dict(c, version=wrong) if c["name"] == n else c for c in truth_bom]
        label = ("wrong_version", n)
        case("M2b_fabricated_version", n, "honest", label, bom, clean, syft_clean)
        r = mutate.clone(clean, cases_dir / "case"); mutate.db_set_version(r, n, wrong)
        case("M2b_fabricated_version", n, "colluding", label, bom, r, syft_components(r))

    # M3 phantom component: the BOM lists a package that is not in the firmware.
    absent_pool = sorted(n for n in index if n not in inst and not n.startswith(("kmod-", "luci-i18n"))
                         and index[n]["url"].split("/")[-2] == "base")
    for n in rng.sample(absent_pool, K):
        if not feed.payload(n)["files"]:
            continue
        bom = truth_bom + [{"name": n, "version": index[n]["version"]}]
        label = ("absent", n)
        case("M3_phantom", n, "honest", label, bom, clean, syft_clean)
        r = mutate.clone(clean, cases_dir / "case")
        mutate.db_add(r, n, index[n]["version"], im["arch"], list(feed.payload(n)["files"]))
        case("M3_phantom", n, "colluding", label, bom, r, syft_components(r))

    # M4 implant: a real package's files are dropped into the firmware; BOM and database say nothing.
    cand = [n for n in rng.sample(absent_pool, 60)]
    done = 0
    for n in cand:
        pl = feed.payload(n)
        if done >= K or not any(m["elf"] for m in pl["files"].values()):
            continue
        r = mutate.clone(clean, cases_dir / "case")
        if not mutate.implant(r, feed.payload_members(n)):
            continue
        done += 1
        case("M4_implant", n, "unaware", ("undeclared_component", n), truth_bom, r, syft_components(r))

    # M5 swap: a declared component's binary is replaced by the older release's build; BOM and database unchanged.
    done = 0
    for n in rng.sample(pool, len(pool)):
        if done >= K:
            break
        new_pl, old_pl = feed.payload(n), old.payload(n)
        shared = [p for p, m in new_pl["files"].items() if m["elf"] and p in old_pl["files"]
                  and old_pl["files"][p]["sha256"] != m["sha256"] and (clean / p).is_file()]
        if not shared:
            continue
        r = mutate.clone(clean, cases_dir / "case")
        for p in shared:
            (r / p).write_bytes(old.file_bytes(n, p))
        done += 1
        case("M5_swapped_binary", n, "unaware", ("wrong_version", n), truth_bom, r, syft_components(r))

    # M6 patch: one byte of a declared component's binary is changed; BOM and database unchanged.
    verified = [c["name"] for c in clean_rep["components"] if c["verdict"] == "verified_A"
                and any(m["elf"] for m in feed.payload(c["name"])["files"].values())]
    for n in rng.sample(sorted(verified), K):
        p = next(p for p, m in feed.payload(n)["files"].items() if m["elf"])
        r = mutate.clone(clean, cases_dir / "case")
        blob = bytearray((r / p).read_bytes()); blob[len(blob) // 2] ^= 0x01; (r / p).write_bytes(bytes(blob))
        case("M6_patched_binary", n, "unaware", ("bytes_differ", n), truth_bom, r, syft_components(r))

    shutil.rmtree(cases_dir, ignore_errors=True)

    def agg(rows, tool):
        tp = sum(r[tool]["tp"] for r in rows); fp = sum(r[tool]["fp"] for r in rows); fn = sum(r[tool]["fn"] for r in rows)
        return {"cases": len(rows), "tp": tp, "fp": fp, "fn": fn,
                "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                "recall": round(tp / (tp + fn), 3) if tp + fn else None,
                **({"flagged_as_undeclared_code": sum(1 for r in rows if r["bomwitness_flagged_undeclared_code"])}
                   if tool == "bomwitness" and rows and rows[0]["kind"] == "M4_implant" else {})}

    table = {}
    for kind in sorted({c["kind"] for c in cases}):
        for db in ("honest", "colluding", "stripped", "unaware"):
            rows = [c for c in cases if c["kind"] == kind and c["db"] == db]
            if rows:
                table[f"{kind}/{db}"] = {"bomwitness": agg(rows, "bomwitness"), "syft_diff": agg(rows, "syft_diff")}
    overall = {db: {"bomwitness": agg([c for c in cases if c["db"] == db], "bomwitness"),
                    "syft_diff": agg([c for c in cases if c["db"] == db], "syft_diff")}
               for db in ("honest", "colluding", "stripped", "unaware")}
    overall["all"] = {"bomwitness": agg(cases, "bomwitness"), "syft_diff": agg(cases, "syft_diff")}
    return {
        "image": im, "release": spec["release"], "old_release_for_mutations": OLD_RELEASE, "seed": 20261127,
        "clean_control": {"summary": clean_rep["summary"], "hard_findings": sorted(bw_noise),
                          "review_tier": {k: sum(1 for f in clean_rep["findings"] if f["class"] == k)
                                          for k in ("label_mismatch", "stale", "undeclared_file")},
                          "verify_seconds": round(clean_time, 2),
                          "syft_seconds": round(syft_time, 2), "syft_components": len(syft_clean),
                          "syft_components_db_stripped": len(syft_stripped),
                          "syft_diff_findings_on_correct_bom": len(syft_noise),
                          "syft_diff_findings_on_correct_bom_db_stripped": len(syft_noise_stripped),
                          "syft_diff_findings_on_correct_bom_sample": sorted(syft_noise)[:8]},
        "by_class": table, "overall": overall, "cases": cases,
        "reference_packages_fetched": len(list((feed.cache / "payload").glob("*.json"))),
    }


if __name__ == "__main__":
    out = ROOT / "results/spike-r1"
    out.mkdir(parents=True, exist_ok=True)
    for image_id in sys.argv[1:]:
        t = time.time()
        res = run(image_id)
        (out / f"{image_id}.json").write_text(json.dumps(res, indent=1))
        print(image_id, round(time.time() - t), "s")
        print(" clean:", json.dumps(res["clean_control"]))
        for k, v in res["by_class"].items():
            print(f" {k:32s} BW {v['bomwitness']}  | SYFT {v['syft_diff']}")
        print(" overall:", json.dumps(res["overall"]))
