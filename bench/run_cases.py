"""Seeded-error benchmark on one official image: BOMwitness (with ablations) against three baselines.

Usage: run_cases.py <image-id> [--k 12] [--out results/r2/cases] [--no-baselines]

Every case is one mutation with one ground-truth label (class, component). `db` says what happened to the
device's own package database: honest (untouched), colluding (edited to agree with the wrong BOM), stripped
(removed), or unaware (the firmware changed and neither BOM nor database mentions it).

Scoring. Each tool's findings on the unmodified image with a correct BOM are its clean-control false alarms.
They are reported per image and counted once per image and database condition in the pooled precision
(bench/summarize.py). Inside a case they are subtracted, so a case's false positives are the findings that
the mutation itself caused beyond its label.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import time
from pathlib import Path

from bomwitness import devicedb, mutate
from bomwitness.elfinfo import upstream_token
from bomwitness.reference import Reference
from bomwitness.verify import HARD, scan_rootfs, verify

import baselines

ROOT = Path(__file__).resolve().parent.parent
SEED = 20261127
OTHER = {"24.10.8": "23.05.6", "23.05.6": "24.10.8"}
DB_CLASSES = ("absent", "wrong_version", "undeclared_component")


def bw_configs(manifest, snaps) -> dict[str, dict]:
    return {
        "bw": dict(manifest=manifest, snapshots=snaps),
        "bw_no_snapshot": dict(manifest=manifest),
        "bw_feed_only": dict(),
        "bw_A_only": dict(manifest=manifest, snapshots=snaps, use_markers=False),
        "bw_B_only": dict(use_hashes=False),
        "bw_no_normalize": dict(manifest=manifest, snapshots=snaps, normalize_timestamps=False),
    }


def hard(rep: dict) -> set[tuple[str, str]]:
    return {(f["class"], f["component"]) for f in rep["findings"] if f["class"] in HARD}


def run(image_id: str, k: int, out_dir: Path, use_baselines: bool) -> dict:
    spec = json.loads((ROOT / "bench/images.json").read_text())
    im = next(i for i in spec["images"] if i["id"] == image_id)
    clean = ROOT / "work/rootfs" / image_id
    cases_dir = ROOT / "work/cases" / image_id
    ref = Reference(im["release"], im["target"], ROOT / "work/cache")
    alt = Reference(OTHER[im["release"]], im["target"], ROOT / "work/cache")
    index, alt_index = ref.index(), alt.index()
    manifest = ref.manifest()
    snap_path = ROOT / "work/snapshots" / f"{image_id}.json"
    snaps = [json.loads(snap_path.read_text())] if snap_path.exists() else []
    configs = bw_configs(manifest, snaps)
    inst = devicedb.installed(clean)
    truth = [{"name": n, "version": r["Version"]} for n, r in inst.items()]
    arch = ref.arch
    cvebin = baselines.CveBin(ROOT / "work/baselines" / f"cvebin-cache-{image_id}.json") if use_baselines else None
    timing = {"bw": [], "syft": [], "cvebin": [], "bomtrace": []}

    def bw_all(rootfs: Path, declared: list[dict]) -> tuple[dict[str, set], dict]:
        files = scan_rootfs(rootfs)
        out, default_rep = {}, None
        for name, kw in configs.items():
            t = time.time()
            rep = verify(rootfs, declared, ref, [alt], files=files, **kw)
            if name == "bw":
                timing["bw"].append(time.time() - t)
                default_rep = rep
            out[name] = hard(rep)
        db = devicedb.compare(rootfs, declared, default_rep["components"])
        out["bw_with_db"] = out["bw"] | {(f["class"], f["component"]) for f in db["findings"] if f["class"] in DB_CLASSES}
        return out, default_rep

    def tool_views(rootfs: Path) -> dict:
        """Tree-level outputs of the baselines that do not depend on the declared BOM."""
        if not use_baselines:
            return {}
        t = time.time(); s = baselines.syft_components(rootfs); timing["syft"].append(time.time() - t)
        t = time.time(); c = cvebin.scan(rootfs); timing["cvebin"].append(time.time() - t)
        return {"syft": s, "cvebin": c}

    def base_all(rootfs: Path, declared: list[dict], views: dict) -> dict[str, set]:
        if not use_baselines:
            return {}
        t = time.time(); bt = baselines.bomtrace(declared, rootfs); timing["bomtrace"].append(time.time() - t)
        return {"syft_diff": baselines.syft_diff(declared, views["syft"]),
                "cvebin_diff": baselines.cvebin_diff(declared, views["cvebin"]),
                "bomtrace": bt["findings"], "_bomtrace_ran": bt["ran"], "_bomtrace_error": bt["error"]}

    # ---- clean controls ----------------------------------------------------------------------------------
    stripped = mutate.clone(clean, cases_dir / "stripped"); mutate.db_strip(stripped)
    views = {"honest": tool_views(clean), "stripped": tool_views(stripped)}
    noise, control = {}, {}
    for cond, tree in (("honest", clean), ("stripped", stripped)):
        bw, rep = bw_all(tree, truth)
        base = base_all(tree, truth, views[cond])
        noise[cond] = {**bw, **{t: v for t, v in base.items() if not t.startswith("_")}}
        control[cond] = {"findings": {t: sorted(map(list, v)) for t, v in noise[cond].items()},
                         "bomtrace_ran": base.get("_bomtrace_ran"), "bomtrace_error": base.get("_bomtrace_error")}
        if cond == "honest":
            clean_rep = rep
            control["summary"] = rep["summary"]
            control["review_tier"] = {c: sum(1 for f in rep["findings"] if f["class"] == c) for c in ("label_unconfirmed", "stale")}
            control["verdicts_by_config"] = {}
            files = scan_rootfs(tree)
            for name, kw in configs.items():
                control["verdicts_by_config"][name] = verify(tree, truth, ref, [alt], files=files, **kw)["summary"]["verdicts"]
            control["label_sources"] = {}
            for c in rep["components"]:
                if c["verdict"] == "verified_A":
                    control["label_sources"][c.get("label_source", "?")] = control["label_sources"].get(c.get("label_source", "?"), 0) + 1
            control["unverifiable_reasons"] = {}
            for c in rep["components"]:
                if c["verdict"] == "unverifiable":
                    control["unverifiable_reasons"][c["reason"]] = control["unverifiable_reasons"].get(c["reason"], 0) + 1
            control["not_verified"] = [{"name": c["name"], "verdict": c["verdict"], "reason": c["reason"]}
                                       for c in rep["components"] if not c["verdict"].startswith("verified")]
            control["syft_components"] = len(views["honest"].get("syft", {}))
            control["cvebin_products"] = sorted(views["honest"].get("cvebin", {}))
        else:
            control["syft_components_db_stripped"] = len(views["stripped"].get("syft", {}))
    cases = []

    def case(kind: str, target: str, db: str, label: tuple[str, str], declared: list[dict], rootfs: Path, view: dict | None,
             implanted: list[str] = ()):
        ncond = "stripped" if db == "stripped" else "honest"
        bw, rep = bw_all(rootfs, declared)
        if view is None:
            view = tool_views(rootfs)
        base = base_all(rootfs, declared, view)
        row = {"kind": kind, "target": target, "db": db, "label": list(label), "tools": {}}
        for tool, found in {**bw, **base}.items():
            if tool.startswith("_"):
                continue
            extra = found - noise[ncond].get(tool, set())
            hit = label in extra or (tool == "cvebin_diff" and baselines.cvebin_label_match(extra, label))
            fp = extra - {label}
            # A file the mutation really implanted, flagged as unaccounted code, is a correct finding that lacks
            # the package name. It does not earn the label (recall stays strict) and is not a false positive.
            flagged = {f for f in fp if f[0] == "undeclared_file" and f[1] in implanted}
            fp = fp - flagged
            if tool == "bw":
                row["bw_implanted_files_flagged"] = len(flagged)
            if tool == "cvebin_diff" and hit:
                fp = {f for f in fp if not baselines.cvebin_label_match({f}, label)}
            row["tools"][tool] = {"tp": int(hit), "fp": len(fp), "extra": sorted(map(list, fp))[:6]}
        row["bw_alternative_named"] = any(f["class"] == label[0] and label[1] in f.get("alternatives", []) for f in rep["findings"])
        row["bw_flagged_undeclared_code"] = any(f["class"] in ("undeclared_component", "undeclared_file") for f in rep["findings"]
                                                if (f["class"], f["component"]) not in noise[ncond]["bw"])
        row["bw_verdict_for_target"] = next((c["verdict"] for c in rep["components"] if c["name"] == target), None)
        row["bw_reason_for_target"] = next((c.get("reason") for c in rep["components"] if c["name"] == target), None)
        row["bomtrace_ran"] = base.get("_bomtrace_ran")
        cases.append(row)

    def three_db(kind, n, label, bom, collude):
        case(kind, n, "honest", label, bom, clean, views["honest"])
        r = mutate.clone(clean, cases_dir / "case"); collude(r)
        case(kind, n, "colluding", label, bom, r, None)
        case(kind, n, "stripped", label, bom, stripped, views["stripped"])

    def rng_for(kind: str) -> random.Random:
        return random.Random(f"{SEED}:{image_id}:{kind}")

    with_files = sorted(n for n in inst if n in index and any(p for p in ref.payload(n)["files"] if (clean / p).is_file()))

    # M1 omitted component: delete one entry from the BOM.
    for n in rng_for("M1").sample(with_files, min(k, len(with_files))):
        bom = [c for c in truth if c["name"] != n]
        three_db("M1_omitted", n, ("undeclared_component", n), bom, lambda r, n=n: mutate.db_remove(r, n))

    # M2 version from the other release series: a stale BOM (24.10 image, 23.05 label) or an optimistic one (the reverse).
    pool = sorted(n for n in with_files if n in alt_index
                  and upstream_token(alt_index[n]["version"]) != upstream_token(inst[n]["Version"]))
    for n in rng_for("M2").sample(pool, min(k, len(pool))):
        wrong = alt_index[n]["version"]
        bom = [dict(c, version=wrong) if c["name"] == n else c for c in truth]
        three_db("M2_other_release_version", n, ("wrong_version", n), bom, lambda r, n=n, w=wrong: mutate.db_set_version(r, n, w))

    # M2b fabricated version: last number of the version bumped by one (a version no feed ever shipped).
    def bump(v: str) -> str | None:
        m = list(re.finditer(r"\d+", v.split("~")[0].split("-r")[0]))
        if not m:
            return None
        e = m[-1]
        return v[:e.start()] + str(int(e.group()) + 1) + v[e.end():]
    done = 0
    for n in rng_for("M2b").sample(with_files, len(with_files)):
        wrong = bump(inst[n]["Version"])
        if done >= k or not wrong:
            continue
        done += 1
        bom = [dict(c, version=wrong) if c["name"] == n else c for c in truth]
        three_db("M2b_fabricated_version", n, ("wrong_version", n), bom, lambda r, n=n, w=wrong: mutate.db_set_version(r, n, w))

    # M3 phantom component: the BOM lists a package that is not in the firmware.
    absent_pool = sorted(n for n, r in index.items() if n not in inst and r["feed"] == "base"
                         and not n.startswith(("kmod-", "luci-i18n")) and r["size"] <= 4 << 20)
    done = 0
    for n in rng_for("M3").sample(absent_pool, len(absent_pool)):
        if done >= k:
            break
        pl = ref.payload(n)
        if not pl["files"]:
            continue
        done += 1
        bom = truth + [{"name": n, "version": index[n]["version"]}]
        three_db("M3_phantom", n, ("absent", n), bom,
                 lambda r, n=n, pl=pl: mutate.db_add(r, n, index[n]["version"], arch, list(pl["files"])))

    # M4 implant: a real package's files are dropped into the firmware; BOM and database say nothing.
    def implants(kind: str, names: list[str], limit: int):
        done = 0
        for n in names:
            if done >= limit:
                break
            pl = ref.payload(n)
            if not any(m["elf"] for m in pl["files"].values()):
                continue
            r = mutate.clone(clean, cases_dir / "case")
            written = mutate.implant(r, ref.members(n))
            if not written:
                continue
            done += 1
            case(kind, n, "unaware", ("undeclared_component", n), truth, r, None, implanted=written)
    implants("M4_implant", rng_for("M4").sample(absent_pool, len(absent_pool)), k)
    extra_pool = sorted(n for n, r in index.items() if n not in inst and r["feed"] == "packages" and 20_000 <= r["size"] <= 1_500_000
                        and not n.startswith(("luci-", "python3", "perl", "php", "ruby", "node", "golang", "kmod-")))
    implants("M4u_implant_unindexed_feed", rng_for("M4u").sample(extra_pool, min(40, len(extra_pool))), max(k // 2, 1))

    # M5 swap: a declared component's binary is replaced by the other release's build; BOM and database unchanged.
    done = 0
    for n in rng_for("M5").sample(pool, len(pool)):
        if done >= k:
            break
        new_pl, old_pl = ref.payload(n), alt.payload(n)
        shared = [p for p, m in new_pl["files"].items() if m["elf"] and p in old_pl["files"]
                  and old_pl["files"][p]["sha256"] != m["sha256"] and (clean / p).is_file()]
        if not shared:
            continue
        r = mutate.clone(clean, cases_dir / "case")
        for p in shared:
            (r / p).write_bytes(alt.file_bytes(n, p))
        done += 1
        case("M5_swapped_binary", n, "unaware", ("wrong_version", n), truth, r, None)

    # M6 patch: one byte of a declared component's binary is changed; BOM and database unchanged.
    verified = sorted(c["name"] for c in clean_rep["components"] if c["verdict"] == "verified_A" and c.get("package")
                      and any(m["elf"] and (clean / p).is_file() for p, m in ref.payload(c["package"])["files"].items()))
    for n in rng_for("M6").sample(verified, min(k, len(verified))):
        pkg = next(c["package"] for c in clean_rep["components"] if c["name"] == n)
        p = next(p for p, m in sorted(ref.payload(pkg)["files"].items()) if m["elf"] and (clean / p).is_file())
        r = mutate.clone(clean, cases_dir / "case")
        blob = bytearray((r / p).read_bytes()); blob[len(blob) // 2] ^= 0x01; (r / p).write_bytes(bytes(blob))
        case("M6_patched_binary", n, "unaware", ("bytes_differ", n), truth, r, None)

    shutil.rmtree(cases_dir, ignore_errors=True)

    def med(xs):
        xs = sorted(xs)
        return round(xs[len(xs) // 2], 3) if xs else None

    res = {"image": im, "seed": SEED, "k": k, "arch": arch, "declared_components": len(truth),
           "reference": ref.provenance(), "alt_release": alt.release,
           "snapshot": snaps[0]["source"] if snaps else None, "bomtrace_commit": baselines.bomtrace_commit() if use_baselines else None,
           "clean_control": control, "cases": cases,
           "seconds_median": {t: med(v) for t, v in timing.items()}, "runs": {t: len(v) for t, v in timing.items()}}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{image_id}.json").write_text(json.dumps(res, indent=1))
    return res


def brief(res: dict) -> None:
    tools = sorted({t for c in res["cases"] for t in c["tools"]})
    print(res["image"]["id"], "clean:", json.dumps(res["clean_control"]["summary"]))
    print("  clean hard findings (bw):", res["clean_control"]["findings"]["bw"] if "findings" in res["clean_control"] else
          res["clean_control"]["honest"]["findings"]["bw"])
    for db in ("honest", "colluding", "stripped", "unaware"):
        rows = [c for c in res["cases"] if c["db"] == db]
        line = []
        for t in tools:
            tp = sum(c["tools"][t]["tp"] for c in rows); fp = sum(c["tools"][t]["fp"] for c in rows)
            line.append(f"{t} R={tp}/{len(rows)} FP={fp}")
        print(f"  {db:9s}", " | ".join(line))
    for kind in sorted({c["kind"] for c in res["cases"]}):
        rows = [c for c in res["cases"] if c["kind"] == kind and c["db"] in ("colluding", "unaware")]
        print(f"  {kind:28s} bw {sum(c['tools']['bw']['tp'] for c in rows)}/{len(rows)}",
              "misses:", [c["target"] + ":" + str(c["bw_verdict_for_target"]) for c in rows if not c["tools"]["bw"]["tp"]][:8],
              "fp:", [c["tools"]["bw"]["extra"] for c in rows if c["tools"]["bw"]["fp"]][:4])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image_id")
    ap.add_argument("--k", type=int, default=12)
    ap.add_argument("--out", default="results/r2/cases")
    ap.add_argument("--no-baselines", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    res = run(a.image_id, a.k, ROOT / a.out, not a.no_baselines)
    brief(res)
    print("  seconds", round(time.time() - t0), res["seconds_median"])
