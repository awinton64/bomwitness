"""Post-freeze analysis of the committed results, written after an independent review of the paper.

Nothing is rerun and no rule is touched: every figure below is recomputed from files that were already
committed under results/r2/ (the per-image case files, official-bom.json, inventory.json). The review asked
for facts the first summary did not state:

  1. how many distinct seeded errors there are (the honest, colluding and stripped rows repeat the same error);
  2. how much recall varies from image to image (errors on one image are not independent);
  3. what BomTrace and the Syft-based diff actually returned in the stripped condition;
  4. the full verdict totals for OpenWrt's published BOMs;
  5. both denominators of the inventory measurement;
  6. what the timing columns measure.

Usage: python bench/review_r3.py            writes results/r2/review-r3.json
       python bench/review_r3.py --check    fails if the committed file differs from a recomputation
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results/r2"
OUT = RES / "review-r3.json"
BW = ("bw_feed_only", "bw_no_snapshot", "bw")
BOM_LEVEL = ("honest", "colluding", "stripped")


def med(xs: list[float]) -> float:
    xs = sorted(xs)
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def build() -> dict:
    docs = {p.stem: json.loads(p.read_text()) for p in sorted((RES / "cases").glob("*.json"))}
    out: dict = {"note": "post-freeze analysis of committed result files; nothing was rerun (bench/review_r3.py)"}

    # 1. distinct seeded errors against condition rows
    for split, prefix in (("heldout", "h-"), ("tuning", "t-")):
        rows = [(iid, c) for iid, d in docs.items() if iid.startswith(prefix) for c in d["cases"]]
        bom_err = {(iid, c["kind"], c["target"]) for iid, c in rows if c["db"] in BOM_LEVEL}
        unaware = {(iid, c["kind"], c["target"]) for iid, c in rows if c["db"] == "unaware"}
        per_db = {db: sum(1 for _i, c in rows if c["db"] == db) for db in (*BOM_LEVEL, "unaware")}
        assert all(per_db[db] == len(bom_err) for db in BOM_LEVEL) and per_db["unaware"] == len(unaware)
        out.setdefault("distinct_errors", {})[split] = {
            "images": len({iid for iid, _c in rows}), "condition_rows": len(rows), "rows_by_database_condition": per_db,
            "distinct_bom_level_errors": len(bom_err), "distinct_unaware_errors": len(unaware),
            "distinct_errors": len(bom_err) + len(unaware),
            "how": "a BOM-level error (M1 to M3) is one (image, class, component) scored under three database states; "
                   "an unaware error (M4 to M6) is scored once",
        }
        # BOMwitness never reads the database, so its answer per distinct BOM-level error must not depend on the row.
        for tool in BW:
            by = {}
            for iid, c in rows:
                if c["db"] in BOM_LEVEL:
                    by.setdefault((iid, c["kind"], c["target"]), set()).add(c["tools"][tool]["tp"])
            assert all(len(v) == 1 for v in by.values()), tool

    # 2. recall per held-out image: the unit of variability is the image, not the case
    held = {iid: d for iid, d in docs.items() if iid.startswith("h-")}
    var: dict = {}
    for cond, dbs in (("bom_level", ("colluding",)), ("unaware", ("unaware",))):
        for tool in BW:
            per = {}
            for iid, d in held.items():
                rows = [c for c in d["cases"] if c["db"] in dbs]
                per[iid] = {"found": sum(c["tools"][tool]["tp"] for c in rows), "errors": len(rows)}
            rec = [v["found"] / v["errors"] for v in per.values()]
            var.setdefault(cond, {})[tool] = {
                "per_image": per, "min": round(min(rec), 3), "median": round(med(rec), 3), "max": round(max(rec), 3),
                "images_with_every_error_found": sum(1 for r in rec if r == 1.0), "images": len(rec),
                "pooled_found": sum(v["found"] for v in per.values()), "pooled_errors": sum(v["errors"] for v in per.values()),
            }
    out["recall_per_heldout_image"] = var

    # 3. what the baselines returned without a database
    rows = [c for d in held.values() for c in d["cases"]]
    bt = {db: {"rows": sum(1 for c in rows if c["db"] == db),
               "verifier_produced_a_result": sum(1 for c in rows if c["db"] == db and c["bomtrace_ran"]),
               "labels_found": sum(c["tools"]["bomtrace"]["tp"] for c in rows if c["db"] == db)} for db in (*BOM_LEVEL, "unaware")}
    sy_str = {}
    for c in rows:
        if c["db"] == "stripped":
            k = sy_str.setdefault(c["kind"], {"rows": 0, "credited": 0})
            k["rows"] += 1
            k["credited"] += c["tools"]["syft_diff"]["tp"]
    clean_err = {iid: d["clean_control"]["stripped"].get("bomtrace_error") for iid, d in held.items()}
    out["baselines_without_database"] = {
        "bomtrace": bt,
        "bomtrace_clean_control_stripped_ran": sum(1 for d in held.values() if d["clean_control"]["stripped"].get("bomtrace_ran")),
        "bomtrace_error_messages_stripped_clean_control": sorted({str(e)[:160] for e in clean_err.values()}),
        "syft_diff_stripped_by_class": sy_str,
        "syft_diff_stripped_credited_total": sum(v["credited"] for v in sy_str.values()),
        "syft_diff_clean_findings_stripped": {"min": min(len(d["clean_control"]["stripped"]["findings"]["syft_diff"]) for d in held.values()),
                                              "max": max(len(d["clean_control"]["stripped"]["findings"]["syft_diff"]) for d in held.values())},
        "syft_diff_clean_findings_honest": {"min": min(len(d["clean_control"]["honest"]["findings"]["syft_diff"]) for d in held.values()),
                                            "max": max(len(d["clean_control"]["honest"]["findings"]["syft_diff"]) for d in held.values())},
    }

    # 4. OpenWrt's published BOMs: every verdict, so the totals add up
    ob = json.loads((RES / "official-bom.json").read_text())
    verdicts: dict[str, int] = {}
    for v in ob.values():
        for k, n in v["verdicts"].items():
            verdicts[k] = verdicts.get(k, 0) + n
    claims = sum(v["bom_components"] for v in ob.values())
    assert sum(verdicts.values()) == claims
    wrong = [x for v in ob.values() for x in v["not_verified"] if x["verdict"] == "wrong_version"]
    kernel_only = [x for x in wrong if x["name"].startswith("kmod-")
                   and any(pre + x["declared_version"] + sep in x["reason"] for sep in (".", "+")
                           # the committed result file has the first wording; the tool now writes the second
                           for pre in ("bytes are the reference build ", "the files present match the reference build "))]
    differ = sorted({x["name"] for v in ob.values() for x in v["not_verified"] if x["verdict"] == "bytes_differ"})
    out["official_bom"] = {
        "images": len(ob), "claims": claims, "verdicts": dict(sorted(verdicts.items())),
        "verified": verdicts.get("verified_A", 0) + verdicts.get("verified_B", 0),
        "wrong_version_where_the_reference_label_extends_the_declared_one": len(kernel_only),
        "wrong_version_total": len(wrong), "bytes_differ_components": differ,
        "note": "a wrong_version here is a label-granularity disagreement: the BOM gives the kernel version, the frozen feed labels "
                "the same package with the kernel version followed by the driver version. No database-reading verifier was run on "
                "these BOMs; bench/official_bom.py uses the device database only to confirm that packages beyond the BOM are installed.",
    }

    # 5. inventory from bytes alone: both denominators
    inv = json.loads((RES / "inventory.json").read_text())
    out["inventory"] = {
        "images": len(inv),
        "installed_packages": sum(v["installed_packages"] for v in inv.values()),
        "installed_packages_owning_a_regular_file": sum(v["installed_packages_with_files"] for v in inv.values()),
        "named": sum(v["correct_names"] for v in inv.values()),
        "wrong_names": sum(len(v["extra"]) for v in inv.values()),
        "note": "the measurement is eligible-package recall: a package counts only if the device database lists at least one regular, "
                "non-symlink file for it that is in the image; packages without such a file cannot be named from bytes",
    }
    out["inventory"]["installed_packages_without_such_a_file"] = out["inventory"]["installed_packages"] - out["inventory"]["installed_packages_owning_a_regular_file"]

    # 6. what the committed timing numbers are
    out["timing"] = {
        "bomwitness_seconds_median_per_image": {iid: d["seconds_median"]["bw"] for iid, d in held.items()},
        "bomtrace_seconds_median_per_image": {iid: d["seconds_median"]["bomtrace"] for iid, d in held.items()},
        "syft_seconds_median_per_image": {iid: d["seconds_median"]["syft"] for iid, d in held.items()},
        "what_is_timed": {
            "bomwitness": "one in-process call of verify() per case with the root filesystem already unpacked and hashed and the reference "
                          "cache warm (bench/run_cases.py, bw_all); unpacking, hashing and reference downloads are outside the timer",
            "bomtrace": "wall time of one run of its command line per case, including process start, writing the input BOM and archive, "
                        "and, in the stripped condition, an immediate exit with no result",
            "syft": "wall time of one Syft run over the unpacked directory",
        },
        "comparable": False,
        "end_to_end": "see results/r2/timing-e2e.json for the command-line run of the repository example, measured separately",
    }
    return out


def main() -> int:
    text = json.dumps(build(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("results/r2/review-r3.json is stale")
            return 1
        print("results/r2/review-r3.json is current")
        return 0
    OUT.write_text(text)
    d = json.loads(text)
    print("distinct held-out errors:", d["distinct_errors"]["heldout"]["distinct_errors"], "in", d["distinct_errors"]["heldout"]["condition_rows"], "rows")
    print("official BOM verdicts:", d["official_bom"]["verdicts"])
    print("inventory:", {k: v for k, v in d["inventory"].items() if k != "note"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
