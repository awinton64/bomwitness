"""Generate results/r2/HEADLINE.md: the numbers that the README quotes, computed from the committed result files.

The README carries this block between <!-- headline:start --> and <!-- headline:end -->;
tests/test_docs.py fails when the two differ. Usage: headline.py [results-dir]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def pr(m: dict | None, unsupported: bool = False) -> str:
    if not m:
        return "n/a"
    if unsupported:
        return f"unsupported input, 0 labels returned (0/{m['cases']})"
    p = "n/a" if m["precision"] is None else f"{m['precision']:.3f}"
    return f"{p} / {m['recall']:.3f} ({m['tp']}/{m['cases']})"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if not n:
        return 0.0, 0.0
    phat = k / n
    den = 1 + z * z / n
    mid = (phat + z * z / (2 * n)) / den
    half = z * ((phat * (1 - phat) / n + z * z / (4 * n * n)) ** 0.5) / den
    return mid - half, mid + half


def build(res: Path) -> str:
    s = json.loads((res / "summary.json").read_text())
    h, t = s["splits"]["heldout"], s["splits"]["tuning"]
    run = json.loads((res / "RUN.json").read_text())
    archs = sorted({im["arch"] for im in h["clean"]["images"].values()})
    rv = json.loads((res / "review-r3.json").read_text())
    de = rv["distinct_errors"]["heldout"]
    L = [f"Held-out set: {len(h['images'])} official OpenWrt images (23.05.6 and 24.10.8, {len(archs)} package architectures), "
         f"{de['distinct_errors']} distinct seeded errors scored in {h['cases']} condition rows (each of the {de['distinct_bom_level_errors']} BOM-level errors "
         f"is scored under three database states, each of the {de['distinct_unaware_errors']} unaware errors once). "
         f"The verdict rules were frozen at commit `{run['commit'][:7]}` (tag `rules-frozen-r2a`) before the held-out images were scored in this primary evaluation; "
         f"the other measurements below were made afterwards. Cells are precision / recall (found/rows).", "",
         "| Device database | Cases | BOMwitness | BOMwitness, no sibling snapshot | BOMwitness, feeds only | BomTrace | Syft-diff | cve-bin-tool-diff |",
         "|---|---|---|---|---|---|---|---|"]
    names = {"honest": "honest (untouched, BOM wrong)", "colluding": "colluding (edited to agree with the BOM)", "stripped": "stripped (removed)",
             "unaware": "unaware (firmware changed, BOM and database silent)", "all": "all"}
    for db in ("honest", "colluding", "stripped", "unaware", "all"):
        row = h["by_db"][db]
        bt_ran = rv["baselines_without_database"]["bomtrace"].get(db, {}).get("verifier_produced_a_result", 1)
        L.append(f"| {names[db]} | {row['bw']['cases']} | {pr(row['bw'])} | {pr(row['bw_no_snapshot'])} | {pr(row['bw_feed_only'])} | "
                 f"{pr(row.get('bomtrace'), unsupported=not bt_ran)} | {pr(row.get('syft_diff'))} | {pr(row.get('cvebin_diff'))} |")
    col, una = h["by_db"]["colluding"]["bw"], h["by_db"]["unaware"]["bw"]
    (c_lo, c_hi), (u_lo, u_hi) = wilson(col["tp"], col["cases"]), wilson(una["tp"], una["cases"])
    L += ["", f"- BOMwitness recall with 95% Wilson intervals: colluding and stripped {col['recall']:.3f} [{c_lo:.3f}, {c_hi:.3f}], "
              f"unaware {una['recall']:.3f} [{u_lo:.3f}, {u_hi:.3f}]. Lowest recall on any single held-out image: "
              f"{col['recall_per_image_min']:.3f} (colluding), {una['recall_per_image_min']:.3f} (unaware). The honest, colluding and stripped "
              f"rows are the same {col['cases']} errors with three database states, not {3 * col['cases']} independent cases. The intervals treat errors as "
              f"independent, which errors on one image are not, so read them as a description of these cases; the unit that varies is the image."]
    pv = rv["recall_per_heldout_image"]
    def rng(cond, tool):
        v = pv[cond][tool]
        return f"{v['min']:.3f} to {v['max']:.3f} (median {v['median']:.3f})"
    L += [f"- Recall per held-out image, lowest to highest over the {len(h['images'])} images. BOM-level errors: feeds only {rng('bom_level', 'bw_feed_only')}, "
          f"with the manifest {rng('bom_level', 'bw_no_snapshot')}, with the sibling {rng('bom_level', 'bw')}. Unaware errors: without the sibling "
          f"{rng('unaware', 'bw_no_snapshot')}, with it {rng('unaware', 'bw')}."]
    bwd = rv["baselines_without_database"]
    L += [f"- Baselines without a database, stated exactly. BomTrace needs the package database as input: in all {bwd['bomtrace']['stripped']['rows']} stripped rows its "
          f"verifier exited without a result (unsupported input), which is different from running and finding nothing; with a colluding database it ran in all "
          f"{bwd['bomtrace']['colluding']['verifier_produced_a_result']} rows and returned no label. The Syft-based diff, with no inventory to compare, reports every declared "
          f"component as absent: that credits it with the {bwd['syft_diff_stripped_credited_total']} phantom rows and with none of the other "
          f"{sum(v['rows'] for v in bwd['syft_diff_stripped_by_class'].values()) - bwd['syft_diff_stripped_credited_total']}, at the cost of "
          f"{bwd['syft_diff_clean_findings_stripped']['min']} to {bwd['syft_diff_clean_findings_stripped']['max']} findings per clean image. With an honest database its "
          f"{bwd['syft_diff_clean_findings_honest']['min']} to {bwd['syft_diff_clean_findings_honest']['max']} clean findings per image are naming differences in our diff script "
          f"(Syft also lists kernel modules as components), a penalty of the adapter and not of Syft."]
    c = h["clean"]["totals"]
    L += [f"- Clean controls (held-out images, correct BOM): {c['declared']} declared components, "
              f"{c['verdicts'].get('verified_A', 0)} verified at grade A ({c['verified_A_share']:.1%}), {c['verdicts'].get('verified_B', 0)} by version marker, "
              f"{c['verdicts'].get('unverifiable', 0)} unverifiable, {c['bw_hard']} false alarms ({c['clean_false_alarm_rate_per_declared_component']:.2%} of declared components). "
              f"{c['accounted']} of {c['files']} files and {c['code'] - c['orphan_code']} of {c['code']} executables accounted for. Grade A is the tool's verdict under its rules "
              f"(the package's files that are present match the publisher's build; configuration files and build-time strings are tolerated), not a proof that a package is complete."]
    b, g = h["by_db"]["colluding"], h["by_db"]["all"]
    L.append(f"- Ablations on the colluding condition: grade A only {pr(b['bw_A_only'])}; grade B only {pr(b['bw_B_only'])}; "
             f"with the device database shown as grade C, honest condition {pr(h['by_db']['honest']['bw_with_db'])}.")
    mg = h["errors"]["miss_groups"]
    L.append(f"- BOMwitness misses on the held-out set: {sum(mg.values())} distinct cases. " + "; ".join(f"{k} ({n})" for k, n in mg.items()) +
             f". Case-level false positives: {len(h['errors']['false_positives'])}.")
    L.append(f"- Tuning set ({len(t['images'])} images, {t['cases']} cases), for comparison: BOMwitness colluding {pr(t['by_db']['colluding']['bw'])}, "
             f"unaware {pr(t['by_db']['unaware']['bw'])}.")
    far = res / "far-sibling/summary.json"
    if far.exists():
        f = json.loads(far.read_text())["splits"]["heldout"]
        L.append(f"- With the least similar sibling instead of the most similar one ({len(f['images'])} held-out images that have siblings): "
                 f"colluding {pr(f['by_db']['colluding']['bw'])}, unaware {pr(f['by_db']['unaware']['bw'])}.")
    wide = sorted((res / "wide-index/cases").glob("*.json")) if (res / "wide-index/cases").exists() else []
    if wide:
        def m4u(doc):
            rows = [c for c in doc["cases"] if c["kind"] == "M4u_implant_unindexed_feed"]
            return sum(c["tools"]["bw"]["tp"] for c in rows), len(rows)
        after = [m4u(json.loads(p.read_text())) for p in wide]
        before = [m4u(json.loads((res / "cases" / p.name).read_text())) for p in wide]
        wi = json.loads((res / "wide-index/index.json").read_text())
        L.append(f"- Index coverage: with the large `packages`, `routing` and `telephony` feeds indexed too ({len(wide)} held-out images, "
                 f"{min(w['downloaded_bytes'] for w in wi) / 1e6:.0f} to {max(w['downloaded_bytes'] for w in wi) / 1e6:.0f} MB more per release and architecture), "
                 f"implants from those feeds are named in {sum(a for a, _ in after)} of {sum(n for _, n in after)} cases "
                 f"instead of {sum(a for a, _ in before)} of {sum(n for _, n in before)}.")
    ov = json.loads((res / "sibling-overlap.json").read_text())
    with_sib = [v for v in ov.values() if v.get("sibling")]
    L.append(f"- Sibling snapshots: {len(with_sib)} of {len(ov)} images have one; for {sum(1 for v in with_sib if v['identical_root_filesystem_contents'])} "
             f"of them the sibling has the same regular-file paths and contents as the tested image (symlinks, file metadata and the SquashFS container are not compared), "
             f"so the no-snapshot column is the conservative reading.")
    tot = {"cases": 0, "tp": 0, "fp": 0, "fn": 0}
    for p in sorted((res / "cbom").glob("*.json")):
        o = json.loads(p.read_text())["overall"]
        for k in tot:
            tot[k] += o[k]
    L.append(f"- CBOM and cross-BOM (14 images, 15 seeded classes): {tot['cases']} cases, {tot['tp']} of {tot['tp'] + tot['fn']} expected findings produced, "
             f"{tot['fp']} extra. The correct CBOM is generated by the same detector, so this shows consistency, not detection power.")
    d = json.loads((res / "drift.json").read_text())["releases"]
    old = min((r for r in d if r["release"].startswith("24.10")), key=lambda r: r["release"])
    new = max((r for r in d if r["release"].startswith("24.10")), key=lambda r: r["release"])

    def dr(r):
        c = r["configs"]
        return (f"{r['release']} ({r['age_days']} days old): {c['feeds_only']['verified_A_share']:.1%} feeds only, "
                f"{c['feeds_manifest']['verified_A_share']:.1%} with the manifest, {c['feeds_manifest_snapshot']['verified_A_share']:.1%} with a sibling snapshot")
    L.append(f"- Reference drift, same device across 15 point releases, share of a correct BOM confirmed byte for byte: {dr(old)}; {dr(new)}. "
             f"False alarms on the oldest 24.10 image: {len(old['configs']['feeds_only']['hard_findings'])} feeds only, "
             f"{len(old['configs']['feeds_manifest_snapshot']['hard_findings'])} with the snapshot.")
    ob = json.loads((res / "official-bom.json").read_text())
    claims = sum(v["bom_components"] for v in ob.values())
    ver = sum(v["verdicts"].get("verified_A", 0) + v["verdicts"].get("verified_B", 0) for v in ob.values())
    wv = sum(v["verdicts"].get("wrong_version", 0) for v in ob.values())
    ab = sum(v["verdicts"].get("absent", 0) for v in ob.values())
    beyond = [len(v["components_in_image_not_in_bom"]) for v in ob.values()]
    vd = rv["official_bom"]["verdicts"]
    L.append(f"- OpenWrt's published per-target BOMs, verified unchanged against the 14 device images: {ver} of {claims} claims verified "
             f"({vd.get('verified_A', 0)} at grade A, {vd.get('verified_B', 0)} at grade B), {vd.get('unverifiable', 0)} unverifiable, "
             f"{wv} version labels contradicted at package granularity (wireless kernel-module packages listed with the kernel version only, where the frozen feed labels "
             f"the same bytes with the kernel and the driver version), {vd.get('bytes_differ', 0)} `bytes_differ`, {ab} components absent from the device image, "
             f"and {min(beyond)} to {max(beyond)} packages per image beyond what the per-target BOM lists. No database-reading verifier was run on these BOMs.")
    inv = json.loads((res / "inventory.json").read_text())
    L.append(f"- Inventory from bytes alone (no BOM, no database): of {sum(v['installed_packages'] for v in inv.values())} installed packages, "
             f"{sum(v['installed_packages_with_files'] for v in inv.values())} own at least one regular, non-symlink file in the image and are therefore eligible; "
             f"{sum(v['correct_names'] for v in inv.values())} of those are named, with {sum(len(v['extra']) for v in inv.values())} wrong names. "
             f"Syft on the same trees without the database lists {min(v['syft_components_database_removed'] for v in inv.values())} to "
             f"{max(v['syft_components_database_removed'] for v in inv.values())} components; cve-bin-tool identifies "
             f"{min(v['cvebin_products'] for v in inv.values())} to {max(v['cvebin_products'] for v in inv.values())} products.")
    cs = json.loads((res / "case-study-immortalwrt.json").read_text())
    p1, p2 = cs["part1_against_upstream"], cs["part2_against_own_publisher"]
    L.append(f"- Unmodified downstream fork (ImmortalWrt {cs['subject']['release']}, same device): against its own signed download tree "
             f"{p2['verdicts'].get('verified_A', 0) + p2['verdicts'].get('verified_B', 0)} of {p2['declared']} components verify with "
             f"{sum(p2['hard_findings'].values())} findings; against upstream OpenWrt {p1['verdicts'].get('verified_A', 0)} of {p1['declared']} are upstream's bytes "
             f"and {p1['executables_byte_identical_to_upstream_image']} of {p1['executables_total']} executables are identical to the upstream image.")
    secs = [im["seconds_median"] for im in h["clean"]["images"].values()]
    te = json.loads((res / "timing-e2e.json").read_text())
    L.append(f"- Cost. The benchmark timer covers only the in-process verifier call on a tree that is already unpacked and hashed, with a warm reference cache: "
             f"median {min(x['bw'] for x in secs):.2f} to {max(x['bw'] for x in secs):.2f} s per case. The baselines were timed as whole command-line runs "
             f"(BomTrace up to {max(x['bomtrace'] for x in secs):.2f} s, Syft up to {max(x['syft'] for x in secs):.1f} s), so these figures are not comparable with each other. "
             f"End to end, the command line on the repository example (unpack two images, hash every file, verify, write the report; measured after the freeze on one machine) "
             f"takes {te['warm_cache_seconds_median']:.1f} s with a warm cache and {te['cold_cache_seconds']:.1f} s with an empty one. ")
    ri = json.loads((res / "reference-index.json").read_text())
    full = sorted((r for r in ri["targets"] if r["downloaded_bytes"] > 100e6), key=lambda r: r["seconds"])
    L[-1] += (f"Building the reference index for one release and target, once: {full[0]['seconds']:.0f} to {full[-1]['seconds']:.0f} s and "
              f"{min(r['downloaded_bytes'] for r in full) / 1e6:.0f} to {max(r['downloaded_bytes'] for r in full) / 1e6:.0f} MB of downloads "
              f"({ri['total_downloaded_bytes'] / 1e9:.1f} GB for all {len(ri['targets'])} targets of the benchmark).")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    res = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results/r2"
    text = build(res)
    (res / "HEADLINE.md").write_text(text)
    print(text)
