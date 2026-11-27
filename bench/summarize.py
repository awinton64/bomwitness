"""Pool per-image case files into summary.json and SUMMARY.md.

Usage: summarize.py <cases-dir> <out-dir>

Metrics, per tool and database condition:
  recall     labelled errors found / labelled errors
  precision  TP / (TP + case FP + clean FP), where "case FP" are findings a mutation caused beyond its label
             and "clean FP" are the tool's findings on the unmodified image with a correct BOM, counted once
             per image for that database condition
  attributable precision  TP / (TP + case FP): what remains when the clean-control findings are set aside
  clean false alarms      findings on the unmodified image with a correct BOM, per image and per declared component
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DBS = ("honest", "colluding", "stripped", "unaware")
TOOL_ORDER = ["bw", "bw_with_db", "bw_no_snapshot", "bw_feed_only", "bw_A_only", "bw_B_only", "bw_no_normalize",
              "bomtrace", "syft_diff", "cvebin_diff"]
TOOL_NAME = {"bw": "BOMwitness", "bw_with_db": "BOMwitness + device database (grade C shown)",
             "bw_no_snapshot": "BOMwitness, no sibling snapshot", "bw_feed_only": "BOMwitness, feeds only (no manifest, no snapshot)",
             "bw_A_only": "BOMwitness, grade A only", "bw_B_only": "BOMwitness, grade B only",
             "bw_no_normalize": "BOMwitness, no timestamp normalisation",
             "bomtrace": "BomTrace", "syft_diff": "Syft-diff", "cvebin_diff": "cve-bin-tool-diff"}


def clean_cond(db: str) -> str:
    return "stripped" if db == "stripped" else "honest"


def ratio(a: int, b: int):
    return round(a / b, 4) if b else None


def pool(results: list[dict], rows_filter=lambda c: True) -> dict:
    """{db: {tool: metrics}} plus "all"."""
    out = {}
    tools = sorted({t for r in results for c in r["cases"] for t in c["tools"]}, key=lambda t: TOOL_ORDER.index(t) if t in TOOL_ORDER else 99)
    for db in DBS + ("all",):
        out[db] = {}
        for tool in tools:
            cases = tp = fp = clean_fp = 0
            per_image = []
            for r in results:
                rows = [c for c in r["cases"] if (db == "all" or c["db"] == db) and rows_filter(c) and tool in c["tools"]]
                if not rows:
                    continue
                cases += len(rows)
                itp = sum(c["tools"][tool]["tp"] for c in rows)
                tp += itp
                fp += sum(c["tools"][tool]["fp"] for c in rows)
                per_image.append(itp / len(rows))
                for cond in ({clean_cond(c["db"]) for c in rows} if db != "all" else {clean_cond(d) for d in {c["db"] for c in rows}}):
                    n = len(r["clean_control"][cond]["findings"].get(tool if tool != "bw_with_db" else "bw_with_db", []))
                    clean_fp += n * (len({c["db"] for c in rows if clean_cond(c["db"]) == cond}) if db == "all" else 1)
            if not cases:
                continue
            per_image.sort()
            out[db][tool] = {"cases": cases, "tp": tp, "fn": cases - tp, "case_fp": fp, "clean_fp": clean_fp,
                             "recall": ratio(tp, cases), "precision": ratio(tp, tp + fp + clean_fp),
                             "attributable_precision": ratio(tp, tp + fp),
                             "recall_per_image_min": round(per_image[0], 3), "recall_per_image_median": round(per_image[len(per_image) // 2], 3)}
    return out


def by_kind(results: list[dict]) -> dict:
    kinds = sorted({c["kind"] for r in results for c in r["cases"]})
    return {k: pool(results, lambda c, k=k: c["kind"] == k) for k in kinds}


def clean_summary(results: list[dict]) -> dict:
    images = {}
    tot = {"declared": 0, "verdicts": {}, "bw_hard": 0, "files": 0, "accounted": 0, "code": 0, "orphan_code": 0}
    for r in results:
        cc = r["clean_control"]
        s = cc["summary"]
        hard = {t: len(v) for t, v in cc["honest"]["findings"].items()}
        hard_stripped = {t: len(v) for t, v in cc["stripped"]["findings"].items()}
        images[r["image"]["id"]] = {
            "split": r["image"]["split"], "release": r["image"]["release"], "target": r["image"]["target"], "arch": r["arch"],
            "declared": s["declared"], "verdicts": s["verdicts"], "verdicts_by_config": cc["verdicts_by_config"],
            "label_sources": cc["label_sources"], "unverifiable_reasons": cc["unverifiable_reasons"], "review_tier": cc["review_tier"],
            "rootfs_files": s["rootfs_files"], "files_accounted": s["files_accounted"], "code_files": s["code_files"],
            "orphan_code_files": s["orphan_code_files"], "clean_findings_honest": hard, "clean_findings_stripped": hard_stripped,
            "bw_clean_findings": cc["honest"]["findings"]["bw"], "snapshot": r["snapshot"],
            "syft_components": cc.get("syft_components"), "syft_components_db_stripped": cc.get("syft_components_db_stripped"),
            "cvebin_products": cc.get("cvebin_products"), "bomtrace_ran_stripped": cc["stripped"].get("bomtrace_ran"),
            "bomtrace_error_stripped": cc["stripped"].get("bomtrace_error"), "seconds_median": r["seconds_median"]}
        tot["declared"] += s["declared"]
        tot["bw_hard"] += hard.get("bw", 0)
        tot["files"] += s["rootfs_files"]; tot["accounted"] += s["files_accounted"]
        tot["code"] += s["code_files"]; tot["orphan_code"] += s["orphan_code_files"]
        for k, v in s["verdicts"].items():
            tot["verdicts"][k] = tot["verdicts"].get(k, 0) + v
    v = tot["verdicts"]
    tot["verified_A_share"] = ratio(v.get("verified_A", 0), tot["declared"])
    tot["verified_share"] = ratio(v.get("verified_A", 0) + v.get("verified_B", 0), tot["declared"])
    tot["clean_false_alarm_rate_per_declared_component"] = ratio(tot["bw_hard"], tot["declared"])
    tot["files_accounted_share"] = ratio(tot["accounted"], tot["files"])
    return {"images": images, "totals": tot}


def errors(results: list[dict]) -> dict:
    """Every BOMwitness miss and every case-level false positive, for the error analysis."""
    misses, fps = [], []
    for r in results:
        for c in r["cases"]:
            if c["db"] not in ("colluding", "unaware"):
                continue                      # honest and stripped rows repeat the colluding row for BOMwitness
            if not c["tools"]["bw"]["tp"]:
                misses.append({"image": r["image"]["id"], "kind": c["kind"], "target": c["target"],
                               "verdict": c.get("bw_verdict_for_target"), "reason": c.get("bw_reason_for_target"),
                               "alternative_named": c.get("bw_alternative_named"), "flagged_undeclared_code": c.get("bw_flagged_undeclared_code"),
                               "other_findings": c["tools"]["bw"]["extra"]})
            if c["tools"]["bw"]["fp"]:
                fps.append({"image": r["image"]["id"], "kind": c["kind"], "target": c["target"], "extra": c["tools"]["bw"]["extra"]})
    groups: dict[str, int] = {}
    for m in misses:
        key = f"{m['kind']}: {m['verdict'] or ('flagged as undeclared code, not named' if m['flagged_undeclared_code'] else 'not flagged')}"
        groups[key] = groups.get(key, 0) + 1
    return {"misses": misses, "false_positives": fps, "miss_groups": dict(sorted(groups.items(), key=lambda kv: -kv[1]))}


def table(pooled: dict, tools: list[str], title: str) -> list[str]:
    lines = [f"### {title}", "", "| Database condition | Cases | " + " | ".join(f"{TOOL_NAME[t]} P / R" for t in tools) + " |",
             "|---|---|" + "---|" * len(tools)]
    for db in DBS + ("all",):
        if not pooled.get(db):
            continue
        any_tool = next(iter(pooled[db].values()))
        cells = []
        for t in tools:
            m = pooled[db].get(t)
            cells.append("n/a" if not m else f"{m['precision'] if m['precision'] is not None else 'n/a'} / {m['recall']} ({m['tp']}/{m['cases']})")
        lines.append(f"| {db} | {any_tool['cases']} | " + " | ".join(cells) + " |")
    return lines + [""]


def main() -> None:
    cases_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    results = [json.loads(p.read_text()) for p in sorted(cases_dir.glob("*.json"))]
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {"seed": results[0]["seed"], "k": results[0]["k"], "bomtrace_commit": results[0]["bomtrace_commit"], "splits": {}}
    for split in ("heldout", "tuning"):
        rs = [r for r in results if r["image"]["split"] == split]
        if not rs:
            continue
        summary["splits"][split] = {"images": [r["image"]["id"] for r in rs], "cases": sum(len(r["cases"]) for r in rs),
                                    "by_db": pool(rs), "by_kind": by_kind(rs), "clean": clean_summary(rs), "errors": errors(rs)}
    h = summary["splits"].get("heldout")
    if h:
        c, s = h["by_db"]["colluding"]["bw"], h["by_db"]["stripped"]["bw"]
        summary["stopping_rule_2"] = {
            "rule": "held-out precision >= 0.95 and recall >= 0.75 in the colluding and stripped database conditions",
            "colluding": {"precision": c["precision"], "recall": c["recall"]}, "stripped": {"precision": s["precision"], "recall": s["recall"]},
            "met": all(x["precision"] >= 0.95 and x["recall"] >= 0.75 for x in (c, s))}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1))

    md = ["# Benchmark summary (generated by bench/summarize.py; do not edit)", "",
          f"Seed {summary['seed']}, {summary['k']} targets per class per image. BomTrace commit {summary['bomtrace_commit']}.", ""]
    for split, name in (("heldout", "Held-out images"), ("tuning", "Tuning images")):
        sp = summary["splits"].get(split)
        if not sp:
            continue
        md += [f"## {name}: {len(sp['images'])} images, {sp['cases']} cases", ""]
        md += table(sp["by_db"], ["bw", "bomtrace", "syft_diff", "cvebin_diff"], "BOMwitness and baselines (precision / recall)")
        md += table(sp["by_db"], ["bw", "bw_with_db", "bw_no_snapshot", "bw_feed_only", "bw_A_only", "bw_B_only", "bw_no_normalize"], "Ablations")
        md += ["### Recall by error class (BOMwitness; baselines in the colluding or unaware condition)", "",
               "| Class | Condition | Cases | BOMwitness | BomTrace | Syft-diff | cve-bin-tool-diff |", "|---|---|---|---|---|---|---|"]
        for kind, pooled in sp["by_kind"].items():
            for db in DBS:
                row = pooled.get(db)
                if not row:
                    continue
                def cell(t):
                    m = row.get(t)
                    return "n/a" if not m else f"{m['recall']} ({m['tp']}/{m['cases']}), case FP {m['case_fp']}"
                md.append(f"| {kind} | {db} | {row['bw']['cases']} | {cell('bw')} | {cell('bomtrace')} | {cell('syft_diff')} | {cell('cvebin_diff')} |")
        t = sp["clean"]["totals"]
        md += ["", "### Clean controls (unmodified image, correct BOM)", "",
               f"Declared components: {t['declared']}. Verdicts: {json.dumps(t['verdicts'])}. Verified with grade A: {t['verified_A_share']}; "
               f"verified with A or B: {t['verified_share']}. BOMwitness hard findings on clean images: {t['bw_hard']} "
               f"({t['clean_false_alarm_rate_per_declared_component']} per declared component). Files accounted for: "
               f"{t['accounted']}/{t['files']} ({t['files_accounted_share']}); executable files unaccounted: {t['orphan_code']}/{t['code']}.", "",
               "| Image | Arch | Declared | verified A | verified B | unverifiable | review | BOMwitness clean findings | BomTrace | Syft-diff (db / no db) | cve-bin-tool-diff | Syft components (db / no db) | cve-bin-tool products |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for iid, im in sp["clean"]["images"].items():
            v = im["verdicts"]
            ch, cs = im["clean_findings_honest"], im["clean_findings_stripped"]
            md.append(f"| {iid} | {im['arch']} | {im['declared']} | {v.get('verified_A', 0)} | {v.get('verified_B', 0)} | {v.get('unverifiable', 0)} | "
                      f"{v.get('bytes_differ', 0) + v.get('label_unconfirmed', 0)} | {ch.get('bw', 0)} | {ch.get('bomtrace', 'n/a')} | "
                      f"{ch.get('syft_diff', 'n/a')} / {cs.get('syft_diff', 'n/a')} | {ch.get('cvebin_diff', 'n/a')} | "
                      f"{im['syft_components']} / {im['syft_components_db_stripped']} | {len(im['cvebin_products'] or [])} |")
        md += ["", "### BOMwitness misses, grouped", ""]
        md += [f"- {k}: {n}" for k, n in sp["errors"]["miss_groups"].items()] or ["- none"]
        md += ["", f"Case-level false positives: {len(sp['errors']['false_positives'])}.", ""]
    if "stopping_rule_2" in summary:
        sr = summary["stopping_rule_2"]
        md += ["## Stopping rule 2", "", f"{sr['rule']}.", "",
               f"Colluding: precision {sr['colluding']['precision']}, recall {sr['colluding']['recall']}. "
               f"Stripped: precision {sr['stripped']['precision']}, recall {sr['stripped']['recall']}. Met: {sr['met']}.", ""]
    (out_dir / "SUMMARY.md").write_text("\n".join(md))
    print("\n".join(md[:60]))


if __name__ == "__main__":
    main()
