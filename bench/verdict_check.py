"""Show that a change to reason strings changed no verdict: compare a rerun of bench/run_cases.py with the committed case files.

Usage: verdict_check.py <rerun dir> [--baseline-rerun <dir>] [--out results/r2/r4-verdict-check/COMPARISON.json]

<rerun dir> holds <image-id>.json files written by `run_cases.py <image-id> --out <dir> --no-baselines` with the code
under test. --baseline-rerun is the same rerun made with the code of the previous commit; it shows that a rerun on
this machine and date reproduces the committed files at all, so that a difference could be blamed on the change.

Compared, field by field, for BOMwitness and each of its ablation configurations (tool names that start with "bw"):
  per case     kind, target, database condition, label; tp, fp and the extra findings; the verdict for the seeded
               target; the three BOMwitness flags the runner records
  per image    clean-control hard findings (honest and stripped trees), the clean summary, verdict counts per
               configuration, label sources, review tier, and the name and verdict of every component that did
               not verify
Not compared: reason text (it is what changed; the number of changed strings is reported), timings, and the
baselines' columns (the rerun does not run them and they do not use the changed code).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "results/r2/cases"
CASE_FIELDS = ("kind", "target", "db", "label", "bw_implanted_files_flagged", "bw_alternative_named", "bw_flagged_undeclared_code",
               "bw_verdict_for_target")
IMAGE_FIELDS = ("image", "seed", "k", "arch", "declared_components", "reference", "alt_release", "snapshot")


def bw_only(d: dict) -> dict:
    return {k: v for k, v in d.items() if k.startswith("bw")}


def compare(old: dict, new: dict) -> dict:
    diffs: list[str] = []
    reason = {"same": 0, "changed": 0}
    examples: list[dict] = []

    def note(old_text, new_text):
        if old_text == new_text:
            reason["same"] += 1
        else:
            reason["changed"] += 1
            if len(examples) < 400:
                examples.append({"before": old_text, "after": new_text})

    for f in IMAGE_FIELDS:
        if old.get(f) != new.get(f):
            diffs.append(f"image field {f}")
    oc, nc = old["clean_control"], new["clean_control"]
    for cond in ("honest", "stripped"):
        if bw_only(oc[cond]["findings"]) != bw_only(nc[cond]["findings"]):
            diffs.append(f"clean control findings, {cond} tree")
    so, sn = dict(oc["summary"]), dict(nc["summary"])
    so.pop("seconds", None); sn.pop("seconds", None)
    if so != sn:
        diffs.append("clean control summary")
    for f in ("review_tier", "verdicts_by_config", "label_sources"):
        if oc[f] != nc[f]:
            diffs.append(f"clean control {f}")
    if sorted(oc["unverifiable_reasons"].values()) != sorted(nc["unverifiable_reasons"].values()):
        diffs.append("clean control unverifiable counts")
    if [(c["name"], c["verdict"]) for c in oc["not_verified"]] != [(c["name"], c["verdict"]) for c in nc["not_verified"]]:
        diffs.append("clean control components that did not verify")
    else:
        for a, b in zip(oc["not_verified"], nc["not_verified"]):
            note(a["reason"], b["reason"])
    if len(old["cases"]) != len(new["cases"]):
        diffs.append(f"number of cases {len(old['cases'])} != {len(new['cases'])}")
    for i, (a, b) in enumerate(zip(old["cases"], new["cases"])):
        for f in CASE_FIELDS:
            if a.get(f) != b.get(f):
                diffs.append(f"case {i} ({a['kind']} {a['target']} {a['db']}): {f}: {a.get(f)!r} != {b.get(f)!r}")
        if bw_only(a["tools"]) != bw_only(b["tools"]):
            diffs.append(f"case {i} ({a['kind']} {a['target']} {a['db']}): scores {bw_only(a['tools'])} != {bw_only(b['tools'])}")
        note(a.get("bw_reason_for_target"), b.get("bw_reason_for_target"))
    return {"split": old["image"]["split"], "cases": len(old["cases"]), "configurations": sorted(bw_only(old["cases"][0]["tools"])),
            "differences": diffs, "reason_strings_same": reason["same"], "reason_strings_changed": reason["changed"], "_examples": examples}


def run(rerun: Path) -> dict:
    images, examples = {}, []
    for p in sorted(CASES.glob("*.json")):
        q = rerun / p.name
        if not q.exists():
            images[p.stem] = {"missing": True, "differences": ["no rerun file"]}
            continue
        r = compare(json.loads(p.read_text()), json.loads(q.read_text()))
        examples += r.pop("_examples")
        images[p.stem] = r
    seen, pairs = set(), []
    for e in examples:
        key = (e["before"], e["after"])
        if key not in seen and e["before"] and e["after"]:
            seen.add(key)
            pairs.append(e)
    held = [v for v in images.values() if v.get("split") == "heldout"]
    return {"images": images,
            "totals": {"images": len(images), "heldout_images": len(held), "cases": sum(v.get("cases", 0) for v in images.values()),
                       "heldout_cases": sum(v["cases"] for v in held),
                       "differences": sum(len(v["differences"]) for v in images.values()),
                       "reason_strings_changed": sum(v.get("reason_strings_changed", 0) for v in images.values()),
                       "reason_strings_same": sum(v.get("reason_strings_same", 0) for v in images.values())},
            "reason_text_examples": sorted(pairs, key=lambda e: (len(e["before"]), e["before"]))[:12]}


def git(*a: str) -> str:
    return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("rerun")
    ap.add_argument("--baseline-rerun")
    ap.add_argument("--baseline-commit", help="commit the baseline rerun's code was taken from")
    ap.add_argument("--out", default="results/r2/r4-verdict-check/COMPARISON.json")
    a = ap.parse_args()
    out = {"note": "Rerun of bench/run_cases.py (BOMwitness and its ablations, --no-baselines) on every benchmark image, compared with "
                   "the committed case files of the frozen run in results/r2/cases/. See the docstring of bench/verdict_check.py for "
                   "what is and is not compared. 'differences' lists every compared field that is not equal.",
           "compared_with": "results/r2/cases/ (frozen run, commit " + json.loads((ROOT / "results/r2/RUN.json").read_text())["commit"][:7] + ")",
           "rule_file_blobs_at_rerun": {f: git("hash-object", f) for f in ("bomwitness/verify.py", "bomwitness/reference.py", "bench/run_cases.py")},
           "changed_code": run(ROOT / a.rerun if not Path(a.rerun).is_absolute() else Path(a.rerun))}
    if a.baseline_rerun:
        b = Path(a.baseline_rerun)
        out["unchanged_code"] = dict(run(ROOT / b if not b.is_absolute() else b), code_commit=a.baseline_commit)
        out["unchanged_code"].pop("reason_text_examples", None)
    snaps = ROOT / "work/snapshots"
    if snaps.exists():
        out["snapshot_files_sha256"] = {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(snaps.glob("*.json"))}
    dest = ROOT / a.out
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for name in ("unchanged_code", "changed_code"):
        if name in out:
            t = out[name]["totals"]
            print(f"{name}: {t['images']} images ({t['heldout_images']} held-out), {t['cases']} rows ({t['heldout_cases']} held-out), "
                  f"{t['differences']} differences, {t['reason_strings_changed']} reason strings changed, {t['reason_strings_same']} unchanged")
            for im, v in out[name]["images"].items():
                for d in v["differences"][:20]:
                    print("  DIFF", im, d)


if __name__ == "__main__":
    main()
