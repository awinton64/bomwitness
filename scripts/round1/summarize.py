"""Pool the per-image spike results into results/spike-r1/summary.json and print a table."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
out = ROOT / "results/spike-r1"
ids = [i["id"] for i in json.loads((ROOT / "images.json").read_text())["images"]]
res = {i: json.loads((out / f"{i}.json").read_text()) for i in ids if (out / f"{i}.json").exists()}
pooled = {}
for r in res.values():
    for c in r["cases"]:
        for tool in ("bomwitness", "syft_diff"):
            a = pooled.setdefault(f"{c['kind']}/{c['db']}", {}).setdefault(tool, {"cases": 0, "tp": 0, "fp": 0, "fn": 0})
            a["cases"] += 1
            for k in ("tp", "fp", "fn"):
                a[k] += c[tool][k]
        if c["kind"] == "M4_implant":
            a = pooled[f"{c['kind']}/{c['db']}"]["bomwitness"]
            a["flagged_as_undeclared_code"] = a.get("flagged_as_undeclared_code", 0) + int(c["bomwitness_flagged_undeclared_code"])


def pr(a):
    a["precision"] = round(a["tp"] / (a["tp"] + a["fp"]), 3) if a["tp"] + a["fp"] else None
    a["recall"] = round(a["tp"] / (a["tp"] + a["fn"]), 3) if a["tp"] + a["fn"] else None
    return a


by_db = {}
for key, tools in pooled.items():
    db = key.split("/")[1]
    for tool, a in tools.items():
        pr(a)
        b = by_db.setdefault(db, {}).setdefault(tool, {"cases": 0, "tp": 0, "fp": 0, "fn": 0})
        for k in ("cases", "tp", "fp", "fn"):
            b[k] += a[k]
total = {}
for db, tools in by_db.items():
    for tool, a in tools.items():
        pr(a)
        t = total.setdefault(tool, {"cases": 0, "tp": 0, "fp": 0, "fn": 0})
        for k in ("cases", "tp", "fp", "fn"):
            t[k] += a[k]
for a in total.values():
    pr(a)
clean = {i: r["clean_control"] for i, r in res.items()}
summary = {"images": list(res), "seed": 20261127, "by_class_and_database_condition": pooled,
           "by_database_condition": by_db, "all_cases": total, "clean_controls": clean}
(out / "summary.json").write_text(json.dumps(summary, indent=1))
print("| seeded error / device database | cases | BOMwitness P | BOMwitness R | Syft-diff P | Syft-diff R |")
print("|---|---|---|---|---|---|")
for key in sorted(pooled):
    b, s = pooled[key]["bomwitness"], pooled[key]["syft_diff"]
    print(f"| {key} | {b['cases']} | {b['precision']} | {b['recall']} ({b['tp']}/{b['tp'] + b['fn']}) | {s['precision']} | {s['recall']} ({s['tp']}/{s['tp'] + s['fn']}) |")
for db in ("honest", "colluding", "stripped", "unaware"):
    if db in by_db:
        b, s = by_db[db]["bomwitness"], by_db[db]["syft_diff"]
        print(f"| ALL / {db} | {b['cases']} | {b['precision']} | {b['recall']} ({b['tp']}/{b['tp'] + b['fn']}) | {s['precision']} | {s['recall']} ({s['tp']}/{s['tp'] + s['fn']}) |")
b, s = total["bomwitness"], total["syft_diff"]
print(f"| ALL | {b['cases']} | {b['precision']} | {b['recall']} ({b['tp']}/{b['tp'] + b['fn']}) | {s['precision']} | {s['recall']} ({s['tp']}/{s['tp'] + s['fn']}) |")
for i, c in clean.items():
    print(i, c["summary"]["verdicts"], "hard:", c["hard_findings"], "review:", c["review_tier"], "verify s", c["verify_seconds"],
          "syft comps", c["syft_components"], "stripped", c["syft_components_db_stripped"])
