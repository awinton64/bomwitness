"""CI gate for the small benchmark: BOMwitness must keep its floor on one image. Usage: check_small.py <cases.json>"""
import json
import sys

res = json.load(open(sys.argv[1]))
ok = True
clean = res["clean_control"]["honest"]["findings"]["bw"]
print("clean-image hard findings:", clean)
ok &= len(clean) <= 1
for db in ("honest", "colluding", "stripped", "unaware"):
    rows = [c for c in res["cases"] if c["db"] == db]
    tp = sum(c["tools"]["bw"]["tp"] for c in rows)
    fp = sum(c["tools"]["bw"]["fp"] for c in rows)
    print(f"{db:9s} recall {tp}/{len(rows)}  case false positives {fp}")
    ok &= tp / len(rows) >= 0.75 and fp <= 1
h = {c["target"]: c["tools"]["bw"]["tp"] for c in res["cases"] if c["db"] == "honest"}
c = {c["target"]: c["tools"]["bw"]["tp"] for c in res["cases"] if c["db"] == "colluding"}
s = {c["target"]: c["tools"]["bw"]["tp"] for c in res["cases"] if c["db"] == "stripped"}
print("verdicts identical across database conditions:", h == c == s)
ok &= h == c == s
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
