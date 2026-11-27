"""Compare a fresh example run with the expected findings. Exit 0 when they match."""
import json
import sys
from pathlib import Path

out, obj = Path(sys.argv[1]), Path(sys.argv[2])
expected = json.loads((obj / "expected-findings.json").read_text())
HARD = {"wrong_version", "wrong_component", "absent", "bytes_differ", "undeclared_component", "undeclared_file"}
POLICY = {"deprecated_algorithm", "expired_certificate", "weak_key", "deprecated_signature_hash", "embedded_private_key"}


def findings(rep):
    sbom = sorted([f["class"], f["component"]] for f in rep["sbom"]["findings"] if f["class"] in HARD)
    cbom = sorted([f["class"], f["asset"]] for f in (rep["cbom"] or {"findings": []})["findings"] if f["class"] not in POLICY)
    return sbom, cbom


ok = True
clean = json.loads((out / "report-correct.json").read_text())
s, c = findings(clean)
print("correct declaration:   ", clean["triage"], "| SBOM findings", len(s), "| CBOM findings", len(c))
ok &= not s and not c
bad = json.loads((out / "report-with-errors.json").read_text())
s, c = findings(bad)
print("declaration with errors:", bad["triage"])
consequences = expected.get("cbom_consequences", [])
print(f"  cross-BOM consequences of the seeded SBOM errors: {sum(1 for x in consequences if x in c)}/{len(consequences)}")
ok &= all(x in c for x in consequences)
c = [x for x in c if x not in consequences]
for kind, got, want in (("SBOM", s, sorted(expected["sbom"])), ("CBOM", c, sorted(expected["cbom"]))):
    missing = [x for x in want if x not in got]
    extra = [x for x in got if x not in want]
    print(f"  {kind}: {len(want) - len(missing)}/{len(want)} seeded errors found, {len(extra)} other findings")
    for x in missing:
        print("    MISSING", x)
    for x in extra:
        print("    EXTRA  ", x)
    ok &= not missing and not extra
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
