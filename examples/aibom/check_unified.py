"""Check the report of examples/aibom/unified.sh: the SBOM, CBOM and AI-BOM findings must all be the expected ones."""
import json
import sys
from pathlib import Path

rep, pipeline_expected, ai_expected = (json.loads(Path(p).read_text()) for p in sys.argv[1:4])
HARD = {"wrong_version", "wrong_component", "absent", "bytes_differ", "undeclared_component", "undeclared_file"}
POLICY = {"deprecated_algorithm", "expired_certificate", "weak_key", "deprecated_signature_hash", "embedded_private_key"}
sbom = sorted([f["class"], f["component"]] for f in rep["sbom"]["findings"] if f["class"] in HARD)
cbom = sorted([f["class"], f["asset"]] for f in rep["cbom"]["findings"] if f["class"] not in POLICY)
ai = sorted([f["class"], f["asset"]] for f in rep["aibom"]["findings"])
want_cbom = sorted(pipeline_expected["cbom"] + pipeline_expected.get("cbom_consequences", []))
ok = True
for kind, got, want in (("SBOM", sbom, sorted(pipeline_expected["sbom"])), ("CBOM and cross-BOM", cbom, want_cbom), ("AI-BOM", ai, sorted(ai_expected))):
    same = got == want
    ok &= same
    print(f"{kind}: {len(got)} finding(s), {'as expected' if same else 'NOT as expected: ' + json.dumps(got)}")
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
