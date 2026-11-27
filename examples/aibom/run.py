"""Check the two example AI-BOMs against the synthetic root filesystem. Run: python examples/aibom/run.py"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from bomwitness import aibom, bomio  # noqa: E402


def check(name: str) -> list[list[str]]:
    doc = bomio.load(HERE / name)
    findings = aibom.verify_aibom(HERE / "rootfs", bomio.models(doc))
    print(f"{name}: {len(bomio.models(doc))} declared model(s), {len(aibom.discover(HERE / 'rootfs'))} model file(s) in the tree, {len(findings)} finding(s)")
    for f in findings:
        print(f"  {f['class']:17s} {f['asset']}  [{f['grade']}] {f['detail']}")
    return sorted([f["class"], f["asset"]] for f in findings)


if __name__ == "__main__":
    ok = check("aibom-correct.cdx.json") == []
    ok &= check("aibom-with-errors.cdx.json") == sorted(json.loads((HERE / "expected-findings.json").read_text()))
    print("PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)
