"""Check every number in the paper against the committed result files.

Four checks, all must pass:
  1. generated   numbers.tex, the table bodies and the plot data on disk equal what gen_numbers.py derives
                 from the result files right now (nothing stale, nothing edited by hand);
  2. source      bomwitness.tex contains no literal number except the identifiers listed in ALLOWED below,
                 so every result number in the text has to come through a generated macro;
  3. pdf         every token containing a digit in the built PDF is a generated fact, an allowed
                 identifier, part of the bibliography, or structural numbering (sections, floats, citations);
  4. pages       the body ends on page 5 or earlier and the PDF has at most 7 pages (the track's limits).

Usage: check_numbers.py [paper.pdf] [--json report.json]      (needs pdftotext for checks 3 and 4)
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_numbers  # noqa: E402

# Literal tokens with digits that may appear in the paper without coming from a result file, and why.
ALLOWED = {
    "23.05.6": "OpenWrt release under test (bench/images.json)",
    "24.10.8": "OpenWrt release under test (bench/images.json)",
    "24.10.0": "OpenWrt release named in the drift paragraph (results/r2/drift.json)",
    "24.10": "OpenWrt release series",
    "23.05": "OpenWrt release series",
    "25.12": "OpenWrt release series that is not supported",
    "1.57.2": "Syft version used as baseline (docs/EVALUATION.md)",
    "3.4": "cve-bin-tool version used as baseline (docs/EVALUATION.md)",
    "95": "confidence level of the Wilson intervals",
    "sha256sums": "file name",
    "SHA-256": "hash function name",
    "X.509": "certificate standard",
    "Ed25519": "signature scheme",
    "M1": "error class id", "M2": "error class id", "M2b": "error class id", "M3": "error class id",
    "M4": "error class id", "M4u": "error class id", "M5": "error class id", "M6": "error class id",
    "mac80211": "kernel subsystem name", "cfg80211": "kernel subsystem name", "mt76": "driver name",
    "MD5": "algorithm name", "SHA-1": "algorithm name", "RC4": "algorithm name", "3DES": "algorithm name",
    "HDF5": "file format name", "e2fsprogs": "package name", "results/r2/": "directory name",
    "50": "plot axis tick", "60": "plot axis tick", "70": "plot axis tick", "80": "plot axis tick",
    "90": "plot axis tick", "100": "plot axis tick",
    "AArch64": "architecture name", "ARMv7": "architecture name", "x86-64": "architecture name",
    "23.05.x": "plot axis label", "24.10.x": "plot axis label",
    "github.com/awinton64/bomwitness": "repository URL",
}
STAGES = ("Collect", "Extract", "Normalize", "Compare", "Cross-check", "Report")

TOKEN = re.compile(r"[A-Za-z0-9_.~/+\-]*\d[A-Za-z0-9_.~/+%,\-]*")


def tokens(text: str) -> list[str]:
    out = []
    for t in TOKEN.findall(text):
        t = t.strip(".,;:-/+").rstrip("%")
        t = re.sub(r"(?<=\d),(?=\d{3}\b)", "", t)          # 1,860 -> 1860
        parts = t.split(",")                               # "474,480" style lists
        if re.fullmatch(r"[\d/]+", t):                     # "120/0/0": table cells set tight by pdftotext
            parts = t.split("/")
        for part in parts:
            part = re.sub(r"^(https?://)?(dx\.)?doi\.org/", "", part.strip(".,;:-/+").rstrip("%"))
            if re.search(r"\d", part):
                out.append(part)
    return out


def strip_tex(src: str) -> str:
    """The prose and table cells of the paper, with markup that legitimately holds digits removed."""
    src = re.sub(r"(?<!\\)%.*", "", src)
    src = src[src.index("\\begin{abstract}"):src.index("\\bibliographystyle")] + src[src.index("\\appendix"):]
    src = re.sub(r"\\begin\{tikzpicture\}.*?\\end\{tikzpicture\}", " ", src, flags=re.S)
    src = re.sub(r"\\(label|ref|cite|input|url|bibliography|usepackage|setlength)\*?(\[[^\]]*\])?\{[^}]*\}(\{[^}]*\})?", " ", src)
    src = re.sub(r"\\begin\{(tabular|table\*?|figure\*?)\}(\[[^\]]*\])?(\{[^{}]*(\{[^{}]*\}[^{}]*)*\})?", " ", src)
    src = re.sub(r"\\(multicolumn|cmidrule)(\([a-z]+\))?\{[^}]*\}(\{[^}]*\})?", " ", src)
    src = re.sub(r"\d+(\.\d+)?\\columnwidth|\d+(\.\d+)?(pt|mm|em)\b", " ", src)
    src = src.replace("\\_", "_").replace("\\%", "%").replace("\\allowbreak", "").replace("~", " ")
    return src


def main() -> int:
    argv = sys.argv[1:]
    json_out = None
    if "--json" in argv:
        i = argv.index("--json")
        json_out = Path(argv[i + 1])
        del argv[i:i + 2]
    pdf = Path(argv[0]) if argv else HERE / "bomwitness.pdf"
    report: dict = {"checks": {}}
    ok = True

    # 1. generated files are current
    out = gen_numbers.build()
    facts = gen_numbers.FACTS
    stale = [n for n, text in out.items() if not (HERE / n).exists() or (HERE / n).read_text() != text]
    report["checks"]["generated"] = {"facts": len(facts), "files": sorted(out), "stale": stale}
    ok &= not stale

    fact_tokens: dict[str, str] = {}
    for name, f in facts.items():
        for t in tokens(f["value"].replace("\\_", "_").replace("\\%", "%")):
            fact_tokens.setdefault(t, f"{name} <- {f['source']}: {f['how']}")
    allowed = {tokens(k)[0] if tokens(k) else k: v for k, v in ALLOWED.items()}

    # 2. no literal numbers in the source
    tex = (HERE / "bomwitness.tex").read_text()
    body = strip_tex(tex)
    literal = sorted({t for t in tokens(body) if t not in allowed})
    used_macros = sorted({m for m in re.findall(r"\\([A-Za-z]+)", tex) if m in facts})
    report["checks"]["source"] = {"literal_numbers_not_allowed": literal, "macros_used": len(used_macros),
                                  "allowed_identifiers_present": sorted({t for t in tokens(body) if t in allowed})}
    ok &= not literal

    # 3 and 4 need the PDF text
    if not shutil.which("pdftotext") or not pdf.exists():
        report["checks"]["pdf"] = {"skipped": "pdftotext or the PDF is missing"}
        print(json.dumps(report, indent=1))
        print("NUMBER CHECK:", "PARTIAL (generated files and source only; the PDF was not checked)" if ok else "FAIL")
        return 0 if ok else 1
    pages = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], capture_output=True, text=True, check=True).stdout.split("\f")
    pages = [p for p in pages if p.strip()]
    text = "\n".join(pages)
    bib = (HERE / "refs.bib").read_text()
    bib_flat = re.sub(r"[{}]", "", bib).replace("--", " ")
    bib_tokens = set(tokens(bib)) | set(tokens(bib_flat))
    n_refs = len(re.findall(r"^@", bib, flags=re.M))

    scan = text
    scan = re.sub(r"\[\d+(,\s*\d+)*\]", " ", scan)                                   # citations and reference labels
    scan = re.sub(r"(Table|Figure|Appendix|§)\s*[A-C0-9]+(\.\d+)?(\s+(to|and)\s+§\s*\d+(\.\d+)?)?", " ", scan)   # cross references
    for title in re.findall(r"\\section\{([^}]*)\}", tex):                             # section headings (set in capitals)
        scan = re.sub(r"\b\d\s+(?=%s)" % re.escape(title.upper()), " ", scan)
    for title in re.findall(r"\\subsection\{([^}]*)\}", tex):                          # subsection headings
        scan = re.sub(r"\b\d\.\d\s+(?=%s)" % re.escape(title.replace("'", chr(0x2019))[:12]), " ", scan)
    scan = re.sub(r"\b[1-6]\s+(?=(%s)\b)" % "|".join(STAGES), " ", scan)              # stage numbers in Figure 1
    scan = re.sub(r"^(\s+\.\d){6,}\s*$", " ", scan, flags=re.M)                       # point-release tick labels of Figure 2
    unexplained, explained = [], {"fact": 0, "allowed": 0, "bibliography": 0}
    seen_fact_tokens = set()
    for t in tokens(scan):
        if t in fact_tokens:
            explained["fact"] += 1
            seen_fact_tokens.add(t)
        elif t in allowed:
            explained["allowed"] += 1
        elif t in bib_tokens or t.rstrip(".") in bib_tokens or any(t in b for b in bib_tokens if len(t) > 5):
            explained["bibliography"] += 1
        else:
            unexplained.append(t)
    missing = []
    for m in used_macros:
        for t in tokens(facts[m]["value"].replace("\\%", "%")):
            if t not in set(tokens(text)):
                missing.append(f"{m}={facts[m]['value']}")
    report["checks"]["pdf"] = {"tokens_with_digits": sum(explained.values()) + len(unexplained), "explained": explained,
                               "distinct_fact_values_seen": len(seen_fact_tokens), "unexplained": sorted(set(unexplained)),
                               "macros_used_but_value_not_in_pdf": sorted(set(missing)), "references": n_refs}
    ok &= not unexplained and not missing

    # 4. page limits
    ref_page = next((i + 1 for i, p in enumerate(pages) if re.search(r"^\s*REFERENCES\s*$|\sREFERENCES\s*$", p, flags=re.M)), None)
    ack_page = next((i + 1 for i, p in enumerate(pages) if "ACKNOWLEDGMENTS" in p), None)
    body_end = ack_page or ref_page
    report["checks"]["pages"] = {"pages": len(pages), "body_ends_on_page": body_end, "references_start_on_page": ref_page,
                                 "limit_body": 5, "limit_total": 7}
    ok &= len(pages) <= 7 and body_end is not None and body_end <= 5

    report["ok"] = bool(ok)
    if json_out:
        json_out.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))
    print("NUMBER CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
