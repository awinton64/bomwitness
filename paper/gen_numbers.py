"""Derive every result number the paper quotes from the committed result files.

Writes, next to this script:
  numbers.tex    one \\newcommand per fact; the paper uses these macros and no literal result numbers
  numbers.json   the same facts with the result file and the computation each one comes from
  tab-main.tex, tab-classes.tex, fig-drift.tex   generated table bodies and plot coordinates

Usage: gen_numbers.py [--check]   (--check regenerates in memory and fails if a file on disk differs)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RES = ROOT / "results/r2"

FACTS: dict[str, dict] = {}


def load(rel: str):
    return json.loads((ROOT / rel).read_text())


def fact(name: str, value, source: str, how: str = "") -> str:
    """Register a fact. `name` becomes a LaTeX macro, so letters only."""
    assert name.isalpha(), name
    value = str(value)
    if name in FACTS:
        assert FACTS[name]["value"] == value, (name, FACTS[name]["value"], value)
    FACTS[name] = {"value": value, "source": source, "how": how}
    return value


def n(x: int) -> str:
    return f"{x:,}"


def f3(x: float) -> str:
    return f"{x:.3f}"


def pct(x: float, digits: int = 1) -> str:
    return f"{100 * x:.{digits}f}"


def wilson(k: int, total: int, z: float = 1.96) -> tuple[float, float]:
    phat = k / total
    den = 1 + z * z / total
    mid = (phat + z * z / (2 * total)) / den
    half = z * ((phat * (1 - phat) / total + z * z / (4 * total * total)) ** 0.5) / den
    return mid - half, mid + half


TOOLS = [("bw_feed_only", "Fo"), ("bw_no_snapshot", "Ns"), ("bw", "Bw"), ("bomtrace", "Bt"), ("syft_diff", "Sy"), ("cvebin_diff", "Cv")]
DBS = [("honest", "Hon"), ("colluding", "Col"), ("stripped", "Str"), ("unaware", "Una"), ("all", "All")]
KINDS = [("M1_omitted", "M1", "omitted"),
         ("M2_other_release_version", "M2", "other-release version"),
         ("M2b_fabricated_version", "M2b", "fabricated version"),
         ("M3_phantom", "M3", "phantom"),
         ("M4_implant", "M4", "implant"),
         ("M4u_implant_unindexed_feed", "M4u", "implant, unindexed"),
         ("M5_swapped_binary", "M5", "swapped binary"),
         ("M6_patched_binary", "M6", "patched byte")]
LETTERS = {"M1": "MOne", "M2": "MTwo", "M2b": "MTwoB", "M3": "MThree", "M4": "MFour", "M4u": "MFourU", "M5": "MFive", "M6": "MSix"}


def build() -> dict[str, str]:
    FACTS.clear()
    out: dict[str, str] = {}
    SJ = "results/r2/summary.json"
    s = load(SJ)
    h, t = s["splits"]["heldout"], s["splits"]["tuning"]
    run = load("results/r2/RUN.json")
    RV = "results/r2/review-r3.json"
    rv = load(RV)

    # ---- data set
    fact("nHeldImages", len(h["images"]), SJ, "len(splits.heldout.images)")
    fact("nTuneImages", len(t["images"]), SJ, "len(splits.tuning.images)")
    fact("nImages", len(h["images"]) + len(t["images"]), SJ, "held-out plus tuning images")
    archs_h = {im["arch"] for im in h["clean"]["images"].values()}
    archs_all = archs_h | {im["arch"] for im in t["clean"]["images"].values()}
    fact("nArchHeld", len(archs_h), SJ, "distinct splits.heldout.clean.images[*].arch")
    fact("nArchAll", len(archs_all), SJ, "distinct arch over both splits")
    fact("nTargetsHeld", len({(im["release"], im["target"]) for im in h["clean"]["images"].values()}), SJ, "distinct (release, target), held-out")
    fact("nHeldCases", n(h["cases"]), SJ, "splits.heldout.cases")
    fact("nTuneCases", n(t["cases"]), SJ, "splits.tuning.cases")
    fact("nAllCases", n(h["cases"] + t["cases"]), SJ, "held-out plus tuning cases")
    de = rv["distinct_errors"]
    assert de["heldout"]["condition_rows"] == h["cases"] and de["tuning"]["condition_rows"] == t["cases"]
    fact("nDistinctErr", n(de["heldout"]["distinct_errors"]), RV, "distinct_errors.heldout.distinct_errors")
    fact("nAllDistinctErr", n(de["heldout"]["distinct_errors"] + de["tuning"]["distinct_errors"]), RV, "distinct errors, held-out plus tuning")
    fact("kPerClass", s["k"], SJ, "k")
    fact("seed", s["seed"], SJ, "seed")
    fact("freezeCommit", run["commit"][:7], "results/r2/RUN.json", "commit[:7]")
    fact("bomtraceCommit", s["bomtrace_commit"][:7], SJ, "bomtrace_commit[:7]")
    fact("nBomErrCases", h["by_db"]["colluding"]["bw"]["cases"], SJ, "splits.heldout.by_db.colluding.bw.cases")
    fact("nUnawareCases", h["by_db"]["unaware"]["bw"]["cases"], SJ, "splits.heldout.by_db.unaware.bw.cases")
    fact("nMFourUCases", h["by_kind"]["M4u_implant_unindexed_feed"]["unaware"]["bw"]["cases"], SJ, "by_kind.M4u.unaware.bw.cases")
    fact("kUnindexed", h["by_kind"]["M4u_implant_unindexed_feed"]["unaware"]["bw"]["cases"] // len(h["images"]), SJ, "M4u cases per held-out image")

    # ---- main table: precision / recall per database condition and tool
    rows = []
    names = {"honest": "honest", "colluding": "colluding", "stripped": "stripped", "unaware": "unaware", "all": "all cases"}
    for db, dbl in DBS:
        cells = []
        for tool, tl in TOOLS:
            m = h["by_db"][db][tool]
            src = f"splits.heldout.by_db.{db}.{tool}"
            p = "n/a" if m["precision"] is None else fact(f"p{dbl}{tl}", f3(m["precision"]), SJ, src + ".precision")
            r = fact(f"r{dbl}{tl}", f3(m["recall"]), SJ, src + ".recall")
            fact(f"tp{dbl}{tl}", n(m["tp"]), SJ, src + ".tp")
            # BomTrace needs the database as input: where its verifier produced no result at all, say so instead of "found none".
            ran = rv["baselines_without_database"]["bomtrace"].get(db, {}).get("verifier_produced_a_result", 1)
            cells.append("unsupported" if tool == "bomtrace" and not ran else f"{p} / {r}")
        cases = fact(f"cases{dbl}", n(h["by_db"][db]["bw"]["cases"]), SJ, f"splits.heldout.by_db.{db}.bw.cases")
        rule = "\\midrule\n" if db == "all" else ""
        rows.append(f"{rule}{names[db]} & {cases} & " + " & ".join(cells) + " \\\\")
    out["tab-main.tex"] = "% generated by gen_numbers.py\n\\def\\tabmainrows{%\n" + "\n".join(rows) + "\n}\n"

    # ---- intervals and per-image minima
    for db, dbl in (("colluding", "Col"), ("unaware", "Una")):
        for tool, tl in (("bw", "Bw"), ("bw_no_snapshot", "Ns"), ("bw_feed_only", "Fo")):
            m = h["by_db"][db][tool]
            lo, hi = wilson(m["tp"], m["cases"])
            fact(f"lo{dbl}{tl}", f3(lo), SJ, f"Wilson 95% lower bound from by_db.{db}.{tool}.tp and cases")
            fact(f"hi{dbl}{tl}", f3(hi), SJ, f"Wilson 95% upper bound from by_db.{db}.{tool}.tp and cases")
            fact(f"min{dbl}{tl}", f3(m["recall_per_image_min"]), SJ, f"by_db.{db}.{tool}.recall_per_image_min")
    pv = rv["recall_per_heldout_image"]
    for cond, dbl in (("bom_level", "Col"), ("unaware", "Una")):
        for tool, tl in (("bw", "Bw"), ("bw_no_snapshot", "Ns"), ("bw_feed_only", "Fo")):
            v = pv[cond][tool]
            assert f3(v["min"]) == f3(h["by_db"]["colluding" if cond == "bom_level" else "unaware"][tool]["recall_per_image_min"])
            src = f"recall_per_heldout_image.{cond}.{tool}"
            fact(f"imgMin{dbl}{tl}", f3(v["min"]), RV, src + ".min")
            fact(f"imgMax{dbl}{tl}", f3(v["max"]), RV, src + ".max")
            fact(f"imgMed{dbl}{tl}", f3(v["median"]), RV, src + ".median")
            fact(f"imgPerfect{dbl}{tl}", v["images_with_every_error_found"], RV, src + ".images_with_every_error_found")
    bwd = rv["baselines_without_database"]
    fact("btStrNoResult", bwd["bomtrace"]["stripped"]["rows"] - bwd["bomtrace"]["stripped"]["verifier_produced_a_result"], RV,
         "baselines_without_database.bomtrace.stripped: rows - verifier_produced_a_result")
    fact("btColRan", bwd["bomtrace"]["colluding"]["verifier_produced_a_result"], RV, "baselines_without_database.bomtrace.colluding.verifier_produced_a_result")
    fact("syStrCredited", bwd["syft_diff_stripped_credited_total"], RV, "baselines_without_database.syft_diff_stripped_credited_total")
    assert set(k for k, v in bwd["syft_diff_stripped_by_class"].items() if v["credited"]) == {"M3_phantom"}
    fact("caseFp", h["by_db"]["all"]["bw"]["case_fp"], SJ, "splits.heldout.by_db.all.bw.case_fp")
    fact("nErrFalsePositives", len(h["errors"]["false_positives"]), SJ, "len(splits.heldout.errors.false_positives)")

    # ---- ablations (colluding condition) and grade C
    for tool, tl in (("bw_A_only", "Ao"), ("bw_B_only", "Bo")):
        m = h["by_db"]["colluding"][tool]
        fact(f"rCol{tl}", f3(m["recall"]), SJ, f"by_db.colluding.{tool}.recall")
        fact(f"tpCol{tl}", n(m["tp"]), SJ, f"by_db.colluding.{tool}.tp")
        fact(f"pCol{tl}", f3(m["precision"]), SJ, f"by_db.colluding.{tool}.precision")
    m = h["by_db"]["honest"]["bw_with_db"]
    fact("tpHonWithDb", n(m["tp"]), SJ, "by_db.honest.bw_with_db.tp")
    fact("rHonWithDb", f3(m["recall"]), SJ, "by_db.honest.bw_with_db.recall")
    m = h["by_db"]["unaware"]["bw_B_only"]
    fact("rUnaBo", f3(m["recall"]), SJ, "by_db.unaware.bw_B_only.recall")
    m = h["by_db"]["colluding"]["bw_no_normalize"]
    fact("pColNoNorm", f3(m["precision"]), SJ, "by_db.colluding.bw_no_normalize.precision")
    fact("cleanFpNoNorm", m["clean_fp"], SJ, "by_db.colluding.bw_no_normalize.clean_fp")

    # ---- per-class table (appendix)
    rows = []
    for kind, short, label in KINDS:
        cond = "unaware" if kind.startswith(("M4", "M5", "M6")) else "colluding"
        k = h["by_kind"][kind]
        cells = []
        for tool, tl in (("bw_feed_only", "Fo"), ("bw_no_snapshot", "Ns"), ("bw", "Bw")):
            m = k[cond][tool]
            tp = fact(f"k{LETTERS[short]}{tl}", m["tp"], SJ, f"by_kind.{kind}.{cond}.{tool}.tp")
            cells.append(tp)
        cases = fact(f"k{LETTERS[short]}Cases", k[cond]["bw"]["cases"], SJ, f"by_kind.{kind}.{cond}.bw.cases")
        base = []
        for tool, tl in (("bomtrace", "Bt"), ("syft_diff", "Sy"), ("cvebin_diff", "Cv")):
            if cond == "colluding":
                a = fact(f"k{LETTERS[short]}{tl}Hon", k["honest"][tool]["tp"], SJ, f"by_kind.{kind}.honest.{tool}.tp")
                b = fact(f"k{LETTERS[short]}{tl}Col", k["colluding"][tool]["tp"], SJ, f"by_kind.{kind}.colluding.{tool}.tp")
                c = fact(f"k{LETTERS[short]}{tl}Str", k["stripped"][tool]["tp"], SJ, f"by_kind.{kind}.stripped.{tool}.tp")
                base.append(f"{a} / {b} / {c}")
            else:
                a = fact(f"k{LETTERS[short]}{tl}Una", k["unaware"][tool]["tp"], SJ, f"by_kind.{kind}.unaware.{tool}.tp")
                base.append(f"{a}")
        rows.append(f"{short} & {label} & {cases} & " + " & ".join(cells) + " & " + " & ".join(base) + " \\\\")
    out["tab-classes.tex"] = "% generated by gen_numbers.py\n\\def\\tabclassrows{%\n" + "\n".join(rows) + "\n}\n"

    m6 = h["by_kind"]["M6_patched_binary"]["unaware"]
    fact("patchMissNoSnap", m6["bw"]["cases"] - m6["bw_no_snapshot"]["tp"], SJ, "by_kind.M6.unaware: cases - bw_no_snapshot.tp")
    sys.path.insert(0, str(ROOT))
    from bomwitness import crypto
    fact("nAlgPatterns", len(crypto.ALGORITHMS), "bomwitness/crypto.py", "len(ALGORITHMS)")

    # ---- clean controls
    c = h["clean"]["totals"]
    fact("cleanDeclared", n(c["declared"]), SJ, "splits.heldout.clean.totals.declared")
    fact("cleanVerA", n(c["verdicts"]["verified_A"]), SJ, "clean.totals.verdicts.verified_A")
    fact("cleanVerAPct", pct(c["verified_A_share"]), SJ, "clean.totals.verified_A_share")
    fact("cleanVerB", c["verdicts"]["verified_B"], SJ, "clean.totals.verdicts.verified_B")
    fact("cleanUnver", c["verdicts"]["unverifiable"], SJ, "clean.totals.verdicts.unverifiable")
    fact("cleanAlarms", c["bw_hard"], SJ, "clean.totals.bw_hard")
    fact("cleanAlarmPct", pct(c["bw_hard"] / c["declared"], 2), SJ, "clean.totals.bw_hard / declared")
    fact("cleanFiles", n(c["files"]), SJ, "clean.totals.files")
    fact("cleanAccounted", n(c["accounted"]), SJ, "clean.totals.accounted")
    fact("cleanCode", n(c["code"]), SJ, "clean.totals.code")
    fact("cleanCodeAccounted", n(c["code"] - c["orphan_code"]), SJ, "clean.totals.code - orphan_code")
    meta = sum(im["unverifiable_reasons"].get("metadata-only package with no files to check", 0) for im in h["clean"]["images"].values())
    fact("cleanUnverMeta", meta, SJ, "sum of clean.images[*].unverifiable_reasons[metadata-only]")
    fact("cleanUnverMoved", c["verdicts"]["unverifiable"] - meta, SJ, "unverifiable minus metadata-only")
    syh = [im["clean_findings_honest"]["syft_diff"] for im in h["clean"]["images"].values()]
    sys_ = [im["clean_findings_stripped"]["syft_diff"] for im in h["clean"]["images"].values()]
    fact("syftCleanMin", min(syh), SJ, "min clean.images[*].clean_findings_honest.syft_diff")
    fact("syftCleanMax", max(syh), SJ, "max clean.images[*].clean_findings_honest.syft_diff")
    fact("syftCleanStrMin", min(sys_), SJ, "min clean.images[*].clean_findings_stripped.syft_diff")
    fact("syftCleanStrMax", max(sys_), SJ, "max clean.images[*].clean_findings_stripped.syft_diff")

    fact("cleanPassPct", pct(c["verified_share"]), SJ, "clean.totals.verified_share")
    fact("cleanUnverPct", pct(c["verdicts"]["unverifiable"] / c["declared"]), SJ, "clean.totals.verdicts.unverifiable / declared")

    # ---- worked example: the committed pipeline output
    EJ = "pipeline/4_analysis_output/bomwitness/report-with-errors.json"
    ex = load(EJ)
    tri = ex["triage"]
    fact("exDeclared", ex["sbom"]["summary"]["declared"], EJ, "sbom.summary.declared")
    fact("exPass", tri["automatic_pass"], EJ, "triage.automatic_pass")
    fact("exFail", tri["automatic_fail"], EJ, "triage.automatic_fail")
    exv = ex["sbom"]["summary"]["verdicts"]
    fact("exFailDeclared", sum(exv.get(k_, 0) for k_ in ("wrong_version", "wrong_component", "absent")), EJ,
         "sbom.summary.verdicts: wrong_version + wrong_component + absent (declared claims that fail)")
    assert tri["automatic_pass"] + int(FACTS["exFailDeclared"]["value"]) + tri["needs_review"] + tri["unverifiable"] == ex["sbom"]["summary"]["declared"]
    fact("exReview", tri["needs_review"], EJ, "triage.needs_review")
    fact("exUnver", tri["unverifiable"], EJ, "triage.unverifiable")
    fact("exFiles", ex["sbom"]["summary"]["rootfs_files"], EJ, "sbom.summary.rootfs_files")
    fact("exFilesAccounted", ex["sbom"]["summary"]["files_accounted"], EJ, "sbom.summary.files_accounted")
    cb = ex["cbom"]["findings"]
    fact("exDeprecated", sum(1 for f_ in cb if f_["class"] == "deprecated_algorithm"), EJ, "cbom.findings with class deprecated_algorithm")
    fact("exDbDisagree", len(ex["device_db"]["findings"]), EJ, "len(device_db.findings)")

    def tex(x: str) -> str:
        return x.replace("_", "\\_").replace("~", "\\textasciitilde{}")
    import re
    rows = []
    hard = [f_ for f_ in ex["sbom"]["findings"] if f_["class"] in ("wrong_version", "absent", "undeclared_component", "wrong_component", "undeclared_file", "bytes_differ")]
    for f_ in hard:
        d_ = f_["detail"]
        m_ = re.match(r"declared (\S+); actual (\S+)\.", d_)
        if m_:
            ev = f"declared {m_.group(1)}; bytes are the publisher's build {m_.group(2)}"
        elif f_["class"] == "absent":
            ev = "no file of the reference package is in the image"
        elif f_["class"] == "undeclared_component":
            m_ = re.match(r"(\d+) file\(s\) present, byte-identical to reference (\S+) (\S+)", d_)
            ev = f"{m_.group(1)} files byte-identical to {m_.group(2)} {m_.group(3)}, not in the BOM"
        else:
            ev = d_
        rows.append(f"SBOM & \\vd{{{tex(f_['class'])}}} & {tex(f_['component'])} & {f_['grade']} & {tex(ev)} \\\\")
    for f_ in cb:
        if f_["class"] == "undeclared_certificate":
            m_ = re.match(r"CN=([^,]+),", f_["detail"])
            rows.append(f"CBOM & \\vd{{{tex(f_['class'])}}} & certificate {tex(m_.group(1)) if m_ else ''} & {f_['grade']} & in the image's CA bundle, not in the CBOM \\\\")
        elif f_["class"] not in ("deprecated_algorithm", "provider_unverified", "algorithm_not_evidenced"):
            raise AssertionError(f"example finding of class {f_['class']} is not in the table")
        if f_["class"] in ("provider_unverified", "algorithm_not_evidenced"):
            who = f_["asset"]
            d_ = f_["detail"]
            if f_["class"] == "provider_unverified":
                m_ = re.match(r"the CBOM says (\S+) provides (\S+); the SBOM check of \S+ ended in (\S+)", d_)
                ev = f"CBOM names it as provider of {m_.group(2)}, but its SBOM check ended in \\vd{{{tex(m_.group(3))}}}"
            else:
                ev = "no file of the named provider carries the algorithm's name"
            rows.append(f"cross & \\vd{{{tex(f_['class'])}}} & {tex(who.replace('@', ' in '))} & {f_['grade']} & {ev} \\\\")
    out["tab-example.tex"] = "% generated by gen_numbers.py from " + EJ + "\n\\def\\tabexamplerows{%\n" + "\n".join(rows) + "\n}\n"
    FACTS["example:table"] = {"value": " ".join(rows), "source": EJ, "how": "sbom.findings and cbom.findings, classes and versions as reported (table only)"}

    # ---- misses
    mg = h["errors"]["miss_groups"]
    fact("nMisses", sum(mg.values()), SJ, "sum(splits.heldout.errors.miss_groups)")
    fact("missImplant", sum(v for k, v in mg.items() if k.startswith("M4u")), SJ, "miss_groups M4u*")
    fact("missPhantom", sum(v for k, v in mg.items() if k.startswith("M3")), SJ, "miss_groups M3*")
    fact("missFabricated", sum(v for k, v in mg.items() if k.startswith("M2b")), SJ, "miss_groups M2b*")

    # ---- tuning split, for comparison
    for db, dbl in (("colluding", "Col"), ("unaware", "Una")):
        m = t["by_db"][db]["bw"]
        fact(f"tune{dbl}R", f3(m["recall"]), SJ, f"splits.tuning.by_db.{db}.bw.recall")
        fact(f"tune{dbl}Tp", m["tp"], SJ, f"splits.tuning.by_db.{db}.bw.tp")
        fact(f"tune{dbl}Cases", m["cases"], SJ, f"splits.tuning.by_db.{db}.bw.cases")

    # ---- least similar sibling
    FJ = "results/r2/far-sibling/summary.json"
    f = load(FJ)["splits"]["heldout"]
    fact("farImages", len(f["images"]), FJ, "len(splits.heldout.images)")
    for db, dbl in (("colluding", "Col"), ("unaware", "Una")):
        m = f["by_db"][db]["bw"]
        fact(f"far{dbl}R", f3(m["recall"]), FJ, f"by_db.{db}.bw.recall")
        fact(f"far{dbl}P", f3(m["precision"]), FJ, f"by_db.{db}.bw.precision")
        fact(f"far{dbl}Tp", m["tp"], FJ, f"by_db.{db}.bw.tp")
        fact(f"far{dbl}Cases", m["cases"], FJ, f"by_db.{db}.bw.cases")

    # ---- sibling overlap
    OJ = "results/r2/sibling-overlap.json"
    ov = load(OJ)
    with_sib = [v for v in ov.values() if v.get("sibling")]
    fact("sibHave", len(with_sib), OJ, "entries with a sibling")
    fact("sibTwins", sum(1 for v in with_sib if v["identical_root_filesystem_contents"]), OJ, "identical_root_filesystem_contents")
    rest = [v["share_of_files_identical"] for v in with_sib if not v["identical_root_filesystem_contents"]]
    fact("sibRest", len(rest), OJ, "siblings that are not identical")
    fact("sibRestMinPct", pct(min(rest)), OJ, "min share_of_files_identical among the rest")
    fact("sibRestMaxPct", pct(max(rest)), OJ, "max share_of_files_identical among the rest")
    fact("sibNone", len(ov) - len(with_sib), OJ, "entries without a sibling")

    # ---- per-image table (appendix)
    rows = []
    for iid in h["images"]:
        im = h["clean"]["images"][iid]
        v = im["verdicts"]
        o = ov.get(iid, {})
        if not o.get("sibling"):
            sib = "none"
        elif o["identical_root_filesystem_contents"]:
            sib = "twin"
        else:
            sib = pct(o["share_of_files_identical"]) + "\\%"
        review = v.get("bytes_differ", 0) + v.get("label_unconfirmed", 0)
        dev = iid.split("-", 2)[2]
        rows.append(f"{dev} & {im['release']} & {im['arch'].replace('_', chr(92) + '_')} & {im['declared']} & {v.get('verified_A', 0)} & {v.get('verified_B', 0)} & "
                    f"{v.get('unverifiable', 0)} & {review} & {sib} \\\\")
    out["tab-images.tex"] = "% generated by gen_numbers.py\n\\def\\tabimagerows{%\n" + "\n".join(rows) + "\n}\n"
    FACTS["images:table"] = {"value": " ".join(rows), "source": SJ + " and " + OJ, "how": "splits.heldout.clean.images[*] verdicts; sibling-overlap share_of_files_identical (table only)"}

    # ---- wide index
    wide = sorted((RES / "wide-index/cases").glob("*.json"))

    def m4u(doc):
        rows_ = [c_ for c_ in doc["cases"] if c_["kind"] == "M4u_implant_unindexed_feed"]
        return sum(c_["tools"]["bw"]["tp"] for c_ in rows_), len(rows_)
    after = [m4u(json.loads(p.read_text())) for p in wide]
    before = [m4u(json.loads((RES / "cases" / p.name).read_text())) for p in wide]
    WJ = "results/r2/wide-index/cases/*.json"
    fact("wideImages", len(wide), WJ, "number of files")
    fact("wideAfter", sum(a for a, _ in after), WJ, "M4u cases named with the wide index")
    fact("wideBefore", sum(a for a, _ in before), "results/r2/cases/*.json", "the same M4u cases with the default index")
    fact("wideCases", sum(c_ for _, c_ in after), WJ, "M4u cases")
    wi = load("results/r2/wide-index/index.json")
    fact("wideMbMin", f"{min(w['downloaded_bytes'] for w in wi) / 1e6:.0f}", "results/r2/wide-index/index.json", "min downloaded_bytes / 1e6")
    fact("wideMbMax", f"{max(w['downloaded_bytes'] for w in wi) / 1e6:.0f}", "results/r2/wide-index/index.json", "max downloaded_bytes / 1e6")

    # ---- CBOM and cross-BOM
    tot = {"cases": 0, "tp": 0, "fp": 0, "fn": 0}
    classes = set()
    files = sorted((RES / "cbom").glob("*.json"))
    for p in files:
        doc = json.loads(p.read_text())
        classes |= set(doc["by_class"])
        for k_ in tot:
            tot[k_] += doc["overall"][k_]
    CJ = "results/r2/cbom/*.json"
    fact("cbomImages", len(files), CJ, "number of files")
    fact("cbomClasses", len(classes), CJ, "distinct by_class keys")
    fact("cbomCases", n(tot["cases"]), CJ, "sum overall.cases")
    fact("cbomTp", n(tot["tp"]), CJ, "sum overall.tp")
    fact("cbomExpected", n(tot["tp"] + tot["fn"]), CJ, "sum overall.tp + fn")
    fact("cbomMissed", tot["fn"], CJ, "sum overall.fn")
    fact("cbomExtra", tot["fp"], CJ, "sum overall.fp")

    # ---- reference drift
    DJ = "results/r2/drift.json"
    d = load(DJ)
    rel = d["releases"]
    fact("driftReleases", len(rel), DJ, "len(releases)")
    by = {r["release"]: r for r in rel}
    keys = (("feeds_only", "Fo"), ("feeds_manifest", "Ma"), ("feeds_manifest_snapshot", "Sn"))
    for name, tag in (("24.10.0", "OldTwentyFour"), ("24.10.8", "NewTwentyFour"), ("23.05.0", "OldTwentyThree"), ("23.05.6", "NewTwentyThree")):
        r = by[name]
        fact(f"drift{tag}Age", n(r["age_days"]), DJ, f"releases[{name}].age_days")
        for cfg, cl in keys:
            fact(f"drift{tag}{cl}", pct(r["configs"][cfg]["verified_A_share"]), DJ, f"releases[{name}].configs.{cfg}.verified_A_share")
            fact(f"drift{tag}{cl}Alarms", len(r["configs"][cfg]["hard_findings"]), DJ, f"len(releases[{name}].configs.{cfg}.hard_findings)")
        fact(f"drift{tag}Relabelled", r["components_whose_feed_label_changed"], DJ, f"releases[{name}].components_whose_feed_label_changed")
        fact(f"drift{tag}Declared", r["declared"], DJ, f"releases[{name}].declared")
    fact("driftSnapAlarmsTotal", sum(len(r["configs"]["feeds_manifest_snapshot"]["hard_findings"]) for r in rel), DJ, "sum of hard findings with a snapshot over all releases")
    fact("driftFeedAlarmsTotal", sum(len(r["configs"]["feeds_only"]["hard_findings"]) for r in rel), DJ, "sum of hard findings, feeds only, over all releases")
    fact("driftSnapMinPct", pct(min(r["configs"]["feeds_manifest_snapshot"]["verified_A_share"] for r in rel)), DJ, "min verified_A_share with a snapshot")
    fact("driftSnapMaxPct", pct(max(r["configs"]["feeds_manifest_snapshot"]["verified_A_share"] for r in rel)), DJ, "max verified_A_share with a snapshot")
    for name, tag in (("24.10.8", "TwentyFour"), ("23.05.6", "TwentyThree")):
        b = d["shared_base_feed"][name]
        fact(f"republished{tag}Pct", pct(b["share_republished"]), DJ, f"shared_base_feed[{name}].share_republished")
        fact(f"republished{tag}", b["republished_after_release_build"], DJ, f"shared_base_feed[{name}].republished_after_release_build")
        fact(f"baseFeed{tag}", b["base_feed_packages"], DJ, f"shared_base_feed[{name}].base_feed_packages")
    order = sorted(rel, key=lambda r: tuple(int(x) for x in r["release"].split(".")))
    ticks = ",".join(r["release"] for r in order)
    ticklabels = ",".join("." + r["release"].rsplit(".", 1)[1] for r in order)
    plots = []
    styles = {"feeds_only": ("feeds only", "mark=o, mark size=1.3pt, densely dashed"), "feeds_manifest": ("+ release manifest", "mark=triangle*, mark size=1.5pt"),
              "feeds_manifest_snapshot": ("+ sibling snapshot", "mark=square*, mark size=1.1pt, thick")}
    series = sorted({r["release"].rsplit(".", 1)[0] for r in order})
    for cfg, _ in keys:
        for i, ser in enumerate(series):
            coords = " ".join(f"({r['release']},{pct(r['configs'][cfg]['verified_A_share'])})" for r in order if r["release"].startswith(ser + "."))
            extra = ", forget plot" if i else ""
            plots.append(f"\\addplot[black, {styles[cfg][1]}{extra}] coordinates {{{coords}}};")
            if not i:
                plots.append(f"\\addlegendentry{{{styles[cfg][0]}}}")
    out["fig-drift.tex"] = f"% generated by gen_numbers.py from {DJ}\n\\def\\driftticks{{{ticks}}}\n\\def\\driftticklabels{{{ticklabels}}}\n\\def\\driftplots{{%\n" + "\n".join(plots) + "\n}\n"
    for r in order:  # every plotted point is a fact, so the checker can account for it
        for cfg, cl in keys:
            FACTS[f"plot:{r['release']}:{cfg}"] = {"value": pct(r["configs"][cfg]["verified_A_share"]), "source": DJ,
                                                  "how": f"releases[{r['release']}].configs.{cfg}.verified_A_share (figure only)"}

    # ---- OpenWrt's published BOMs
    BJ = "results/r2/official-bom.json"
    ob = load(BJ)
    fact("obImages", len(ob), BJ, "number of images")
    fact("obClaims", n(sum(v["bom_components"] for v in ob.values())), BJ, "sum bom_components")
    fact("obVerified", n(sum(v["verdicts"].get("verified_A", 0) + v["verdicts"].get("verified_B", 0) for v in ob.values())), BJ, "sum verified_A + verified_B")
    fact("obWrongVersion", sum(v["verdicts"].get("wrong_version", 0) for v in ob.values()), BJ, "sum verdicts.wrong_version")
    fact("obWrongVersionImages", sum(1 for v in ob.values() if v["verdicts"].get("wrong_version", 0)), BJ, "images with a wrong_version verdict")
    fact("obAbsent", sum(v["verdicts"].get("absent", 0) for v in ob.values()), BJ, "sum verdicts.absent")
    fact("obUnverifiable", sum(v["verdicts"].get("unverifiable", 0) for v in ob.values()), BJ, "sum verdicts.unverifiable")
    fact("obBytesDiffer", sum(v["verdicts"].get("bytes_differ", 0) for v in ob.values()), BJ, "sum verdicts.bytes_differ")
    fact("obVerA", n(sum(v["verdicts"].get("verified_A", 0) for v in ob.values())), BJ, "sum verdicts.verified_A")
    fact("obVerB", sum(v["verdicts"].get("verified_B", 0) for v in ob.values()), BJ, "sum verdicts.verified_B")
    assert rv["official_bom"]["verdicts"]["verified_A"] == sum(v["verdicts"].get("verified_A", 0) for v in ob.values())
    assert sum(sum(v["verdicts"].values()) for v in ob.values()) == sum(v["bom_components"] for v in ob.values())
    assert rv["official_bom"]["wrong_version_where_the_reference_label_extends_the_declared_one"] == rv["official_bom"]["wrong_version_total"]
    beyond = [len(v["components_in_image_not_in_bom"]) for v in ob.values()]
    fact("obBeyondMin", min(beyond), BJ, "min len(components_in_image_not_in_bom)")
    fact("obBeyondMax", max(beyond), BJ, "max len(components_in_image_not_in_bom)")
    fact("obBeyondTotal", sum(beyond), BJ, "sum len(components_in_image_not_in_bom)")
    fact("obBeyondImages", sum(1 for b_ in beyond if b_), BJ, "images with at least one package beyond the BOM")
    fact("obBeyondFiles", sum(v["their_files"] for v in ob.values()), BJ, "sum their_files")
    fact("obOrphanCode", sum(v["executable_files_unaccounted"] for v in ob.values()), BJ, "sum executable_files_unaccounted")

    # ---- inventory from bytes alone
    IJ = "results/r2/inventory.json"
    inv = load(IJ)
    fact("invNamed", n(sum(v["correct_names"] for v in inv.values())), IJ, "sum correct_names")
    fact("invInstalled", n(sum(v["installed_packages_with_files"] for v in inv.values())), IJ, "sum installed_packages_with_files")
    fact("invInstalledAll", n(sum(v["installed_packages"] for v in inv.values())), IJ, "sum installed_packages")
    fact("invWrong", sum(len(v["extra"]) for v in inv.values()), IJ, "sum len(extra)")
    fact("invSyftMin", min(v["syft_components_database_removed"] for v in inv.values()), IJ, "min syft_components_database_removed")
    fact("invSyftMax", max(v["syft_components_database_removed"] for v in inv.values()), IJ, "max syft_components_database_removed")
    fact("invCveMin", min(v["cvebin_products"] for v in inv.values()), IJ, "min cvebin_products")
    fact("invCveMax", max(v["cvebin_products"] for v in inv.values()), IJ, "max cvebin_products")

    # ---- downstream fork case study
    KJ = "results/r2/case-study-immortalwrt.json"
    cs = load(KJ)
    p1, p2 = cs["part1_against_upstream"], cs["part2_against_own_publisher"]
    fact("forkRelease", cs["subject"]["release"], KJ, "subject.release")
    fact("forkDeclared", p1["declared"], KJ, "part1_against_upstream.declared")
    fact("forkOwnVerified", p2["verdicts"].get("verified_A", 0) + p2["verdicts"].get("verified_B", 0), KJ, "part2 verified_A + verified_B")
    fact("forkOwnFindings", sum(p2["hard_findings"].values()), KJ, "sum part2.hard_findings")
    fact("forkOwnUnver", p2["verdicts"].get("unverifiable", 0), KJ, "part2.verdicts.unverifiable")
    fact("forkUpVerA", p1["verdicts"]["verified_A"], KJ, "part1.verdicts.verified_A")
    fact("forkUpVerAPct", pct(p1["verdicts"]["verified_A"] / p1["declared"], 0), KJ, "part1 verified_A / declared")
    fact("forkUpWrongVersion", p1["verdicts"]["wrong_version"], KJ, "part1.verdicts.wrong_version")
    fact("forkUpBytesDiffer", p1["verdicts"]["bytes_differ"], KJ, "part1.verdicts.bytes_differ")
    fact("forkUpAbsent", p1["verdicts"]["absent"], KJ, "part1.verdicts.absent")
    fact("forkUpOrphans", p1["hard_findings"]["undeclared_file"], KJ, "part1.hard_findings.undeclared_file")
    fact("forkExeSame", p1["executables_byte_identical_to_upstream_image"], KJ, "part1.executables_byte_identical_to_upstream_image")
    fact("forkExeTotal", p1["executables_total"], KJ, "part1.executables_total")
    fact("forkFilesSame", p1["files_byte_identical_to_upstream_image"], KJ, "part1.files_byte_identical_to_upstream_image")
    fact("forkFilesTotal", p1["files_total"], KJ, "part1.files_total")
    om = p2["omitted_component_found_by_database_condition"]
    fact("forkOmitted", len(om), KJ, "len(part2.omitted_component_found_by_database_condition)")
    fact("forkOmittedFound", sum(1 for o in om if o["honest"] and o["colluding"] and o["stripped"]), KJ, "omitted components found in all three database conditions")

    # ---- cost
    secs = [im["seconds_median"] for im in h["clean"]["images"].values()]
    fact("secMin", f"{min(x['bw'] for x in secs):.2f}", SJ, "min clean.images[*].seconds_median.bw")
    fact("secMax", f"{max(x['bw'] for x in secs):.2f}", SJ, "max clean.images[*].seconds_median.bw")
    fact("secBomtrace", f"{max(x['bomtrace'] for x in secs):.2f}", SJ, "max seconds_median.bomtrace")
    fact("secSyft", f"{max(x['syft'] for x in secs):.1f}", SJ, "max seconds_median.syft")
    TJ = "results/r2/timing-e2e.json"
    te = load(TJ)
    fact("eTwoEWarm", f"{te['warm_cache_seconds_median']:.1f}", TJ, "warm_cache_seconds_median (post-freeze cost measurement)")
    fact("eTwoECold", f"{te['cold_cache_seconds']:.1f}", TJ, "cold_cache_seconds (post-freeze cost measurement)")
    RJ = "results/r2/reference-index.json"
    ri = load(RJ)
    full = [r for r in ri["targets"] if r["downloaded_bytes"] > 100e6]
    fact("indexSecMin", f"{min(r['seconds'] for r in full):.0f}", RJ, "min seconds over full index builds")
    fact("indexSecMax", f"{max(r['seconds'] for r in full):.0f}", RJ, "max seconds over full index builds")
    fact("indexMbMin", f"{min(r['downloaded_bytes'] for r in full) / 1e6:.0f}", RJ, "min downloaded_bytes / 1e6")
    fact("indexMbMax", f"{max(r['downloaded_bytes'] for r in full) / 1e6:.0f}", RJ, "max downloaded_bytes / 1e6")
    fact("indexGbTotal", f"{ri['total_downloaded_bytes'] / 1e9:.1f}", RJ, "total_downloaded_bytes / 1e9")
    fact("indexTargets", len(ri["targets"]), RJ, "len(targets)")
    fact("indexPkgsMin", n(min(r["path_index_packages"] for r in full)), RJ, "min path_index_packages")
    fact("indexPkgsMax", n(max(r["path_index_packages"] for r in full)), RJ, "max path_index_packages")

    # ---- post-freeze check
    PJ = "results/r2/postfreeze-check/COMPARISON.json"
    pf = load(PJ)["images"]
    fact("postImages", len(pf), PJ, "len(images)")
    fact("postCases", sum(v["cases"] for v in pf.values()), PJ, "sum images[*].cases")
    fact("postDiffs", sum(len(v["score_differences"]) for v in pf.values()), PJ, "sum len(score_differences)")

    macros = ["% generated by paper/gen_numbers.py from the committed result files; do not edit"]
    for name, f_ in FACTS.items():
        if ":" in name:
            continue
        macros.append(f"\\newcommand{{\\{name}}}{{{f_['value']}}}")
    out["numbers.tex"] = "\n".join(macros) + "\n"
    out["numbers.json"] = json.dumps(FACTS, indent=1, sort_keys=True) + "\n"
    return out


def main() -> int:
    out = build()
    if "--check" in sys.argv:
        stale = [name for name, text in out.items() if not (HERE / name).exists() or (HERE / name).read_text() != text]
        if stale:
            print("stale generated files:", ", ".join(stale))
            return 1
        print(f"{len(out)} generated files are current ({len(FACTS)} facts)")
        return 0
    for name, text in out.items():
        (HERE / name).write_text(text)
    print(f"wrote {', '.join(out)} ({len(FACTS)} facts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
