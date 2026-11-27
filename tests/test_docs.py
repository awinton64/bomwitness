"""The documentation may only quote numbers that the committed result files produce."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results/r2"


@pytest.mark.skipif(not (RESULTS / "summary.json").exists(), reason="result files not present")
def test_readme_headline_block_is_generated_from_results():
    sys.path.insert(0, str(ROOT / "bench"))
    import headline
    want = headline.build(RESULTS)
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"<!-- headline:start -->\n(.*?)<!-- headline:end -->", readme, re.S)
    assert m, "README has no headline block"
    assert m.group(1) == want, "README headline block differs from bench/headline.py output; run scripts/update_readme.py"
    assert (RESULTS / "HEADLINE.md").read_text() == want


def test_no_em_dashes_or_private_paths_in_tracked_text():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    bad = []
    for f in files:
        p = ROOT / f
        if p.suffix not in (".md", ".py", ".sh", ".yml", ".toml", ".json", ".env", ".txt", ".tex", ".bib") or not p.is_file() or p.name == "test_docs.py":
            continue
        text = p.read_text(errors="replace")
        if chr(0x2014) in text:
            bad.append(f"{f}: em dash")
        if re.search(r"/Users/|/home/[a-z]+/|@gmail\.com", text):
            bad.append(f"{f}: private path or address")
    assert not bad, bad


def test_documents_reference_existing_result_files():
    for doc in ("README.md", "docs/EVALUATION.md", "docs/LIMITATIONS.md"):
        for ref in re.findall(r"`(results/r2/[^`*]+)`", (ROOT / doc).read_text()):
            if not (RESULTS / "summary.json").exists():
                continue
            assert (ROOT / ref.rstrip("/")).exists(), f"{doc} mentions {ref}, which is missing"


@pytest.mark.skipif(not (RESULTS / "summary.json").exists(), reason="result files not present")
def test_post_freeze_review_analysis_matches_the_committed_results():
    r = subprocess.run([sys.executable, str(ROOT / "bench/review_r3.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not (RESULTS / "summary.json").exists(), reason="result files not present")
def test_patch_counts_in_prose_match_the_results():
    """The prose says how many one-byte patches are found with and without the sibling snapshot; it must not say "every time"."""
    import json
    m6 = json.loads((RESULTS / "summary.json").read_text())["splits"]["heldout"]["by_kind"]["M6_patched_binary"]["unaware"]
    cases, with_snap, without = m6["bw"]["cases"], m6["bw"]["tp"], m6["bw_no_snapshot"]["tp"]
    assert with_snap == cases and without < cases
    readme = " ".join((ROOT / "README.md").read_text().split())
    limits = " ".join((ROOT / "docs/LIMITATIONS.md").read_text().split())
    assert f"all {cases} one-byte patches of the held-out set with the sibling snapshot, {without} of {cases} without it" in readme
    assert f"every one of the {cases} one-byte patches was reported with the sibling snapshot and {without} of {cases} without it" in limits
    for doc in ("README.md", "docs/DESIGN.md", "docs/LIMITATIONS.md", "docs/EVALUATION.md", "paper/bomwitness.tex"):
        text = (ROOT / doc).read_text()
        assert "flipped byte every time" not in text, doc
        assert "signed `profiles.json`" not in text and "signed profiles.json" not in text and "signed image list" not in text, doc


@pytest.mark.skipif(not (RESULTS / "r7-verdict-check/COMPARISON.json").exists(), reason="result files not present")
def test_reporting_changes_to_the_rule_file_left_every_verdict_unchanged():
    """verify.py changed after the freeze in what reasons and findings report, four times. Each change has a recorded rerun of
    every image with no difference, and the latest one is a rerun of this verify.py."""
    import json
    summary = json.loads((RESULTS / "summary.json").read_text())["splits"]
    for check in ("r4-verdict-check", "r5-verdict-check", "r6-verdict-check", "r7-verdict-check"):
        c = json.loads((RESULTS / check / "COMPARISON.json").read_text())
        for run in ("unchanged_code", "changed_code"):
            t = c[run]["totals"]
            assert t["differences"] == 0 and all(not v["differences"] for v in c[run]["images"].values()), check
            assert t["images"] == len(summary["heldout"]["images"]) + len(summary["tuning"]["images"])
            assert t["cases"] == summary["heldout"]["cases"] + summary["tuning"]["cases"] and t["heldout_cases"] == summary["heldout"]["cases"]
        changed, before = c["changed_code"]["totals"]["reason_strings_changed"], c["unchanged_code"]["totals"]["reason_strings_changed"]
        # round 4 reworded reasons that were still in the frozen wording; from round 5 on the previous code's reasons already differed from it
        assert (changed > before > 0) if check == "r4-verdict-check" else (changed >= before > 0), check
    # c is now the round 7 check: it must be a rerun of the rule files as they are in this tree
    full = json.loads((RESULTS / "r7-verdict-check/FULL-DIGEST.json").read_text())      # old code against new code, bench/full_digest.py
    assert full["differences"] == [] and full["images"] == c["changed_code"]["totals"]["images"] and full["component_records"] > 30000
    for f, blob in list(c["rule_file_blobs_at_rerun"].items()) + list(full["new_code_blobs"].items()):
        now = subprocess.run(["git", "hash-object", f], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        assert now == blob, f"{f} changed after the verdict check in results/r2/r7-verdict-check; rerun bench/verdict_check.py and bench/full_digest.py"
