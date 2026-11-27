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
