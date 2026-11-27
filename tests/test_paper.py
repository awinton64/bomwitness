"""The paper may only quote numbers that the committed result files produce."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper"


@pytest.mark.skipif(not (ROOT / "results/r2/summary.json").exists() or not (PAPER / "gen_numbers.py").exists(), reason="paper or result files not present")
def test_paper_numbers_are_generated_and_checked():
    r = subprocess.run([sys.executable, str(PAPER / "gen_numbers.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    # Source and generated-file checks always run; the PDF and page-limit checks run when pdftotext is installed.
    r = subprocess.run([sys.executable, str(PAPER / "check_numbers.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr
    assert "NUMBER CHECK: FAIL" not in r.stdout
