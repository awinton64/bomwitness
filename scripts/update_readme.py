"""Regenerate results/r2/HEADLINE.md and paste it into the README between the headline markers."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
import headline  # noqa: E402

text = headline.build(ROOT / "results/r2")
(ROOT / "results/r2/HEADLINE.md").write_text(text)
readme = ROOT / "README.md"
new = re.sub(r"(<!-- headline:start -->\n).*?(<!-- headline:end -->)", lambda m: m.group(1) + text + m.group(2), readme.read_text(), flags=re.S)
readme.write_text(new)
print(text)
