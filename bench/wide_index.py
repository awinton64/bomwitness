"""Index-coverage ablation: also index the large `packages`, `routing` and `telephony` feeds for one target.

The default file-path index leaves those feeds out to keep the one-time download near 180 MB. This script
builds a wider index (packages up to 1.5 MB, the size range the M4u implants are drawn from) in a separate
cache directory, so the default index and its results stay untouched. Then run:

  BW_CACHE_DIR=work/cache-wide python run_cases.py <image-id> --no-baselines --out results/r2/wide-index/cases

Usage: wide_index.py <release>:<target> [...]
"""
import json
import os
import sys
from pathlib import Path

from bomwitness.reference import ARCH_FEEDS, Reference

ROOT = Path(__file__).resolve().parent.parent
wide = ROOT / "work/cache-wide"
wide.mkdir(parents=True, exist_ok=True)
if not (wide / "payload").exists():
    os.symlink(ROOT / "work/cache/payload", wide / "payload")      # reuse the per-package hash manifests already fetched
out = []
for spec in sys.argv[1:]:
    release, target = spec.split(":")
    ref = Reference(release, target, wide)
    stats = ref.build_path_index(feeds=("target", "kmods") + ARCH_FEEDS, max_size=1_500_000)
    out.append({"release": release, "target": target, "arch": ref.arch, "feeds": ["target", "kmods", *ARCH_FEEDS],
                "max_package_size": 1_500_000, **stats})
    print(json.dumps(out[-1]), flush=True)
p = ROOT / "results/r2/wide-index/index.json"
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(out, indent=1))
