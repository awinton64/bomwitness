"""Build the signed reference cache and file-path index for one or more release/target pairs.

Usage: build_reference.py <release>:<target> [...]   e.g. 24.10.8:ath79/generic
Prints one JSON line per pair. Packages are streamed, hashed and discarded; only manifests are kept.
"""
import json
import sys
from pathlib import Path

from bomwitness.reference import Reference

ROOT = Path(__file__).resolve().parent.parent
for spec in sys.argv[1:]:
    release, target = spec.split(":")
    ref = Reference(release, target, ROOT / "work/cache")
    stats = ref.build_path_index() if not ref.has_path_index else {"cached": True}
    print(json.dumps({"release": release, "target": target, **ref.provenance(), **stats}), flush=True)
