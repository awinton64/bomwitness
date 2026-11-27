"""Baseline: cve-bin-tool's binary checkers as a database-free component identifier.

Runs only the version scanner (signature checkers over file contents). No CVE
database is downloaded or queried. Usage: <rootfs> <out.json>; writes
{product: {version: [files]}}.
Run with a Python environment that has cve-bin-tool installed.
"""
import json
import sys
from pathlib import Path

from cve_bin_tool.version_scanner import VersionScanner

root = Path(sys.argv[1]).resolve()
scanner = VersionScanner(should_extract=False)
found = {}
for info, path in scanner.recursive_scan(str(root)):
    found.setdefault(info.product, {}).setdefault(info.version, []).append(str(Path(path).resolve().relative_to(root)))
Path(sys.argv[2]).write_text(json.dumps(found, indent=1, sort_keys=True))
