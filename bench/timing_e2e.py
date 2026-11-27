"""End-to-end latency of the command line on the repository example, measured after the freeze.

The benchmark's per-case time (results/r2/summary.json, seconds_median) covers only the in-process verifier
call on an already unpacked and hashed tree with a warm reference cache. This script measures what a user
waits for: `bomwitness verify --image ...` as a separate process, which unpacks the image, hashes every file,
loads or downloads the reference and writes the report. It is a measurement of cost on one machine and one
image, not part of the held-out evaluation, and it changes no rule.

Usage: python bench/timing_e2e.py [--runs 5]     (run pipeline/pipeline_harness/bomwitness/run.sh first)
Writes results/r2/timing-e2e.json.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "pipeline/.work"
OBJ = ROOT / "pipeline/1_analysis_object/bomwitness"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    a = ap.parse_args()
    env = dict(line.split("=", 1) for line in (OBJ / "objects.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
    bw = WORK / "venv/bin/bomwitness"
    image, sibling = WORK / "objects" / env["IMAGE"], WORK / "objects" / env["SIBLING"]
    assert bw.exists() and image.exists() and sibling.exists(), "run the pipeline harness first"

    def run(cache: Path, out: Path) -> float:
        cmd = [str(bw), "verify", "--image", str(image), "--sibling-image", str(sibling), "--release", env["RELEASE"], "--target", env["TARGET"],
               "--cache", str(cache), "--sbom", str(OBJ / "declared-with-errors.cdx.json"), "--as-of", "2026-11-27",
               "--json", str(out / "report.json"), "--fail-on", "never"]
        t = time.time()
        subprocess.run(cmd, check=True, capture_output=True)
        return round(time.time() - t, 2)

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        cold = run(td / "cache", td)                      # empty cache: signed metadata and the touched packages are downloaded
        warm = [run(td / "cache", td) for _ in range(a.runs)]
        rep = json.loads((td / "report.json").read_text())
        cache_mb = round(sum(p.stat().st_size for p in (td / "cache").rglob("*") if p.is_file()) / 1e6, 1)
    doc = {
        "note": "post-freeze cost measurement on one machine; not part of the held-out evaluation (bench/timing_e2e.py)",
        "command": "bomwitness verify --image <official image> --sibling-image <official sibling> --release 24.10.8 --target ath79/generic --sbom declared-with-errors.cdx.json",
        "includes": "process start, carving and unpacking two SquashFS images, hashing every file, loading the reference, SBOM, CBOM and device-database checks, writing the report",
        "image": env["IMAGE"], "declared_components": rep["sbom"]["summary"]["declared"], "rootfs_files": rep["sbom"]["summary"]["rootfs_files"],
        "path_index": False,
        "cold_cache_seconds": cold, "cold_cache_includes": "network downloads of signed metadata and the reference packages the run touches",
        "warm_cache_seconds": sorted(warm), "warm_cache_seconds_median": sorted(warm)[len(warm) // 2], "runs": a.runs,
        "verifier_call_seconds_inside_the_last_run": rep["sbom"]["summary"]["seconds"],
        "reference_cache_megabytes": cache_mb,
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}",
    }
    (ROOT / "results/r2/timing-e2e.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(json.dumps({k: doc[k] for k in ("cold_cache_seconds", "warm_cache_seconds", "warm_cache_seconds_median", "verifier_call_seconds_inside_the_last_run", "reference_cache_megabytes")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
