# Results

- `r2/` is the round 2 evaluation. Everything the documentation quotes comes from here.
  - `RUN.json`: commit and time window of the frozen full run.
  - `cases/<image>.json`: per-image seeded-error cases with every tool's score, the clean controls and timings.
  - `summary.json`, `SUMMARY.md`: pooled tables (`bench/summarize.py`). `HEADLINE.md`: the README block
    (`bench/headline.py`). `ERROR-ANALYSIS.md`: every miss and false alarm (`bench/error_analysis.py`).
  - `cbom/<image>.json`: seeded CBOM and cross-BOM cases.
  - `drift.json`, `official-bom.json`, `inventory.json`, `sibling-overlap.json`, `reference-index.json`,
    `case-study-immortalwrt.json`: the other measurements described in `docs/EVALUATION.md`.
  - `far-sibling/`: the benchmark rerun (BOMwitness only) with the least similar sibling as snapshot source.
  - `wide-index/`: two held-out images rerun with the `packages`, `routing` and `telephony` feeds indexed as well.
  - `postfreeze-check/`: three images rerun after the post-freeze fixes, with `COMPARISON.json`.
- `spike-r1/` is the round 1 feasibility spike (three images, an earlier and simpler verifier). It is kept
  for the record and is not quoted anywhere. Its scripts are in `scripts/round1/` and no longer run against
  the current package.
