# Results

- `r2/` is the round 2 evaluation. Everything the documentation quotes comes from here.
  - `RUN.json`: commit and time window of the frozen full run.
  - `cases/<image>.json`: per-image seeded-error cases with every tool's score, the clean controls and timings.
  - `summary.json`, `SUMMARY.md`: pooled tables (`bench/summarize.py`). Their "all" rows pool every row. For BomTrace
    that includes the stripped rows in which its verifier returned no result (480 held-out, 192 tuning), so its
    pooled recall there is coverage-inclusive; the README headline gives the figure over the rows where it ran. `HEADLINE.md`: the README block
    (`bench/headline.py`). `ERROR-ANALYSIS.md`: every miss and false alarm (`bench/error_analysis.py`).
  - `cbom/<image>.json`: seeded CBOM and cross-BOM cases.
  - `drift.json`, `official-bom.json`, `inventory.json`, `sibling-overlap.json`, `reference-index.json`,
    `case-study-immortalwrt.json`: the other measurements described in `docs/EVALUATION.md`.
  - `far-sibling/`: the benchmark rerun (BOMwitness only) with the least similar sibling as snapshot source.
  - `wide-index/`: two held-out images rerun with the `packages`, `routing` and `telephony` feeds indexed as well.
  - `postfreeze-check/`: three images rerun after the post-freeze fixes, with `COMPARISON.json`.
  - `r4-verdict-check/COMPARISON.json`: all fourteen images rerun (BOMwitness and its ablations) after the
    reason strings and the snapshot trust field changed, compared with `cases/` by `bench/verdict_check.py`.

The reason strings stored in these result files are the wording of the run that produced them. Files from
the frozen run and the measurements before the second review still say "every file byte-identical to the
reference package" and "official sibling image". The tool no longer writes those words: a grade A reason now
states what was compared, with counts, and a snapshot is described by whether it was authenticated
(`docs/EVALUATION.md`, "Changes after the freeze", item 6). Verdicts, labels and scores are unaffected.
