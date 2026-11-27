# Response to an independent review

Before publication the paper, the repository and the pitch video were reviewed by a second AI model from a
different model family, working read-only on an export of commit `0091965`. Its verdict was "fix before
submitting", with three blockers. This file lists each finding and what changed. No verdict rule was
changed and no benchmark image was rerun in response: where a finding needed a number, it was computed from
result files that were already committed (`bench/review_r3.py`), or measured separately and labelled as a
post-freeze cost measurement (`bench/timing_e2e.py`).

Page numbers refer to `paper/bomwitness.pdf` in this repository.

## Blockers

| Finding | Change |
|---|---|
| The pitch shows no AI-BOM check. | `examples/aibom/unified.sh` runs the SBOM, CBOM and AI-BOM checks in one `bomwitness verify` call on an official image's files plus two synthetic placeholder model files, and checks the findings. The video's recorded run is that command; the two AI-BOM findings are on screen and narrated, and a banner states that the model files are synthetic. CI runs the script. |
| The inventory figure "1,939 of 1,950 installed packages" names the wrong denominator. | 2,083 packages are installed; 1,950 own at least one regular, non-symlink file in the image and are eligible; 1,939 of those are named. Paper section 4.7 (p. 5), README headline, `results/r2/review-r3.json`. |
| Grade A, the "signed reference" and the CBOM evidence are described more strongly than the code behaves. | Grade A is now described as implemented: the package's files that are present match the publisher's package, configuration files and three account files are not compared, build-date strings are masked, completeness is not required (paper Table 1 on p. 2 and Appendix E on p. 7; README; `docs/DESIGN.md`). "Signed" is replaced by the actual chain: one signature on a checksum file that pins indexes, manifest and image list by hash; signed shared indexes; packages pinned by index hash; files by SHA-256. The abstract no longer says CBOM claims use signed reference material: the CBOM checks compare the image with the declaration, and the provider rule accepts grade A or B. The command line now looks a sibling image up in the signed image list, and every report states what was authenticated and what was trusted as supplied (snapshot files, the cache). |
| The repository is not public. | Published with its development history and the tag `rules-frozen-r2a`. No commit was rewritten, so the freeze commit is `0f83a98` here as in the paper. |

## Major

| Finding | Change |
|---|---|
| BomTrace's stripped-database row should read "unsupported input", not "found none". | Its verifier exited without a result in all 480 stripped rows. Table 3 (p. 4), the README table and the slides say "unsupported"; the text explains the difference (section 4.2). |
| Syft-diff's 120 credited phantom rows and the adapter's naming penalty should be explicit. | Section 4.2 and the README state that the diff is credited with the 120 phantom rows and nothing else in the stripped condition, and that its low precision with an honest database is a penalty of our adapter. |
| Broad claims about "open tools" and vendor firmware. | Narrowed to "the open tools we evaluated". "Much vendor firmware" and "vendor firmware is usually a rebuild" are removed; the paper says OpenWrt's build system has an option that removes the database and that prevalence was not measured. EMBA is cited as a firmware-native analyser that was not run. |
| Report 900 distinct errors, not 1,860 cases; treat pooled intervals as descriptive; show image-level variability; state how candidates are chosen. | Abstract, Table 3 caption, section 4.1 and Appendix F. Recall per held-out image (minimum, median, maximum) replaces the Wilson intervals in the main text; the intervals moved to Appendix F with the caveat. Candidate pools are described in Appendix F and `docs/EVALUATION.md`. |
| The freeze covers the primary evaluation only; describe the post-freeze diff; do not claim the benchmark cannot reach the changed code. | Section 4.1, Appendix F and `docs/EVALUATION.md` ("What the freeze covers, and changes after it"). The earlier sentence that the benchmark does not take the changed path is withdrawn; the evidence offered is the frozen run and the rerun of three images (558 rows) with identical labels and scores. |
| The command line reads the device database although "it never reads the database". | Reworded: the verdicts never read it; the command line reads it only for the separate grade C section of the report. |
| Timing compares different things. | Section 4.7 and Appendix F say what each timer covers and that the figures are not comparable. `results/r2/timing-e2e.json` adds the end-to-end time of the command line (5.2 s warm, 13.7 s cold on the example). |
| Published-BOM totals are incomplete; the 34 disagreements are about label granularity; no evidence that a database verifier finds the same pattern. | Section 4.5 (pp. 4 to 5): 1,674 at grade A, 31 at grade B, 122 unverifiable, 34 `wrong_version`, 4 `bytes_differ`, 3 absent, which add up to 1,868. The 34 are described as a label-granularity disagreement. The sentence about a database-reading verifier is replaced by a statement that none was run. |
| Citations. | NIST IR 8425 is now cited for what section 2.2.2 says (the developer creates, gathers and stores component information; the documentation is the developer's). The Cyber Resilience Act is cited for Annex I, Part II, point 1 and Article 71. The 2026 joint minimum-elements guidance is cited next to the 2021 NTIA report it replaces. ECMA-424 is cited by edition; SPDX 2.3 has its own reference. Each was checked against the primary document. Asking builders for authenticated per-file references is presented as this project's proposal. "Would make the question moot" is removed; related work names the technique each paper uses. |

## Minor

| Finding | Change |
|---|---|
| The worked example's counts do not add up in the text. | 139 pass, 3 declared claims fail, 8 are unverifiable (150); the fourth failing finding is an image-level undeclared component. Table 2 now lists every finding except the deprecated-primitive observations, including the seeded `undeclared_certificate`. |
| The replay disclosure is small. | It is a full-width banner in large type, and the slide title says "Replay of a recorded run". |
| The 60 of 120 narration reads as "without the sibling". | It now says "with signed feeds only, and no manifest". |
| "Byte-identical twins" overstates the sibling comparison. | "The same regular-file paths and contents"; symlinks, metadata and the SquashFS container were not compared. |
| `paper/build.sh` could hide a failed number check behind a pipe. | It returns the checker's exit status. (It caught a real page-limit overrun during these edits.) |
| "Seven" seeded classes in `docs/LIMITATIONS.md`. | Eight. |
| README shorthand on performance and false alarms. | Scoped to what was measured; exit-status rules and the trust preconditions are spelled out. |
| "Magic bytes" overstates model detection. | Header for GGUF, TensorFlow Lite and HDF5; header plus file extension for safetensors, PyTorch archives and ONNX. |
| "OpenWrt binaries have no section headers", "frozen feeds never change". | Scoped to official builds with the default sstrip; frozen feeds are described as belonging to one point release and pinned by its signed checksum file. |

## Not changed, and why

- `bomwitness/verify.py`, `crypto.py`, `reference.py`, `aibom.py` and the benchmark scripts are untouched, so
  the partial-presence rule that let three phantom packages pass is still there. Changing it would need a
  fresh held-out set.
- `bomwitness/aibom.py` still says "magic bytes" in its docstring, because editing it would change a rule
  file that is identical to its state at the freeze. The documents describe the behaviour precisely.
- No firmware-native analyser was added as a baseline. The paper says so.

# Second review (of public head `3087589`) and what changed

The same reviewer re-checked the published repository, paper, slides and video. It found the AI-BOM, inventory
and publication blockers cured and the measured results consistent, and it asked for the remaining wording to
match what the code does: grade A is not byte identity, an unauthenticated snapshot is not "official", and
`profiles.json` is not signed. It also found three counting and labelling slips. Everything below is wording,
labelling and one pass-through field. No verdict rule changed, and that was checked by rerunning the benchmark
(last section).

## Grade A and "byte identity"

| Finding | Change |
|---|---|
| Slide 3, the narration and `report.py` still say grade A files are "byte-identical"; the code accepts a file that differs only inside build-date strings, and reasons say "every file". | Grade A is now described everywhere as a match of the compared, present files: SHA-256 equal to the reference package, configuration and account files that differ not compared, build-date strings masked, completeness not required. Slide 3, the narration (two sentences at 0:53), paper Table 1, README, `docs/DESIGN.md`, `docs/LIMITATIONS.md` item 8, the pipeline stage README, and a paragraph at the top of every Markdown report. |
| The per-component reason hides partial presence, masking and exclusions. | Every grade A reason now carries the counts, for example "9 of the 9 package file(s) present in the image have the reference package's SHA-256 (1 of them only after embedded build-date strings are masked)" or "1 of the 1 package file(s) present ...; 1 of the package's 2 files are not in the image". The second is what a phantom package that passes looks like in a report now. Tests: `test_grade_a_reason_states_masking_exclusions_and_partial_presence`. |
| "A flipped byte is found every time" (paper introduction, slide 7, narration, README). | Replaced by the measured statement: a flipped byte is found where a comparable reference covers the file, 120 of 120 one-byte patches with the sibling snapshot and 116 of 120 without it, and never inside a masked date string or an uncompared configuration file. (The review quotes 114 of 120 here; 114 is the fabricated-version count with the manifest. The one-byte-patch count without the snapshot is 116.) A test now ties the prose to the result file. |
| "Confirmed byte for byte" and "upstream's bytes" in the drift and fork results. | "Verified at grade A" in the paper (section 4.4, Figure 2, section 4.6), the README headline, the slides and the narration. |

## Authenticated, supplied, and what is signed

| Finding | Change |
|---|---|
| A local snapshot was marked `authenticated: false` in the JSON report while its findings said "official sibling image"; the same happens for an unlisted sibling, because the trust flag never reaches `verify()`. | A snapshot now carries a `trust` field (`authenticated`, `unlisted`, `supplied`) that the command line sets from its lookup and passes into `verify()`. A snapshot file is always `supplied`: the command line overwrites whatever the file says about its trust and its origin. Reasons use the field: "the sibling image (authenticated: its SHA-256 is in the image list pinned by the signed checksum file)", "the supplied sibling image (not authenticated: ...)" or "the supplied snapshot (not authenticated by this run)". No reason contains the word official. No verdict branch reads the field. Tests: `test_snapshot_trust_changes_reason_text_and_never_a_verdict` (five trust values, four cases, identical verdicts), `test_cli_never_takes_trust_from_a_snapshot_file_and_shows_it_in_the_compact_output` (a file that claims to be authenticated), `test_cli_sibling_image_trust_follows_the_hash_pinned_image_list`. |
| The compact command-line output shows no trust information. | It now prints, before the findings, the pinned key that signed the checksum file and one line per reference input: authenticated, or NOT authenticated and used as supplied. |
| The demo and the pipeline example use a local snapshot file. | Both now pass the sibling with `--sibling-image`, so the run itself looks the image's SHA-256 up in the release's image list. The committed example reports and the video's replay show "authenticated". |
| Several texts call `profiles.json` signed. | The signature is on `sha256sums`; `profiles.json` (the image list) is checked by its hash in that file. Corrected in `cli.py` (notes, warning, help), README, `docs/DESIGN.md`, `docs/LIMITATIONS.md`, `docs/EVALUATION.md`, `docs/EXTENDING.md`, two docstrings (`bomwitness/fetch.py`, `bench/drift.py`), the report header and the paper ("hash-pinned image list"). `docs/LIMITATIONS.md` no longer says "signed binary packages" or "signed release manifest". A test fails if "signed profiles.json" or "signed image list" comes back. |

## CBOM

| Finding | Change |
|---|---|
| The paper says keys are compared field by field; standalone keys are reconciled by fingerprint. | Paper section 3 and Appendix E, README and `docs/DESIGN.md`: certificates are matched by fingerprint and compared field by field; standalone keys are reconciled by fingerprint only. |
| The short description for the submission form says SBOM and CBOM are both checked against authenticated release packages. | Rewritten: the SBOM is checked against the publisher's packages; the CBOM is checked against what is found in the image, with each algorithm claim tied to an SBOM component that verified. |

## Counting and labelling

| Finding | Change |
|---|---|
| BomTrace's pooled recall (0.258 = 480/1,860) includes 480 unsupported rows without saying so. | Labelled coverage-inclusive in the paper's Table 3 caption, in the README table cell with a bullet that also gives the figure over the 1,380 rows where it produced a result (480, 0.348), and on slide 6. `results/README.md` says the same about the pooled rows of the frozen run's own `SUMMARY.md`, which is not regenerated. |
| "1,860 rows over three database conditions" (abstract, form abstract) and the same shorthand for 2,604 rows on page 1. | "1,440 BOM-level rows in three database conditions plus 420 unaware" in the abstract, the README headline and slide 6; "2,016 ... plus 588 unaware rows" on page 1. Generated from the result files. |
| Appendix F omits the M4u candidate pool. | Added (packages of the unindexed feed that are not installed). |
| `docs/EVALUATION.md` says seven held-out images were not rerun; it is eight of ten. | Corrected. |
| `docs/PROVENANCE.md` labels local Eastern times as UTC. | `scripts/provenance.py` now converts to UTC; the regenerated table is five hours later than before, and the file says so. Order and parentage were always right. |

The abstract was also shortened to 192 words, in case the submission form caps it at 200.

## Check that no verdict moved

`bomwitness/verify.py` is a rule file, and this round changed its reason strings and added the trust field. To
show that nothing else changed, `bench/run_cases.py` was rerun for BOMwitness and its five ablations on all
fourteen benchmark images, the ten held-out ones included, and `bench/verdict_check.py` compared every case and
every clean control with the committed files of the frozen run: labels, hits, false positives, extra findings,
the verdict for each seeded target, clean-control findings, verdict counts per configuration, label sources and
the components that did not verify.

- With the code of the previous commit: 14 images, 2,604 rows, 0 differences (402 reason strings differ, all from
  the one message reworded right after the freeze).
- With this round's code: 14 images, 2,604 rows (1,860 held-out), 0 differences, 1,200 reason strings reworded.

The baselines do not use the changed code and were not rerun. The sibling snapshot files have the same SHA-256
as in the frozen run. Output: `results/r2/r4-verdict-check/COMPARISON.json`. A unit test fails if `verify.py`
is edited again without rerunning the check. The paper reports the check in section 4.1 and Appendix F.

## Not changed

- The reason strings inside the committed result files of the frozen run keep their original wording
  (`results/README.md` says so). Rewriting them would have meant editing frozen results.
- The benchmark passes snapshot files to the verifier, so reasons recorded by a rerun say "supplied snapshot",
  although `bench/prepare.py` checked every sibling against the image list. `docs/DESIGN.md` notes this.
- The partial-presence rule itself. It is now visible in each reason, and changing it would need a new held-out set.
- The submission form is not open yet, so the form fields and the video upload route are still unverified.
