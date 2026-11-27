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

# Third review (of public head `155cb60`) and what changed

A third independent read of the public repository and the submission files confirmed the benchmark numbers, the
packaging and the earlier corrections, and returned three blocking defects with some smaller notes. All of them
are about what a finding or a document says, not about a verdict. This section answers each one.

## 1. Findings that rest on a snapshot hid their source and could name the wrong build

The reviewer reused the synthetic feed of `tests/test_verify.py`: the firmware holds an older build of `gamma`
than the feed now ships and the BOM omits it. With a local snapshot, the finding read "byte-identical to
reference gamma 2024.01.01~abc-r1", the feed's current label, although the file matched the snapshot's record of
`2023.12.01~aaa-r1`. A stale note for the declared case carried no trust qualifier.

| What was wrong | What changed |
|---|---|
| The candidate merge for unexplained files kept one version per package and no source per file. | It now keeps, per file, which input matched it (the feed, or which snapshot). The candidate sets, the ranking and the grouping are the same code. The detail text is built from the per-file source: "1 file(s) present: 1 with the SHA-256 that the supplied snapshot (not authenticated by this run) [name] records for gamma 2023.12.01~aaa-r1; none of them has the SHA-256 of the feed's current gamma 2024.01.01~abc-r1". A package matched partly by the feed and partly by a snapshot reports both parts with both versions. |
| The finding did not say which input supported it. | Every verdict and finding that rests on a snapshot, a sibling image or another release names that input (in square brackets after the trust words, or as "release X feed") and carries an `evidence` field in the JSON report: input, trust, version, number of files. |
| The stale note had no trust qualifier. | "firmware has X, verified against the supplied snapshot (not authenticated by this run) [name]; the reference feed now ships Y". The same for a sibling image and for another release. |
| A snapshot's own name could contain the word "official". | The word is dropped from the displayed name of any source that was not authenticated. |

Tests: the reviewer's two cases are reproduced exactly (`test_omitted_component_matched_only_by_a_snapshot_names_the_snapshot_and_its_version`,
`test_stale_note_that_rests_on_a_snapshot_names_it_and_its_trust`), plus one per trust level, one for a package
matched by both sources with and without the file-path index, and one for the name rule.

## 2. Claim scope in the paper, the slides, the video and the README

| Finding | Change |
|---|---|
| Slide 4 and the narration at 1:19 said each claim is compared with the authenticated reference. CBOM and AI-BOM claims are checked against local artifacts. | The figure (paper Figure 1 and slide 4) now labels stage 4 "per SBOM claim", stage 5 "CBOM, AI-BOM against the image's own files; provider rule uses the SBOM verdict", and the reference box "SBOM claims only", with the sibling qualified ("if its hash is in the image list"). Narration and captions: "compare each SBOM claim with the authenticated reference. CBOM and AI-BOM claims are checked against the image's own files; a CBOM algorithm must also be provided by an SBOM component that verified." The paper's introduction says "verifies SBOM claims"; Appendix E has a paragraph "What uses no signed reference"; the README has the same paragraph. |
| Grade A was still framed as a positive file-hash match, although zero matched files can pass. | Grade A is now described everywhere as "no compared file differs", with the consequence stated: a pass can rest on few matched files, in the extreme on none. Paper Table 1 and Appendix E, slide 3, the narration, the README table, `docs/DESIGN.md`, `docs/LIMITATIONS.md` item 8, the report's introduction and its verdict text. A grade A reason with zero matched files now ends "no file was positively matched, so grade A here means only that no compared file differs". The rule is unchanged. |
| The paper and a slide said configuration files are not compared at all. The code counts identical ones as matches and skips those that differ. | Corrected in the paper (Table 1, Appendix E), slide 3, the narration and the documents. |
| The other-release grade A reason was one sentence about one file, with no coverage count, while the report promises counts on every grade A line. | The reason now gives counts: differing files that match the other release's build, files that match neither build, files that match this release, files skipped and missing. It also says that the other release's reference is authenticated through its own signed checksum file. The documents state what the counts make visible: one such file is enough for grade A, even when another matches neither build. That rule is unchanged and is listed as a limit. |
| Paper page 1 said a hash comparison finds a flipped byte wherever a reference covers the file. | "only where bytes are compared, unmasked, with a same-version reference (116 of 120 patches without a sibling snapshot, 120 with one)". Section 4.3 adds that a patch inside a skipped configuration file would not be reported either. |

## 3. The harness exit contract in the paper

The paper said the harness exits non-zero on fail, review, CBOM and AI-BOM findings. It does not: it calls
`bomwitness verify --fail-on never`, compares the SBOM and CBOM findings with the expected ones, exits non-zero
only when they differ, and does not run the AI-BOM example. Section 5 now says exactly that, and separately that
the command line called directly exits non-zero by default on automatic-fail, `bytes_differ`, CBOM and AI-BOM
findings, deprecated-algorithm observations excepted. The README and the two pipeline READMEs say the same.

## Smaller notes

- The compact output did not list `--alt-release`. It now prints one trust line per alternate release with the
  key that signed its checksum file, and the report lists it among the reference inputs (test in
  `tests/test_boms.py`).
- The certificate fallback (matching by subject when the declaration has no fingerprint and the subject is
  unique in the image) is now mentioned in the paper's Appendix E and in the README.

## Check that no verdict moved

`bomwitness/verify.py` changed again, so the check of the second review was repeated and a wider one added.

- `bench/verdict_check.py`, previous head's code: 14 images, 2,604 rows (1,860 held-out), 0 differences.
- `bench/verdict_check.py`, this round's code: 14 images, 2,604 rows (1,860 held-out), 0 differences.
  Output: `results/r2/r5-verdict-check/COMPARISON.json`.
- `bench/full_digest.py`, old code against new code directly, to cover what the case files do not record: all
  fourteen images, six configurations, three declarations each (252 runs), 35,814 component verdict records and
  13,365 findings compared without their text, 0 differences. Output:
  `results/r2/r5-verdict-check/FULL-DIGEST.json`.

A unit test fails if `verify.py`, `reference.py` or `bench/run_cases.py` differ from the files those checks ran.
The frozen run's result files and the freeze tag are untouched.

## Not changed

- No verdict rule. In particular grade A still passes with zero matched files and with one file matching another
  release; both are now disclosed and counted in the reason text.
- `bomwitness inventory` still takes a component's version from the manifest or the first snapshot that lists
  it. It reports names only in the paper (no version accuracy is claimed), and it was left alone.
- The compact output still cuts a detail at 110 characters, so a long input name can fall outside the line. The
  trust lines at the top name every input, and the JSON and Markdown reports carry the full text.

# Fourth review (of public head `401c018`) and what changed

A fourth independent read confirmed the release, the checksums, the paper's number check and the earlier
verdict checks, and returned three remaining truthfulness defects. All three are about what a finding or a
document says. No verdict rule changed.

## 1. A wrong_version finding that another release changes did not name that release

The reviewer's case: the synthetic `duo` package, firmware with the primary release's `2.0-r1` bytes, the BOM
declaring `1.9-r1`, markers off. Alone the run ends in `label_unconfirmed`. With `--alt-release 98.01.0`, whose
build of `1.9-r1` has other bytes, it ends in `wrong_version`, and the detail said only "another release", with
no `evidence` field. The detail now reads "the files present match this release's reference build 2.0-r1; the
98.01.0 release build of the declared version (1.9-r1) has different bytes in 2 of the 2 file(s) compared
(that release's reference is authenticated through its own checksum file, signed by usign key ..., and feed
indexes); ...", and the component and the finding carry `evidence` = {input `release 98.01.0 feed`, trust
`signed reference`, version `1.9-r1`, files 2}, as the positive other-release path does. The branch is taken
under exactly the same condition as before; only the first release that triggers it is now remembered for the
text. Test: `test_a_finding_that_another_release_changes_names_that_release` (it fails on the previous code).

## 2. Grade A wording on configuration files and hash matches

- The statement "identical configuration files count, differing ones are skipped" is now scoped to the
  comparison with this release's package. A sibling snapshot's record leaves configuration and account files
  out, so they are not compared with a snapshot at all; snapshot and other-release comparisons use the raw
  SHA-256. Changed in the paper's Appendix E, the README's grade table, `docs/DESIGN.md`, `docs/LIMITATIONS.md`,
  the module docstring of `verify.py` and the report's grade A paragraph.
- The other-release grade A reason said how many files present "have this release's reference SHA-256" and
  counted files that matched only after a build date was masked. It now gives the raw matches and, separately,
  "N more match it only after embedded build-date strings are masked (their raw SHA-256 differs)". Test:
  `test_other_release_reason_separates_masked_from_raw_matches`.

## 3. The harness exit contract in section 5

Section 5 now says that on a completed run the harness exits non-zero only if the SBOM and CBOM findings differ
from the expected ones, and that a failure in setup, fetching, preprocessing or verification also exits
non-zero (the scripts use `set -e`).

## Check that no verdict moved

- `bench/verdict_check.py`, previous head's code (`401c018`): 14 images, 2,604 rows (1,860 held-out),
  0 differences.
- `bench/verdict_check.py`, this round's code: 14 images, 2,604 rows (1,860 held-out), 0 differences.
  Output: `results/r2/r6-verdict-check/COMPARISON.json`.
- `bench/full_digest.py`, previous head against this round's code: 252 runs, 35,814 component records,
  13,365 findings, 0 differences (the two digest files are byte-identical).
  Output: `results/r2/r6-verdict-check/FULL-DIGEST.json`.

The unit test that guards the rule files now checks against these files. The example reports in
`pipeline/4_analysis_output/bomwitness/` were regenerated; only the grade A paragraph changed.

## Not changed

- No verdict rule, the freeze tag or the frozen run's result files.
- Slides and video: they say "configuration files that differ are skipped", which stays true in every
  comparison, and they do not describe the harness exit status or the other-release finding.
