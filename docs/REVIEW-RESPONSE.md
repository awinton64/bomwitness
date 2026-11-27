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
