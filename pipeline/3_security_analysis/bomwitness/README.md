# Stage 3, security analysis: BOMwitness

`bomwitness verify` checks every claim in the declared BOM against the bytes of the unpacked firmware.
SBOM claims are compared with the publisher's authenticated reference and the evidence is graded:

- **A**: no compared file of the component differs from the publisher's package (authenticated index,
  per-file SHA-256). The files present in the image are compared; configuration files that differ are
  skipped, a file that differs only inside embedded build-date strings is accepted, and the package need
  not be complete, so a pass can rest on few matched files (in the extreme none); each grade A line of the
  report gives the counts. The version label is taken from the feed index, the release
  manifest (pinned by the signed checksum file) or the sibling image. `analyze.sh` passes the sibling with
  `--sibling-image`, so the run itself looks the image's SHA-256 up in the release's image list and the
  report says it was authenticated.
- **B**: evidence inside the bytes themselves, such as the version marker that the reference build carries.
- **C**: the device's own package database. It is shown in its own section of the report and never decides
  a verdict, so a database that was edited to agree with a wrong BOM, or removed, changes nothing.

Per component the result is verified (A or B), wrong version, wrong component, absent, bytes differ (needs
review), label unconfirmed (needs review) or unverifiable. Per image it reports undeclared components and
unaccounted executable files. The CBOM part compares the declaration with the certificates and keys found
in the image (no signed reference is involved) and requires every declared algorithm to be provided by an
SBOM component whose bytes verified and whose files carry the algorithm's name. The AI-BOM part looks for
model files by file header (for some formats, header plus file extension) and compares their hashes with
the declaration; `analyze.sh` does not exercise it.

`analyze.sh` calls `bomwitness verify` with `--fail-on never`, so it exits 0 whatever is found; the harness
then compares the SBOM and CBOM findings with the expected ones. Without that option the command exits 1
on findings (see the root README for the exact classes).

The verification code is the `bomwitness` Python package at the root of the BOMwitness repository
(`bomwitness/verify.py`, `crypto.py`, `aibom.py`, `devicedb.py`). `analyze.sh` runs it on the two example
declarations.

Consumes: `.work/rootfs/`, the sibling image in `.work/objects/`, the reference cache and the declared BOMs.
Produces: a JSON report and a Markdown report per declared BOM.
