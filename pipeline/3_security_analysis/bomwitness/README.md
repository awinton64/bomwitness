# Stage 3, security analysis: BOMwitness

`bomwitness verify` checks every claim in the declared BOM against the bytes of the unpacked firmware and
grades the evidence:

- **A**: the component's files are byte-identical to the publisher's package (signed index, per-file SHA-256),
  with the version label taken from the feed index, the signed release manifest or the official sibling image.
- **B**: evidence inside the bytes themselves, such as the version marker that the reference build carries.
- **C**: the device's own package database. It is shown in its own section of the report and never decides
  a verdict, so a database that was edited to agree with a wrong BOM, or removed, changes nothing.

Per component the result is verified (A or B), wrong version, wrong component, absent, bytes differ (needs
review), label unconfirmed (needs review) or unverifiable. Per image it reports undeclared components and
unaccounted executable files. The CBOM part checks certificates and keys found in the image and requires
every declared algorithm to be provided by an SBOM component whose bytes verified and whose files carry the
algorithm's name. The AI-BOM part looks for model files by file header (for some formats, header plus file extension).

The verification code is the `bomwitness` Python package at the root of the BOMwitness repository
(`bomwitness/verify.py`, `crypto.py`, `aibom.py`, `devicedb.py`). `analyze.sh` runs it on the two example
declarations.

Consumes: `.work/rootfs/`, `.work/snapshot.json`, the reference cache and the declared BOMs.
Produces: a JSON report and a Markdown report per declared BOM.
