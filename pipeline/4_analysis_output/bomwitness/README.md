# Stage 4, analysis output: BOMwitness

One representative run, produced by `pipeline_harness/bomwitness/run.sh` on the example image
(OpenWrt 24.10.8, TP-Link Archer C7 v5).

- `report-correct.md` and `report-correct.json`: the correct declaration. 142 of 150 software claims pass
  automatically, 8 are unverifiable (metadata packages that ship no files), and there are no findings.
- `report-with-errors.md` and `report-with-errors.json`: the declaration with six seeded errors. All six are
  found (omitted component, version from an older release, version that never existed, phantom component,
  trust anchor missing from the CBOM, algorithm claimed for a library that does not carry it), together with
  two cross-BOM consequences: the CBOM names `dropbear` and `busybox` as algorithm providers, and their
  SBOM claims no longer verify.

Each report has a triage table (automatic pass, automatic fail, needs review, unverifiable), the findings
with their evidence grade, a separate section for the device's own package database (grade C), the CBOM
and AI-BOM sections, the per-component table and a closing list of what the report does not establish.
The JSON file carries the same content plus the reference provenance (release, signing key, index trust).

The policy observations in the CBOM section (deprecated primitives named in binaries, one expired root
certificate) are present for the unmodified image as well. They are not BOM errors.
