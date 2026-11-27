# Stage 1, analysis object: BOMwitness

BOMwitness analyses a firmware image together with the BOM that is declared for it.

- `objects.env` names the example firmware: the official OpenWrt 24.10.8 image for the TP-Link Archer C7 v5
  and one official sibling image of the same release and target. Both are fetched by `fetch.sh`, which
  refuses a file whose SHA-256 differs. Firmware is never committed.
- `declared-correct.cdx.json` is a correct CycloneDX 1.6 declaration for that image: 150 software components
  and 194 cryptographic assets (certificates, one key, algorithm entries with their providing component).
- `declared-with-errors.cdx.json` is the same document with six seeded errors. `expected-findings.json`
  lists the finding each one must produce.
- `make_example_boms.py` regenerates the three files from the unpacked image.

The shared BOM format material in `1_analysis_object/general/` (CycloneDX, SPDX) applies unchanged:
BOMwitness reads CycloneDX 1.4 to 1.6 JSON and SPDX 2.3 JSON.
