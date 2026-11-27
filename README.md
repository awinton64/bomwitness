# BOMwitness (round 1 spike)

BOMwitness checks a declared bill of materials for an IoT firmware image against the bytes of
the image, without trusting the package database that ships inside the firmware.

Status: feasibility spike for the SafeIoT Hackathon 2026, Track 2. It is not a finished tool.
The repository directory is still called `bomcheck`; the tool was renamed because that name is
crowded on GitHub.

## Why

Existing open-source SBOM tools for Linux firmware read the device's own package database
(`/usr/lib/opkg/status` on OpenWrt). A verifier built on that inventory can only tell whether
the BOM agrees with what the firmware says about itself. If the database is stale, stripped
(common in vendor firmware), or edited to agree with the BOM, such a verifier has nothing to
check against.

BOMwitness grades evidence instead:

| Grade | Evidence | Used by BOMwitness |
|---|---|---|
| A | A file is byte-identical to the file in the official reference package (feed index SHA-256, then per-file SHA-256) | yes |
| B | Intrinsic to the firmware bytes: versioned file names, SONAMEs, and the version marker the reference build of the same component carries | yes |
| C | The firmware's own package database | no, by design |

Per declared component it returns `verified_A`, `verified_B`, `wrong_version`, `absent`,
`bytes_differ` (rebuild or modification, needs review), `consistent_label_differs` or
`unverifiable`. Per image it reports `undeclared_component`, `undeclared_file` and `stale`.
A first CBOM check covers X.509 certificates found in the image.

## What the spike showed

Three official OpenWrt 24.10.8 device images (MIPS big-endian, MIPS little-endian, AArch64),
466 seeded single-error cases, fixed random seed. Full data is in `results/spike-r1/`.

| Device database condition | Cases | BOMwitness precision / recall | Syft-based diff precision / recall |
|---|---|---|---|
| honest (database untouched, BOM wrong) | 143 | 0.991 / 0.783 | 1.0 / 1.0 |
| colluding (database edited to agree with the BOM) | 143 | 0.991 / 0.783 | n/a / 0.0 |
| stripped (database removed) | 72 | 1.0 / 0.903 | n/a / 0.0 |
| unaware (files implanted, swapped or patched; BOM and database unchanged) | 108 | 1.0 / 0.981 | n/a / 0.0 |
| all | 466 | 0.995 / 0.848 | 1.0 / 0.307 |

Read these with the following in mind.

- The Syft-based diff is our own comparison script around Syft's inventory. Syft is an SBOM
  generator, not a verifier, and it behaves as designed.
- Findings that already appear on the unmodified image with a correct BOM are subtracted for
  both tools. For BOMwitness that is 4 `bytes_differ` findings across the three images
  (busybox on all three, e2fsprogs on one): the shared 24.10 package feed was rebuilt after
  the release, so the same version label now has different bytes.
- With an honest database, the database-reading baseline is better (recall 1.0 against 0.78).
  The two are complementary. BOMwitness misses most fabricated version labels on components
  whose builds carry no version marker (recall 0.39 on that class).
- Swapped and patched binaries are caught by hash comparison, so 100 percent there is
  expected, not impressive. The meaningful numbers are version checking and attribution.
- On unmodified images, 79 to 80 percent of declared components were byte-verified (grade A),
  3 percent supported by a version marker (grade B), and 7 to 8 percent had no checkable bytes.
- cve-bin-tool 3.4's signature checkers, run without any CVE database, identified 8 to 11
  products per image out of 147 to 170 components.
- Certificate CBOM spike on one image: 30 seeded cases, 40 expected findings, all found, no
  extra findings. These are parse-and-compare checks; the hard part of CBOM verification
  (primitives compiled into libraries) is not started.
- Observation, not yet a verified result: the officially published per-target OpenWrt BOMs
  leave out 3, 10 and 21 packages that are installed in the three device images, including
  Wi-Fi drivers and radio firmware (`results/spike-r1/official-bom-gap.json`).

## Known limits

- OpenWrt opkg releases only. The usign signature on the feed index is not yet checked, so the
  trust anchor is TLS to downloads.openwrt.org.
- The reference feed for arch packages is mutable. Version labels that changed without a
  content change cannot be confirmed or refuted from bytes.
- Attributing unaccounted files to a package uses name and SONAME guesses and fetches many
  candidate packages (1,799 packages, 307 MB in this spike). A per-release path index should
  replace it.
- Nothing from a firmware image or package is executed. Encrypted images are out of scope.

## Reproduce

Python 3.10 or newer. Syft is optional and only used by the baseline.

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m bomwitness.fetch                      # 3 images, official BOMs, sha256 checked
for i in archer-c7-v5 mi-router-4a-gigabit gl-mt6000; do
  .venv/bin/python -m bomwitness.unpack work/dl/$i/*sysupgrade.bin work/rootfs/$i
done
.venv/bin/python scripts/clean_run.py                     # correct BOM, unmodified images
.venv/bin/python scripts/spike_eval.py archer-c7-v5       # needs tools/syft/syft (Syft 1.57.2)
.venv/bin/python scripts/spike_crypto.py archer-c7-v5
.venv/bin/python scripts/official_bom_gap.py
.venv/bin/python scripts/summarize.py
```

Image URLs and SHA-256 values are in `images.json`. Firmware, packages and extracted trees
live under `work/`, which is not committed.

## AI assistance

This spike was written with an AI coding agent (Claude) working for the author.

## License

MIT. See `LICENSE`.
