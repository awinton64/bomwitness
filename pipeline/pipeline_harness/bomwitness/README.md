# BOMwitness harness

BOMwitness verifies a declared SBOM (and CBOM, AI-BOM) for an IoT firmware image against the bytes of the
image, without trusting the package database that ships inside the firmware.

## Flow

| Stage | What happens | Where |
|---|---|---|
| 1 analysis object | Fetch one official OpenWrt image and one sibling image, check their SHA-256; two declared BOMs are provided (one correct, one with six seeded errors) | `1_analysis_object/bomwitness/` |
| 2 preprocess | Carve and extract the SquashFS root filesystem; optionally build the full reference index | `2_preprocess/bomwitness/` |
| 3 security analysis | `bomwitness verify` fetches and signature-checks the publisher's reference metadata, authenticates the sibling image against the release's image list, grades every claim against the bytes, cross-checks the CBOM against the SBOM verdicts, and looks for model files | `3_security_analysis/bomwitness/` |
| 4 analysis output | JSON and Markdown reports; one example run is committed | `4_analysis_output/bomwitness/` |

## Run it

```sh
sh pipeline/pipeline_harness/bomwitness/run.sh
```

Prerequisites: Python 3.10 or newer, `curl`, network access to downloads.openwrt.org. The script creates
its own virtual environment under `pipeline/.work/`, installs BOMwitness from this checkout, runs the four
stages and compares the findings with `1_analysis_object/bomwitness/expected-findings.json`. It ends with
`PASS` or `FAIL`. A first run downloads about 20 MB and takes under a minute. `FULL_INDEX=1` also builds
the full file-path index (about 180 MB of downloads).

## Using it on another image

```sh
bomwitness verify --image firmware.bin --sbom declared.cdx.json --cbom declared-cbom.cdx.json \
    --release 24.10.8 --target ath79/generic --sibling-image official-sibling.bin \
    --json report.json --md report.md
```

The exit status is 1 when there are findings, so the command can gate a CI job. `--release` and `--target`
may be left out, in which case they are read from the firmware's `/etc/openwrt_release` and the report says
that the reference was chosen from the firmware's own description.

## Placing this in safeiot-supply-chain-pipeline

The `pipeline/` directory of the BOMwitness repository mirrors the layout of
`systemsecurity-uiuc/safeiot-supply-chain-pipeline`: copy each `<stage>/bomwitness/` directory to the same
stage there. The verification code itself is the `bomwitness` Python package; `run.sh` installs it from the
BOMwitness checkout, and in the pipeline repository that line becomes `pip install` of a tagged release.
