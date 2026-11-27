#!/bin/sh
# One verification run with all three BOM types: SBOM, CBOM and AI-BOM.
#   sh examples/aibom/unified.sh
#
# The subject is SYNTHETIC and says so in the report title: the unpacked root filesystem of the official OpenWrt
# image used by the pipeline example, plus the two placeholder "model" files of this directory (a format header
# followed by padding text, not models). The declared SBOM and CBOM are the pipeline example's documents with
# seeded errors; the declared AI-BOM is aibom-with-errors.cdx.json. Router images carry no models, so this shows
# that the three checks run in one workflow. It measures nothing about AI-BOM accuracy.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PIPE="$REPO/pipeline"
OBJ="$PIPE/1_analysis_object/bomwitness"
WORK="$PIPE/.work"
PY=${PYTHON:-python3}
. "$OBJ/objects.env"
if [ ! -x "$WORK/venv/bin/bomwitness" ]; then
  mkdir -p "$WORK"
  "$PY" -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install -q "$REPO"
fi
export BOMWITNESS="$WORK/venv/bin/bomwitness"
if [ ! -d "$WORK/rootfs" ] || [ ! -f "$WORK/snapshot.json" ]; then
  sh "$OBJ/fetch.sh" "$WORK/objects"
  sh "$PIPE/2_preprocess/bomwitness/preprocess.sh" "$WORK"
fi
DEV="$WORK/device-with-models"
rm -rf "$DEV"
cp -R "$WORK/rootfs" "$DEV"
cp -R "$HERE/rootfs/." "$DEV/"
"$BOMWITNESS" verify --rootfs "$DEV" --name "archer-c7-v5 plus 2 synthetic model files" \
   --release "$RELEASE" --target "$TARGET" --cache "$WORK/cache" --snapshot "$WORK/snapshot.json" \
   --sbom "$OBJ/declared-with-errors.cdx.json" --aibom "$HERE/aibom-with-errors.cdx.json" --as-of 2026-11-27 \
   --json "$WORK/unified.json" --md "$WORK/unified.md" --fail-on never
"$WORK/venv/bin/python" "$HERE/check_unified.py" "$WORK/unified.json" "$OBJ/expected-findings.json" "$HERE/expected-findings.json"
