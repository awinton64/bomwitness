#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OBJ="$HERE/../../1_analysis_object/bomwitness"
. "$OBJ/objects.env"
WORK=${1:-"$HERE/../../.work"}
OUT=${2:-"$WORK/output"}
BW=${BOMWITNESS:-bomwitness}
mkdir -p "$OUT"
for name in correct with-errors; do
  $BW verify --rootfs "$WORK/rootfs" --name "$IMAGE" --release "$RELEASE" --target "$TARGET" --cache "$WORK/cache" \
     --sibling-image "$WORK/objects/$SIBLING" --sbom "$OBJ/declared-$name.cdx.json" --as-of 2026-11-27 \
     --json "$OUT/report-$name.json" --md "$OUT/report-$name.md" --fail-on never
done
