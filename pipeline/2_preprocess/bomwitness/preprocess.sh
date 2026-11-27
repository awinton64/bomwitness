#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../1_analysis_object/bomwitness/objects.env"
WORK=${1:-"$HERE/../../.work"}
BW=${BOMWITNESS:-bomwitness}
rm -rf "$WORK/rootfs"
$BW unpack "$WORK/objects/$IMAGE" "$WORK/rootfs" > "$WORK/unpack.json"
if [ "${FULL_INDEX:-0}" = "1" ]; then
  $BW index --release "$RELEASE" --target "$TARGET" --cache "$WORK/cache" > "$WORK/index.json"
fi
echo "preprocess done"
