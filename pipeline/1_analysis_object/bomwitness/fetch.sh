#!/bin/sh
# Download the example firmware image and its sibling, and refuse either if its SHA-256 differs.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/objects.env"
OUT=${1:-"$HERE/../../.work/objects"}
mkdir -p "$OUT"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() {
  [ -f "$OUT/$1" ] || curl -fsSL --retry 3 -o "$OUT/$1" "$BASE_URL/$1"
  got=$(sha "$OUT/$1")
  [ "$got" = "$2" ] || { echo "sha256 mismatch for $1: $got" >&2; rm -f "$OUT/$1"; exit 1; }
  echo "ok $1"
}
get "$IMAGE" "$IMAGE_SHA256"
get "$SIBLING" "$SIBLING_SHA256"
