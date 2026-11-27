#!/bin/sh
# Build the paper: derive the numbers from the result files, compile with Tectonic, then check every number in the PDF.
#   sh paper/build.sh        (needs tectonic and pdftotext on PATH; PYTHON picks the interpreter)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON:-python3}
"$PY" "$HERE/gen_numbers.py"
(cd "$HERE" && tectonic bomwitness.tex)
"$PY" "$HERE/check_numbers.py" "$HERE/bomwitness.pdf" --json "$HERE/number-check.json" | tail -1
