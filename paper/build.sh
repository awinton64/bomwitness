#!/bin/sh
# Build the paper: derive the numbers from the result files, compile with Tectonic, then check every number in the PDF.
#   sh paper/build.sh        (needs tectonic and pdftotext on PATH; PYTHON picks the interpreter)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON:-python3}
"$PY" "$HERE/gen_numbers.py"
(cd "$HERE" && tectonic bomwitness.tex)
# The check's own exit status decides: a pipe to tail would hide a failure, so the output goes to a file first.
status=0
"$PY" "$HERE/check_numbers.py" "$HERE/bomwitness.pdf" --json "$HERE/number-check.json" > "$HERE/.number-check.out" || status=$?
tail -1 "$HERE/.number-check.out"
rm -f "$HERE/.number-check.out"
exit "$status"
