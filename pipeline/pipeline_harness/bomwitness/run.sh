#!/bin/sh
# BOMwitness end to end, from a clean checkout to a checked result.
#   sh pipeline/pipeline_harness/bomwitness/run.sh
# Environment: FULL_INDEX=1 builds the full file-path index first (about 180 MB of downloads, one minute).
#              PYTHON=python3.x picks the interpreter (3.10 or newer).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PIPE=$(cd "$HERE/../.." && pwd)
REPO=$(cd "$PIPE/.." && pwd)
WORK="$PIPE/.work"
PY=${PYTHON:-python3}
mkdir -p "$WORK"
if [ ! -x "$WORK/venv/bin/bomwitness" ]; then
  "$PY" -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install -q "$REPO"
fi
export BOMWITNESS="$WORK/venv/bin/bomwitness"
echo "[1/4] analysis object";   sh "$PIPE/1_analysis_object/bomwitness/fetch.sh" "$WORK/objects"
echo "[2/4] preprocess";        sh "$PIPE/2_preprocess/bomwitness/preprocess.sh" "$WORK"
echo "[3/4] security analysis"; sh "$PIPE/3_security_analysis/bomwitness/analyze.sh" "$WORK" "$WORK/output"
echo "[4/4] analysis output: $WORK/output"
"$WORK/venv/bin/python" "$HERE/check_example.py" "$WORK/output" "$PIPE/1_analysis_object/bomwitness"
