#!/bin/sh
# Make the single-commit public export of this development repository.
#   sh scripts/export.sh /path/to/new/empty/directory
# The export's tree is identical to HEAD's tree; the script prints both ids. Run scripts/provenance.py first.
set -eu
DEST=$1
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }
[ ! -e "$DEST" ] || { echo "$DEST exists" >&2; exit 1; }
mkdir -p "$DEST"
git archive HEAD | tar -x -C "$DEST"
cd "$DEST"
git init -q -b main
git config user.name "$(git -C "$OLDPWD" config user.name)"
git config user.email "$(git -C "$OLDPWD" config user.email)"
git add -A
git commit -q -m "BOMwitness: verify IoT firmware bills of materials against the bytes

SafeIoT Hackathon 2026, Track 2. Tool, benchmark, results, paper and pipeline harness.
Single-commit export of the development repository; see docs/PROVENANCE.md.

Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
echo "export commit $(git rev-parse HEAD)"
echo "export tree   $(git rev-parse 'HEAD^{tree}')"
echo "source tree   $(git -C "$OLDPWD" rev-parse 'HEAD^{tree}')"
