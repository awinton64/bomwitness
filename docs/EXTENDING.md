# Extending BOMwitness

## Another OpenWrt release or target

Nothing to write. `bomwitness verify --release <r> --target <t>` fetches and checks the reference for any
opkg-based release (tested on 23.05 and 24.10). A release signed by a key that is not pinned is refused;
add the key to `PINNED_KEYS` in `bomwitness/usign.py` with its source. Releases that use apk packages
(25.12) need an apk index and package reader next to `parse_ipk` in `bomwitness/reference.py`.

## Another device in the benchmark

Add an entry to `bench/images.json` (id, split, release, target, image file name) and run
`bench/prepare.py <id>`. The image hash comes from the signed release metadata, so no hash is typed by hand.

## Another firmware family

The verifier needs four things from a `Reference`: `index()` (name to version, feed, hash, URL),
`payload(name)` (per-file SHA-256 manifest), `manifest()` and the path index. A Debian, Yocto or Buildroot
reference would implement those over its own signed metadata (`Release`/`Packages`, `Packages.gz` plus
`.deb` readers). `bomwitness/verify.py` does not contain OpenWrt-specific logic beyond the two built-in
names (`kernel`, `libc`) in `NO_PACKAGE_HINTS`.

## Another BOM format

`bomwitness/bomio.py` turns a document into software claims (`name`, `version`), cryptographic assets and
model components. Add a branch in `detect()` and `software_claims()`.

## Another verdict rule

Rules live in `check_package()` in `bomwitness/verify.py`, in order of evidence strength. Add the rule, add
a test in `tests/test_verify.py` on the synthetic feed (`tests/fakefeed.py`), then rerun the tuning images
(`bench/run_cases.py <id>`). Do not look at held-out images while changing rules; see `docs/EVALUATION.md`.

## Another algorithm

Add a row to `ALGORITHMS` in `bomwitness/crypto.py` (name, primitive, deprecated, byte pattern) and a line
to `test_algorithm_patterns_are_narrow`. Keep patterns narrow: require a digit, a separator or a boundary.

## Another baseline

Add a function to `bench/baselines.py` that returns a set of `(class, component)` findings for a declared
BOM and a tree, and add it to `base_all()` in `bench/run_cases.py`.
