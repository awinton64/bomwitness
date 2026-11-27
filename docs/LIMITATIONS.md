# Limitations

Read these before relying on a result.

1. **One firmware family.** Everything was measured on official OpenWrt opkg releases (23.05 and 24.10).
   Grade A evidence exists because OpenWrt publishes binary packages whose hashes can be reached from a
   signed checksum file or a signed feed index (the packages are not signed one by one). Firmware that a
   vendor rebuilds from source with its own toolchain will not be byte-identical to those packages, so for
   such firmware only grade B evidence (version markers) and the image-level "unaccounted executable"
   finding remain, unless the vendor publishes its own authenticated package feed or per-file hash manifest
   to verify against.
2. **Seeded errors, not field data.** The benchmark mutates correct BOMs and official images in eight
   defined ways. The numbers say how the tool behaves on those error classes. They are not rates of
   real-world BOM errors, and a different error (for example, a statically linked library inside another
   binary) is outside the classes tested. The seeded targets are drawn from packages the reference can
   speak about (installed packages with a reference entry, base-feed packages that are not installed, and
   for the one-byte patch only components that verified at grade A on the clean image), so errors in
   components without a reference package are not in the benchmark. The held-out set has 900 distinct
   errors scored in 1860 rows; errors on one image are not independent of each other, so the per-image
   range of recall in `results/r2/review-r3.json` says more about variability than a pooled interval.
3. **The reference drifts.** OpenWrt's shared feeds are rebuilt and relabelled after a release. The
   release manifest (pinned by hash in the signed checksum file; it has no signature of its own) and a
   sibling image restore most of what drifts, but a component that neither covers
   (a device-specific package from a shared feed whose bytes changed) ends as `unverifiable` or
   `bytes_differ`. `results/r2/drift.json` quantifies this by release age.
4. **Sibling snapshots are only as independent as the sibling.** Devices of one target share most
   packages; some sibling images have the same package set as the tested device
   (`results/r2/sibling-overlap.json`). In the benchmark the snapshot is always taken from a different
   official image, never from the image under test, but the "no sibling snapshot" ablation is the
   conservative reading. Targets with a single device (x86/64, bcm27xx/bcm2711) have no snapshot at all.
5. **`bytes_differ` needs a person, and a patch is found only where a reference covers it.** A one-byte
   patch and a harmless rebuild with different compiler output look the same to a hash. The tool separates
   one harmless case automatically (differences confined to embedded date and time strings) and otherwise
   asks for review. On the held-out set every one of the 120 one-byte patches was reported with the sibling
   snapshot and 116 of 120 without it; the four misses are in packages whose shared-feed copy has moved to a
   newer version, so no same-version reference was left. A change inside a masked date string, or in a
   configuration or account file (which are not compared), is not reported at all.
6. **Unindexed feeds.** The file-path index covers the target, kernel-module, base and LuCI feeds (packages up
   to 4 MB, without translations). A file from the large `packages` feed is always flagged as unaccounted
   executable code, but naming its package depends on a name-similarity search that does not always succeed.
   Indexing that feed as well removes the gap at the cost of a larger one-time download
   (`bench/wide_index.py`, `results/r2/wide-index/`).
7. **Version labels of packages without a marker.** When nothing pins a label (no frozen feed, no manifest
   entry, no sibling, no marker in the bytes), a wrong version on files that match the reference cannot be
   refuted and is reported as `label_unconfirmed`.
8. **Partial presence passes, and grade A is a verdict under stated rules, not byte identity of a
   package.** Configuration files and three account files are not compared, differences inside embedded
   date strings are accepted, and a component is verified from the files that are present. A declared
   package of which only a shared script with the reference SHA-256 is in the image (while its executable
   is missing) is accepted. Three held-out phantom cases were missed this way. The reason text of every
   grade A verdict gives the counts (files present, matched, matched only after masking, not compared,
   missing), so a partial match can be seen in the report.
9. **Algorithm evidence is string-level.** A name in a binary shows the component refers to an algorithm.
   It is not proof of a working implementation, an implementation that carries no name is missed, and the
   pattern table is ours. The CBOM benchmark generates the correct CBOM with the same detector it then
   tests, so its numbers show that the cross-checks are consistent and complete for the seeded classes, not
   that the detector finds all cryptography.
10. **AI-BOM is a presence check only**, tested on synthetic fixtures. The evaluated images contain no models.
    Three of the six formats (safetensors, PyTorch archives, ONNX) are recognised by a generic header plus
    the file extension, so a renamed file of those formats is missed. Nothing checks that the runtime a
    model needs is declared.
11. **Scope of the bytes.** Only the SquashFS root filesystem is analysed. The kernel image, boot loader,
    device tree and radio calibration data are not. Encrypted or signed-and-encrypted vendor images cannot
    be unpacked. Nothing is executed, so run-time behaviour is out of scope.
12. **Trust anchor and local inputs.** Two OpenWrt usign public keys are pinned in the source. If a release
    key or the publisher's build system is compromised, the reference itself is wrong and so are the
    verdicts. A snapshot file given on the command line is used as supplied, a sibling image is checked
    against the image list (`profiles.json`, which the signed checksum file pins by hash) but still used
    (with a warning) when it is not listed, and the reference cache is trusted after the first verified
    download. A verdict can therefore rest on a source nobody authenticated. The report and the reason text
    say so ("supplied", "not authenticated"); they do not stop you.
13. **Baselines are run outside their stated scope in two conditions.** BomTrace and the Syft-based diff
    are designed for an intact package database. With a colluding database both run and return no label.
    With a stripped database BomTrace's verifier has no usable input and returns no result at all, and the
    Syft-based diff is credited only with the phantom rows because it calls every declared component
    absent. This is what their own documentation predicts. It is shown to make the dependency visible, not
    to rank the tools: with an honest database they find every BOM-level error in the benchmark. Two of the
    three baselines are adapters of ours, and no firmware-native analyser such as EMBA was run.
14. **Timing figures are not a comparison.** The benchmark timed only the in-process verifier call on an
    unpacked, hashed tree; the baselines were timed as whole command-line runs. The end-to-end time of the
    command line is in `results/r2/timing-e2e.json` (one machine, one image, measured after the freeze).
