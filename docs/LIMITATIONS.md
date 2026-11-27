# Limitations

Read these before relying on a result.

1. **One firmware family.** Everything was measured on official OpenWrt opkg releases (23.05 and 24.10).
   Grade A evidence exists because OpenWrt publishes signed binary packages. Firmware that a vendor rebuilds
   from source with its own toolchain will not be byte-identical to those packages, so for such firmware
   only grade B evidence (version markers) and the image-level "unaccounted executable" finding remain,
   unless the vendor publishes its own signed package feed or per-file manifest to verify against.
2. **Seeded errors, not field data.** The benchmark mutates correct BOMs and official images in seven
   defined ways. The numbers say how the tool behaves on those error classes. They are not rates of
   real-world BOM errors, and a different error (for example, a statically linked library inside another
   binary) is outside the classes tested.
3. **The reference drifts.** OpenWrt's shared feeds are rebuilt and relabelled after a release. The signed
   release manifest and a sibling image restore most of what drifts, but a component that neither covers
   (a device-specific package from a shared feed whose bytes changed) ends as `unverifiable` or
   `bytes_differ`. `results/r2/drift.json` quantifies this by release age.
4. **Sibling snapshots are only as independent as the sibling.** Devices of one target share most
   packages; some sibling images have the same package set as the tested device
   (`results/r2/sibling-overlap.json`). In the benchmark the snapshot is always taken from a different
   official image, never from the image under test, but the "no sibling snapshot" ablation is the
   conservative reading. Targets with a single device (x86/64, bcm27xx/bcm2711) have no snapshot at all.
5. **`bytes_differ` needs a person.** A one-byte patch and a harmless rebuild with different compiler output
   look the same to a hash. The tool separates one harmless case automatically (differences confined to
   embedded date and time strings) and otherwise asks for review.
6. **Unindexed feeds.** The file-path index covers the target, kernel-module, base and LuCI feeds (packages up
   to 4 MB, without translations). A file from the large `packages` feed is always flagged as unaccounted
   executable code, but naming its package depends on a name-similarity search that does not always succeed.
   Indexing that feed as well removes the gap at the cost of a larger one-time download
   (`bench/wide_index.py`, `results/r2/wide-index/`).
7. **Version labels of packages without a marker.** When nothing pins a label (no frozen feed, no manifest
   entry, no sibling, no marker in the bytes), a wrong version on byte-identical files cannot be refuted
   and is reported as `label_unconfirmed`.
8. **Partial presence passes.** A component is verified from the files that are present. A declared package
   of which only a shared, byte-identical script is in the image (while its executable is missing) is
   accepted. Three held-out phantom cases were missed this way.
9. **Algorithm evidence is string-level.** A name in a binary shows the component refers to an algorithm.
   It is not proof of a working implementation, an implementation that carries no name is missed, and the
   pattern table is ours. The CBOM benchmark generates the correct CBOM with the same detector it then
   tests, so its numbers show that the cross-checks are consistent and complete for the seeded classes, not
   that the detector finds all cryptography.
10. **AI-BOM is a presence check only**, tested on synthetic fixtures. The evaluated images contain no models.
11. **Scope of the bytes.** Only the SquashFS root filesystem is analysed. The kernel image, boot loader,
    device tree and radio calibration data are not. Encrypted or signed-and-encrypted vendor images cannot
    be unpacked. Nothing is executed, so run-time behaviour is out of scope.
12. **Trust anchor.** Two OpenWrt usign public keys are pinned in the source. If a release key or the
    publisher's build system is compromised, the reference itself is wrong and so are the verdicts.
13. **Baselines are run outside their stated scope in two conditions.** BomTrace and the Syft-based diff
    are designed for an intact package database. Their zero recall with a colluding or stripped database is
    what their own documentation predicts. It is shown to make the dependency visible, not to rank the
    tools: with an honest database they find every BOM-level error in the benchmark.
