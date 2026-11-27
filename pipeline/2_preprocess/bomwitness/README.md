# Stage 2, preprocess: BOMwitness

Two things are prepared before any claim is checked.

1. **Unpacking.** `bomwitness unpack` finds the SquashFS superblock inside the image and extracts the root
   filesystem with a pure-Python reader. Nothing from the firmware is executed, device nodes are skipped
   and symlinks are never followed.
2. **Reference evidence.** For the release and target, BOMwitness downloads the publisher's `sha256sums`
   and checks its usign signature against pinned OpenWrt release keys, then the package indexes (pinned by
   that file or signed themselves) and the release manifest. The sibling image is not unpacked here: stage
   3 passes it to `bomwitness verify --sibling-image`, which checks its SHA-256 against the release's image
   list in the same run and then reads its file hashes. (`bomwitness snapshot` can save those hashes to a
   file for reuse, but a snapshot file is a local input that a later run cannot authenticate, so the
   example does not use one.) With `FULL_INDEX=1` the harness also runs
   `bomwitness index`, which hashes every package of the main feeds once (about 180 MB of downloads) so that
   any unaccounted file can be attributed to the package that ships it. Without it, reference packages are
   fetched on demand by name.

Consumes: the image from stage 1. Produces: `.work/rootfs/` and, with `FULL_INDEX=1`, the reference cache
in `.work/cache/` (otherwise stage 3 fills it on demand). `preprocess.sh` runs both steps.
