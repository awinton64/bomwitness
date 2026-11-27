"""Command line interface. `bomwitness verify` is the main entry point."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from . import aibom, bomio, crypto, devicedb, report, unpack
from .reference import Reference
from .verify import HARD, inventory, snapshot_from_rootfs, verify


def _rootfs(args, stack: list) -> tuple[Path, dict]:
    rootfs, subject = _rootfs_inner(args, stack)
    if getattr(args, "name", None):
        subject["name"] = args.name
    return rootfs, subject


def _rootfs_inner(args, stack: list) -> tuple[Path, dict]:
    if args.rootfs:
        return Path(args.rootfs), {"name": Path(args.rootfs).name, "kind": "directory"}
    td = tempfile.TemporaryDirectory()
    stack.append(td)
    info = unpack.extract(Path(args.image), Path(td.name) / "rootfs")
    digest = hashlib.sha256(Path(args.image).read_bytes()).hexdigest()
    return Path(td.name) / "rootfs", {"name": Path(args.image).name, "kind": "image", "sha256": digest, "squashfs": info["superblock"]}


def _reference(args, rootfs: Path, subject: dict) -> Reference:
    hint = unpack.release_hint(rootfs)
    release, target = args.release or hint["release"], args.target or hint["target"]
    if not release or not target:
        raise SystemExit("cannot tell which release and target to compare against; pass --release and --target")
    subject["reference_chosen_from"] = "command line" if args.release and args.target else "the firmware's own /etc/openwrt_release (a hint, not evidence)"
    return Reference(release, target, Path(args.cache), offline=args.offline, **_base(args))


def _base(args) -> dict:
    return {"base": args.base} if getattr(args, "base", None) else {}


def _snapshots(args, stack: list, ref: Reference) -> tuple[list[dict], list[dict]]:
    """Release snapshots plus a record of how far each one was authenticated.

    A sibling image is authenticated when its SHA-256 is listed for this release and target in profiles.json,
    which the usign-signed sha256sums pins. A snapshot JSON file is a local input and is trusted as supplied.
    """
    snaps, trust = [], []
    official = {v: k for k, v in ref.meta().get("images", {}).items()}
    for p in args.snapshot or []:
        snap = json.loads(Path(p).read_text())
        snaps.append(snap)
        note = "local file, trusted as supplied; make it with `bomwitness snapshot` from an image you have checked"
        origin = (snap.get("made_from") or {}).get("sha256")
        if origin:
            note = ("local file, trusted as supplied; it records that it was made from an image with SHA-256 " + origin[:16] + "..., which is "
                    + (f"listed as {official[origin]} in the signed profiles.json of {ref.release} {ref.target}" if origin in official else
                       f"NOT listed in the signed profiles.json of {ref.release} {ref.target}"))
        trust.append({"kind": "snapshot file", "name": Path(p).name, "authenticated": False, "note": note})
    for img in args.sibling_image or []:
        digest = hashlib.sha256(Path(img).read_bytes()).hexdigest()
        td = tempfile.TemporaryDirectory()
        stack.append(td)
        unpack.extract(Path(img), Path(td.name) / "rootfs")
        snaps.append(snapshot_from_rootfs(Path(td.name) / "rootfs", f"sibling image {Path(img).name}"))
        ok = digest in official
        trust.append({"kind": "sibling image", "name": Path(img).name, "sha256": digest, "authenticated": ok,
                      "note": (f"listed as {official[digest]} in the signed profiles.json of {ref.release} {ref.target}" if ok else
                               f"NOT listed in the signed profiles.json of {ref.release} {ref.target}; trusted as supplied")})
        if not ok:
            print(f"warning: sibling image {Path(img).name} is not an official image of {ref.release} {ref.target} "
                  "according to the signed profiles.json; it is used as supplied", file=sys.stderr)
    return snaps, trust


def cmd_verify(args) -> int:
    stack: list = []
    rootfs, subject = _rootfs(args, stack)
    ref = _reference(args, rootfs, subject)
    doc = bomio.load(Path(args.sbom))
    claims = bomio.software_claims(doc)
    alts = [Reference(r, ref.target, Path(args.cache), offline=args.offline, **_base(args)) for r in args.alt_release or []]
    manifest = None if args.no_manifest else ref.manifest()
    snaps, trust = _snapshots(args, stack, ref)
    sbom = verify(rootfs, claims, ref, alts, manifest=manifest, snapshots=snaps,
                  use_markers=not args.no_markers, normalize_timestamps=not args.no_normalize)
    db = devicedb.compare(rootfs, claims, sbom["components"]) if args.db == "compare" else None
    cbom_doc = bomio.load(Path(args.cbom)) if args.cbom else (doc if bomio.crypto_assets(doc) else None)
    cb = None
    if cbom_doc:
        as_of = dt.datetime.fromisoformat(args.as_of).replace(tzinfo=dt.timezone.utc) if args.as_of else dt.datetime.now(dt.timezone.utc)
        assets = crypto.discover_assets(rootfs)
        cb = {"findings": crypto.verify_cbom(rootfs, cbom_doc, as_of, sbom),
              "assets": {"certificates": len(assets["certificates"]), "keys": len(assets["keys"]),
                         "algorithm_pairs": sum(len(v) for v in crypto.component_algorithms(rootfs, sbom).values())}}
    ai_doc = bomio.load(Path(args.aibom)) if args.aibom else (doc if bomio.models(doc) else None)
    ai = {"models_found": len(aibom.discover(rootfs)),
          "findings": aibom.verify_aibom(rootfs, bomio.models(ai_doc) if ai_doc else [])}
    rep = report.build(subject, ref.provenance(), sbom, db, cb, ai,
                       {"sbom": {"file": Path(args.sbom).name, "format": bomio.detect(doc), "components": len(claims)},
                        "reference_inputs": trust})
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1))
    if args.md:
        Path(args.md).write_text(report.markdown(rep))
    t = rep["triage"]
    print(f"{subject['name']}: {len(claims)} declared; pass {t['automatic_pass']}, fail {t['automatic_fail']}, "
          f"review {t['needs_review']}, unverifiable {t['unverifiable']}")
    for f in sbom["findings"]:
        if f["class"] in HARD:
            print(f"  {f['class']:22s} {f['component']:32s} [{f['grade']}] {f['detail'][:110]}")
    for f in (cb or {}).get("findings", []):
        if f["class"] not in ("deprecated_algorithm",):
            print(f"  {f['class']:22s} {str(f['asset'])[:32]:32s} [{f['grade']}] {f['detail'][:110]}")
    for f in ai["findings"]:
        print(f"  {f['class']:22s} {str(f['asset'])[:32]:32s} [{f['grade']}] {f['detail'][:110]}")
    hard = sbom["summary"]["hard_findings"] + len([f for f in (cb or {}).get("findings", []) if f["class"] != "deprecated_algorithm"]) + len(ai["findings"])
    return 1 if hard and args.fail_on == "findings" else 0


def cmd_inventory(args) -> int:
    stack: list = []
    rootfs, subject = _rootfs(args, stack)
    ref = _reference(args, rootfs, subject)
    manifest = None if args.no_manifest else ref.manifest()
    inv = inventory(rootfs, ref, manifest=manifest, snapshots=_snapshots(args, stack, ref)[0])
    doc = bomio.sbom(inv["components"], subject["name"])
    if args.with_cbom:
        rep = verify(rootfs, [{"name": c["name"], "version": c["version"]} for c in inv["components"]], ref, manifest=manifest)
        cb = crypto.inventory(rootfs, subject["name"], rep)
        doc["components"] += cb["components"]
        doc["dependencies"] = cb["dependencies"]
    Path(args.out).write_text(json.dumps(doc, indent=1))
    print(f"{len(inv['components'])} components attributed from bytes, {len(inv['unattributed_code'])} executable files unattributed; wrote {args.out}")
    return 0


def cmd_index(args) -> int:
    ref = Reference(args.release, args.target, Path(args.cache), **_base(args))
    stats = ref.build_path_index() if not ref.has_path_index else {"cached": True}
    print(json.dumps({**ref.provenance(), **stats}, indent=1))
    return 0


def cmd_unpack(args) -> int:
    print(json.dumps(unpack.extract(Path(args.image), Path(args.dest)), indent=1))
    return 0


def cmd_snapshot(args) -> int:
    with tempfile.TemporaryDirectory() as td:
        unpack.extract(Path(args.image), Path(td) / "rootfs")
        snap = snapshot_from_rootfs(Path(td) / "rootfs", f"sibling image {Path(args.image).name}")
        snap["made_from"] = {"file": Path(args.image).name, "sha256": hashlib.sha256(Path(args.image).read_bytes()).hexdigest()}
        Path(args.out).write_text(json.dumps(snap))
    print(f"wrote {args.out}")
    return 0


def _common(p):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--image", help="firmware image containing a SquashFS root filesystem")
    g.add_argument("--rootfs", help="an already unpacked root filesystem")
    p.add_argument("--name", help="name of the firmware to show in reports (default: the file or directory name)")
    p.add_argument("--release", help="OpenWrt release to use as reference, e.g. 24.10.8")
    p.add_argument("--target", help="OpenWrt target, e.g. ath79/generic")
    p.add_argument("--cache", default=str(Path.home() / ".cache/bomwitness"),
                   help="reference cache directory; signatures and hashes are checked when an item is first fetched, "
                        "and the cached copy is trusted afterwards, so keep it where only you can write")
    p.add_argument("--offline", action="store_true", help="use only cached reference data")
    p.add_argument("--base", help="base URL of a release mirror (default: downloads.openwrt.org/releases)")
    p.add_argument("--no-manifest", action="store_true", help="do not use the publisher's release manifest for version labels")
    p.add_argument("--snapshot", action="append", help="release snapshot JSON made by `bomwitness snapshot` (repeatable); a local file, trusted as supplied")
    p.add_argument("--sibling-image", action="append", help="official image of another device of the same release and target (repeatable); its SHA-256 is "
                                                              "looked up in the signed profiles.json and the report says whether it was found")


def main(argv: list[str] | None = None) -> int:
    # A CA bundle can hold certificates that newer versions of `cryptography` warn about (non-positive serial
    # numbers). The certificates are still parsed and reported; the warning is noise on the command line.
    import warnings
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    ap = argparse.ArgumentParser(prog="bomwitness", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check a declared SBOM (and CBOM, AI-BOM) against firmware bytes")
    _common(v)
    v.add_argument("--sbom", required=True, help="CycloneDX 1.4 to 1.6 or SPDX 2.3 JSON")
    v.add_argument("--cbom", help="CycloneDX CBOM (defaults to cryptographic assets inside --sbom)")
    v.add_argument("--aibom", help="CycloneDX AI-BOM (defaults to model components inside --sbom)")
    v.add_argument("--alt-release", action="append", help="another release whose builds may be compared (repeatable)")
    v.add_argument("--db", choices=("compare", "ignore"), default="compare",
                   help="report where the device's own package database disagrees (never used for verdicts)")
    v.add_argument("--no-markers", action="store_true", help="disable grade B version-marker evidence")
    v.add_argument("--no-normalize", action="store_true", help="do not accept build-timestamp-only differences")
    v.add_argument("--as-of", help="date for certificate expiry checks, YYYY-MM-DD (default: today)")
    v.add_argument("--json", help="write the full report here")
    v.add_argument("--md", help="write a Markdown report here")
    v.add_argument("--fail-on", choices=("findings", "never"), default="findings",
                   help="findings (default): exit status 1 when there is an SBOM finding of class wrong_version, "
                        "wrong_component, absent, bytes_differ, undeclared_component or undeclared_file, a CBOM finding other "
                        "than a deprecated-algorithm observation, or an AI-BOM finding. label_unconfirmed, unverifiable "
                        "components and device-database disagreements do not change the exit status")
    v.set_defaults(fn=cmd_verify)
    i = sub.add_parser("inventory", help="derive a component list from the bytes alone (no BOM, no database needed)")
    _common(i)
    i.add_argument("--out", required=True)
    i.add_argument("--with-cbom", action="store_true")
    i.set_defaults(fn=cmd_inventory)
    x = sub.add_parser("index", help="build the signed reference cache and file-path index for a release and target")
    x.add_argument("--release", required=True); x.add_argument("--target", required=True)
    x.add_argument("--cache", default=str(Path.home() / ".cache/bomwitness"))
    x.add_argument("--base", help="base URL of a release mirror")
    x.set_defaults(fn=cmd_index)
    u = sub.add_parser("unpack", help="carve and extract the SquashFS root filesystem of an image")
    u.add_argument("image"); u.add_argument("dest")
    u.set_defaults(fn=cmd_unpack)
    s = sub.add_parser("snapshot", help="make a release snapshot from an official sibling image")
    s.add_argument("--image", required=True); s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_snapshot)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
