"""Check a declared SBOM against the bytes of an unpacked firmware root filesystem.

Evidence grades
  A  byte-identical to the publisher's reference package (signed feed index,
     then per-file SHA-256). The label for those bytes comes from the feed
     index and, when available, from the publisher's signed release manifest.
  B  intrinsic to the firmware bytes: versioned file names, SONAMEs, and the
     version marker that the reference build of the same component carries.
  C  the device's own package database. Reported separately and labelled as
     self-reported (see devicedb.compare); it never changes a verdict here, so
     a database edited to agree with the BOM changes nothing.

Per-claim verdicts
  verified_A, verified_B   the claim is supported by grade A or B evidence
  wrong_version            the component is there, with another version
  wrong_component          the files at this component's paths are another package's
  absent                   no file of the component is in the firmware
  bytes_differ             same label as the reference build, different bytes: a
                           rebuild or a modification; needs human review
  label_unconfirmed        bytes identical to a reference build whose label is
                           different, and nothing pins which label is right
  unverifiable             nothing to compare against

Image-level findings: undeclared_component, undeclared_file, stale.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path

from .elfinfo import has_token, is_elf, same_version, soname, upstream_token
from .reference import Reference

IGNORED_PREFIXES = ("usr/lib/opkg/",)          # the device database itself (grade C)
BUILD_GENERATED = ("lib/modules/%s/modules.builtin", "lib/modules/%s/modules.builtin.modinfo")
NO_PACKAGE_HINTS = {"libc": (r"lib/libc\.so", r"lib/ld-musl-.*"), "kernel": (r"lib/modules/[^/]+/.*\.ko",)}
MUTABLE = {"etc/passwd", "etc/group", "etc/shadow"}  # rewritten by package install scripts at image build
HARD = ("wrong_version", "wrong_component", "absent", "bytes_differ", "undeclared_component", "undeclared_file")
SEVERITY = ["verified_A", "verified_B", "unverifiable", "label_unconfirmed", "absent", "bytes_differ",
            "wrong_component", "wrong_version"]
_SONAME_CACHE: dict[str, str | None] = {}
_TIMESTAMP = re.compile(rb"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
                        rb"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{4}|\d{2}:\d{2}:\d{2}")


def timestamp_only_diff(a: bytes, b: bytes) -> bool:
    """True if two different blobs of equal size differ only inside embedded date or time strings.

    Some builds embed their build time (BusyBox prints it in its banner), so a
    republished reference package differs from the release build in those
    bytes and nowhere else. Every other byte must be identical.
    """
    if len(a) != len(b) or a == b:
        return False
    spans = {m.span() for m in _TIMESTAMP.finditer(a)} & {m.span() for m in _TIMESTAMP.finditer(b)}
    if not spans:
        return False
    ma, mb = bytearray(a), bytearray(b)
    for lo, hi in spans:
        ma[lo:hi] = mb[lo:hi] = b"0" * (hi - lo)
    return ma == mb


def snapshot_from_rootfs(rootfs: Path, source: str) -> dict:
    """A frozen release snapshot: file hashes and package ownership taken from an official sibling image.

    The shared feeds are rebuilt after a release, so the bytes a release image
    was built from can disappear from them. Another official image of the same
    release and target (its hash is pinned by the signed sha256sums) still
    carries those bytes. Its package lists are the publisher's statement inside
    a signed artifact, not the device under test describing itself.
    """
    from . import devicedb
    files = scan_rootfs(rootfs)
    packages = {}
    for n, r in devicedb.installed(rootfs).items():
        conf = Path(rootfs) / devicedb.INFO / f"{n}.conffiles"
        skip = {l.strip().lstrip("/") for l in conf.read_text(errors="replace").splitlines()} if conf.is_file() else set()
        packages[n] = {"version": r.get("Version", ""),
                       "files": [p for p in devicedb.owned_files(rootfs, n) if p in files and p not in skip and p not in MUTABLE]}
    return {"source": source, "files": {p: m["sha256"] for p, m in files.items()}, "packages": packages}


def scan_rootfs(rootfs: Path) -> dict[str, dict]:
    files = {}
    for dp, _dn, fn in os.walk(rootfs):
        for f in fn:
            q = Path(dp) / f
            if q.is_symlink() or not q.is_file():
                continue
            rel = str(q.relative_to(rootfs))
            if rel.startswith(IGNORED_PREFIXES):
                continue
            blob = q.read_bytes()
            digest = hashlib.sha256(blob).hexdigest()
            so = None
            if ".so" in f:
                if digest not in _SONAME_CACHE:
                    _SONAME_CACHE[digest] = soname(blob)
                so = _SONAME_CACHE[digest]
            files[rel] = {"sha256": digest, "size": len(blob), "elf": is_elf(blob), "soname": so}
    return files


def _resolve_maps(ref: Reference) -> dict:
    maps = getattr(ref, "_bw_resolve", None)
    if maps is None:
        abi: dict[str, list[str]] = {}
        prov: dict[str, list[str]] = {}
        for n, r in ref.index().items():
            if r.get("abi") and n.endswith(r["abi"]):
                abi.setdefault(n[: -len(r["abi"])], []).append(n)
            for p in r.get("provides", []):
                prov.setdefault(p, []).append(n)
        maps = ref._bw_resolve = {"abi": abi, "provides": prov}
    return maps


def resolve(name: str, ref: Reference, files: dict) -> tuple[list[str], str]:
    """Reference packages a BOM component name can stand for, and how the name was matched."""
    idx = ref.index()
    if name in idx:
        return [name], "exact"
    maps = _resolve_maps(ref)
    for how, cands in (("abi", maps["abi"].get(name, [])), ("provides", maps["provides"].get(name, [])),
                       ("source", ref.source_packages(name))):
        if cands:
            cands = sorted(cands)[:12]
            here = [n for n in cands if any(p in files for p in ref.payload(n)["files"])]
            return (here or cands[:1]), how
    return [], "none"


def name_candidates(path: str, index: dict[str, dict], so: str | None = None) -> list[str]:
    """Reference packages whose name resembles an unaccounted file's name or SONAME (fallback for unindexed feeds)."""
    stems = set()
    for base in filter(None, (path.rsplit("/", 1)[-1], so)):
        stem = re.sub(r"\.(so(\.[0-9.]+)?|ko|json|js|sh|uc|lua|conf)$", "", base)
        stem = re.sub(r"[-_.]?\d+(\.\d+)*$", "", stem)
        stems |= {stem, stem.replace("_", "-")}
        if stem.startswith("lib"):
            stems.add(stem[3:])
    stems = {s.lower() for s in stems if len(s) >= 3}
    base = path.rsplit("/", 1)[-1]
    out = [base] if base in index else []          # a file named exactly like a package, however short ("pv")
    for n in index:
        if n == base:
            continue
        parts = {x for x in n.split("-") if len(x) >= 3} | {n}
        core = re.sub(r"\d+$", "", n)
        if any(s == n or s == core or s in parts or n.startswith(s) or (len(s) >= 5 and s in n)
               or any(s.startswith(x) for x in parts if x not in ("lib", "kmod", "utils", "tools", "mod"))
               for s in stems):
            out.append(n)
    return out[:1] + sorted(out[1:], key=len)[:40] if out and out[0] == base else sorted(out, key=len)[:40]


def verify(rootfs: Path, declared: list[dict], ref: Reference, alt_refs: list[Reference] = (), *,
           manifest: dict[str, str] | None = None, snapshots: list[dict] = (), use_hashes: bool = True,
           use_markers: bool = True, normalize_timestamps: bool = True, fallback_fetch: bool = True,
           files: dict | None = None) -> dict:
    """Verify `declared` ([{"name", "version"}]) against the bytes under `rootfs`.

    manifest      the publisher's release manifest (name to version), or None
    snapshots     frozen release snapshots from official sibling images (snapshot_from_rootfs)
    normalize_timestamps  accept a file whose only differences from the reference
                  are embedded build date or time strings
    use_hashes    grade A evidence on or off (ablation)
    use_markers   grade B evidence on or off (ablation)
    fallback_fetch  for files no indexed package explains, fetch reference
                  packages with similar names from unindexed feeds
    """
    t0 = time.time()
    rootfs = Path(rootfs)
    index = ref.index()
    files = files if files is not None else scan_rootfs(rootfs)
    manifest = manifest or {}
    image_epoch = ref.meta().get("source_date_epoch")
    kver = next((p.split("/")[2] for p in files if p.startswith("lib/modules/")), None)
    generated = {g % kver for g in BUILD_GENERATED} if kver else set()
    by_soname: dict[str, list[str]] = {}
    for p, m in files.items():
        if m["soname"]:
            by_soname.setdefault(m["soname"], []).append(p)
    blob_cache: dict[str, bytes] = {}

    def fw(path: str) -> bytes:
        if path not in blob_cache:
            blob_cache[path] = (rootfs / path).read_bytes()
        return blob_cache[path]

    def fw_has(paths, token) -> bool:
        return bool(token) and any(has_token(p.encode(), token) or has_token(fw(p), token) for p in paths)

    resolved = {c["name"]: (([], "builtin") if c["name"] in NO_PACKAGE_HINTS and c["name"] not in index
                            else resolve(c["name"], ref, files)) for c in declared}
    ref.payloads([n for names, _how in resolved.values() for n in names])
    declared_pkgs = {n for names, _how in resolved.values() for n in names}
    claimed_paths: set[str] = set()
    results, findings = [], []

    def add(kind, name, grade, detail, **extra):
        findings.append({"class": kind, "component": name, "grade": grade, "detail": detail, **extra})

    def check_package(pkg: str, ver: str) -> dict:
        rec, pl = index[pkg], ref.payload(pkg)
        vr, vm = rec["version"], manifest.get(pkg)
        present, same, differ, siblings = [], [], [], []
        for path, meta in pl["files"].items():
            if path in files:
                present.append(path)
                if files[path]["sha256"] == meta["sha256"]:
                    same.append(path)
                elif path not in MUTABLE and path not in pl["conffiles"]:
                    differ.append(path)
            elif meta.get("soname") and meta["soname"] in by_soname:
                siblings += [(path, s) for s in by_soname[meta["soname"]]]
        normalized = []
        if use_hashes and normalize_timestamps:
            for path in list(differ):
                if files[path]["size"] == pl["files"][path]["size"]:
                    rb = ref.file_bytes(pkg, path)
                    if rb is not None and timestamp_only_diff(rb, fw(path)):
                        differ.remove(path)
                        same.append(path)
                        normalized.append(path)
        sib_paths = [s for _p, s in siblings]
        claimed_paths.update(present)
        claimed_paths.update(sib_paths)
        out = {"package": pkg, "reference_version": vr, "reference_feed": rec["feed"], "manifest_version": vm,
               "payload_files": len(pl["files"]), "present": len(present), "identical": len(same),
               "differing": differ, "soname_siblings": sib_paths}
        if normalized:
            out["normalized_build_timestamp"] = normalized
        token, ref_token = upstream_token(ver), upstream_token(vr)
        label_ok = same_version(ver, vr)
        snap_hit = None          # (snapshot source, version label, paths) when the bytes equal a release snapshot's build
        snap_miss = None         # the same, when a snapshot holds this package and some of its bytes differ here
        for snap in snapshots if use_hashes else ():
            sp = snap["packages"].get(pkg)
            if not sp:
                continue
            here = [p for p in sp["files"] if p in files and p not in pl["conffiles"]]
            if here and all(files[p]["sha256"] == snap["files"][p] for p in here):
                snap_hit = (snap["source"], sp["version"], here)
                claimed_paths.update(here)
                break
            if here and snap_miss is None:
                snap_miss = (snap["source"], sp["version"], [p for p in here if files[p]["sha256"] != snap["files"][p]])
                claimed_paths.update(here)

        def alt_lookup():
            """Compare this component's files with other official releases' builds of the same package."""
            same_as, declared_build_differs = None, False
            for af in alt_refs:
                arec = af.index().get(pkg)
                if not arec:
                    continue
                apl = af.payload(pkg)
                shared = [p for p in apl["files"] if p in files and p not in MUTABLE and p not in apl["conffiles"]]
                eq = [p for p in shared if apl["files"][p]["sha256"] == files[p]["sha256"]]
                if differ and any(p in eq for p in differ):
                    same_as = (af.release, arec["version"])
                if same_version(ver, arec["version"]) and (len(eq) < len(shared) or (apl["files"] and not shared)):
                    declared_build_differs = True
            return same_as, declared_build_differs

        out["files"] = sorted(set(present) | set(sib_paths) | set(snap_hit[2] if snap_hit else ()))
        if not pl["files"]:
            return dict(out, verdict="unverifiable", reason="metadata-only package with no files to check")
        if not present and not siblings:
            return dict(out, verdict="absent", grade="A", reason="none of the reference package's files exist in the firmware")

        if not use_hashes:      # ablation: grade B evidence only
            here = present + sib_paths
            if use_markers and fw_has(here, token):
                return dict(out, verdict="verified_B", grade="B", reason=f"files carry the declared version marker {token}")
            ref_marked = [p for p in present if pl["files"][p].get("marker")]
            if use_markers and token and ref_token and token != ref_token and fw_has(ref_marked, ref_token):
                return dict(out, verdict="wrong_version", grade="B", actual_version=vr,
                            reason=f"files carry the marker {ref_token}, not the declared {token}")
            return dict(out, verdict="unverifiable", reason="files present; no version marker to check (hash evidence disabled)")

        if not differ and not siblings:
            # Every present file is byte-identical to the reference build.
            if same_version(ver, vr):
                return dict(out, verdict="verified_A", grade="A", label_source="feed index",
                            reason="every file byte-identical to the reference package")
            if vm and same_version(ver, vm):
                return dict(out, verdict="verified_A", grade="A", label_source="release manifest",
                            reason=f"every file byte-identical to the reference package; the release manifest labels it {vm} "
                                   f"(the shared feed now labels the same bytes {vr})")
            if snap_hit and same_version(ver, snap_hit[1]):
                return dict(out, verdict="verified_A", grade="A", label_source="release snapshot",
                            reason=f"every file byte-identical to the reference package; the official sibling image labels it {snap_hit[1]}")
            if rec["frozen"]:
                return dict(out, verdict="wrong_version", grade="A", actual_version=vr,
                            reason=f"bytes are the reference build {vr} from a feed that is frozen for this release")
            if snap_hit:
                return dict(out, verdict="wrong_version", grade="A", actual_version=snap_hit[1],
                            reason=f"bytes are the build that the official sibling image labels {snap_hit[1]} (feed label {vr}); neither is the declared version")
            if vm:
                return dict(out, verdict="wrong_version", grade="A", actual_version=vm,
                            reason=f"bytes are the reference build; the release manifest labels it {vm} and the feed {vr}, neither is the declared version")
            _same, declared_build_differs = alt_lookup()
            if declared_build_differs:
                return dict(out, verdict="wrong_version", grade="A", actual_version=vr,
                            reason="files match the reference build of another version; the official build of the declared version has different bytes")
            marked = [p for p in present if pl["files"][p].get("marker")]
            if use_markers and token and ref_token and token != ref_token and marked:
                return dict(out, verdict="wrong_version", grade="A", actual_version=vr,
                            reason="files are byte-identical to the reference build and carry its version marker, not the declared one")
            return dict(out, verdict="label_unconfirmed", grade="A",
                        reason=f"bytes identical to the reference build labelled {vr}; the shared feed may have relabelled it and no release manifest entry pins the label")

        # Some bytes differ from the reference build held for this release.
        if snap_hit:
            if same_version(ver, snap_hit[1]):
                return dict(out, verdict="verified_A", grade="A", label_source="release snapshot",
                            reference_version=snap_hit[1], feed_version=vr, snapshot=snap_hit[0],
                            reason=f"{len(snap_hit[2])} file(s) byte-identical to the build in the official sibling image "
                                   f"({snap_hit[1]}); the shared feed has since moved to {vr}" if not same_version(ver, vr) else
                                   f"{len(snap_hit[2])} file(s) byte-identical to the build in the official sibling image; "
                                   "the shared feed's copy of this version was republished with different bytes")
            return dict(out, verdict="wrong_version", grade="A", actual_version=snap_hit[1],
                        reason=f"bytes are identical to the build that the official sibling image labels {snap_hit[1]}")
        if differ and ref.has_path_index:
            def twin(p, only_declared):
                """Another reference package that ships this exact file at this path."""
                return [q for q in ref.path_owners(p) if q != pkg and (q in declared_pkgs or not only_declared)
                        and ref.payload(q)["files"][p]["sha256"] == files[p]["sha256"]]
            if all(twin(p, True) for p in present):
                owner = twin(differ[0], True)[0]
                return dict(out, verdict="absent", grade="A",
                            reason=f"every file at this package's paths is byte-identical to another declared component ({owner}); nothing of this package is present")
            others = [set(twin(p, False)) for p in differ]
            common = set.intersection(*others) if others else set()
            if common:
                best = sorted(common)[0]
                return dict(out, verdict="wrong_component", grade="A", actual_component=best,
                            reason=f"the differing files at this package's paths are byte-identical to the reference package {best}")
        same_as, _dbd = alt_lookup()
        if same_as:
            if same_version(ver, same_as[1]):
                return dict(out, verdict="verified_A", grade="A", label_source=f"release {same_as[0]} feed",
                            reason=f"bytes are identical to the {same_as[0]} release build of this version")
            return dict(out, verdict="wrong_version", grade="A", actual_version=same_as[1],
                        reason=f"bytes are identical to the {same_as[0]} release build {same_as[1]}")
        changed = differ + sib_paths
        ref_changed = differ + [p for p, _s in siblings]
        ref_marker = any(pl["files"][p].get("marker") for p in ref_changed)
        if label_ok:
            if use_markers and token and ref_marker and not fw_has(changed, token):
                return dict(out, verdict="wrong_version", grade="B", actual_version=None,
                            reason="bytes differ from the reference build and lack the version marker it carries")
            pub = ref.published(pkg)
            rebuilt = bool(pub and image_epoch and pub > image_epoch + 86400)
            return dict(out, verdict="bytes_differ", grade="A", reference_published=pub,
                        reference_rebuilt_after_image=rebuilt,
                        reason="same version label as the reference build, different bytes: a rebuild or a modification, needs review"
                               + ("; the reference package file was republished after this image was built" if rebuilt else ""))
        if snap_miss and same_version(ver, snap_miss[1]):
            return dict(out, verdict="bytes_differ", grade="A", differing=snap_miss[2], reference_rebuilt_after_image=False,
                        reason=f"the official sibling image carries this version ({snap_miss[1]}) with different bytes in "
                               f"{len(snap_miss[2])} file(s): a modification or a device-specific build, needs review")
        if use_markers and fw_has(changed, token):
            return dict(out, verdict="verified_B", grade="B",
                        reason="the reference feed has moved to another version; files carry the declared version marker")
        if use_markers and token and ref_marker:
            found = fw_has(changed, ref_token)
            return dict(out, verdict="wrong_version", grade="B", actual_version=vr if found else None,
                        reason="declared version marker absent from files that carry one in reference builds")
        return dict(out, verdict="unverifiable",
                    reason="the reference feed has moved to another version and the files carry no version marker")

    for c in declared:
        name, ver = c["name"], c["version"]
        names, how = resolved[name]
        if name in NO_PACKAGE_HINTS and name not in index:
            names, how = [], "builtin"
        res = {"name": name, "declared_version": ver, "matched_by": how}
        if not names:
            hint = sorted(p for p in files if any(re.fullmatch(h, p) for h in NO_PACKAGE_HINTS.get(name, ())))
            token = upstream_token(ver)
            if name != "kernel":        # kernel modules belong to their kmod packages; the kernel claim only reads a marker from them
                claimed_paths.update(hint)
            res["files"] = ([f"lib/modules/{kver}/modules.builtin"] if kver else []) if name == "kernel" else hint
            if not use_markers or not hint or not token:
                res.update(verdict="unverifiable", reason="no reference package of this name in the feeds")
            elif any(has_token(fw(p), token) for p in hint[:5]):
                res.update(verdict="verified_B", grade="B", reason=f"version marker {token} found in {hint[0]}")
            else:
                res.update(verdict="wrong_version", grade="B", actual_version=None,
                           reason=f"declared version marker {token} absent from {hint[0]}")
        else:
            checks = [check_package(n, ver) for n in names]
            here = [k for k in checks if k["verdict"] != "absent"] or checks
            worst = max(here, key=lambda k: SEVERITY.index(k["verdict"]))
            res.update(worst)
            if len(checks) > 1:
                res["candidates"] = [{"package": k["package"], "verdict": k["verdict"]} for k in checks]
        v = res["verdict"]
        if v == "wrong_version":
            add("wrong_version", name, res.get("grade", "B"),
                f"declared {ver}" + (f"; actual {res['actual_version']}" if res.get("actual_version") else "") + f". {res['reason']}")
        elif v == "wrong_component":
            add("wrong_component", name, "A", res["reason"])
        elif v == "absent":
            add("absent", name, "A", res["reason"])
        elif v == "bytes_differ":
            add("bytes_differ", name, "A", f"{len(res['differing'])} file(s) differ from the reference build of {ver}. {res['reason']}",
                reference_rebuilt_after_image=res.get("reference_rebuilt_after_image"))
        elif v == "label_unconfirmed":
            add("label_unconfirmed", name, "A", f"declared {ver}; byte-identical reference is labelled {res['reference_version']}")
        feed_v = res.get("feed_version") or res.get("reference_version")
        if v in ("verified_A", "verified_B") and feed_v and not same_version(ver, feed_v):
            add("stale", name, res.get("grade", "A"), f"firmware has {ver}; the reference feed now ships {feed_v}")
        results.append(res)

    # ---- files no declared component accounts for ------------------------------------------------------
    orphans = sorted(p for p in files if p not in claimed_paths and p not in generated)
    orphan_set = set(orphans)
    cand: dict[str, dict] = {}

    def consider(n: str) -> None:
        if n in declared_pkgs or n in cand or n not in index:
            return
        pl = ref.payload(n)
        hit = [p for p in pl["files"] if p in orphan_set]
        sib = [s for meta in pl["files"].values() if meta.get("soname")
               for s in by_soname.get(meta["soname"], []) if s in orphan_set and s not in hit]
        if hit or sib:
            ident = [p for p in hit if files[p]["sha256"] == pl["files"][p]["sha256"]]
            cand[n] = {"hit": set(hit) | set(sib), "ident": set(ident), "payload": len(pl["files"]), "version": pl["version"]}

    if ref.has_path_index:
        for p in orphans:
            for n in ref.path_owners(p):
                consider(n)
            if files[p]["soname"]:
                for n in ref.soname_owners(files[p]["soname"]):
                    consider(n)
    for snap in snapshots if use_hashes else ():
        owner = {}
        for n, sp in snap["packages"].items():
            for p in sp["files"]:
                owner.setdefault(p, n)
        for p in orphans:
            n = owner.get(p)
            if n and n not in declared_pkgs and snap["files"].get(p) == files[p]["sha256"]:
                c = cand.setdefault(n, {"hit": set(), "ident": set(), "payload": len(snap["packages"][n]["files"]),
                                        "version": snap["packages"][n]["version"]})
                c["hit"].add(p)
                c["ident"].add(p)
    explained = set().union(*(c["ident"] for c in cand.values())) if cand else set()
    if fallback_fetch:
        closure = [d for c in declared_pkgs for d in index[c].get("depends", []) if d in index and d not in declared_pkgs]
        guesses = list(dict.fromkeys(closure)) if not ref.has_path_index else []
        for p in orphans:
            if p in explained or not (files[p]["elf"] or not ref.has_path_index):
                continue
            guesses += [n for n in name_candidates(p, index, files[p]["soname"]) if not ref.indexed(n)]
        guesses = [n for n in dict.fromkeys(guesses) if n not in declared_pkgs][:120]
        ref.payloads(guesses)
        for n in guesses:
            consider(n)

    def rank(n: str):
        c = cand[n]
        return (len(c["ident"]), len(c["ident"]) / max(c["payload"], 1), len(c["hit"]), n in manifest, -len(n), n)

    attributed: dict[str, str] = {}
    groups: dict[str, dict] = {}
    for n in sorted(cand, key=rank, reverse=True):
        new = [p for p in cand[n]["hit"] if p not in attributed]
        if not new or (cand[n]["ident"] and not any(p in cand[n]["ident"] for p in new)):
            continue
        for p in new:
            attributed[p] = n
        alts = sorted(m for m in cand if m != n and cand[m]["ident"] and cand[m]["ident"] >= cand[n]["ident"]
                      and len(cand[m]["ident"]) == len(cand[n]["ident"]))
        groups[n] = {"files": sorted(new), "identical": bool(cand[n]["ident"]), "version": cand[n]["version"], "alternatives": alts}
    for n, g in sorted(groups.items()):
        add("undeclared_component", n, "A" if g["identical"] else "B",
            f"{len(g['files'])} file(s) present, {'byte-identical to' if g['identical'] else 'path or SONAME match with'} "
            f"reference {n} {g['version']}", files=g["files"][:20], alternatives=g["alternatives"][:8])
    leftover = [p for p in orphans if p not in attributed]
    code_left = [p for p in leftover if files[p]["elf"]]
    for p in code_left:
        add("undeclared_file", p, "B", "executable code not accounted for by any declared component or reference package")
    verdicts: dict[str, int] = {}
    for r in results:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    code_files = [p for p, m in files.items() if m["elf"]]
    return {
        "summary": {"declared": len(declared), "verdicts": verdicts, "rootfs_files": len(files),
                    "files_accounted": len(files) - len(leftover), "orphan_files": len(leftover),
                    "code_files": len(code_files), "orphan_code_files": len(code_left),
                    "hard_findings": sum(1 for f in findings if f["class"] in HARD),
                    "seconds": round(time.time() - t0, 2)},
        "options": {"use_hashes": use_hashes, "use_markers": use_markers, "release_manifest": bool(manifest),
                    "path_index": ref.has_path_index, "alt_releases": [a.release for a in alt_refs],
                    "snapshots": [s["source"] for s in snapshots], "normalize_timestamps": normalize_timestamps},
        "components": results, "findings": findings, "orphans": leftover,
    }


def inventory(rootfs: Path, ref: Reference, *, manifest: dict[str, str] | None = None, snapshots: list[dict] = ()) -> dict:
    """A component list derived from the bytes alone: every file is attributed to the reference package that ships it.

    This is what BOMwitness can say about an image that comes with no BOM and no package database.
    """
    rep = verify(rootfs, [], ref, manifest=manifest, snapshots=snapshots)
    comps = []
    for f in rep["findings"]:
        if f["class"] != "undeclared_component":
            continue
        name = f["component"]
        version = (manifest or {}).get(name) if f["grade"] == "A" else None
        for snap in snapshots:
            if name in snap["packages"] and f["grade"] == "A":
                version = version or snap["packages"][name]["version"]
        comps.append({"name": name, "version": version or ref.index()[name]["version"] if name in ref.index() else version or "",
                      "grade": f["grade"], "files": f.get("files", []), "alternatives": f.get("alternatives", [])})
    return {"components": comps, "unattributed_code": [f["component"] for f in rep["findings"] if f["class"] == "undeclared_file"],
            "unattributed_files": rep["orphans"], "summary": rep["summary"]}
