"""Check a declared SBOM against the bytes of an unpacked firmware root filesystem.

Evidence grades
  A  byte-identical to the official reference package (feed index hash, then
     per-file SHA-256)
  B  intrinsic to the firmware bytes: versioned file names, SONAMEs, and the
     version marker that the reference build of the same component carries
  C  the device's own package database. Recorded by other tools; never used
     here, so a database edited to agree with the BOM changes nothing.

Per-claim verdicts: verified_A, verified_B, wrong_version, absent,
bytes_differ (manual review), unverifiable. Image-level findings:
undeclared_component, undeclared_file, stale.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .feed import Feed, soname

IGNORED_PREFIXES = ("usr/lib/opkg/",)          # the device database itself (grade C, by design unused)
BUILD_GENERATED = {"lib/modules/%s/modules.builtin", "lib/modules/%s/modules.builtin.modinfo"}
NO_PACKAGE_HINTS = {"libc": (r"lib/libc\.so", r"lib/ld-musl-.*"), "kernel": (r"lib/modules/[^/]+/.*\.ko",)}
MUTABLE = {"etc/passwd", "etc/group", "etc/shadow"}  # rewritten by package install scripts at image build


def upstream_token(version: str) -> str | None:
    """Leading dotted release number of an OpenWrt version string, if any.

    "2.93-r1" gives "2.93"; "6.6.144~7024...-r1" gives "6.6.144". Date-style
    versions of OpenWrt's own tools also yield a token, but no build carries
    it, so it never produces a verdict on its own.
    """
    m = re.match(r"\d+(\.\d+)+[a-z]?(?![0-9])", version)
    return m.group(0) if m else None


def has_token(blob: bytes, token: str) -> bool:
    pat = rb"(?<![0-9])(?<![0-9]\.)" + re.escape(token.encode()) + rb"(?![0-9])(?!\.[0-9])"
    return re.search(pat, blob) is not None


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
            files[rel] = {"sha256": hashlib.sha256(blob).hexdigest(), "elf": blob[:4] == b"\x7fELF",
                          "soname": soname(blob) if ".so" in f else None}
    return files


def name_candidates(path: str, index: dict[str, dict], so: str | None = None) -> list[str]:
    """Reference packages whose name resembles an unaccounted file's name or SONAME."""
    stems = set()
    for base in filter(None, (path.rsplit("/", 1)[-1], so)):
        stem = re.sub(r"\.(so(\.[0-9.]+)?|ko|json|js|sh|uc|lua|conf)$", "", base)
        stem = re.sub(r"[-_.]?\d+(\.\d+)*$", "", stem)
        stems |= {stem, stem.replace("_", "-")}
        if stem.startswith("lib"):
            stems.add(stem[3:])
    stems = {s.lower() for s in stems if len(s) >= 3}
    out = []
    for n in index:
        parts = {x for x in n.split("-") if len(x) >= 3} | {n}
        core = re.sub(r"\d+$", "", n)
        if any(s == n or s == core or s in parts or n.startswith(s) or (len(s) >= 5 and s in n)
               or any(s.startswith(x) for x in parts if x not in ("lib", "kmod", "utils", "tools", "mod"))
               for s in stems):
            out.append(n)
    return sorted(out, key=len)[:60]


def verify(rootfs: Path, declared: list[dict], feed: Feed, alt_feeds: list[Feed] = ()) -> dict:
    index = feed.index()
    files = scan_rootfs(rootfs)
    kver = next((p.split("/")[2] for p in files if p.startswith("lib/modules/")), None)
    generated = {g % kver for g in BUILD_GENERATED} if kver else set()
    by_soname: dict[str, list[str]] = {}
    for p, m in files.items():
        if m["soname"]:
            by_soname.setdefault(m["soname"], []).append(p)

    payloads = feed.payloads([c["name"] for c in declared])
    claimed_paths: set[str] = set()
    results, findings = [], []

    def add(kind, name, grade, detail):
        findings.append({"class": kind, "component": name, "grade": grade, "detail": detail})

    for c in declared:
        name, ver = c["name"], c["version"]
        ref = index.get(name)
        res = {"name": name, "declared_version": ver, "reference_version": ref["version"] if ref else None}
        if ref is None:
            hint = [p for p in files if any(re.fullmatch(h, p) for h in NO_PACKAGE_HINTS.get(name, ()))]
            token = upstream_token(ver)
            claimed_paths.update(hint[:1] if name == "kernel" else hint)
            if hint and token and any(has_token((rootfs / p).read_bytes(), token) for p in hint[:5]):
                res.update(verdict="verified_B", reason=f"version marker {token} found in {hint[0]}")
            elif hint and token:
                res.update(verdict="wrong_version", actual_version=None,
                           reason=f"declared version marker {token} absent from {hint[0]}")
                add("wrong_version", name, "B", f"declared {ver}; marker {token} absent from {hint[0]}")
            else:
                res.update(verdict="unverifiable", reason="no reference package of this name in the feed")
            results.append(res)
            continue
        pl = payloads[name]
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
        claimed_paths.update(present)
        claimed_paths.update(s for _p, s in siblings)
        res.update(payload_files=len(pl["files"]), present=len(present), identical=len(same),
                   differing=differ, soname_siblings=[s for _p, s in siblings])
        token = upstream_token(ver)
        ref_token = upstream_token(ref["version"])
        code_here = present + [s for _p, s in siblings]

        def alt_lookup():
            """Compare this component's files with other official releases' builds of the same package."""
            same_as, declared_build_differs = None, False
            for af in alt_feeds:
                arec = af.index().get(name)
                if not arec:
                    continue
                apl = af.payload(name)
                shared = [p for p in apl["files"] if p in files and p not in MUTABLE and p not in apl["conffiles"]]
                eq = [p for p in shared if apl["files"][p]["sha256"] == files[p]["sha256"]]
                if differ and any(p in eq for p in differ):
                    same_as = (af.release, arec["version"])
                if arec["version"] == ver and (len(eq) < len(shared) or (apl["files"] and not shared)):
                    declared_build_differs = True
            return same_as, declared_build_differs

        if pl["files"] and not code_here:
            res.update(verdict="absent", reason="none of the reference package's files exist in the firmware")
            add("absent", name, "A", "declared, but no file of the reference package is present")
        elif not pl["files"]:
            res.update(verdict="unverifiable", reason="metadata-only package with no files to check")
        elif ref["version"] == ver and not differ and not siblings:
            res.update(verdict="verified_A", reason="every file byte-identical to the reference package")
        elif ref["version"] != ver and not differ and not siblings:
            # Bytes are identical to a reference build that carries another version label.
            marker = ref_token and any(has_token(p.encode(), ref_token) or has_token((rootfs / p).read_bytes(), ref_token)
                                       for p in present)
            _same, declared_build_differs = alt_lookup()
            if token and marker and token != ref_token:
                res.update(verdict="wrong_version", actual_version=ref["version"],
                           reason="files are byte-identical to the reference build and carry its version marker, not the declared one")
                add("wrong_version", name, "A", f"declared {ver}; bytes match reference {ref['version']}")
            elif declared_build_differs:
                res.update(verdict="wrong_version", actual_version=ref["version"],
                           reason="files match the reference build of another version; the official build of the declared version has different bytes")
                add("wrong_version", name, "A", f"declared {ver}; bytes match {ref['version']}, not the official {ver} build")
            else:
                # A rebuild or a version bump can leave every file unchanged, so the label alone is not refuted.
                res.update(verdict="consistent_label_differs",
                           reason=f"bytes identical to the reference build labelled {ref['version']}; label not checkable from bytes")
                add("label_mismatch", name, "A", f"declared {ver}; byte-identical reference is labelled {ref['version']}")
        else:
            # Some bytes differ from the only reference build we hold for this release.
            blobs = {p: (rootfs / p).read_bytes() for p in (differ + [s for _p, s in siblings]) or present}
            marker_here = bool(token) and any(has_token(p.encode(), token) or has_token(b, token) for p, b in blobs.items())
            ref_marker = False
            if ref_token:
                for path in differ + [p for p, _s in siblings]:
                    rb = feed.file_bytes(name, path)
                    if rb and (has_token(rb, ref_token) or has_token(path.encode(), ref_token)):
                        ref_marker = True
            same_as, _dbd = alt_lookup()
            if same_as and same_as[1] != ver:
                res.update(verdict="wrong_version", actual_version=same_as[1],
                           reason=f"bytes are identical to the {same_as[0]} release build of this package")
                add("wrong_version", name, "A", f"declared {ver}; bytes match {same_as[1]} from release {same_as[0]}")
            elif ref["version"] == ver:
                if token and ref_marker and not marker_here:
                    res.update(verdict="wrong_version", actual_version=None,
                               reason="bytes differ from the reference build and lack the version marker it carries")
                    add("wrong_version", name, "B", f"declared {ver}; version marker {token} absent from differing files")
                else:
                    res.update(verdict="bytes_differ",
                               reason="same version label as the reference build, different bytes: a rebuild or a modification, needs review")
                    add("bytes_differ", name, "A", f"{len(differ)} file(s) differ from the reference build of {ver}")
            elif marker_here:
                res.update(verdict="verified_B",
                           reason="reference feed has moved to another version; files carry the declared version marker")
            elif token and ref_marker:
                found = any(has_token(p.encode(), ref_token) or has_token(b, ref_token) for p, b in blobs.items())
                res.update(verdict="wrong_version", actual_version=ref["version"] if found else None,
                           reason="declared version marker absent from files that carry one in reference builds")
                add("wrong_version", name, "B", f"declared {ver}; marker {token} absent" + (f", marker {ref_token} present" if found else ""))
            else:
                res.update(verdict="unverifiable",
                           reason="reference feed has moved to another version and the files carry no version marker")
        if ref and res["verdict"] in ("verified_A", "verified_B") and ref["version"] != ver:
            add("stale", name, "A", f"firmware has {ver}; the reference feed now ships {ref['version']}")
        results.append(res)

    # Files no declared component accounts for.
    orphans = sorted(p for p in files if p not in claimed_paths and p not in generated)
    declared_names = {c["name"] for c in declared}
    closure = []
    for c in declared:
        for d in (index.get(c["name"]) or {}).get("depends", []):
            if d in index and d not in declared_names and d not in closure:
                closure.append(d)
    candidates = list(closure)
    for p in orphans:
        for n in name_candidates(p, index, files[p]["soname"]):
            if n not in declared_names and n not in candidates:
                candidates.append(n)
    orphan_set, attributed = set(orphans), {}
    cand_payloads = feed.payloads(candidates[:600])
    for n in candidates[:600]:
        pl = cand_payloads.get(n)
        if not pl or not pl["files"]:
            continue
        hit = [p for p in pl["files"] if p in orphan_set]
        sib = [s for meta in pl["files"].values() if meta.get("soname")
               for s in by_soname.get(meta["soname"], []) if s in orphan_set]
        if not hit and not sib:
            continue
        ident = [p for p in hit if files[p]["sha256"] == pl["files"][p]["sha256"]]
        score = (len(ident), len(hit) + len(sib))
        for p in set(hit) | set(sib):
            if p not in attributed or score > attributed[p][1]:
                attributed[p] = (n, score, bool(ident), pl["version"], n in closure)
    groups: dict[str, dict] = {}
    for p, (n, _s, ident, v, dep) in attributed.items():
        g = groups.setdefault(n, {"files": [], "identical": ident, "version": v, "dependency": dep})
        g["files"].append(p)
    for n, g in sorted(groups.items()):
        add("undeclared_component", n, "A" if g["identical"] else "B",
            f"{len(g['files'])} file(s) present, {'byte-identical to' if g['identical'] else 'path or SONAME match with'} "
            f"reference {n} {g['version']}" + ("; a dependency of a declared component" if g["dependency"] else ""))
    leftover = [p for p in orphans if p not in attributed]
    code_left = [p for p in leftover if files[p]["elf"]]
    for p in code_left:
        add("undeclared_file", p, "B", "executable code not accounted for by any declared component")
    verdicts = {}
    for r in results:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    return {"summary": {"declared": len(declared), "verdicts": verdicts, "rootfs_files": len(files),
                        "files_accounted": len(files) - len(leftover), "orphan_files": len(leftover),
                        "orphan_code_files": len(code_left)},
            "components": results, "findings": findings, "orphans": leftover}
