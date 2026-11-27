"""One test per verdict rule, plus the property the tool is built around: the device database changes nothing."""
import shutil

import pytest

import fakefeed
from bomwitness import devicedb, mutate
from bomwitness.elfinfo import has_token, same_version, strip_release, upstream_token
from bomwitness.verify import HARD, inventory, name_candidates, resolve, scan_rootfs, snapshot_from_rootfs, timestamp_only_diff, verify
from conftest import INSTALLED


def verdicts(rep):
    return {c["name"]: c["verdict"] for c in rep["components"]}


def hard(rep):
    return {(f["class"], f["component"]) for f in rep["findings"] if f["class"] in HARD}


def swap(claims, name, version):
    return [dict(c, version=version) if c["name"] == name else c for c in claims]


# ---- small helpers ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("version,token", [("2.93-r1", "2.93"), ("6.6.144~7024abc-r1", "6.6.144"), ("1.36.1-r3", "1.36.1"),
                                             ("20260601-r1", None), ("1674~443ec4032a", None), ("3.0.15a-r2", "3.0.15a"), ("", None)])
def test_upstream_token(version, token):
    assert upstream_token(version) == token


def test_has_token_respects_number_boundaries():
    assert has_token(b"BusyBox v1.36.1 (x)", "1.36.1")
    assert not has_token(b"v1.36.10", "1.36.1")
    assert not has_token(b"v11.36.1", "1.36.1")
    assert not has_token(b"v1.36.1.2", "1.36.1")
    assert not has_token(b"v2.1.36.1", "1.36.1")


def test_same_version_and_release_suffix():
    assert same_version("1.36.1-r3", "1.36.1-r3") == "exact"
    assert same_version("1.36.1", "1.36.1-r3") == "upstream"
    assert same_version("1.36.1-r2", "1.36.1-r3") is None
    assert strip_release("2024.01.01~abc-r1") == "2024.01.01~abc"


def test_timestamp_only_diff():
    a = b"x built (2026-10-29 20:36:30 UTC) y"
    assert timestamp_only_diff(a, b"x built (2026-07-24 07:21:50 UTC) y")
    assert not timestamp_only_diff(a, b"X built (2026-07-24 07:21:50 UTC) y")      # another byte differs too
    assert not timestamp_only_diff(a, a)
    assert not timestamp_only_diff(a, a + b"z")
    assert timestamp_only_diff(b"built Jul 24 2026 07:21:50", b"built Oct 29 2026 20:36:30")


def test_name_candidates_finds_similar_package_names():
    idx = {"tcpdump": {}, "libpcap1": {}, "kmod-usb-core": {}, "zlib": {}}
    assert "tcpdump" in name_candidates("usr/sbin/tcpdump", idx)
    assert "libpcap1" in name_candidates("usr/lib/libpcap.so.1.10.4", idx, "libpcap.so.1")
    assert name_candidates("usr/bin/pv", {"pv": {}, "zlib": {}}) == ["pv"]       # exact file name, even when short


def test_scan_ignores_the_device_database_and_symlinks(rootfs):
    (rootfs / "usr/bin/link").symlink_to("alpha")
    files = scan_rootfs(rootfs)
    assert "usr/bin/alpha" in files and "usr/bin/link" not in files
    assert not any(p.startswith("usr/lib/opkg/") for p in files)


# ---- per-claim verdicts ----------------------------------------------------------------------------------
def test_correct_bom_on_clean_image_has_no_hard_findings(rootfs, truth, ref):
    rep = verify(rootfs, truth, ref, manifest=ref.manifest())
    v = verdicts(rep)
    assert v["alpha"] == v["kmod-foo"] == v["gamma"] == v["libbeta5"] == v["base-files"] == "verified_A"
    assert v["meta"] == "unverifiable"                      # a package with no files gives nothing to check
    assert hard(rep) == set() and rep["summary"]["orphan_code_files"] == 0


def test_wrong_version_in_a_frozen_feed(rootfs, truth, ref):
    rep = verify(rootfs, swap(truth, "kmod-foo", "6.6.2-r1"), ref)
    assert ("wrong_version", "kmod-foo") in hard(rep)


def test_wrong_version_in_a_shared_feed_needs_the_manifest_or_a_marker(rootfs, truth, ref):
    bom = swap(truth, "gamma", "2024.01.02~abc-r1")         # gamma's bytes carry no version marker
    assert verdicts(verify(rootfs, bom, ref))["gamma"] == "label_unconfirmed"
    rep = verify(rootfs, bom, ref, manifest=ref.manifest())
    assert ("wrong_version", "gamma") in hard(rep)
    bom = swap(truth, "alpha", "1.2.4-r1")                  # alpha's bytes say 1.2.3
    assert ("wrong_version", "alpha") in hard(verify(rootfs, bom, ref))


def test_upstream_granularity_version_is_accepted(rootfs, truth, ref):
    assert verdicts(verify(rootfs, swap(truth, "alpha", "1.2.3"), ref))["alpha"] == "verified_A"


def test_abi_and_provides_names_resolve(rootfs, truth, ref):
    bom = [c for c in truth if c["name"] != "libbeta5"] + [{"name": "libbeta", "version": "2.0.1"}]
    rep = verify(rootfs, bom, ref)
    c = next(c for c in rep["components"] if c["name"] == "libbeta")
    assert c["verdict"] == "verified_A" and c["matched_by"] == "abi" and c["package"] == "libbeta5"
    assert hard(rep) == set()
    assert resolve("no-such-thing", ref, {}) == ([], "none")


def test_absent_component(rootfs, truth, ref):
    rep = verify(rootfs, truth + [{"name": "delta", "version": "3.0-r1"}], ref)
    assert hard(rep) == {("absent", "delta")}


def test_phantom_variant_sharing_a_path_is_absent_not_bytes_differ(rootfs, truth, ref):
    rep = verify(rootfs, truth + [{"name": "alpha-variant", "version": "1.2.3-r1"}], ref)
    assert hard(rep) == {("absent", "alpha-variant")}


def test_wrong_component_when_the_bytes_are_another_package(rootfs, truth, ref):
    bom = [c for c in truth if c["name"] != "alpha"] + [{"name": "alpha-variant", "version": "1.2.3-r1"}]
    rep = verify(rootfs, bom, ref)
    c = next(c for c in rep["components"] if c["name"] == "alpha-variant")
    assert c["verdict"] == "wrong_component" and c["actual_component"] == "alpha"


def test_one_changed_byte_is_bytes_differ(rootfs, truth, ref):
    p = rootfs / "usr/bin/gamma"
    b = bytearray(p.read_bytes()); b[-1] ^= 1; p.write_bytes(bytes(b))
    assert hard(verify(rootfs, truth, ref, manifest=ref.manifest())) == {("bytes_differ", "gamma")}


def test_swapped_binary_without_the_reference_marker_is_wrong_version(rootfs, truth, ref):
    (rootfs / "usr/bin/alpha").write_bytes(fakefeed.elf(b"alpha version 1.1.0 ok"))
    rep = verify(rootfs, truth, ref)
    assert ("wrong_version", "alpha") in hard(rep)


def test_build_timestamp_difference_is_normalised(rootfs, truth, ref):
    (rootfs / "usr/bin/stamp").write_bytes(fakefeed.elf(b"stamp 1.0 built (2026-07-24 07:21:50 UTC) end"))
    rep = verify(rootfs, truth, ref)
    c = next(c for c in rep["components"] if c["name"] == "stamp")
    assert c["verdict"] == "verified_A" and c["normalized_build_timestamp"] == ["usr/bin/stamp"]
    assert ("bytes_differ", "stamp") in hard(verify(rootfs, truth, ref, normalize_timestamps=False))


def test_conffiles_may_differ(rootfs, truth, ref):
    (rootfs / "etc/config/system").write_bytes(b"config system\n\toption hostname 'x'\n")
    assert verdicts(verify(rootfs, truth, ref))["base-files"] == "verified_A"


# ---- image-level findings --------------------------------------------------------------------------------
def test_omitted_component_is_named(rootfs, truth, ref):
    rep = verify(rootfs, [c for c in truth if c["name"] != "gamma"], ref)
    assert hard(rep) == {("undeclared_component", "gamma")}
    f = next(f for f in rep["findings"] if f["class"] == "undeclared_component")
    assert f["grade"] == "A" and f["files"] == ["usr/bin/gamma"]


def test_omitted_variant_names_the_package_whose_bytes_match(rootfs, truth, ref):
    rep = verify(rootfs, [c for c in truth if c["name"] != "alpha"], ref)
    assert hard(rep) == {("undeclared_component", "alpha")}


def test_implant_from_unindexed_feed_is_found_by_name(rootfs, truth, ref):
    (rootfs / "usr/bin/extra-tool").write_bytes(fakefeed.elf(b"extra tool 0.9"))
    assert hard(verify(rootfs, truth, ref)) == {("undeclared_component", "extra-tool")}


def test_unknown_executable_is_flagged_as_undeclared_file(rootfs, truth, ref):
    (rootfs / "usr/bin/backdoor").write_bytes(fakefeed.elf(b"nothing known"))
    (rootfs / "etc/notes.txt").write_text("not code")
    rep = verify(rootfs, truth, ref)
    assert hard(rep) == {("undeclared_file", "usr/bin/backdoor")}
    assert "etc/notes.txt" in rep["orphans"]


def test_inventory_from_bytes_alone(rootfs, ref):
    shutil.rmtree(rootfs / "usr/lib/opkg")
    inv = inventory(rootfs, ref, manifest=ref.manifest())
    got = {c["name"]: c["version"] for c in inv["components"]}
    assert got == {"alpha": "1.2.3-r1", "base-files": "1-r1", "gamma": "2024.01.01~abc-r1", "kmod-foo": "6.6.1-r1",
                   "libbeta5": "2.0.1-r2", "stamp": "1.0-r1"}


# ---- feed drift, markers and release snapshots -----------------------------------------------------------
@pytest.fixture()
def drifted(tmp_path, signer):
    """A firmware built from older packages than the shared feed now carries."""
    old = dict(fakefeed.DEFAULT_PACKAGES)
    old["alpha"] = ("base", "1.2.2-r1", {"usr/bin/alpha": fakefeed.elf(b"alpha version 1.2.2 ok")}, "")
    old["gamma"] = ("base", "2023.12.01~aaa-r1", {"usr/bin/gamma": fakefeed.elf(b"gamma tool older build")}, "")
    fw = fakefeed.make_rootfs(tmp_path / "fw", INSTALLED, old)
    sibling = fakefeed.make_rootfs(tmp_path / "sibling", INSTALLED, old)
    return fw, fakefeed.claims(INSTALLED, old), snapshot_from_rootfs(sibling, "test sibling")


def test_moved_feed_marker_gives_verified_b(drifted, ref):
    fw, bom, _snap = drifted
    v = verdicts(verify(fw, bom, ref))
    assert v["alpha"] == "verified_B" and v["gamma"] == "unverifiable"
    assert ("wrong_version", "alpha") in hard(verify(fw, swap(bom, "alpha", "1.2.9-r1"), ref))


def test_snapshot_restores_grade_a_after_feed_drift(drifted, ref):
    fw, bom, snap = drifted
    rep = verify(fw, bom, ref, snapshots=[snap])
    v = verdicts(rep)
    assert v["alpha"] == v["gamma"] == "verified_A" and hard(rep) == set()
    assert any(f["class"] == "stale" and f["component"] == "gamma" for f in rep["findings"])


def test_snapshot_label_mismatch_is_wrong_version(drifted, ref):
    fw, bom, snap = drifted
    assert ("wrong_version", "gamma") in hard(verify(fw, swap(bom, "gamma", "2023.12.02~aaa-r1"), ref, snapshots=[snap]))


def test_patch_against_snapshot_is_bytes_differ(drifted, ref):
    fw, bom, snap = drifted
    (fw / "usr/bin/gamma").write_bytes(fakefeed.elf(b"gamma tool older buile"))
    assert ("bytes_differ", "gamma") in hard(verify(fw, bom, ref, snapshots=[snap]))


# ---- trust of a snapshot: wording only ----------------------------------------------------------------------
def _texts(rep):
    return " | ".join([c.get("reason", "") for c in rep["components"]] + [f["detail"] for f in rep["findings"]])


@pytest.mark.parametrize("case", ["correct", "wrong_label", "patched", "omitted"])
def test_snapshot_trust_changes_reason_text_and_never_a_verdict(drifted, ref, case):
    fw, bom, snap = drifted
    if case == "wrong_label":
        bom = swap(bom, "gamma", "2023.12.02~aaa-r1")
    elif case == "patched":
        (fw / "usr/bin/gamma").write_bytes(fakefeed.elf(b"gamma tool older buile"))
    elif case == "omitted":
        bom = [c for c in bom if c["name"] != "gamma"]
    reps = {}
    for trust in ("authenticated", "unlisted", "supplied", None, "official"):       # None: no field; "official": not a known value
        s = {k: v for k, v in snap.items() if k != "trust"}
        if trust is not None:
            s["trust"] = trust
        reps[trust] = verify(fw, bom, ref, snapshots=[s])
    base = reps["authenticated"]
    for trust, rep in reps.items():
        assert verdicts(rep) == verdicts(base) and hard(rep) == hard(base)
        assert [(f["class"], f["component"], f["grade"]) for f in rep["findings"]] == [(f["class"], f["component"], f["grade"]) for f in base["findings"]]
        assert rep["summary"]["verdicts"] == base["summary"]["verdicts"]
        text = _texts(rep)
        assert "official" not in text                      # no source is called official, whatever the caller passes
        if trust != "authenticated":
            assert "(authenticated:" not in text
    assert reps["authenticated"]["options"]["snapshot_trust"] == ["authenticated"]
    assert reps["unlisted"]["options"]["snapshot_trust"] == ["unlisted"]
    assert reps[None]["options"]["snapshot_trust"] == reps["official"]["options"]["snapshot_trust"] == ["supplied"]
    if case != "omitted":                                  # gamma's verdict rests on the snapshot in these three cases
        def reason(trust):
            return next(c["reason"] for c in reps[trust]["components"] if c["name"] == "gamma")
        assert "the sibling image (authenticated: its SHA-256 is in the image list pinned by the signed checksum file)" in reason("authenticated")
        assert "the supplied sibling image (not authenticated: it is not in the image list" in reason("unlisted")
        for trust in ("supplied", None, "official"):
            assert "the supplied snapshot (not authenticated by this run)" in reason(trust)


def test_snapshot_from_rootfs_defaults_to_supplied_and_rejects_unknown_trust(rootfs):
    assert snapshot_from_rootfs(rootfs, "a tree")["trust"] == "supplied"
    assert snapshot_from_rootfs(rootfs, "a tree", trust="authenticated")["trust"] == "authenticated"
    with pytest.raises(AssertionError):
        snapshot_from_rootfs(rootfs, "a tree", trust="official")


# ---- what a grade A reason says about its own scope ----------------------------------------------------------
def test_grade_a_reason_states_masking_exclusions_and_partial_presence(rootfs, truth, ref):
    def reason(rep, name):
        c = next(c for c in rep["components"] if c["name"] == name)
        assert c["verdict"] == "verified_A"
        return c["reason"]
    rep = verify(rootfs, truth, ref)
    assert reason(rep, "alpha") == "1 of the 1 package file(s) present in the image have the reference package's SHA-256"
    assert "byte-identical" not in _texts(rep) and "every file" not in _texts(rep)
    # a file accepted only because its differences are inside build-date strings is counted as such
    (rootfs / "usr/bin/stamp").write_bytes(fakefeed.elf(b"stamp 1.0 built (2026-07-24 07:21:50 UTC) end"))
    assert "(1 of them only after embedded build-date strings are masked)" in reason(verify(rootfs, truth, ref), "stamp")
    # a changed configuration file is not compared, and the reason says so
    (rootfs / "etc/config/system").write_bytes(b"config system\n\toption hostname 'changed'\n")
    r = reason(verify(rootfs, truth, ref), "base-files")
    assert r.startswith("1 of the 2 package file(s) present") and "1 configuration or account file(s) differ and are not compared" in r
    # a package that is only partly present still passes at grade A, and the reason gives the missing count
    (rootfs / "etc/banner").unlink()
    r = reason(verify(rootfs, truth, ref), "base-files")
    assert r.startswith("0 of the 1 package file(s) present") and "1 of the package's 2 files were not found among the image files compared" in r


def test_report_text_does_not_call_grade_a_byte_identity():
    from bomwitness import report
    assert "byte-identical" not in " ".join(report.VERDICT_TEXT.values())
    assert "no compared file differs" in report.VERDICT_TEXT["verified_A"]       # not "the files match": zero matches can pass


def test_grade_a_with_zero_matched_files_says_so(rootfs, truth, ref):
    """The rule passes a package whose only file present is a changed configuration file. The reason must not read as a match."""
    (rootfs / "etc/config/system").write_bytes(b"config system\n\toption hostname 'changed'\n")
    (rootfs / "etc/banner").unlink()
    c = next(c for c in verify(rootfs, truth, ref)["components"] if c["name"] == "base-files")
    assert c["verdict"] == "verified_A" and c["identical"] == 0
    assert c["reason"].startswith("0 of the 1 package file(s) present")
    assert c["reason"].endswith("no file was positively matched, so grade A here means only that no compared file differs")
    # and a normal match does not carry that sentence
    assert "positively matched" not in next(c for c in verify(rootfs, truth, ref)["components"] if c["name"] == "alpha")["reason"]


def test_snapshot_attributes_omitted_component(drifted, ref):
    fw, bom, snap = drifted
    rep = verify(fw, [c for c in bom if c["name"] != "gamma"], ref, snapshots=[snap])
    assert ("undeclared_component", "gamma") in hard(rep)


# ---- which input supported a finding (independent review, round 4, blocking defect 1) ---------------------------
SUPPLIED = "the supplied snapshot (not authenticated by this run) [test sibling]"
OLD_GAMMA, FEED_GAMMA = "2023.12.01~aaa-r1", "2024.01.01~abc-r1"


def _gamma_finding(rep, kind):
    return next(f for f in rep["findings"] if f["class"] == kind and f["component"] == "gamma")


def test_omitted_component_matched_only_by_a_snapshot_names_the_snapshot_and_its_version(drifted, ref):
    """The reviewer's case. The firmware holds an older gamma than the feed now ships, and the BOM omits it.

    Without the snapshot the feed can only match the path (grade B). With it the file matches the snapshot's record,
    so the finding must name the snapshot, say it was not authenticated, and report the snapshot's version of gamma.
    It must not present the feed's current label as the build that matched.
    """
    fw, bom, snap = drifted
    bom = [c for c in bom if c["name"] != "gamma"]
    alone = _gamma_finding(verify(fw, bom, ref), "undeclared_component")
    assert alone["grade"] == "B" and alone["detail"] == f"1 file(s) present, path or SONAME match with reference gamma {FEED_GAMMA}"
    assert "evidence" not in alone
    f = _gamma_finding(verify(fw, bom, ref, snapshots=[snap]), "undeclared_component")
    assert f["grade"] == "A"
    assert f["detail"] == (f"1 file(s) present: 1 with the SHA-256 that {SUPPLIED} records for gamma {OLD_GAMMA}; "
                           f"none of them has the SHA-256 of the feed's current gamma {FEED_GAMMA}")
    assert "byte-identical to reference" not in f["detail"]
    assert f["evidence"] == [{"input": "test sibling", "trust": "supplied", "version": OLD_GAMMA, "files": 1}]


def test_stale_note_that_rests_on_a_snapshot_names_it_and_its_trust(drifted, ref):
    """The reviewer's second case: gamma is declared with the older version and verifies against the snapshot."""
    fw, bom, snap = drifted
    rep = verify(fw, bom, ref, snapshots=[snap])
    c = next(c for c in rep["components"] if c["name"] == "gamma")
    assert c["verdict"] == "verified_A" and c["label_source"] == "release snapshot"
    assert c["evidence"] == {"input": "test sibling", "trust": "supplied", "version": OLD_GAMMA, "files": 1}
    f = _gamma_finding(rep, "stale")
    assert f["grade"] == "A"
    assert f["detail"] == f"firmware has {OLD_GAMMA}, verified against {SUPPLIED}; the reference feed now ships {FEED_GAMMA}"
    assert f["evidence"] == c["evidence"]
    # alpha verifies against the same snapshot and its stale note is qualified in the same way
    assert SUPPLIED in next(f for f in rep["findings"] if f["class"] == "stale" and f["component"] == "alpha")["detail"]


@pytest.mark.parametrize("trust,words", [
    ("authenticated", "the sibling image (authenticated: its SHA-256 is in the image list pinned by the signed checksum file) [dev-b.bin]"),
    ("unlisted", "the supplied sibling image (not authenticated: it is not in the image list pinned by the signed checksum file) [dev-b.bin]"),
    ("supplied", "the supplied snapshot (not authenticated by this run) [dev-b.bin]")])
def test_attribution_and_stale_findings_carry_the_trust_of_the_snapshot(drifted, ref, trust, words):
    fw, bom, snap = drifted
    snap = dict(snap, trust=trust, source="dev-b.bin")
    assert words in _gamma_finding(verify(fw, [c for c in bom if c["name"] != "gamma"], ref, snapshots=[snap]), "undeclared_component")["detail"]
    rep = verify(fw, bom, ref, snapshots=[snap])
    assert words in _gamma_finding(rep, "stale")["detail"] and _gamma_finding(rep, "stale")["evidence"]["trust"] == trust
    for other in ("authenticated", "unlisted", "supplied"):          # and never the words of another trust level
        if other != trust:
            assert verify.__globals__["SNAPSHOT_TRUST"][other] not in _texts(rep)


def test_per_file_source_is_kept_when_feed_and_snapshot_each_match_part_of_a_package(release_root, signer, tmp_path):
    """Two files of an omitted package: one has the feed's bytes, the other only the snapshot's. Both sources are reported."""
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool same in both"), "usr/lib/duo.dat": b"data, feed build\n"}, "")
    old = dict(pk)
    old["duo"] = ("base", "1.9-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool same in both"), "usr/lib/duo.dat": b"data, older build\n"}, "")
    root = tmp_path / "releases"
    fakefeed.make_release(root, signer, packages=pk)
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw", names, old)
    snap = snapshot_from_rootfs(fakefeed.make_rootfs(tmp_path / "sib", names, old), "dev-b.bin", trust="authenticated")
    bom = [c for c in fakefeed.claims(names, old) if c["name"] != "duo"]
    auth = "the sibling image (authenticated: its SHA-256 is in the image list pinned by the signed checksum file) [dev-b.bin]"
    r = fakefeed.reference(root, signer, tmp_path / "cache-indexed")
    f = next(f for f in verify(fw, bom, r, snapshots=[snap])["findings"] if f["class"] == "undeclared_component")
    assert f["component"] == "duo" and f["grade"] == "A"
    assert f["detail"] == f"2 file(s) present: 1 with the SHA-256 that {auth} records for duo 1.9-r1, 1 with the SHA-256 of the feed's reference duo 2.0-r1"
    assert f["evidence"] == [{"input": "feed index", "trust": "signed reference", "version": "2.0-r1", "files": 1},
                             {"input": "dev-b.bin", "trust": "authenticated", "version": "1.9-r1", "files": 2}]
    # Without the file-path index the feed is fetched only for files the snapshot leaves unexplained. Here it explains both,
    # so the feed's duo is never compared and the finding says nothing about it: only the snapshot and its version are named.
    lazy = fakefeed.reference(root, signer, tmp_path / "cache-lazy", index=False)
    f = next(f for f in verify(fw, bom, lazy, snapshots=[snap])["findings"] if f["class"] == "undeclared_component")
    assert f["component"] == "duo" and f["grade"] == "A"
    assert f["detail"] == f"2 file(s) present: 2 with the SHA-256 that {auth} records for duo 1.9-r1"
    assert f["evidence"] == [{"input": "dev-b.bin", "trust": "authenticated", "version": "1.9-r1", "files": 2}]
    # when the feed matches every file, the snapshot adds nothing to the text and the wording is the feed's
    same = snapshot_from_rootfs(fakefeed.make_rootfs(tmp_path / "sib2", names, pk), "dev-b.bin")
    fw2 = fakefeed.make_rootfs(tmp_path / "fw2", names, pk)
    f = next(f for f in verify(fw2, [c for c in fakefeed.claims(names, pk) if c["name"] != "duo"], r, snapshots=[same])["findings"]
             if f["class"] == "undeclared_component")
    assert f["detail"] == "2 file(s) present, all byte-identical to reference duo 2.0-r1"
    assert [e["input"] for e in f["evidence"]] == ["feed index", "dev-b.bin"]


def test_a_snapshot_name_cannot_call_an_unauthenticated_source_official(drifted, ref):
    fw, bom, snap = drifted
    for trust, expect in (("supplied", "[sibling image x.bin]"), ("unlisted", "[sibling image x.bin]"), ("authenticated", "[official sibling image x.bin]")):
        s = dict(snap, source="official sibling image x.bin", trust=trust)
        text = _texts(verify(fw, bom, ref, snapshots=[s])) + _texts(verify(fw, [c for c in bom if c["name"] != "gamma"], ref, snapshots=[s]))
        assert expect in text and ("official" in text) == (trust == "authenticated")


# ---- another release as evidence: named, with coverage counts ---------------------------------------------------
@pytest.fixture()
def other_release(tmp_path, signer):
    """The primary release ships duo 2.0; release 98.01.0 of the same target shipped duo 1.9 with other bytes in both files."""
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 2.0 build"), "usr/lib/duo.dat": b"data 2.0\n"}, "")
    old = dict(pk)
    old["duo"] = ("base", "1.9-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 1.9 build"), "usr/lib/duo.dat": b"data 1.9\n"}, "")
    root = tmp_path / "releases"
    fakefeed.make_release(root, signer, packages=pk)
    fakefeed.make_release(root, signer, release="98.01.0", packages=old)
    names = INSTALLED + ["duo"]
    return (root, fakefeed.reference(root, signer, tmp_path / "cache"), fakefeed.reference(root, signer, tmp_path / "cache", release="98.01.0"),
            fakefeed.make_rootfs(tmp_path / "fw", names, old), fakefeed.claims(names, old))


def test_other_release_verdict_names_the_release_and_gives_coverage_counts(other_release):
    _root, r, alt, fw, bom = other_release
    rep = verify(fw, bom, r, [alt])
    c = next(c for c in rep["components"] if c["name"] == "duo")
    assert c["verdict"] == "verified_A" and c["label_source"] == "release 98.01.0 feed"
    assert c["reason"] == ("2 of the 2 compared file(s) that differ from this release's reference have the SHA-256 of the 98.01.0 release build "
                           "of this version (1.9-r1) (that release's reference is authenticated through its own signed checksum file and feed "
                           "indexes); 0 of the 2 package file(s) present have this release's reference SHA-256")
    assert c["evidence"] == {"input": "release 98.01.0 feed", "trust": "signed reference", "version": "1.9-r1", "files": 2}
    stale = next(f for f in rep["findings"] if f["class"] == "stale" and f["component"] == "duo")
    assert stale["detail"] == ("firmware has 1.9-r1, verified against the release 98.01.0 feed (signed reference of that release); "
                               "the reference feed now ships 2.0-r1")
    # The rule asks for one differing file to match the other release. When another file matches neither, the count shows it.
    (fw / "usr/lib/duo.dat").write_bytes(b"data, changed\n")
    c = next(c for c in verify(fw, bom, r, [alt])["components"] if c["name"] == "duo")
    assert c["verdict"] == "verified_A"                      # unchanged rule, now visible in the reason
    assert c["reason"].startswith("1 of the 2 compared file(s) that differ") and "; 1 differ from both builds" in c["reason"]
    assert c["evidence"]["files"] == 1
    # a wrong label is refuted by the same evidence and names the release too
    w = next(f for f in verify(fw, swap(bom, "duo", "1.8-r1"), r, [alt])["findings"] if f["class"] == "wrong_version" and f["component"] == "duo")
    assert "the 98.01.0 release build 1.9-r1" in w["detail"] and w["evidence"]["input"] == "release 98.01.0 feed"


def test_a_finding_that_another_release_changes_names_that_release(other_release, tmp_path, signer):
    """Reviewer's case: primary duo 2.0-r1 bytes declared as 1.9-r1, markers off. Release 98.01.0's build of 1.9-r1
    has other bytes, which turns label_unconfirmed into wrong_version. The finding names the release, its key and the
    version it records, and carries the evidence record, like the positive other-release path."""
    root, r, alt, _fw, _bom = other_release
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 2.0 build"), "usr/lib/duo.dat": b"data 2.0\n"}, "")
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw2", names, pk)
    bom = swap(fakefeed.claims(names, pk), "duo", "1.9-r1")
    alone = verify(fw, bom, r, use_markers=False)
    assert next(c for c in alone["components"] if c["name"] == "duo")["verdict"] == "label_unconfirmed"
    assert not [f for f in alone["findings"] if f["component"] == "duo" and f.get("evidence")]
    rep = verify(fw, bom, r, [alt], use_markers=False)
    c = next(c for c in rep["components"] if c["name"] == "duo")
    key = alt.meta()["sha256sums_signed_by"]
    assert key and c["verdict"] == "wrong_version" and c["actual_version"] == "2.0-r1"
    assert c["evidence"] == {"input": "release 98.01.0 feed", "trust": "signed reference", "version": "1.9-r1", "files": 2}
    f = next(f for f in rep["findings"] if f["class"] == "wrong_version" and f["component"] == "duo")
    assert f["evidence"] == c["evidence"]
    assert f["detail"] == ("declared 1.9-r1; actual 2.0-r1. the files present match this release's reference build 2.0-r1; the 98.01.0 "
                           "release build of the declared version (1.9-r1) has different bytes in 2 of the 2 file(s) compared (that "
                           f"release's reference is authenticated through its own checksum file, signed by usign key {key}, and feed "
                           "indexes); 2 of the 2 package file(s) present in the image have the reference package's SHA-256")
    assert "another release" not in f["detail"]


def test_other_release_reason_separates_masked_from_raw_matches(other_release, tmp_path, signer):
    """A file accepted against this release's reference only after its build date is masked is not counted as a raw SHA-256 match."""
    root = tmp_path / "rel2"
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 2.0 build"),
                                    "usr/lib/duo.txt": b"duo built Nov 27 2026 10:00:00 here\n"}, "")
    old = dict(pk)
    old["duo"] = ("base", "1.9-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 1.9 build"),
                                     "usr/lib/duo.txt": b"duo built Nov 27 2026 10:00:00 here\n"}, "")
    fakefeed.make_release(root, signer, packages=pk)
    fakefeed.make_release(root, signer, release="98.01.0", packages=old)
    r = fakefeed.reference(root, signer, tmp_path / "c2")
    alt = fakefeed.reference(root, signer, tmp_path / "c2", release="98.01.0")
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw3", names, old)
    (fw / "usr/lib/duo.txt").write_bytes(b"duo built Dec 01 2026 11:22:33 here\n")      # same size, other build date
    c = next(c for c in verify(fw, fakefeed.claims(names, old), r, [alt])["components"] if c["name"] == "duo")
    assert c["verdict"] == "verified_A" and c["normalized_build_timestamp"] == ["usr/lib/duo.txt"]
    assert c["reason"].endswith("0 of the 2 package file(s) present have this release's reference SHA-256 and 1 more match it "
                                "only after embedded build-date strings are masked (their raw SHA-256 differs)")


# ---- ablations -------------------------------------------------------------------------------------------
def test_grade_b_only_cannot_see_a_patched_byte(rootfs, truth, ref):
    p = rootfs / "usr/bin/alpha"
    b = bytearray(p.read_bytes()); b[8] ^= 1; p.write_bytes(bytes(b))
    assert hard(verify(rootfs, truth, ref, use_hashes=False)) == set()
    assert ("bytes_differ", "alpha") in hard(verify(rootfs, truth, ref))


def test_grade_a_only_still_catches_frozen_feed_labels(rootfs, truth, ref):
    rep = verify(rootfs, swap(truth, "kmod-foo", "6.6.2-r1"), ref, use_markers=False)
    assert ("wrong_version", "kmod-foo") in hard(rep)


# ---- the device database is never evidence ---------------------------------------------------------------
@pytest.mark.parametrize("bom_error", ["omit", "version", "phantom"])
def test_verdicts_do_not_depend_on_the_device_database(rootfs, truth, ref, bom_error, tmp_path):
    if bom_error == "omit":
        bom = [c for c in truth if c["name"] != "gamma"]
        collude = lambda r: mutate.db_remove(r, "gamma")
    elif bom_error == "version":
        bom = swap(truth, "kmod-foo", "6.6.2-r1")
        collude = lambda r: mutate.db_set_version(r, "kmod-foo", "6.6.2-r1")
    else:
        bom = truth + [{"name": "delta", "version": "3.0-r1"}]
        collude = lambda r: mutate.db_add(r, "delta", "3.0-r1", "testarch", ["usr/bin/delta"])
    honest = hard(verify(rootfs, bom, ref, manifest=ref.manifest()))
    colluding = mutate.clone(rootfs, tmp_path / "colluding"); collude(colluding)
    stripped = mutate.clone(rootfs, tmp_path / "stripped"); mutate.db_strip(stripped)
    assert len(honest) == 1
    assert hard(verify(colluding, bom, ref, manifest=ref.manifest())) == honest
    assert hard(verify(stripped, bom, ref, manifest=ref.manifest())) == honest
    # and the colluding database really does agree with the wrong BOM
    assert [f for f in devicedb.compare(colluding, bom, []).get("findings", []) if f["class"] != "db_contradicted_by_bytes"] == []


def test_database_comparison_reports_disagreements(rootfs, truth, ref):
    bom = swap([c for c in truth if c["name"] != "gamma"], "alpha", "9.9.9") + [{"name": "delta", "version": "3.0-r1"}]
    rep = verify(rootfs, bom, ref)
    got = {(f["class"], f["component"]) for f in devicedb.compare(rootfs, bom, rep["components"])["findings"]}
    assert got == {("undeclared_component", "gamma"), ("wrong_version", "alpha"), ("absent", "delta")}
    assert all(f["grade"] == "C" and f["source"] == "device_db" for f in devicedb.compare(rootfs, bom, rep["components"])["findings"])


def test_database_contradicted_by_bytes(rootfs, truth, ref, tmp_path):
    bom = swap(truth, "kmod-foo", "6.6.2-r1")
    mutate.db_set_version(rootfs, "kmod-foo", "6.6.2-r1")
    rep = verify(rootfs, bom, ref)
    got = {(f["class"], f["component"]) for f in devicedb.compare(rootfs, bom, rep["components"])["findings"]}
    assert got == {("db_contradicted_by_bytes", "kmod-foo")}


def test_no_database_is_reported_as_absent_not_as_an_error(rootfs, truth):
    mutate.db_strip(rootfs)
    assert devicedb.compare(rootfs, truth, []) == {"present": False, "packages": 0, "findings": []}


def test_kernel_claim_does_not_hide_an_omitted_kernel_module(rootfs, truth, ref):
    """Regression: the built-in `kernel` claim reads a version marker from a module but must not claim the file."""
    bom = [c for c in truth if c["name"] != "kmod-foo"] + [{"name": "kernel", "version": "6.6.1~abc-r1"}]
    rep = verify(rootfs, bom, ref)
    assert verdicts(rep)["kernel"] == "verified_B"
    assert hard(rep) == {("undeclared_component", "kmod-foo")}
    assert ("wrong_version", "kernel") in hard(verify(rootfs, swap(bom, "kernel", "6.6.9~abc-r1"), ref))


def test_snapshot_and_feed_attribution_are_merged_without_a_path_index(release_root, signer, tmp_path, truth):
    """Regression (found by the pipeline example after the freeze): on-demand mode, snapshot plus feed evidence.

    The sibling snapshot leaves configuration files out of a package's file list. Without merging, those files
    were attributed to a second package that ships identical defaults.
    """
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["gamma"] = ("base", "2024.01.01~abc-r1", {"usr/bin/gamma": fakefeed.elf(b"gamma tool no marker"), "etc/config/gamma": b"defaults\n"}, "")
    pk["gamma-full"] = ("base", "2024.01.01~abc-r1", {"usr/bin/gamma": fakefeed.elf(b"gamma FULL"), "etc/config/gamma": b"defaults\n"}, "")
    root = tmp_path / "releases"
    fakefeed.make_release(root, signer, packages=pk)
    r = fakefeed.reference(root, signer, tmp_path / "cache", index=False)
    fw = fakefeed.make_rootfs(tmp_path / "fw", INSTALLED, pk)
    snap = snapshot_from_rootfs(fakefeed.make_rootfs(tmp_path / "sib", INSTALLED, pk), "sibling")
    bom = [c for c in fakefeed.claims(INSTALLED, pk) if c["name"] != "gamma"]
    assert hard(verify(fw, bom, r, snapshots=[snap])) == {("undeclared_component", "gamma")}


NONE_COMPARED = ("has none of its {n} file(s) compared: no file it ships is both present in the image and among the files "
                 "this tool compares")


def test_other_release_with_no_comparable_file_says_none_compared(other_release, tmp_path, signer):
    """Round 6 reviewer's case: the only file the 98.01.0 build shares with the image is a configuration file, which is
    not compared. The detail must say no file was compared, not that none of its files is present."""
    root = tmp_path / "rel3"
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 2.0 build"), "etc/config/duo": b"config duo\n"}, "")
    old = dict(pk)
    old["duo"] = ("base", "1.9-r1", {"usr/lib/old-duo.dat": b"old data\n", "etc/config/duo": b"config duo\n"}, "")
    fakefeed.make_release(root, signer, packages=pk)
    fakefeed.make_release(root, signer, release="98.01.0", packages=old)
    r = fakefeed.reference(root, signer, tmp_path / "c3")
    alt = fakefeed.reference(root, signer, tmp_path / "c3", release="98.01.0")
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw4", names, pk)
    assert (fw / "etc/config/duo").read_bytes() == b"config duo\n"
    rep = verify(fw, swap(fakefeed.claims(names, pk), "duo", "1.9-r1"), r, [alt], use_markers=False)
    f = next(f for f in rep["findings"] if f["class"] == "wrong_version" and f["component"] == "duo")
    assert f["evidence"]["files"] == 0
    assert NONE_COMPARED.format(n=2) in f["detail"]
    assert "has none of its 2 file(s) in the image (" not in f["detail"]     # the round 6 wording
    assert "apart from" not in f["detail"]                                   # the round 7 wording, which listed what is excluded


def test_other_release_detail_does_not_list_what_is_excluded(other_release, tmp_path, signer):
    """Round 7 reviewer's case: the other release's build also ships a byte-identical regular file under usr/lib/opkg/,
    which the image scan skips, and the image holds it. Round 7's detail said that no file was in the image apart from
    configuration and account files; that is false here. The detail must say only that no file was compared."""
    root = tmp_path / "rel4"
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/bin/duo": fakefeed.elf(b"duo tool 2.0 build"), "etc/config/duo": b"config duo\n"}, "")
    old = dict(pk)
    record = b"release record\n"
    old["duo"] = ("base", "1.9-r1", {"usr/lib/old-duo.dat": b"old data\n", "etc/config/duo": b"config duo\n",
                                    "usr/lib/opkg/info/duo.release-record": record}, "")
    fakefeed.make_release(root, signer, packages=pk)
    fakefeed.make_release(root, signer, release="98.01.0", packages=old)
    r = fakefeed.reference(root, signer, tmp_path / "c4")
    alt = fakefeed.reference(root, signer, tmp_path / "c4", release="98.01.0")
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw5", names, pk)
    held = fw / "usr/lib/opkg/info/duo.release-record"
    held.parent.mkdir(parents=True, exist_ok=True)
    held.write_bytes(record)
    assert held.is_file() and not held.is_symlink() and held.read_bytes() == record     # present on disk
    assert "usr/lib/opkg/info/duo.release-record" not in scan_rootfs(fw)               # and skipped by the scan
    rep = verify(fw, swap(fakefeed.claims(names, pk), "duo", "1.9-r1"), r, [alt], use_markers=False)
    f = next(f for f in rep["findings"] if f["class"] == "wrong_version" and f["component"] == "duo")
    assert f["evidence"]["files"] == 0
    assert NONE_COMPARED.format(n=3) in f["detail"]
    assert "apart from" not in f["detail"] and "configuration and account" not in f["detail"]
    assert "none of its 3 file(s) in the image" not in f["detail"]


def test_absence_wording_does_not_claim_more_than_the_compared_files(tmp_path, signer):
    """A reference file under a path the scan skips (usr/lib/opkg/) can be on disk. No reason may say it is not in the
    image or the firmware; it says it was not found among the files compared."""
    root = tmp_path / "rel5"
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    pk["duo"] = ("base", "2.0-r1", {"usr/lib/opkg/info/duo.record": b"record\n", "usr/lib/opkg/duo-extra": b"extra\n"}, "")
    fakefeed.make_release(root, signer, packages=pk)
    r = fakefeed.reference(root, signer, tmp_path / "c5")
    names = INSTALLED + ["duo"]
    fw = fakefeed.make_rootfs(tmp_path / "fw6", names, pk)
    for rel in ("usr/lib/opkg/info/duo.record", "usr/lib/opkg/duo-extra"):
        (fw / rel).parent.mkdir(parents=True, exist_ok=True)
        (fw / rel).write_bytes(b"record\n" if rel.endswith("record") else b"extra\n")
        assert (fw / rel).is_file()
    rep = verify(fw, fakefeed.claims(names, pk), r)
    text = next(c for c in rep["components"] if c["name"] == "duo")["reason"]
    assert text == "none of the reference package's files was found among the firmware files this tool compares"
    assert "exist in the firmware" not in text and "not in the image" not in text


# ---- round 9: the reasons say what was compared and matched, nothing beyond it ------------------------------
def test_twin_file_reason_and_label_do_not_overstate_attribution(tmp_path, signer):
    """Round 8 reviewer's case. alpha-variant ships usr/share/twin/common.txt (byte-identical to alpha's copy, and present
    in the image), usr/bin/alpha (the image holds alpha's build of it) and a record file under usr/lib/opkg/ that is
    byte-identical on disk and skipped by the scan. The reason must say what was compared (two files found among the
    compared ones, each equal to a file of another declared component) and must not say that no file at the package's
    paths is attributable to it, which a skipped file contradicts; the Markdown label must not say no file was found."""
    from bomwitness import report
    pk = dict(fakefeed.DEFAULT_PACKAGES)
    common = b"shared by both packages\n"
    record = b"alpha-variant release record\n"
    pk["alpha"] = ("base", "1.2.3-r1", {"usr/bin/alpha": fakefeed.elf(b"alpha version 1.2.3 ok"), "usr/share/twin/common.txt": common}, "")
    pk["alpha-variant"] = ("base", "1.2.3-r1", {"usr/bin/alpha": fakefeed.elf(b"alpha VARIANT 1.2.3 ok"), "usr/share/twin/common.txt": common,
                                               "usr/lib/opkg/info/alpha-variant.record": record}, "")
    root = tmp_path / "rel6"
    fakefeed.make_release(root, signer, packages=pk)
    r = fakefeed.reference(root, signer, tmp_path / "c6")
    fw = fakefeed.make_rootfs(tmp_path / "fw7", INSTALLED, pk)
    held = fw / "usr/lib/opkg/info/alpha-variant.record"
    held.write_bytes(record)
    assert held.is_file() and "usr/lib/opkg/info/alpha-variant.record" not in scan_rootfs(fw)
    bom = fakefeed.claims(INSTALLED, pk) + [{"name": "alpha-variant", "version": "1.2.3-r1"}]
    rep = verify(fw, bom, r)
    comp = next(c for c in rep["components"] if c["name"] == "alpha-variant")
    assert comp["verdict"] == "absent" and comp["present"] == 2 and comp["identical"] == 1
    assert comp["reason"] == ("each of the 2 file(s) of this package found among the image files compared has the SHA-256 of another "
                              "declared component's file (for the first differing file, alpha); none of the files compared separates "
                              "this package from that component")
    assert "attributable" not in comp["reason"] and "alone" not in comp["reason"]
    md = report.markdown(report.build({"name": "fw"}, r.provenance(), rep, None, None, {"models_found": 0, "findings": []}))
    row = next(l for l in md.splitlines() if l.startswith("| alpha-variant |"))
    assert report.VERDICT_TEXT["absent"] in row and comp["reason"] in row
    assert "was found" not in report.VERDICT_TEXT["absent"] and "no file of the package" not in row


def _supplied_snapshot(drifted_parts):
    fw, bom, snap = drifted_parts
    (fw / "etc").mkdir(exist_ok=True)
    (fw / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/ash\n")
    return fw, bom, snap


def test_supplied_snapshot_file_list_is_used_as_given_and_generated_ones_leave_account_files_out(drifted, ref, tmp_path):
    """Round 8 reviewer's case. A snapshot this tool generates leaves configuration and account files out of a package's
    file list. A supplied snapshot's list is used as given: an account file in it is compared, counted, and decides the
    verdict. Documentation may scope the exclusion to generated snapshots only."""
    fw, bom, snap = _supplied_snapshot(drifted)
    # generated: a sibling whose gamma package owns etc/passwd records it in no package file list
    sib = fakefeed.make_rootfs(tmp_path / "sib2", INSTALLED, {**fakefeed.DEFAULT_PACKAGES, "gamma": drifted_gamma()})
    (sib / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/ash\n")
    with (sib / "usr/lib/opkg/info/gamma.list").open("a") as fh:
        fh.write("/etc/passwd\n")
    generated = snapshot_from_rootfs(sib, "generated sibling")
    assert "etc/passwd" in generated["files"] and not any("etc/passwd" in p["files"] for p in generated["packages"].values())
    # supplied: the same record edited by hand to list the account file for gamma
    digest = scan_rootfs(fw)["etc/passwd"]["sha256"]
    snap = {**snap, "files": {**snap["files"], "etc/passwd": digest}, "packages": {**snap["packages"]}}
    snap["packages"]["gamma"] = dict(snap["packages"]["gamma"], files=snap["packages"]["gamma"]["files"] + ["etc/passwd"])
    rep = verify(fw, bom, ref, snapshots=[snap])
    gamma = next(c for c in rep["components"] if c["name"] == "gamma")
    assert gamma["verdict"] == "verified_A" and "2 of them compared" in gamma["reason"]
    snap["files"] = {**snap["files"], "etc/passwd": "0" * 64}           # change only the account file's supplied digest
    gamma = next(c for c in verify(fw, bom, ref, snapshots=[snap])["components"] if c["name"] == "gamma")
    assert gamma["verdict"] == "bytes_differ"


def drifted_gamma():
    return ("base", "2023.12.01~aaa-r1", {"usr/bin/gamma": fakefeed.elf(b"gamma tool older build")}, "")
