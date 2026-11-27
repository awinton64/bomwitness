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


def test_snapshot_attributes_omitted_component(drifted, ref):
    fw, bom, snap = drifted
    rep = verify(fw, [c for c in bom if c["name"] != "gamma"], ref, snapshots=[snap])
    assert ("undeclared_component", "gamma") in hard(rep)


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
