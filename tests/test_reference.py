"""Signature checking, signed metadata and the reference package layer."""
import base64
import gzip
import hashlib

import pytest

import fakefeed
from bomwitness import usign
from bomwitness.reference import Reference, ReferenceError, parse_control, parse_ipk, split_list


def test_usign_accepts_good_signature(signer):
    assert usign.verify(b"message", signer.sign(b"message"), signer.keys) == fakefeed.KEY_ID.hex()


def test_usign_rejects_changed_message(signer):
    with pytest.raises(usign.SignatureError):
        usign.verify(b"message!", signer.sign(b"message"), signer.keys)


def test_usign_rejects_unknown_key(signer):
    with pytest.raises(usign.SignatureError, match="unknown key"):
        usign.verify(b"m", signer.sign(b"m"), {})


def test_usign_rejects_malformed_signature(signer):
    with pytest.raises(usign.SignatureError):
        usign.verify(b"m", "untrusted comment: x\n" + base64.b64encode(b"nope").decode(), signer.keys)


def test_pinned_openwrt_keys_are_well_formed():
    for key_id, (b64, _comment) in usign.PINNED_KEYS.items():
        assert usign.parse_public_key(b64)[0] == key_id


def test_parse_control_and_lists():
    recs = parse_control("Package: a\nVersion: 1\nDescription: x\n more\n\nPackage: b\nDepends: libc, libfoo (>= 2)\n")
    assert [r["Package"] for r in recs] == ["a", "b"]
    assert recs[0]["Description"] == "x\nmore"
    assert split_list(recs[1]["Depends"]) == ["libc", "libfoo"]


def test_parse_ipk_records_hashes_markers_and_conffiles():
    blob = fakefeed.ipk("alpha", "1.2.3-r1", {"usr/bin/alpha": fakefeed.elf(b"alpha 1.2.3"), "etc/config/a": b"x"}, conffiles=["etc/config/a"])
    pl = parse_ipk(blob)
    f = pl["files"]["usr/bin/alpha"]
    assert f["sha256"] == hashlib.sha256(fakefeed.elf(b"alpha 1.2.3")).hexdigest()
    assert f["elf"] and f["marker"] and pl["conffiles"] == ["etc/config/a"]
    assert pl["sde"] == 1700000000 and pl["source_name"] == "alpha"
    assert not pl["files"]["etc/config/a"]["marker"]


def test_meta_and_index_are_signed(ref):
    m = ref.meta()
    assert m["arch"] == "testarch" and m["sha256sums_signed_by"] == fakefeed.KEY_ID.hex()
    trust = ref.index_trust()
    assert trust["target"] == trust["kmods"] == "sha256 in signed sha256sums"
    assert trust["base"].startswith("usign ")
    idx = ref.index()
    assert idx["kmod-foo"]["frozen"] and not idx["alpha"]["frozen"]
    assert idx["libbeta5"]["abi"] == "5" and idx["libbeta5"]["provides"] == ["libbeta"]


def test_manifest_comes_from_signed_file(ref):
    assert ref.manifest()["alpha"] == "1.2.3-r1"


def test_path_index_maps_paths_to_packages(ref):
    assert ref.has_path_index
    assert sorted(ref.path_owners("usr/bin/alpha")) == ["alpha", "alpha-variant"]
    assert ref.path_owners("usr/bin/extra-tool") == []          # the "packages" feed is not indexed
    assert not ref.indexed("extra-tool") and ref.indexed("alpha")


def test_unindexed_package_is_fetched_by_name(ref):
    assert "usr/bin/extra-tool" in ref.payload("extra-tool")["files"]
    assert ref.file_bytes("extra-tool", "usr/bin/extra-tool") == fakefeed.elf(b"extra tool 0.9")


def _fresh(tmp_path, signer):
    root = tmp_path / "releases"
    fakefeed.make_release(root, signer)
    return root


def test_tampered_sha256sums_is_refused(tmp_path, signer):
    root = _fresh(tmp_path, signer)
    p = root / "99.01.0/targets/fake/generic/sha256sums"
    p.write_bytes(p.read_bytes() + b"0" * 64 + b" *extra\n")
    with pytest.raises(usign.SignatureError):
        Reference("99.01.0", "fake/generic", tmp_path / "c", base=root.as_uri(), keys=signer.keys).meta()


def test_tampered_frozen_index_is_refused(tmp_path, signer):
    root = _fresh(tmp_path, signer)
    d = root / "99.01.0/targets/fake/generic/packages"
    (d / "Packages.gz").write_bytes(gzip.compress((d / "Packages").read_bytes() + b"\nPackage: evil\nVersion: 1\n"))
    with pytest.raises(ReferenceError, match="signed sha256sums"):
        Reference("99.01.0", "fake/generic", tmp_path / "c", base=root.as_uri(), keys=signer.keys).index()


def test_tampered_shared_index_is_refused(tmp_path, signer):
    root = _fresh(tmp_path, signer)
    d = root / "99.01.0/packages/testarch/base"
    (d / "Packages.gz").write_bytes(gzip.compress((d / "Packages").read_bytes().replace(b"1.2.3-r1", b"1.2.4-r1")))
    with pytest.raises(usign.SignatureError):
        Reference("99.01.0", "fake/generic", tmp_path / "c", base=root.as_uri(), keys=signer.keys).index()


def test_tampered_package_is_refused(tmp_path, signer):
    root = _fresh(tmp_path, signer)
    p = root / "99.01.0/packages/testarch/base/alpha_1.2.3-r1_testarch.ipk"
    p.write_bytes(p.read_bytes() + b"x")
    r = Reference("99.01.0", "fake/generic", tmp_path / "c", base=root.as_uri(), keys=signer.keys)
    with pytest.raises(ReferenceError, match="hash mismatch"):
        r.payload("alpha")


def test_offline_mode_uses_cache_only(release_root, signer, tmp_path):
    cache = tmp_path / "c"
    fakefeed.reference(release_root, signer, cache)
    off = Reference("99.01.0", "fake/generic", cache, base="file:///nonexistent", keys=signer.keys, offline=True)
    assert off.payload("alpha")["version"] == "1.2.3-r1"
    with pytest.raises(ReferenceError, match="offline"):
        off.payload("extra-tool")
