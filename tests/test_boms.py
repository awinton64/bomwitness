"""BOM formats, CBOM and cross-BOM rules, the AI-BOM presence check, the CLI and the benchmark helpers."""
import datetime as dt
import json
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import fakefeed
from bomwitness import aibom, bomio, cli, crypto, mutate, report, unpack, usign
from bomwitness.verify import verify

AS_OF = dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc)


# ---- BOM input formats -----------------------------------------------------------------------------------
def test_cyclonedx_14_and_16_and_nested_components():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [
        {"type": "application", "name": "busybox", "version": "1.36.1"},
        {"type": "library", "name": "outer", "version": "1", "components": [{"type": "library", "name": "inner", "purl": "pkg:opkg/x/inner@2.0"}]},
        {"type": "cryptographic-asset", "name": "AES"}, {"type": "machine-learning-model", "name": "m"}]}
    assert bomio.detect(doc) == "CycloneDX 1.4"
    assert [(c["name"], c["version"]) for c in bomio.software_claims(doc)] == [("busybox", "1.36.1"), ("outer", "1"), ("inner", "2.0")]
    assert [c["name"] for c in bomio.crypto_assets(doc)] == ["AES"] and [c["name"] for c in bomio.models(doc)] == ["m"]
    assert bomio.detect(bomio.sbom([{"name": "a", "version": "1"}], "fw")) == "CycloneDX 1.6"


def test_spdx_23_packages():
    doc = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-fw"], "packages": [
        {"SPDXID": "SPDXRef-fw", "name": "firmware", "versionInfo": "1"},
        {"SPDXID": "SPDXRef-a", "name": "alpha", "versionInfo": "1.2.3-r1"},
        {"SPDXID": "SPDXRef-b", "name": "beta", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:opkg/x/beta@2.0"}]}]}
    assert [(c["name"], c["version"]) for c in bomio.software_claims(doc)] == [("alpha", "1.2.3-r1"), ("beta", "2.0")]


def test_unknown_document_is_rejected():
    with pytest.raises(ValueError):
        bomio.detect({"hello": "world"})


# ---- certificates and keys -------------------------------------------------------------------------------
def make_cert(bits: int, days_to: int, cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(AS_OF - dt.timedelta(days=900))
            .not_valid_after(AS_OF + dt.timedelta(days=days_to)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture()
def crypto_fw(rootfs, truth, ref):
    (rootfs / "etc/ssl/certs").mkdir(parents=True)
    (rootfs / "etc/ssl/certs/ca.crt").write_bytes(make_cert(2048, 365, "good.example") + make_cert(2048, 365, "second.example"))
    (rootfs / "etc/opkg/keys").mkdir(parents=True)
    b64, _ = next(iter(usign.PINNED_KEYS.values()))
    (rootfs / "etc/opkg/keys/d310c6f2833e97f7").write_text(f"untrusted comment: test\n{b64}\n")
    rep = verify(rootfs, truth, ref)
    return rootfs, rep, crypto.inventory(rootfs, "fw", rep)


def classes(findings, skip=("deprecated_algorithm",)):
    return sorted({(f["class"], f["asset"]) for f in findings if f["class"] not in skip})


def test_correct_cbom_has_no_findings(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    assert len(crypto.declared_certs(cbom)) == 2 and len(crypto.declared_keys(cbom)) == 1
    assert {(d["algorithm"], d["provider"]) for d in crypto.declared_algorithms(cbom)} == {("AES", "libbeta5"), ("SHA-1", "libbeta5")}
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == []
    assert ("deprecated_algorithm", "SHA-1@libbeta5") in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep), skip=())


def test_certificate_rules(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    certs = [c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
    fp = certs[0]["hashes"][0]["content"]
    for p in certs[0]["properties"]:
        if p["name"] == "bomwitness:keyBits":
            p["value"] = "4096"
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == [("wrong_key", fp)]
    cbom["components"].remove(certs[0])
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == [("undeclared_certificate", fp)]


def test_weak_and_expired_certificates_are_policy_findings(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    (rootfs / "etc/ssl/certs/weak.crt").write_bytes(make_cert(1024, 365, "weak.example"))
    (rootfs / "etc/ssl/certs/old.crt").write_bytes(make_cert(2048, -30, "old.example"))
    got = {c for c, _a in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep))}
    assert got == {"undeclared_certificate", "weak_key", "expired_certificate"}


def test_key_rules(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    (rootfs / "etc/uhttpd.key").write_bytes(pem)
    got = {c for c, _a in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep))}
    assert got == {"undeclared_key", "embedded_private_key"}
    k = next(k for k in crypto.discover_assets(rootfs)["keys"] if k["kind"] == "private-key")
    assert k["algorithm"] == "RSA" and k["bits"] == 2048
    (rootfs / "etc/uhttpd.key").unlink()
    cbom["components"] = [c for c in cbom["components"] if c["cryptoProperties"]["assetType"] != "related-crypto-material"]
    assert {c for c, _a in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep))} == {"undeclared_key"}


def test_pem_key_inside_an_elf_is_not_reported(rootfs):
    (rootfs / "usr/lib/libselftest.so").write_bytes(fakefeed.elf(b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"))
    assert crypto.discover_assets(rootfs)["keys"] == []


# ---- algorithms and cross-BOM rules ----------------------------------------------------------------------
def test_algorithm_patterns_are_narrow():
    assert crypto.algorithms_in(b"\0aes256-ctr\0hmac-sha1\0") == ["AES", "SHA-1"]
    assert crypto.algorithms_in(b"description of design, a harc4x and sha1234") == []
    assert "3DES" in crypto.algorithms_in(b"DES-EDE3-CBC") and "RC4" in crypto.algorithms_in(b"\0arc4\0")


def algs(cbom):
    return [c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"]


def test_phantom_algorithm_is_not_evidenced(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    cbom["components"].append({"type": "cryptographic-asset", "bom-ref": "alg:ML-KEM@libbeta5", "name": "ML-KEM",
                               "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem"}}})
    next(d for d in cbom["dependencies"] if d["ref"] == "pkg:libbeta5")["provides"].append("alg:ML-KEM@libbeta5")
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == [("algorithm_not_evidenced", "ML-KEM@libbeta5")]


def test_omitted_algorithm_and_omitted_crypto_component(crypto_fw):
    rootfs, rep, cbom = crypto_fw
    aes = next(c for c in algs(cbom) if c["name"] == "AES")
    cbom["components"].remove(aes)
    cbom["dependencies"][0]["provides"].remove(aes["bom-ref"])
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == [("undeclared_algorithm", "AES@libbeta5")]
    cbom["components"] = [c for c in cbom["components"] if c not in algs(cbom)]
    cbom["dependencies"] = []
    assert classes(crypto.verify_cbom(rootfs, cbom, AS_OF, rep)) == [("crypto_component_without_cbom_entry", "libbeta5")]


def test_provider_must_be_a_verified_sbom_component(crypto_fw, truth, ref):
    rootfs, _rep, cbom = crypto_fw
    without = verify(rootfs, [c for c in truth if c["name"] != "libbeta5"], ref)
    assert ("provider_not_in_sbom", "libbeta5") in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, without))
    p = rootfs / "usr/lib/libbeta.so.2.0.1"
    b = bytearray(p.read_bytes()); b[10] ^= 1; p.write_bytes(bytes(b))
    patched = verify(rootfs, truth, ref)
    assert ("provider_unverified", "libbeta5") in classes(crypto.verify_cbom(rootfs, cbom, AS_OF, patched))


# ---- AI-BOM ----------------------------------------------------------------------------------------------
def test_model_file_presence_check(rootfs):
    """Synthetic fixture: four magic bytes and padding, not a real model."""
    assert aibom.discover(rootfs) == []
    (rootfs / "usr/share").mkdir(parents=True, exist_ok=True)
    (rootfs / "usr/share/wake.gguf").write_bytes(b"GGUF" + struct.pack("<I", 3) + b"\0" * 64)
    (rootfs / "usr/share/kws.tflite").write_bytes(b"\x1c\0\0\0TFL3" + b"\0" * 32)
    found = aibom.discover(rootfs)
    assert [(m["path"], m["format"]) for m in found] == [("usr/share/kws.tflite", "TensorFlow Lite"), ("usr/share/wake.gguf", "GGUF")]
    doc = aibom.to_aibom(found, "fw")
    assert aibom.verify_aibom(rootfs, bomio.models(doc)) == []
    assert {f["class"] for f in aibom.verify_aibom(rootfs, [])} == {"undeclared_model"}
    (rootfs / "usr/share/wake.gguf").write_bytes(b"GGUF" + struct.pack("<I", 3) + b"\1" * 64)
    assert sorted(f["class"] for f in aibom.verify_aibom(rootfs, bomio.models(doc))) == ["absent_model", "undeclared_model"]


# ---- unpacking -------------------------------------------------------------------------------------------
def superblock(inodes=10, bytes_used=96, major=4) -> bytes:
    return struct.pack("<4sIIIIHHHHHHQQ", b"hsqs", inodes, 1700000000, 1 << 18, 1, 4, 18, 0, 1, major, 0, 0, bytes_used) + b"\0" * 48


def test_find_squashfs_superblocks():
    blob = b"\0" * 100 + b"hsqs junk that is not a superblock" + b"\0" * 80 + superblock() + b"\0" * 64
    hits = unpack.find_squashfs(blob)
    assert len(hits) == 1 and hits[0]["inodes"] == 10 and hits[0]["mkfs_time"] == 1700000000
    assert unpack.find_squashfs(superblock(major=3) + b"\0" * 64) == []


def test_release_hint_reads_the_firmware_self_description(rootfs):
    assert unpack.release_hint(rootfs) == {"release": "99.01.0", "target": "fake/generic", "arch": "testarch"}


# ---- mutations used by the benchmark ---------------------------------------------------------------------
def test_database_mutations(rootfs):
    from bomwitness import devicedb
    mutate.db_set_version(rootfs, "alpha", "9.9")
    assert devicedb.installed(rootfs)["alpha"]["Version"] == "9.9"
    mutate.db_remove(rootfs, "alpha")
    assert "alpha" not in devicedb.installed(rootfs) and devicedb.owned_files(rootfs, "alpha") == []
    mutate.db_add(rootfs, "delta", "3.0-r1", "testarch", ["usr/bin/delta"])
    assert devicedb.owned_files(rootfs, "delta") == ["usr/bin/delta"]
    mutate.db_strip(rootfs)
    assert devicedb.installed(rootfs) == {}


def test_implant_writes_only_new_files(rootfs, ref):
    written = mutate.implant(rootfs, ref.members("delta"))
    assert written == ["usr/bin/delta"]
    assert mutate.implant(rootfs, ref.members("alpha")) == []           # already present, left alone


# ---- report and CLI --------------------------------------------------------------------------------------
def test_markdown_report_has_triage_and_limits(rootfs, truth, ref):
    sbom = verify(rootfs, truth + [{"name": "delta", "version": "3.0-r1"}], ref)
    rep = report.build({"name": "fw"}, ref.provenance(), sbom, None, None, {"models_found": 0, "findings": []})
    assert rep["triage"] == {"automatic_pass": 6, "automatic_fail": 1, "needs_review": 0, "unverifiable": 1}
    md = report.markdown(rep)
    assert "| absent | delta |" in md and "What this report does not establish" in md and chr(0x2014) not in md


def test_cli_verify_end_to_end(rootfs, truth, release_root, signer, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(usign, "PINNED_KEYS", signer.keys)
    cache = tmp_path / "cache"
    assert cli.main(["index", "--release", "99.01.0", "--target", "fake/generic", "--cache", str(cache), "--base", release_root.as_uri()]) == 0
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(bomio.sbom(truth, "fw")))
    bad.write_text(json.dumps(bomio.sbom([c for c in truth if c["name"] != "gamma"], "fw")))
    common = ["--rootfs", str(rootfs), "--cache", str(cache), "--base", release_root.as_uri()]
    assert cli.main(["verify", *common, "--sbom", str(good), "--json", str(tmp_path / "r.json"), "--md", str(tmp_path / "r.md")]) == 0
    rep = json.loads((tmp_path / "r.json").read_text())
    assert rep["subject"]["reference_chosen_from"].startswith("the firmware's own")
    assert rep["device_db"]["present"] and rep["device_db"]["findings"] == []
    assert cli.main(["verify", *common, "--sbom", str(bad)]) == 1
    assert "undeclared_component" in capsys.readouterr().out
    assert cli.main(["verify", *common, "--sbom", str(bad), "--fail-on", "never"]) == 0
    assert cli.main(["inventory", *common, "--out", str(tmp_path / "inv.json"), "--with-cbom"]) == 0
    inv = json.loads((tmp_path / "inv.json").read_text())
    assert {c["name"] for c in bomio.software_claims(inv)} >= {"alpha", "gamma", "kmod-foo"}
    # A snapshot file is a local input: the report must say it was trusted as supplied, not authenticated.
    from bomwitness.verify import snapshot_from_rootfs
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(snapshot_from_rootfs(rootfs, "a local tree")))
    assert cli.main(["verify", *common, "--sbom", str(good), "--snapshot", str(snap), "--json", str(tmp_path / "s.json"), "--md", str(tmp_path / "s.md")]) == 0
    trust = json.loads((tmp_path / "s.json").read_text())["inputs"]["reference_inputs"]
    assert trust == [{"kind": "snapshot file", "name": "snap.json", "authenticated": False, "note": trust[0]["note"]}]
    assert "trusted as supplied" in trust[0]["note"] and "snapshot file snap.json: local file, trusted as supplied" in (tmp_path / "s.md").read_text()


# ---- benchmark helpers (bench/baselines.py) --------------------------------------------------------------
def test_baseline_diffs():
    import baselines
    declared = [{"name": "busybox", "version": "1.36.1-r3"}, {"name": "dnsmasq", "version": "2.93-r1"}, {"name": "ghost", "version": "1"}]
    seen = {"busybox": {"1.36.1-r3"}, "dnsmasq": {"2.90-r1"}, "extra": {"1"}}
    assert baselines.syft_diff(declared, seen) == {("wrong_version", "dnsmasq"), ("absent", "ghost"), ("undeclared_component", "extra")}
    products = {"busybox": {"1.36.1"}, "dnsmasq": {"2.90"}, "dropbear_ssh": {"2024.86"}}
    got = baselines.cvebin_diff(declared, products)
    assert got == {("wrong_version", "dnsmasq"), ("undeclared_component", "dropbear_ssh")}
    assert baselines.cvebin_label_match(got, ("undeclared_component", "dropbear"))
    assert not baselines.cvebin_label_match(got, ("undeclared_component", "uhttpd"))


def test_aibom_example_produces_its_expected_findings():
    """The shipped synthetic AI-BOM example must keep working: examples/aibom/run.py ends with PASS."""
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([sys.executable, str(root / "examples/aibom/run.py")], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip().endswith("PASS"), r.stdout + r.stderr
