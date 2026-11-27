"""CBOM verification: cryptographic assets found in the firmware bytes, checked against a declared CBOM
and cross-checked against the SBOM verdicts.

Three asset kinds:
  certificates   X.509 certificates in PEM bundles and DER files (parsed)
  keys           usign public keys, PEM public and private keys, OpenSSH and Dropbear host keys (parsed or
                 recognised by format)
  algorithms     names of primitives and protocols found in the bytes of a component's files

Algorithm evidence is string-level (grade B): a name inside a binary shows that the component refers to the
algorithm. It is not proof of a working implementation, and an implementation that carries no name is
missed. The useful direction is the negative one: when no file of the declared provider carries any name of
a declared algorithm, the claim has no support in the bytes.

Cross-BOM rules:
  provider_not_in_sbom                 a CBOM algorithm names a provider the SBOM does not declare
  provider_unverified                  the provider is declared, but its bytes did not verify
  algorithm_not_evidenced              no file of the declared provider carries the algorithm
  undeclared_algorithm                 a component's files carry an algorithm the CBOM does not list for it
  crypto_component_without_cbom_entry  an SBOM component carries algorithm evidence and the CBOM has no entry for it
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
KEY_RE = re.compile(rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PUBLIC KEY)-----.+?-----END \1-----", re.S)
MIN_BITS = {"RSA": 2048, "DSA": 2048, "EC": 224}
DEPRECATED_HASHES = {"md5", "sha1"}
VERIFIED = ("verified_A", "verified_B")

# (name, primitive, deprecated, pattern). Patterns are matched against the bytes of ELF files and kernel
# module lists. They are deliberately narrow: a bare "DES" or "RC4" inside unrelated text does not count.
ALGORITHMS = [
    ("AES", "block-cipher", False, rb"(?i)(?<![a-z0-9])aes[-_ ]?(128|192|256)(?![0-9])|(?<![a-z0-9])aes[-_](generic|ce|arm|ni|ccm|gcm|cbc|ctr)"),
    ("ChaCha20-Poly1305", "ae", False, rb"(?i)chacha20[-_]?poly1305"),
    ("3DES", "block-cipher", True, rb"(?i)(?<![a-z0-9])3des(?![a-z0-9])|des-ede3|des3_ede|(?<![a-z0-9])des_generic"),
    ("RC4", "stream-cipher", True, rb"(?i)(?<![a-z0-9])arc4(?![a-z0-9])|(?<![a-z0-9])arcfour|(?<![a-z0-9])rc4(?![a-z0-9])"),
    ("MD5", "hash", True, rb"(?i)(?<![a-z0-9])md5(?![a-z0-9])"),
    ("SHA-1", "hash", True, rb"(?i)(?<![a-z0-9])sha-?1(?![0-9a-z])|hmac-sha1(?![0-9])|sha1_generic"),
    ("SHA-256", "hash", False, rb"(?i)(?<![a-z0-9])sha-?256(?![0-9])|sha2-256|sha256_generic"),
    ("SHA-512", "hash", False, rb"(?i)(?<![a-z0-9])sha-?512(?![0-9])|sha2-512|sha512_generic"),
    ("RSA", "pke", False, rb"(?<![A-Za-z0-9])RSA(?![A-Za-z0-9])|ssh-rsa|rsa-sha2-"),
    ("ECDSA", "signature", False, rb"(?i)(?<![a-z0-9])ecdsa(?![a-z0-9])|ecdsa-sha2-"),
    ("Ed25519", "signature", False, rb"(?i)(?<![a-z0-9])ed25519"),
    ("X25519", "key-agree", False, rb"(?i)curve25519|(?<![a-z0-9])x25519"),
    ("DH", "key-agree", False, rb"(?i)diffie-hellman"),
    ("WEP", "other", True, rb"(?<![A-Za-z0-9])WEP(40|104)?(?![A-Za-z0-9])"),
    ("TKIP", "other", True, rb"(?<![A-Za-z0-9])TKIP(?![A-Za-z0-9])"),
    ("CCMP", "ae", False, rb"(?<![A-Za-z0-9])CCMP(?![A-Za-z0-9])"),
    ("SAE", "key-agree", False, rb"(?<![A-Za-z0-9])SAE(?![A-Za-z0-9])"),
    ("ML-KEM", "kem", False, rb"(?i)(?<![a-z0-9])ml-?kem|(?<![a-z0-9])kyber"),
    ("ML-DSA", "signature", False, rb"(?i)(?<![a-z0-9])ml-?dsa|dilithium"),
]
ALG_INFO = {a[0]: {"primitive": a[1], "deprecated": a[2]} for a in ALGORITHMS}
_ALG_RE = [(a[0], re.compile(a[3])) for a in ALGORITHMS]
_ALG_CACHE: dict[str, list[str]] = {}


# ---- certificates ----------------------------------------------------------------------------------------
def describe(cert: x509.Certificate, path: str) -> dict:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        alg, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        alg, bits = "EC", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        alg, bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        alg, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        alg, bits = "Ed448", 456
    else:
        alg, bits = type(key).__name__, None
    h = cert.signature_hash_algorithm
    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "key_algorithm": alg, "key_bits": bits, "signature_hash": h.name if h else None,
        "not_after": cert.not_valid_after_utc.isoformat(), "path": path,
    }


def _walk(rootfs: Path, max_size: int = 16 << 20):
    for dp, _dn, fn in os.walk(rootfs):
        for f in fn:
            q = Path(dp) / f
            if q.is_symlink() or not q.is_file() or q.stat().st_size > max_size:
                continue
            yield str(q.relative_to(rootfs)), q.read_bytes()


def discover(rootfs: Path) -> list[dict]:
    """Every X.509 certificate in the tree (kept for callers that only need certificates)."""
    return discover_assets(rootfs)["certificates"]


def _key_from_pem(block: bytes, kind: bytes) -> tuple[str, int | None]:
    try:
        if kind == b"PUBLIC KEY":
            key = serialization.load_pem_public_key(block)
        elif kind == b"OPENSSH PRIVATE KEY":
            key = serialization.load_ssh_private_key(block, None)
        else:
            key = serialization.load_pem_private_key(block, None)
    except Exception:
        return "unknown", None
    for cls, name in ((rsa.RSAPrivateKey, "RSA"), (rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePrivateKey, "EC"),
                      (ec.EllipticCurvePublicKey, "EC"), (ed25519.Ed25519PrivateKey, "Ed25519"), (ed25519.Ed25519PublicKey, "Ed25519"),
                      (dsa.DSAPrivateKey, "DSA"), (dsa.DSAPublicKey, "DSA")):
        if isinstance(key, cls):
            return name, getattr(key, "key_size", 256 if name == "Ed25519" else None) if name != "EC" else key.curve.key_size
    return "unknown", None


def discover_assets(rootfs: Path) -> dict:
    """Certificates and keys found in the firmware tree."""
    certs: dict[str, dict] = {}
    keys: dict[str, dict] = {}

    def add_key(material: bytes, **meta):
        fp = hashlib.sha256(material).hexdigest()
        keys.setdefault(fp, {"fingerprint_sha256": fp, **meta})

    for rel, blob in _walk(rootfs, 8 << 20):
        found = []
        for m in PEM_RE.finditer(blob):
            try:
                found.append(x509.load_pem_x509_certificate(m.group(0)))
            except ValueError:
                pass
        if not found and rel.lower().endswith((".der", ".cer", ".crt")) and blob[:1] == b"\x30":
            try:
                found.append(x509.load_der_x509_certificate(blob))
            except ValueError:
                pass
        for c in found:
            d = describe(c, rel)
            certs.setdefault(d["fingerprint_sha256"], d)
        # PEM keys inside ELF files are skipped: crypto libraries compile in self-test vectors (mbedTLS does).
        for m in KEY_RE.finditer(blob) if blob[:4] != b"\x7fELF" else ():
            kind = m.group(1)
            alg, bits = _key_from_pem(m.group(0), kind)
            add_key(m.group(0), kind="public-key" if kind == b"PUBLIC KEY" else "private-key",
                    format="PEM " + kind.decode(), algorithm=alg, bits=bits, path=rel)
        if rel.startswith("etc/opkg/keys/") or blob[:18] == b"untrusted comment:":
            try:
                line = [l for l in blob.decode("ascii").splitlines() if l.strip() and not l.startswith("untrusted comment:")][0]
                raw = base64.b64decode(line.strip(), validate=True)
                if raw[:2] == b"Ed" and len(raw) == 42:
                    add_key(raw[10:], kind="public-key", format="usign", algorithm="Ed25519", bits=256, path=rel, key_id=raw[2:10].hex())
                elif raw[:2] == b"Ed" and len(raw) == 104:
                    add_key(raw, kind="private-key", format="usign", algorithm="Ed25519", bits=256, path=rel, key_id=raw[32:40].hex())
            except Exception:
                pass
        if blob[:4] == b"\x00\x00\x00\x07" and blob[4:11] == b"ssh-rsa" or blob[:4] == b"\x00\x00\x00\x0b" and blob[4:15] == b"ssh-ed25519" \
                or blob[:4] == b"\x00\x00\x00\x13" and blob[4:23].startswith(b"ecdsa-sha2-nistp"):
            if rel.startswith(("etc/dropbear/", "etc/ssh/")) or "host_key" in rel:
                name = blob[4:4 + blob[3]].decode()
                add_key(blob, kind="private-key", format="Dropbear host key", bits=None, path=rel,
                        algorithm={"ssh-rsa": "RSA", "ssh-ed25519": "Ed25519"}.get(name, "EC"))
    return {"certificates": sorted(certs.values(), key=lambda d: d["fingerprint_sha256"]),
            "keys": sorted(keys.values(), key=lambda d: d["fingerprint_sha256"])}


# ---- algorithms ------------------------------------------------------------------------------------------
def algorithms_in(blob: bytes) -> list[str]:
    digest = hashlib.sha256(blob).hexdigest()
    if digest not in _ALG_CACHE:
        _ALG_CACHE[digest] = [name for name, rx in _ALG_RE if rx.search(blob)]
    return _ALG_CACHE[digest]


def component_algorithms(rootfs: Path, sbom_report: dict) -> dict[str, dict[str, list[str]]]:
    """{component: {algorithm: [files]}} for every SBOM component whose files carry algorithm evidence."""
    out: dict[str, dict[str, list[str]]] = {}
    for c in sbom_report["components"]:
        for rel in c.get("files", []):
            q = Path(rootfs) / rel
            if not q.is_file() or q.is_symlink():
                continue
            blob = q.read_bytes()
            if blob[:4] != b"\x7fELF" and not rel.endswith("modules.builtin"):
                continue
            for alg in algorithms_in(blob):
                out.setdefault(c["name"], {}).setdefault(alg, []).append(rel)
    return out


# ---- CBOM documents --------------------------------------------------------------------------------------
def to_cbom(certs: list[dict], subject: str, keys: list[dict] = (), algorithms: dict | None = None) -> dict:
    comps = [{
        "type": "cryptographic-asset", "bom-ref": f"cert:{c['fingerprint_sha256'][:16]}", "name": c["subject"],
        "hashes": [{"alg": "SHA-256", "content": c["fingerprint_sha256"]}],
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
            "subjectName": c["subject"], "issuerName": c["issuer"], "notValidAfter": c["not_after"],
            "certificateFormat": "X.509"}},
        "properties": [{"name": "bomwitness:keyAlgorithm", "value": c["key_algorithm"]},
                       {"name": "bomwitness:keyBits", "value": str(c["key_bits"])},
                       {"name": "bomwitness:signatureHash", "value": str(c["signature_hash"])}],
    } for c in certs]
    comps += [{
        "type": "cryptographic-asset", "bom-ref": f"key:{k['fingerprint_sha256'][:16]}", "name": f"{k['format']} {k['kind']} ({k['path']})",
        "hashes": [{"alg": "SHA-256", "content": k["fingerprint_sha256"]}],
        "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {
            "type": k["kind"], "format": k["format"], **({"size": k["bits"]} if k.get("bits") else {})}},
        "properties": [{"name": "bomwitness:keyAlgorithm", "value": str(k["algorithm"])}],
    } for k in keys]
    deps = []
    for comp, algs in sorted((algorithms or {}).items()):
        refs = []
        for alg in sorted(algs):
            ref = f"alg:{alg}@{comp}"
            refs.append(ref)
            comps.append({"type": "cryptographic-asset", "bom-ref": ref, "name": alg,
                          "cryptoProperties": {"assetType": "algorithm",
                                               "algorithmProperties": {"primitive": ALG_INFO.get(alg, {}).get("primitive", "other")}}})
        deps.append({"ref": f"pkg:{comp}", "provides": refs})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": subject}}, "components": comps, "dependencies": deps}


def declared_certs(cbom: dict) -> list[dict]:
    out = []
    for c in cbom.get("components", []):
        cp = c.get("cryptoProperties", {})
        if c.get("type") != "cryptographic-asset" or cp.get("assetType") != "certificate":
            continue
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        fp = next((h["content"].lower() for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None)
        out.append({"fingerprint_sha256": fp, "subject": cp.get("certificateProperties", {}).get("subjectName"),
                    "not_after": cp.get("certificateProperties", {}).get("notValidAfter"),
                    "key_algorithm": props.get("bomwitness:keyAlgorithm"),
                    "key_bits": props.get("bomwitness:keyBits"), "signature_hash": props.get("bomwitness:signatureHash")})
    return out


def declared_keys(cbom: dict) -> list[dict]:
    out = []
    for c in cbom.get("components", []):
        cp = c.get("cryptoProperties", {})
        if c.get("type") == "cryptographic-asset" and cp.get("assetType") == "related-crypto-material":
            fp = next((h["content"].lower() for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None)
            out.append({"fingerprint_sha256": fp, "kind": cp.get("relatedCryptoMaterialProperties", {}).get("type"), "name": c.get("name")})
    return out


def declared_algorithms(cbom: dict) -> list[dict]:
    """[{algorithm, provider (SBOM component name or None), ref}] from algorithm assets and dependency "provides"."""
    provider = {}
    for d in cbom.get("dependencies", []) or []:
        for asset in d.get("provides", []) or []:
            provider[asset] = re.sub(r"^pkg:", "", d.get("ref", ""))
    out = []
    for c in cbom.get("components", []):
        cp = c.get("cryptoProperties", {})
        if c.get("type") == "cryptographic-asset" and cp.get("assetType") == "algorithm":
            ref = c.get("bom-ref")
            out.append({"algorithm": c.get("name"), "provider": provider.get(ref), "ref": ref})
    return out


# ---- verification ----------------------------------------------------------------------------------------
def verify_cbom(rootfs: Path, cbom: dict, as_of: dt.datetime, sbom_report: dict | None = None) -> list[dict]:
    assets = discover_assets(rootfs)
    seen = assets["certificates"]
    by_fp = {c["fingerprint_sha256"]: c for c in seen}
    by_subject: dict[str, list[dict]] = {}
    for c in seen:
        by_subject.setdefault(c["subject"], []).append(c)
    findings, matched = [], set()

    def add(kind, ident, detail, grade="A"):
        findings.append({"class": kind, "asset": ident, "grade": grade, "detail": detail})

    for d in declared_certs(cbom):
        actual = by_fp.get(d["fingerprint_sha256"] or "")
        if actual is None and d["fingerprint_sha256"] is None and len(by_subject.get(d["subject"], [])) == 1:
            actual = by_subject[d["subject"]][0]
        if actual is None:
            add("absent_certificate", d["fingerprint_sha256"] or d["subject"], "declared certificate not found among the certificates this tool extracted from the firmware")
            continue
        fp = actual["fingerprint_sha256"]
        matched.add(fp)
        if d["key_bits"] and str(actual["key_bits"]) != str(d["key_bits"]) or d["key_algorithm"] and actual["key_algorithm"] != d["key_algorithm"]:
            add("wrong_key", fp, f"declared {d['key_algorithm']}-{d['key_bits']}; certificate has {actual['key_algorithm']}-{actual['key_bits']}")
        if d["signature_hash"] and str(actual["signature_hash"]) != d["signature_hash"]:
            add("wrong_signature_hash", fp, f"declared {d['signature_hash']}; certificate has {actual['signature_hash']}")
        if d["not_after"] and d["not_after"] != actual["not_after"]:
            add("wrong_expiry", fp, f"declared {d['not_after']}; certificate has {actual['not_after']}")
    for c in seen:
        fp = c["fingerprint_sha256"]
        if fp not in matched:
            add("undeclared_certificate", fp, f"{c['subject']} in {c['path']}")
        if c["key_algorithm"] in MIN_BITS and c["key_bits"] < MIN_BITS[c["key_algorithm"]]:
            add("weak_key", fp, f"{c['key_algorithm']}-{c['key_bits']} in {c['path']}")
        if dt.datetime.fromisoformat(c["not_after"]) < as_of:
            add("expired_certificate", fp, f"expired {c['not_after']} ({c['path']})")
        if c["signature_hash"] in DEPRECATED_HASHES and not c["self_signed"]:
            add("deprecated_signature_hash", fp, f"{c['signature_hash']} on a non-root certificate ({c['path']})")

    # keys
    key_fp = {k["fingerprint_sha256"]: k for k in assets["keys"]}
    declared_k = {d["fingerprint_sha256"] for d in declared_keys(cbom)}
    for fp in sorted(declared_k - set(key_fp)):
        add("absent_key", fp, "declared key material not found among the keys this tool extracted from the firmware")
    for fp, k in sorted(key_fp.items()):
        if fp not in declared_k:
            add("undeclared_key", fp, f"{k['format']} {k['kind']} in {k['path']}")
        if k["kind"] == "private-key":
            add("embedded_private_key", fp, f"{k['format']} private key shipped in the image ({k['path']})")

    # algorithms and cross-BOM consistency
    if sbom_report is not None:
        verdict = {c["name"]: c["verdict"] for c in sbom_report["components"]}
        evidence = component_algorithms(rootfs, sbom_report)
        claimed: dict[str, set[str]] = {}
        for d in declared_algorithms(cbom):
            alg, prov = d["algorithm"], d["provider"]
            ident = f"{alg}@{prov}"
            if not prov:
                add("algorithm_without_provider", alg, "the CBOM does not say which component provides this algorithm", "B")
                continue
            claimed.setdefault(prov, set()).add(alg)
            if prov not in verdict:
                add("provider_not_in_sbom", prov, f"the CBOM says {prov} provides {alg}; the SBOM does not declare {prov}")
            elif verdict[prov] not in VERIFIED:
                add("provider_unverified", prov, f"the CBOM says {prov} provides {alg}; the SBOM check of {prov} ended in {verdict[prov]}")
            elif alg not in evidence.get(prov, {}):
                add("algorithm_not_evidenced", ident, f"no file of {prov} that this tool checked carries a name of {alg}", "B")
        for comp, algs in sorted(evidence.items()):
            missing = sorted(set(algs) - claimed.get(comp, set()))
            if comp not in claimed:
                add("crypto_component_without_cbom_entry", comp,
                    f"files of {comp} carry {', '.join(sorted(algs))}; the CBOM has no algorithm entry for it", "B")
            else:
                for alg in missing:
                    add("undeclared_algorithm", f"{alg}@{comp}", f"{algs[alg][0]} carries a name of {alg}; the CBOM does not list it for {comp}", "B")
        for comp, algs in sorted(evidence.items()):
            for alg in sorted(algs):
                if ALG_INFO[alg]["deprecated"]:
                    add("deprecated_algorithm", f"{alg}@{comp}", f"deprecated primitive named in {algs[alg][0]}", "B")
    # de-duplicate provider-level findings (one per provider, not one per algorithm)
    out, seen_keys = [], set()
    for f in findings:
        key = (f["class"], f["asset"])
        if key not in seen_keys:
            seen_keys.add(key)
            out.append(f)
    return out


def inventory(rootfs: Path, subject: str, sbom_report: dict | None = None) -> dict:
    """A CBOM generated from the bytes: what a correct declaration for this image would contain."""
    assets = discover_assets(rootfs)
    algs = component_algorithms(rootfs, sbom_report) if sbom_report else {}
    return to_cbom(assets["certificates"], subject, assets["keys"], algs)
