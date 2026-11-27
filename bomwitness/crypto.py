"""Cryptographic evidence: X.509 certificates found in the firmware bytes, checked against a declared CBOM.

Round 1 covers certificates only (the CA bundle and any other PEM or DER
certificate in the tree). Keys, protocol configuration and primitives compiled
into libraries are round 2.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
MIN_BITS = {"RSA": 2048, "DSA": 2048, "EC": 224}
DEPRECATED_HASHES = {"md5", "sha1"}


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


def discover(rootfs: Path) -> list[dict]:
    found: dict[str, dict] = {}
    for dp, _dn, fn in os.walk(rootfs):
        for f in fn:
            q = Path(dp) / f
            if q.is_symlink() or not q.is_file() or q.stat().st_size > 8 << 20:
                continue
            blob = q.read_bytes()
            rel = str(q.relative_to(rootfs))
            certs = []
            for m in PEM_RE.finditer(blob):
                try:
                    certs.append(x509.load_pem_x509_certificate(m.group(0)))
                except ValueError:
                    pass
            if not certs and f.lower().endswith((".der", ".cer", ".crt")) and blob[:1] == b"\x30":
                try:
                    certs.append(x509.load_der_x509_certificate(blob))
                except ValueError:
                    pass
            for c in certs:
                d = describe(c, rel)
                found.setdefault(d["fingerprint_sha256"], d)
    return sorted(found.values(), key=lambda d: d["fingerprint_sha256"])


def to_cbom(certs: list[dict], subject: str) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": subject}},
            "components": [{
                "type": "cryptographic-asset", "bom-ref": f"cert:{c['fingerprint_sha256'][:16]}", "name": c["subject"],
                "hashes": [{"alg": "SHA-256", "content": c["fingerprint_sha256"]}],
                "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                    "subjectName": c["subject"], "issuerName": c["issuer"], "notValidAfter": c["not_after"],
                    "certificateFormat": "X.509"}},
                "properties": [{"name": "bomwitness:keyAlgorithm", "value": c["key_algorithm"]},
                               {"name": "bomwitness:keyBits", "value": str(c["key_bits"])},
                               {"name": "bomwitness:signatureHash", "value": str(c["signature_hash"])}],
            } for c in certs]}


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


def verify_cbom(rootfs: Path, cbom: dict, as_of: dt.datetime) -> list[dict]:
    seen = discover(rootfs)
    by_fp = {c["fingerprint_sha256"]: c for c in seen}
    by_subject: dict[str, list[dict]] = {}
    for c in seen:
        by_subject.setdefault(c["subject"], []).append(c)
    findings, matched = [], set()

    def add(kind, ident, detail):
        findings.append({"class": kind, "asset": ident, "detail": detail})

    for d in declared_certs(cbom):
        actual = by_fp.get(d["fingerprint_sha256"] or "")
        if actual is None and d["fingerprint_sha256"] is None and len(by_subject.get(d["subject"], [])) == 1:
            actual = by_subject[d["subject"]][0]
        if actual is None:
            add("absent_certificate", d["fingerprint_sha256"] or d["subject"], "declared certificate not found in the firmware")
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
    return findings
