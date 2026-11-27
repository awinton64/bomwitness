"""Round 1 crypto spike: seeded CBOM errors about X.509 certificates in one official image."""
from __future__ import annotations

import copy
import datetime as dt
import json
import random
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bomwitness import crypto, mutate

ROOT = Path(__file__).resolve().parent.parent
AS_OF = dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc)


def make_cert(bits: int, days_from: int, days_to: int, cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)   # private key is discarded
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BOMwitness synthetic test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(AS_OF + dt.timedelta(days=days_from)).not_valid_after(AS_OF + dt.timedelta(days=days_to))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def main(image_id: str) -> None:
    clean = ROOT / "work/rootfs" / image_id
    work = ROOT / "work/crypto-cases" / image_id
    rng = random.Random(20261127)
    certs = crypto.discover(clean)
    truth = crypto.to_cbom(certs, image_id)
    base = crypto.verify_cbom(clean, truth, AS_OF)
    noise = {(f["class"], f["asset"]) for f in base}
    cases = []

    def case(kind, labels, cbom, rootfs):
        found = {(f["class"], f["asset"]) for f in crypto.verify_cbom(rootfs, cbom, AS_OF)} - noise
        labels = set(labels)
        cases.append({"kind": kind, "labels": sorted(labels), "tp": len(found & labels), "fp": len(found - labels),
                      "fn": len(labels - found), "extra": sorted(found - labels)[:4]})

    idx = list(range(len(certs)))
    def prop(c, name, value):
        for p in c["properties"]:
            if p["name"] == name:
                p["value"] = value
    for i in rng.sample(idx, 5):       # C1 wrong key size declared
        b = copy.deepcopy(truth); prop(b["components"][i], "bomwitness:keyBits", "4096" if certs[i]["key_bits"] != 4096 else "2048")
        case("C1_wrong_key_size", [("wrong_key", certs[i]["fingerprint_sha256"])], b, clean)
    for i in rng.sample(idx, 5):       # C2 wrong signature hash declared
        b = copy.deepcopy(truth); prop(b["components"][i], "bomwitness:signatureHash", "sha512" if certs[i]["signature_hash"] != "sha512" else "sha256")
        case("C2_wrong_signature_hash", [("wrong_signature_hash", certs[i]["fingerprint_sha256"])], b, clean)
    for i in rng.sample(idx, 5):       # C3 trust anchor omitted from the CBOM
        b = copy.deepcopy(truth); del b["components"][i]
        case("C3_omitted_certificate", [("undeclared_certificate", certs[i]["fingerprint_sha256"])], b, clean)
    for n in range(5):                 # C4 CBOM lists a certificate that is not in the firmware
        pem = make_cert(2048, -1, 365, f"phantom-{n}.example")
        d = crypto.describe(x509.load_pem_x509_certificate(pem), "(not in firmware)")
        b = copy.deepcopy(truth); b["components"] += crypto.to_cbom([d], image_id)["components"]
        case("C4_phantom_certificate", [("absent_certificate", d["fingerprint_sha256"])], b, clean)
    for n in range(5):                 # C5 undeclared weak-key certificate implanted
        r = mutate.clone(clean, work / "case")
        pem = make_cert(1024, -1, 365, f"weak-{n}.example")
        (r / "etc/ssl/certs" / f"extra-{n}.crt").write_bytes(pem)
        fp = x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()
        case("C5_implanted_weak_key_certificate", [("undeclared_certificate", fp), ("weak_key", fp)], truth, r)
    for n in range(5):                 # C6 expired certificate present, CBOM declares it valid for another year
        r = mutate.clone(clean, work / "case")
        pem = make_cert(2048, -800, -30, f"expired-{n}.example")
        (r / "etc/ssl/certs" / f"old-{n}.crt").write_bytes(pem)
        d = crypto.describe(x509.load_pem_x509_certificate(pem), "x")
        fp = d["fingerprint_sha256"]
        d["not_after"] = (AS_OF + dt.timedelta(days=365)).isoformat()
        b = copy.deepcopy(truth); b["components"] += crypto.to_cbom([d], image_id)["components"]
        case("C6_expired_declared_valid", [("wrong_expiry", fp), ("expired_certificate", fp)], b, r)
    shutil.rmtree(work, ignore_errors=True)

    table = {}
    for k in sorted({c["kind"] for c in cases}):
        rows = [c for c in cases if c["kind"] == k]
        tp, fp, fn = (sum(r[x] for r in rows) for x in ("tp", "fp", "fn"))
        table[k] = {"cases": len(rows), "tp": tp, "fp": fp, "fn": fn}
    tp, fp, fn = (sum(c[x] for c in cases) for x in ("tp", "fp", "fn"))
    natural = {}
    for f in base:
        natural[f["class"]] = natural.get(f["class"], 0) + 1
    hashes_seen, keys_seen = {}, {}
    for c in certs:
        hashes_seen[str(c["signature_hash"])] = hashes_seen.get(str(c["signature_hash"]), 0) + 1
        k = f"{c['key_algorithm']}-{c['key_bits']}"; keys_seen[k] = keys_seen.get(k, 0) + 1
    out = {"image": image_id, "as_of": AS_OF.isoformat(), "certificates_found": len(certs),
           "certificate_files": sorted({c["path"] for c in certs}), "key_types": keys_seen, "signature_hashes": hashes_seen,
           "findings_on_unmodified_image_with_correct_cbom": natural,
           "by_class": table, "overall": {"cases": len(cases), "tp": tp, "fp": fp, "fn": fn,
                                          "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                                          "recall": round(tp / (tp + fn), 3) if tp + fn else None},
           "note": "Synthetic certificates are generated for the test and their private keys are discarded. No tool in the baseline set reads certificates, so there is no baseline column here yet."}
    (ROOT / "results/spike-r1" / f"{image_id}-crypto.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
