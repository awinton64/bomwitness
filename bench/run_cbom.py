"""Seeded CBOM and cross-BOM errors on one official image. Usage: run_cbom.py <image-id> [--k 5] [--out results/r2/cbom]

The correct CBOM is generated from the image (certificates, keys, and algorithm names per verified component).
Each case changes the CBOM, the SBOM or the firmware in one way and lists the findings it must produce.
Findings already present for the unmodified image with the correct CBOM are subtracted; they are policy
observations (expired roots, deprecated primitives), not BOM errors, and are reported separately.

There is no baseline column: none of the tools we could run verifies a declared CBOM against firmware bytes.
Synthetic certificates and keys are generated per run and their private halves are discarded or, for the
implanted-key class, written only into the temporary case tree.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import random
import shutil
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bomwitness import crypto, devicedb, mutate
from bomwitness.reference import Reference
from bomwitness.verify import verify

ROOT = Path(__file__).resolve().parent.parent
AS_OF = dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc)
SEED = 20261127


def make_cert(bits: int, days_from: int, days_to: int, cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BOMwitness synthetic test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(AS_OF + dt.timedelta(days=days_from)).not_valid_after(AS_OF + dt.timedelta(days=days_to))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def run(image_id: str, k: int, out_dir: Path) -> dict:
    spec = json.loads((ROOT / "bench/images.json").read_text())
    im = next(i for i in spec["images"] if i["id"] == image_id)
    clean = ROOT / "work/rootfs" / image_id
    work = ROOT / "work/cbom-cases" / image_id
    ref = Reference(im["release"], im["target"], ROOT / "work/cache")
    snap_path = ROOT / "work/snapshots" / f"{image_id}.json"
    snaps = [json.loads(snap_path.read_text())] if snap_path.exists() else []
    kw = dict(manifest=ref.manifest(), snapshots=snaps)
    truth_sbom = [{"name": n, "version": r["Version"]} for n, r in devicedb.installed(clean).items()]
    rep = verify(clean, truth_sbom, ref, **kw)
    truth = crypto.inventory(clean, image_id, rep)
    assets = crypto.discover_assets(clean)
    evidence = crypto.component_algorithms(clean, rep)
    verdict = {c["name"]: c["verdict"] for c in rep["components"]}
    base = crypto.verify_cbom(clean, truth, AS_OF, rep)
    noise = {(f["class"], f["asset"]) for f in base}
    natural: dict[str, int] = {}
    for f in base:
        natural[f["class"]] = natural.get(f["class"], 0) + 1
    rng = random.Random(f"{SEED}:{image_id}:cbom")
    cases = []

    def case(kind, labels, cbom, rootfs=clean, sbom_report=rep):
        t = time.time()
        found = {(f["class"], f["asset"]) for f in crypto.verify_cbom(rootfs, cbom, AS_OF, sbom_report)} - noise
        labels = set(labels)
        cases.append({"kind": kind, "labels": sorted(map(list, labels)), "tp": len(found & labels), "fp": len(found - labels),
                      "fn": len(labels - found), "extra": sorted(map(list, found - labels))[:4], "seconds": round(time.time() - t, 3)})

    def prop(c, name, value):
        for p in c["properties"]:
            if p["name"] == name:
                p["value"] = value

    def comps(doc, kind):
        return [c for c in doc["components"] if c["cryptoProperties"]["assetType"] == kind]

    certs = assets["certificates"]
    cert_idx = {c["fingerprint_sha256"]: i for i, c in enumerate(certs)}

    def cert_comp(doc, fp):
        return next(c for c in comps(doc, "certificate") if c["hashes"][0]["content"] == fp)

    for c in rng.sample(certs, min(k, len(certs))):            # C1 wrong key size declared
        b = copy.deepcopy(truth); prop(cert_comp(b, c["fingerprint_sha256"]), "bomwitness:keyBits", "4096" if c["key_bits"] != 4096 else "2048")
        case("C1_wrong_key_size", [("wrong_key", c["fingerprint_sha256"])], b)
    for c in rng.sample(certs, min(k, len(certs))):            # C2 wrong signature hash declared
        b = copy.deepcopy(truth); prop(cert_comp(b, c["fingerprint_sha256"]), "bomwitness:signatureHash", "sha512" if c["signature_hash"] != "sha512" else "sha256")
        case("C2_wrong_signature_hash", [("wrong_signature_hash", c["fingerprint_sha256"])], b)
    for c in rng.sample(certs, min(k, len(certs))):            # C3 trust anchor omitted from the CBOM
        b = copy.deepcopy(truth); b["components"].remove(cert_comp(b, c["fingerprint_sha256"]))
        case("C3_omitted_certificate", [("undeclared_certificate", c["fingerprint_sha256"])], b)
    for n in range(k):                                         # C4 CBOM lists a certificate that is not in the firmware
        d = crypto.describe(x509.load_pem_x509_certificate(make_cert(2048, -1, 365, f"phantom-{n}.example")), "(not in firmware)")
        b = copy.deepcopy(truth); b["components"] += crypto.to_cbom([d], image_id)["components"]
        case("C4_phantom_certificate", [("absent_certificate", d["fingerprint_sha256"])], b)
    for n in range(k):                                         # C5 undeclared weak-key certificate implanted
        r = mutate.clone(clean, work / "case")
        pem = make_cert(1024, -1, 365, f"weak-{n}.example")
        (r / "etc/ssl/certs").mkdir(parents=True, exist_ok=True)
        (r / "etc/ssl/certs" / f"extra-{n}.crt").write_bytes(pem)
        fp = x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()
        case("C5_implanted_weak_key_certificate", [("undeclared_certificate", fp), ("weak_key", fp)], truth, r)
    for n in range(k):                                         # C6 expired certificate present, declared valid for another year
        r = mutate.clone(clean, work / "case")
        pem = make_cert(2048, -800, -30, f"expired-{n}.example")
        (r / "etc/ssl/certs").mkdir(parents=True, exist_ok=True)
        (r / "etc/ssl/certs" / f"old-{n}.crt").write_bytes(pem)
        d = crypto.describe(x509.load_pem_x509_certificate(pem), "x")
        fp = d["fingerprint_sha256"]
        d["not_after"] = (AS_OF + dt.timedelta(days=365)).isoformat()
        b = copy.deepcopy(truth); b["components"] += crypto.to_cbom([d], image_id)["components"]
        case("C6_expired_declared_valid", [("wrong_expiry", fp), ("expired_certificate", fp)], b, r)

    keys = assets["keys"]
    for key in rng.sample(keys, min(k, len(keys))):            # K1 key omitted from the CBOM
        b = copy.deepcopy(truth)
        b["components"] = [c for c in b["components"] if not (c["cryptoProperties"]["assetType"] == "related-crypto-material"
                                                              and c["hashes"][0]["content"] == key["fingerprint_sha256"])]
        case("K1_omitted_key", [("undeclared_key", key["fingerprint_sha256"])], b)
    for n in range(k):                                         # K2 CBOM lists key material that is not in the firmware
        fp = f"{rng.getrandbits(256):064x}"
        b = copy.deepcopy(truth)
        b["components"] += crypto.to_cbom([], image_id, [{"fingerprint_sha256": fp, "kind": "public-key", "format": "usign",
                                                          "algorithm": "Ed25519", "bits": 256, "path": "(not in firmware)"}])["components"]
        case("K2_phantom_key", [("absent_key", fp)], b)
    for n in range(k):                                         # K3 private key shipped in the image, CBOM silent
        r = mutate.clone(clean, work / "case")
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        (r / "etc/ssl/private").mkdir(parents=True, exist_ok=True)
        (r / "etc/ssl/private" / f"server-{n}.key").write_bytes(pem)
        import hashlib
        fp = hashlib.sha256(pem.strip()).hexdigest()
        fp = next(x["fingerprint_sha256"] for x in crypto.discover_assets(r)["keys"] if x["path"].endswith(f"server-{n}.key"))
        case("K3_implanted_private_key", [("undeclared_key", fp), ("embedded_private_key", fp)], truth, r)

    pairs = sorted((comp, alg) for comp, algs in evidence.items() for alg in algs if verdict.get(comp) in crypto.VERIFIED)
    providers = sorted({c for c, _a in pairs})

    def drop_alg(doc, comp, alg):
        ref_id = f"alg:{alg}@{comp}"
        doc["components"] = [c for c in doc["components"] if c.get("bom-ref") != ref_id]
        for d in doc["dependencies"]:
            if d["ref"] == f"pkg:{comp}":
                d["provides"] = [x for x in d["provides"] if x != ref_id]

    def add_alg(doc, comp, alg):
        ref_id = f"alg:{alg}@{comp}"
        doc["components"].append({"type": "cryptographic-asset", "bom-ref": ref_id, "name": alg,
                                  "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": crypto.ALG_INFO[alg]["primitive"]}}})
        dep = next((d for d in doc["dependencies"] if d["ref"] == f"pkg:{comp}"), None)
        if dep is None:
            dep = {"ref": f"pkg:{comp}", "provides": []}
            doc["dependencies"].append(dep)
        dep["provides"].append(ref_id)

    multi = [(c, a) for c, a in pairs if len(evidence[c]) > 1]
    for comp, alg in rng.sample(multi, min(k, len(multi))):    # A1 algorithm omitted from the CBOM
        b = copy.deepcopy(truth); drop_alg(b, comp, alg)
        case("A1_omitted_algorithm", [("undeclared_algorithm", f"{alg}@{comp}")], b)
    for comp in rng.sample(providers, min(k, len(providers))):  # A2 algorithm claimed for a component that does not carry it
        absent = sorted(a for a in crypto.ALG_INFO if a not in evidence[comp])
        alg = rng.choice(absent)
        b = copy.deepcopy(truth); add_alg(b, comp, alg)
        case("A2_phantom_algorithm", [("algorithm_not_evidenced", f"{alg}@{comp}")], b)
    for comp, alg in rng.sample(multi, min(k, len(multi))):    # A3 algorithm attributed to the wrong provider
        others = [p for p in providers if p != comp and alg not in evidence[p]]
        if not others:
            continue
        z = rng.choice(others)
        b = copy.deepcopy(truth); drop_alg(b, comp, alg); add_alg(b, z, alg)
        case("A3_wrong_provider", [("undeclared_algorithm", f"{alg}@{comp}"), ("algorithm_not_evidenced", f"{alg}@{z}")], b)
    for comp in rng.sample(providers, min(k, len(providers))):  # X1 the SBOM omits a component the CBOM relies on
        rep2 = verify(clean, [c for c in truth_sbom if c["name"] != comp], ref, **kw)
        case("X1_provider_not_in_sbom", [("provider_not_in_sbom", comp)], truth, clean, rep2)
    patchable = [c for c in providers if any((clean / f).read_bytes()[:4] == b"\x7fELF" for f in next(x for x in rep["components"] if x["name"] == c).get("files", []))]
    for comp in rng.sample(patchable, min(k, len(patchable))):  # X2 a crypto provider's binary is patched; both BOMs unchanged
        files = next(x for x in rep["components"] if x["name"] == comp)["files"]
        p = next(f for f in sorted(files) if (clean / f).read_bytes()[:4] == b"\x7fELF")
        r = mutate.clone(clean, work / "case")
        blob = bytearray((r / p).read_bytes()); blob[len(blob) // 2] ^= 0x01; (r / p).write_bytes(bytes(blob))
        rep2 = verify(r, truth_sbom, ref, **kw)
        case("X2_provider_bytes_patched", [("provider_unverified", comp)], truth, r, rep2)
    for comp in rng.sample(providers, min(k, len(providers))):  # X3 a crypto component has no CBOM entry at all
        b = copy.deepcopy(truth)
        for alg in list(evidence[comp]):
            drop_alg(b, comp, alg)
        b["dependencies"] = [d for d in b["dependencies"] if d["ref"] != f"pkg:{comp}"]
        case("X3_crypto_component_without_entry", [("crypto_component_without_cbom_entry", comp)], b)
    shutil.rmtree(work, ignore_errors=True)

    table = {}
    for kind in sorted({c["kind"] for c in cases}):
        rows = [c for c in cases if c["kind"] == kind]
        table[kind] = {"cases": len(rows), **{x: sum(r[x] for r in rows) for x in ("tp", "fp", "fn")}}
    tp, fp, fn = (sum(c[x] for c in cases) for x in ("tp", "fp", "fn"))
    key_types, sig_hashes = {}, {}
    for c in certs:
        key_types[f"{c['key_algorithm']}-{c['key_bits']}"] = key_types.get(f"{c['key_algorithm']}-{c['key_bits']}", 0) + 1
        sig_hashes[str(c["signature_hash"])] = sig_hashes.get(str(c["signature_hash"]), 0) + 1
    deprecated = sorted(f"{a}@{c}" for c, algs in evidence.items() for a in algs if crypto.ALG_INFO[a]["deprecated"])
    res = {"image": im, "as_of": AS_OF.isoformat(), "seed": SEED, "k": k,
           "assets": {"certificates": len(certs), "certificate_key_types": key_types, "certificate_signature_hashes": sig_hashes,
                      "keys": [{x: key[x] for x in ("kind", "format", "algorithm", "path")} for key in keys],
                      "crypto_components": len(evidence), "component_algorithm_pairs": sum(len(v) for v in evidence.values()),
                      "algorithms_by_component": {c: sorted(a) for c, a in sorted(evidence.items())}, "deprecated_pairs": deprecated},
           "findings_on_unmodified_image_with_correct_cbom": natural, "by_class": table,
           "overall": {"cases": len(cases), "tp": tp, "fp": fp, "fn": fn,
                       "precision": round(tp / (tp + fp), 4) if tp + fp else None, "recall": round(tp / (tp + fn), 4) if tp + fn else None},
           "cases": cases}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{image_id}.json").write_text(json.dumps(res, indent=1))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image_id"); ap.add_argument("--k", type=int, default=5); ap.add_argument("--out", default="results/r2/cbom")
    a = ap.parse_args()
    t0 = time.time()
    res = run(a.image_id, a.k, ROOT / a.out)
    print(a.image_id, json.dumps(res["overall"]), "natural:", json.dumps(res["findings_on_unmodified_image_with_correct_cbom"]), round(time.time() - t0), "s")
    for kind, row in res["by_class"].items():
        print(f"  {kind:36s} {row}", [c["extra"] for c in res["cases"] if c["kind"] == kind and (c["fp"] or c["fn"])][:2])
