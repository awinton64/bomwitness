"""Regenerate the example declared BOMs from the unpacked example image.

declared-correct.cdx.json    every installed package with its real version (from the image's own database,
                             used here only to write a correct declaration), plus a correct CBOM section
declared-with-errors.cdx.json  the same with six seeded errors, listed in expected-findings.json

Usage: make_example_boms.py <rootfs> <reference-cache> <snapshot.json>
"""
import copy
import datetime as dt
import json
import sys
from pathlib import Path

from bomwitness import bomio, crypto, devicedb
from bomwitness.reference import Reference
from bomwitness.verify import verify

here = Path(__file__).resolve().parent
rootfs, cache, snap = Path(sys.argv[1]), Path(sys.argv[2]), json.loads(Path(sys.argv[3]).read_text())
ref = Reference("24.10.8", "ath79/generic", cache)
truth = [{"name": n, "version": r["Version"]} for n, r in sorted(devicedb.installed(rootfs).items())]
rep = verify(rootfs, truth, ref, manifest=ref.manifest(), snapshots=[snap])
subject = "openwrt-24.10.8-ath79-generic-tplink_archer-c7-v5"
good = bomio.sbom(truth, subject)
cb = crypto.inventory(rootfs, subject, rep)
good["components"] += cb["components"]
good["dependencies"] = cb["dependencies"]
(here / "declared-correct.cdx.json").write_text(json.dumps(good, indent=1) + "\n")

bad = copy.deepcopy(good)
sw = [c for c in bad["components"] if c["type"] == "library"]
bad["components"].remove(next(c for c in sw if c["name"] == "dnsmasq"))                      # 1 omitted component
next(c for c in sw if c["name"] == "dropbear")["version"] = "2022.82-6"                    # 2 version from an older release
next(c for c in sw if c["name"] == "busybox")["version"] = "1.36.2-r3"                      # 3 version that never existed
bad["components"].append({"type": "library", "bom-ref": "pkg:tcpdump", "name": "tcpdump", "version": "4.99.5-r1"})   # 4 phantom
cert = next(c for c in bad["components"] if c.get("cryptoProperties", {}).get("assetType") == "certificate")
bad["components"].remove(cert)                                                                # 5 trust anchor omitted from the CBOM
bad["components"].append({"type": "cryptographic-asset", "bom-ref": "alg:ML-KEM@libmbedtls21", "name": "ML-KEM",
                          "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem"}}})
next(d for d in bad["dependencies"] if d["ref"] == "pkg:libmbedtls21")["provides"].append("alg:ML-KEM@libmbedtls21")  # 6 unsupported claim
(here / "declared-with-errors.cdx.json").write_text(json.dumps(bad, indent=1) + "\n")
expected = {"sbom": [["undeclared_component", "dnsmasq"], ["wrong_version", "dropbear"], ["wrong_version", "busybox"], ["absent", "tcpdump"]],
            "cbom": [["undeclared_certificate", cert["hashes"][0]["content"]], ["algorithm_not_evidenced", "ML-KEM@libmbedtls21"]],
            # Cross-BOM consequences of errors 2 and 3: the CBOM names dropbear and busybox as algorithm providers,
            # and their SBOM claims no longer verify.
            "cbom_consequences": [["provider_unverified", "busybox"], ["provider_unverified", "dropbear"]]}
(here / "expected-findings.json").write_text(json.dumps(expected, indent=1) + "\n")
print("wrote", len(truth), "software components,", len(cb["components"]), "cryptographic assets; 6 seeded errors")
