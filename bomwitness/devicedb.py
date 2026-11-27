"""The device's own opkg database: grade C evidence.

It is self-reported by the firmware, so it never decides a verdict. It is
read for three purposes only: to report, clearly labelled, where it disagrees
with the BOM or with the bytes; as ground truth when building benchmark cases
from official images; and by the baselines.
"""
from __future__ import annotations

import re
from pathlib import Path

from .elfinfo import same_version
from .reference import parse_control, split_list

STATUS = "usr/lib/opkg/status"
INFO = "usr/lib/opkg/info"


def installed(rootfs: Path) -> dict[str, dict]:
    p = Path(rootfs) / STATUS
    if not p.is_file():
        return {}
    return {r["Package"]: r for r in parse_control(p.read_text(errors="replace"))}


def owned_files(rootfs: Path, name: str) -> list[str]:
    p = Path(rootfs) / INFO / f"{name}.list"
    if not p.is_file():
        return []
    return [l.strip().lstrip("/") for l in p.read_text(errors="replace").splitlines() if l.strip()]


def depends(rec: dict) -> list[str]:
    return split_list(rec.get("Depends", ""))


def compare(rootfs: Path, claims: list[dict], results: list[dict]) -> dict:
    """Where does the device database disagree with the BOM, and with the byte-level verdicts?"""
    inst = installed(rootfs)
    if not inst:
        return {"present": False, "packages": 0, "findings": []}
    alias: dict[str, set[str]] = {}
    for n, r in inst.items():
        alias.setdefault(n, set()).add(n)
        for a in split_list(r.get("Provides", "")):
            alias.setdefault(a, set()).add(n)
        abi = r.get("ABIVersion", "")
        if abi and n.endswith(abi):
            alias.setdefault(n[: -len(abi)], set()).add(n)
    by_name = {r["name"]: r for r in results}
    findings, matched = [], set()

    def add(kind, component, detail):
        findings.append({"class": kind, "component": component, "grade": "C", "source": "device_db", "detail": detail})

    for c in claims:
        names = {c["name"]} if c["name"] in inst else alias.get(c["name"], set())
        byte_verdict = by_name.get(c["name"], {}).get("verdict")
        if not names:
            add("absent", c["name"], "declared in the BOM; the device database does not list it")
            continue
        matched |= names
        versions = {inst[n].get("Version", "") for n in names}
        agrees = any(same_version(c["version"], v) for v in versions)
        if not agrees:
            add("wrong_version", c["name"], f"BOM declares {c['version']}; the device database says {', '.join(sorted(versions))}")
        elif byte_verdict in ("wrong_version", "absent", "bytes_differ", "wrong_component"):
            add("db_contradicted_by_bytes", c["name"],
                f"the device database agrees with the BOM ({c['version']}), but the bytes say: {byte_verdict}")
    for n in sorted(set(inst) - matched):
        add("undeclared_component", n, f"the device database lists {n} {inst[n].get('Version', '')}; the BOM does not")
    return {"present": True, "packages": len(inst), "findings": findings}
