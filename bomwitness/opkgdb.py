"""Parse the device's own opkg database.

BOMwitness never uses this as verification evidence. It is read for two
purposes only: as ground truth when building benchmark cases from official
images, and to label what a database-trusting verifier would have concluded.
"""
from __future__ import annotations

import re
from pathlib import Path

STATUS = "usr/lib/opkg/status"
INFO = "usr/lib/opkg/info"


def parse_control(text: str) -> list[dict]:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        rec, key = {}, None
        for line in block.splitlines():
            if line[:1] in " \t" and key:
                rec[key] += "\n" + line.strip()
            elif ":" in line:
                key, val = line.split(":", 1)
                rec[key] = val.strip()
        if rec.get("Package"):
            out.append(rec)
    return out


def installed(rootfs: Path) -> dict[str, dict]:
    p = rootfs / STATUS
    if not p.is_file():
        return {}
    return {r["Package"]: r for r in parse_control(p.read_text(errors="replace"))}


def owned_files(rootfs: Path, name: str) -> list[str]:
    p = rootfs / INFO / f"{name}.list"
    if not p.is_file():
        return []
    return [l.strip().lstrip("/") for l in p.read_text(errors="replace").splitlines() if l.strip()]


def depends(rec: dict) -> list[str]:
    raw = rec.get("Depends", "")
    return [re.sub(r"\s*\(.*?\)", "", d).strip() for d in raw.split(",") if d.strip()]
