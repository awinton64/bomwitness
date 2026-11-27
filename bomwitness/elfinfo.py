"""Small ELF facts read without section headers (OpenWrt strips them with sstrip)."""
from __future__ import annotations

import io
import re

ELF_MAGIC = b"\x7fELF"


def is_elf(blob: bytes) -> bool:
    return blob[:4] == ELF_MAGIC


def soname(blob: bytes) -> str | None:
    """DT_SONAME from the PT_DYNAMIC segment, or None."""
    if not is_elf(blob):
        return None
    try:
        from elftools.elf.dynamic import DynamicSegment
        from elftools.elf.elffile import ELFFile
        for seg in ELFFile(io.BytesIO(blob)).iter_segments():
            if isinstance(seg, DynamicSegment):
                for tag in seg.iter_tags():
                    if tag.entry.d_tag == "DT_SONAME":
                        return tag.soname
    except Exception:
        return None
    return None


def upstream_token(version: str) -> str | None:
    """Leading dotted release number of a version string, if any.

    "2.93-r1" gives "2.93"; "6.6.144~7024...-r1" gives "6.6.144". Single
    numbers (dates such as "20260601", or "1674~443ec4032a") give None: they
    are too short or too generic to look for in bytes.
    """
    m = re.match(r"\d+(\.\d+)+[a-z]?(?![0-9])", version or "")
    return m.group(0) if m else None


def has_token(blob: bytes, token: str) -> bool:
    """True if `token` occurs in `blob` as a whole version number (not inside a longer one)."""
    pat = rb"(?<![0-9])(?<![0-9]\.)" + re.escape(token.encode()) + rb"(?![0-9])(?!\.[0-9])"
    return re.search(pat, blob) is not None


def strip_release(version: str) -> str:
    """Drop OpenWrt's package release suffix: "1.36.1-r3" gives "1.36.1"."""
    return re.sub(r"-r?\d+$", "", version or "")


def same_version(declared: str, reference: str) -> str | None:
    """How a declared version matches a reference version: "exact", "upstream" or None.

    OpenWrt's published BOMs carry upstream versions without the "-rN"
    package release, so a declared "1.36.1" matches a reference "1.36.1-r3" at
    upstream granularity.
    """
    if declared == reference:
        return "exact"
    if declared and declared == strip_release(reference) and declared != reference:
        return "upstream"
    return None
