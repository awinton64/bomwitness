"""AI-BOM presence check: find model files by magic bytes and compare with declared models.

Scope, stated plainly: this answers "does the image contain a model file that the AI-BOM does not list, or
list one that is not there, or list one whose bytes differ". It does not inspect weights, licences, training
data or model behaviour. The OpenWrt router images in the benchmark contain no model files, so this module
is exercised only by unit tests on labelled synthetic fixtures.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

EXTENSIONS = (".gguf", ".onnx", ".tflite", ".safetensors", ".pt", ".pth", ".h5", ".pb", ".mlmodel", ".bin.model")


def model_format(name: str, head: bytes) -> str | None:
    if head[:4] == b"GGUF":
        return "GGUF"
    if head[4:8] == b"TFL3":
        return "TensorFlow Lite"
    if head[:8] == b"\x89HDF\r\n\x1a\n":
        return "HDF5 (Keras)"
    if len(head) >= 9 and head[8:9] == b"{":
        n = struct.unpack("<Q", head[:8])[0]
        if 2 <= n < 100 << 20 and name.endswith(".safetensors"):
            return "safetensors"
    if head[:2] == b"PK" and name.endswith((".pt", ".pth")):
        return "PyTorch archive"
    if name.endswith(".onnx") and head[:1] == b"\x08":
        return "ONNX"
    return None


def discover(rootfs: Path) -> list[dict]:
    out = []
    for dp, _dn, fn in os.walk(rootfs):
        for f in fn:
            q = Path(dp) / f
            if q.is_symlink() or not q.is_file():
                continue
            with q.open("rb") as fh:
                head = fh.read(16)
            fmt = model_format(f.lower(), head)
            if fmt:
                out.append({"path": str(q.relative_to(rootfs)), "format": fmt, "size": q.stat().st_size,
                            "sha256": hashlib.sha256(q.read_bytes()).hexdigest()})
    return sorted(out, key=lambda m: m["path"])


def verify_aibom(rootfs: Path, models: list[dict]) -> list[dict]:
    """`models` are CycloneDX machine-learning-model components; a SHA-256 hash identifies the file."""
    seen = {m["sha256"]: m for m in discover(rootfs)}
    findings, matched = [], set()
    for m in models:
        fp = next((h["content"].lower() for h in m.get("hashes", []) if h.get("alg") == "SHA-256"), None)
        if fp in seen:
            matched.add(fp)
        else:
            findings.append({"class": "absent_model", "asset": m.get("name"), "grade": "A",
                             "detail": "none of the model files this tool found in the firmware has the declared SHA-256" if fp
                             else "the declared model carries no SHA-256, so it cannot be matched to a file"})
    for fp, m in seen.items():
        if fp not in matched:
            findings.append({"class": "undeclared_model", "asset": m["path"], "grade": "A",
                             "detail": f"{m['format']} model file, {m['size']} bytes, not listed in the AI-BOM"})
    return findings


def to_aibom(models: list[dict], subject: str) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": subject}},
            "components": [{"type": "machine-learning-model", "bom-ref": f"model:{m['sha256'][:16]}", "name": m["path"],
                            "hashes": [{"alg": "SHA-256", "content": m["sha256"]}],
                            "properties": [{"name": "bomwitness:format", "value": m["format"]}]} for m in models]}


if __name__ == "__main__":
    import sys
    print(json.dumps(discover(Path(sys.argv[1])), indent=1))
