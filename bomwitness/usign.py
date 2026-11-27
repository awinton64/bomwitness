"""Verify usign (signify-style Ed25519) signatures on OpenWrt feed indexes and checksum files.

A usign public key is base64("Ed" + 8-byte key id + 32-byte Ed25519 key). A
signature is base64("Ed" + 8-byte key id + 64-byte signature) over the raw
file bytes. The release keys below are pinned from the OpenWrt keyring
(https://git.openwrt.org/keyring.git, directory usign/, file name = key id),
so the trust anchor is these two keys and not TLS or the firmware's own
/etc/opkg/keys directory.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PINNED_KEYS = {
    # key id: (base64 public key, comment line in the OpenWrt keyring)
    "d310c6f2833e97f7": ("RWTTEMbygz6X95lKDAulctZy3aj15823THXfyrfXgwGbxZlXBd2brNcw",
                         "Public usign key for 24.10 release builds"),
    "b5043e70f9a75cde": ("RWS1BD5w+adc3j2Hqg9+b66CvLR7NlHbsj7wjNVj0XGt/othDgIAOJS+",
                         "Public usign key for unattended snapshot builds (also signs 23.05 release files)"),
}


class SignatureError(ValueError):
    pass


def _payload(text: str) -> bytes:
    lines = [l.strip() for l in text.strip().splitlines() if l.strip() and not l.startswith("untrusted comment:")]
    if len(lines) != 1:
        raise SignatureError("expected one base64 line")
    return base64.b64decode(lines[0], validate=True)


def parse_public_key(text: str) -> tuple[str, bytes]:
    raw = _payload(text)
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise SignatureError("not a usign Ed25519 public key")
    return raw[2:10].hex(), raw[10:]


def parse_signature(text: str) -> tuple[str, bytes]:
    raw = _payload(text)
    if len(raw) != 74 or raw[:2] != b"Ed":
        raise SignatureError("not a usign Ed25519 signature")
    return raw[2:10].hex(), raw[10:]


def verify(message: bytes, signature_text: str, keys: dict[str, tuple[str, str]] | None = None) -> str:
    """Return the id of the pinned key that signed `message`, or raise SignatureError."""
    keys = PINNED_KEYS if keys is None else keys
    key_id, sig = parse_signature(signature_text)
    if key_id not in keys:
        raise SignatureError(f"signature made by unknown key {key_id}")
    pub_id, pub = parse_public_key(keys[key_id][0])
    if pub_id != key_id:
        raise SignatureError("pinned key id does not match its key bytes")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    except InvalidSignature as e:
        raise SignatureError(f"bad signature for key {key_id}") from e
    return key_id
