"""Application-level cryptography.

* AES-256-GCM envelope for secrets at rest (TOTP seeds, PII, face templates).
* HMAC-SHA256 for deterministic, non-reversible lookup keys.
* SHA-256 for refresh tokens (high-entropy, so a fast hash is appropriate).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fraudmesh.config import get_settings


def _key() -> bytes:
    key = base64.b64decode(get_settings().data_key)
    if len(key) != 32:
        raise ValueError("FM_DATA_KEY must be base64 encoding of exactly 32 bytes")
    return key


def encrypt(plaintext: bytes, aad: bytes = b"fraudmesh") -> bytes:
    nonce = os.urandom(12)
    return b"v1" + nonce + AESGCM(_key()).encrypt(nonce, plaintext, aad)


def decrypt(blob: bytes, aad: bytes = b"fraudmesh") -> bytes:
    if not blob.startswith(b"v1"):
        raise ValueError("unknown ciphertext version")
    nonce, ct = blob[2:14], blob[14:]
    return AESGCM(_key()).decrypt(nonce, ct, aad)


def encrypt_str(value: str) -> bytes:
    return encrypt(value.encode())


def decrypt_str(blob: bytes) -> str:
    return decrypt(blob).decode()


def hmac_hex(value: str) -> str:
    return hmac.new(get_settings().hmac_key.encode(), value.encode(), hashlib.sha256).hexdigest()


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
