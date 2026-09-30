"""Privacy service: tokenization of identifiers and metadata sanitisation.

* Identifiers (customer, account, device, IP, beneficiary, KYC record, cloud
  principal/resource) are replaced by keyed HMAC-SHA256 tokens, e.g.
  ``CUSTOMER_10291 -> usr_8af31c02d1``. Raw values are never persisted.
* Tokenization is deterministic for a given secret so the same entity always
  maps to the same token (required for correlation), but tokens cannot be
  reversed without the secret.
* Display labels are only derived from raw values when those values match a
  *synthetic demo* pattern (``SBI-DEMO-1042``, ``DEVICE-7F21``); anything else
  is masked. Customer identifiers and IP addresses are always masked.
* Metadata is scrubbed of PII-like keys and PII-like string values.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from app.config import get_settings

PREFIXES: dict[str, str] = {
    "customer": "usr",
    "account": "acc",
    "device": "dev",
    "ip": "ip",
    "beneficiary": "ben",
    "kyc": "kyc",
    "principal": "prn",
    "resource": "res",
}

_TOKEN_RE = {kind: re.compile(rf"^{prefix}_[0-9a-f]{{10}}$") for kind, prefix in PREFIXES.items()}

_SYNTHETIC_PATTERNS = [
    re.compile(r"^(SBI|HDFC|ICICI)-DEMO-\d{3,6}$"),
    re.compile(r"^(SBI|HDFC|ICICI)-SYN-\d{3,6}$"),
    re.compile(r"^DEVICE-[0-9A-F]{4}$"),
    re.compile(r"^SYN-[A-Z0-9-]{2,24}$"),
    re.compile(r"^(svc|ops|iam|role|bucket|vm|db|key)[-:/][a-z0-9:/_-]{1,40}$"),
]

# Keys that must never be stored, whatever their value.
PII_KEYS = {
    "name", "full_name", "first_name", "last_name", "customer_name", "email", "phone", "mobile",
    "pan", "aadhaar", "aadhar", "address", "dob", "date_of_birth", "password", "otp", "pin", "cvv",
    "card_number", "card", "image", "image_base64", "media", "selfie", "document_image", "raw_image",
    "raw_media", "passport_number", "ssn",
}

# Identifier-bearing metadata keys and the token kind they map to.
ID_KEYS = {
    "beneficiary_id": ("beneficiary", "beneficiary_token"),
    # an account-number beneficiary shares the account token space so a transfer
    # to an account we also observe links to the same graph node
    "beneficiary_account": ("account", "beneficiary_token"),
    "kyc_record_id": ("kyc", "kyc_token"),
    "principal": ("principal", "principal_token"),
    "cloud_principal": ("principal", "principal_token"),
    "resource": ("resource", "resource_token"),
    "cloud_resource": ("resource", "resource_token"),
    "previous_device_id": ("device", "previous_device_token"),
    "linked_account_id": ("account", "linked_account_token"),
}

_VALUE_PATTERNS = [
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),                 # email
    re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),                   # PAN
    re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),                # Aadhaar-like
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),                   # card-like
    re.compile(r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)"),    # Indian mobile
]


def _secret() -> bytes:
    return get_settings().token_secret.encode()


def is_token(kind: str, value: str | None) -> bool:
    return bool(value) and bool(_TOKEN_RE[kind].match(str(value)))


def tokenize(kind: str, raw: str | None) -> str | None:
    """Return a stable, non-reversible token for ``raw`` (idempotent on tokens)."""
    if raw is None or str(raw).strip() == "":
        return None
    value = str(raw).strip()
    if kind not in PREFIXES:
        raise ValueError(f"unknown identifier kind: {kind}")
    if is_token(kind, value):
        return value
    digest = hmac.new(_secret(), f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"{PREFIXES[kind]}_{digest}"


def is_synthetic_identifier(raw: str | None) -> bool:
    return bool(raw) and any(p.match(str(raw)) for p in _SYNTHETIC_PATTERNS)


def display_label(kind: str, raw: str | None, token: str | None = None) -> str | None:
    """A label that is safe to show in the UI.

    Synthetic demo identifiers are shown verbatim (they are fictional);
    customers and IPs are always pseudonymous; anything else is masked.
    """
    if raw is None and token is None:
        return None
    token = token or tokenize(kind, raw)
    if raw is None or is_token(kind, str(raw)):
        return token
    raw = str(raw).strip()
    if kind == "customer":
        return token
    if kind == "ip":
        parts = raw.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x #{token[-4:]}"
        return token
    if get_settings().show_synthetic_labels and is_synthetic_identifier(raw):
        return raw
    tail = re.sub(r"\W", "", raw)[-4:]
    return f"{kind.upper()[:3]}-••{tail}" if tail else token


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in _VALUE_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        return value
    if isinstance(value, dict):
        return sanitize_metadata(value)[0]
    if isinstance(value, list):
        return [_scrub_value(v) for v in value[:50]]
    return value


def sanitize_metadata(metadata: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """Remove PII keys, tokenize identifier keys and scrub PII-like values.

    Returns the sanitised metadata and the list of keys that were removed or
    transformed (key names only — never values — so it is safe to audit).
    """
    clean: dict[str, Any] = {}
    touched: list[str] = []
    for key, value in (metadata or {}).items():
        k = str(key)
        lk = k.lower()
        if lk in PII_KEYS:
            touched.append(k)
            continue
        if lk in ID_KEYS:
            kind, token_key = ID_KEYS[lk]
            clean[token_key] = tokenize(kind, None if value is None else str(value))
            label = display_label(kind, None if value is None else str(value))
            if label and kind != "principal":
                clean[token_key.replace("_token", "_label")] = label
            touched.append(k)
            continue
        scrubbed = _scrub_value(value)
        if scrubbed != value:
            touched.append(k)
        clean[k] = scrubbed
    return clean, touched


def media_fingerprint(data: bytes) -> str:
    """SHA-256 of KYC media — stored instead of the media itself."""
    return hashlib.sha256(data).hexdigest()
