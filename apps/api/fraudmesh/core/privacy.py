"""PII masking helpers. Anything rendered to the UI goes through these."""

from __future__ import annotations

import re


def mask_phone(phone: str | None) -> str | None:
    if not phone:
        return phone
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "****"
    cc = "+" + digits[:-10] + " " if len(digits) > 10 else ""
    return f"{cc}******{digits[-4:]}"


def mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    keep = local[:1]
    return f"{keep}{'*' * max(3, len(local) - 1)}@{domain}"


def mask_account(number: str | None) -> str | None:
    if not number:
        return number
    return f"XXXX{number[-4:]}"


def mask_document(number: str | None) -> str | None:
    if not number:
        return number
    if len(number) <= 4:
        return "*" * len(number)
    return f"{number[:1]}{'*' * (len(number) - 3)}{number[-2:]}"


def mask_ip(ip: str | None) -> str | None:
    """IPs are operational data for analysts; they are kept intact (not customer PII)."""
    return ip
