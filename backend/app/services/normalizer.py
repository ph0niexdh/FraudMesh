"""EVENT → NORMALIZE: tokenize identifiers, sanitise metadata, fill defaults."""
from __future__ import annotations

import uuid
from typing import Any

from app.privacy.tokenizer import display_label, is_token, sanitize_metadata, tokenize
from app.schemas.events import EventIn, EventType, NormalizedEvent
from app.utils.timeutil import ensure_utc, utcnow


def _resolve(kind: str, raw: str | None, token: str | None) -> tuple[str | None, str | None]:
    """Return (token, display label) from a raw id or a pre-tokenized value."""
    if raw:
        tok = tokenize(kind, raw)
        return tok, display_label(kind, raw, tok)
    if token:
        if not is_token(kind, token):
            # treat unknown formats as raw identifiers so they are never stored verbatim
            tok = tokenize(kind, token)
            return tok, display_label(kind, token, tok)
        return token, token
    return None, None


def normalize(event: EventIn) -> tuple[NormalizedEvent, dict[str, str | None], list[str]]:
    """Returns (normalized event, safe display labels, sanitised metadata keys)."""
    cust, cust_label = _resolve("customer", event.customer_id, event.customer_token)
    acct, acct_label = _resolve("account", event.account_id, event.account_token)
    dev, dev_label = _resolve("device", event.device_id, event.device_token)
    ip, ip_label = _resolve("ip", event.ip_address, event.ip_token)

    event_id = event.event_id or f"evt_{uuid.uuid4().hex[:16]}"
    metadata, touched = sanitize_metadata(event.metadata)
    if event.bank_name:
        metadata["bank_name"] = event.bank_name
    if event.event_type == EventType.cloud_event:
        # keep a safe principal display name for synthetic service principals only
        raw_principal = event.metadata.get("principal") or event.metadata.get("cloud_principal")
        if raw_principal:
            metadata["principal_display"] = display_label("principal", str(raw_principal))
    if event.event_type == EventType.kyc_verification and "kyc_token" not in metadata:
        metadata["kyc_token"] = tokenize("kyc", f"{cust or acct}:{event_id}")

    normalized = NormalizedEvent(
        event_id=event_id,
        event_type=event.event_type,
        timestamp=ensure_utc(event.timestamp) if event.timestamp else utcnow(),
        customer_token=cust,
        account_token=acct,
        device_token=dev,
        ip_token=ip,
        channel=event.channel.lower(),
        amount=float(event.amount or 0.0),
        metadata=metadata,
    )
    labels: dict[str, Any] = {"customer": cust_label, "account": acct_label, "device": dev_label, "ip": ip_label}
    return normalized, labels, touched
