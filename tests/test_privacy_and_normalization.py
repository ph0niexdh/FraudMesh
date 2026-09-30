import logging

import pytest
from pydantic import ValidationError

from app.privacy.tokenizer import display_label, is_token, sanitize_metadata, tokenize
from app.schemas.events import EventIn
from app.services.normalizer import normalize
from app.utils.logging import RedactingFilter, redact


# ---------------------------------------------------------------- privacy tokenization
def test_tokenize_is_deterministic_prefixed_and_idempotent():
    t1 = tokenize("customer", "CUSTOMER_10291")
    t2 = tokenize("customer", "CUSTOMER_10291")
    assert t1 == t2 and t1.startswith("usr_") and is_token("customer", t1)
    assert tokenize("customer", t1) == t1  # tokens are not re-hashed
    assert tokenize("account", "CUSTOMER_10291") != t1  # kind is part of the key
    assert "10291" not in t1


def test_all_identifier_kinds_have_prefixes():
    assert tokenize("account", "SBI-DEMO-1042").startswith("acc_")
    assert tokenize("device", "DEVICE-7F21").startswith("dev_")
    assert tokenize("ip", "100.99.203.7").startswith("ip_")


def test_display_labels_never_expose_customers_or_ips():
    assert display_label("customer", "CUSTOMER_10291").startswith("usr_")
    ip_label = display_label("ip", "100.99.203.7")
    assert "203.7" not in ip_label and ip_label.startswith("100.99.x.x")
    # synthetic demo identifiers may be shown, real-looking ones are masked
    assert display_label("account", "SBI-DEMO-1042") == "SBI-DEMO-1042"
    masked = display_label("account", "123456789012")
    assert "123456789012" not in masked and masked.endswith("9012")


def test_sanitize_metadata_removes_pii_and_tokenizes_ids():
    clean, touched = sanitize_metadata({
        "name": "Real Person", "email": "a@b.com", "aadhaar": "1234 5678 9012", "selfie": "base64...",
        "beneficiary_id": "SYN-BEN-12345", "note": "call me at 9876543210 or x@y.org", "city": "Pune",
    })
    for key in ("name", "email", "aadhaar", "selfie", "beneficiary_id"):
        assert key not in clean
    assert clean["beneficiary_token"].startswith("ben_")
    assert "9876543210" not in clean["note"] and "x@y.org" not in clean["note"]
    assert clean["city"] == "Pune"
    assert set(touched) >= {"name", "email", "aadhaar", "selfie", "beneficiary_id", "note"}


def test_log_redaction_filter():
    assert "a@b.com" not in redact("user a@b.com logged in")
    assert "9876543210" not in redact("phone 9876543210")
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "ip=%s email=%s", ("10.1.2.3", "a@b.com"), None)
    RedactingFilter().filter(record)
    msg = record.getMessage()
    assert "10.1.2.3" not in msg and "a@b.com" not in msg


# ---------------------------------------------------------------- event normalization
def test_normalization_produces_common_schema():
    ev = EventIn(event_type="transaction", customer_id="CUSTOMER_1", account_id="SBI-DEMO-1042", device_id="DEVICE-7F21",
                 ip_address="100.99.203.7", amount=185000, bank_name="sbi",
                 metadata={"beneficiary_account": "HDFC-DEMO-7781", "custom_field": {"nested": 1}, "email": "x@y.z"})
    norm, labels, touched = normalize(ev)
    assert norm.event_id.startswith("evt_")
    assert norm.customer_token.startswith("usr_") and norm.account_token.startswith("acc_")
    assert norm.device_token.startswith("dev_") and norm.ip_token.startswith("ip_")
    assert norm.metadata["bank_name"] == "SBI"
    assert norm.metadata["custom_field"] == {"nested": 1}  # extra metadata is preserved
    assert "email" not in norm.metadata
    # an account-number beneficiary shares the account token space (graph linkage)
    assert norm.metadata["beneficiary_token"] == tokenize("account", "HDFC-DEMO-7781")
    assert labels["account"] == "SBI-DEMO-1042" and labels["customer"].startswith("usr_")
    assert norm.timestamp.tzinfo is not None


def test_normalization_accepts_pre_tokenized_ids():
    tok = tokenize("customer", "CUSTOMER_2")
    norm, _, _ = normalize(EventIn(event_type="login", customer_token=tok))
    assert norm.customer_token == tok


@pytest.mark.parametrize("payload", [
    {"event_type": "wire_fraud", "customer_id": "C1"},
    {"event_type": "transaction", "customer_id": "C1", "amount": 0},
    {"event_type": "login"},
    {"event_type": "login", "customer_id": "C1", "bank_name": "Real Bank Ltd"},
    {"event_type": "login", "customer_id": "C1", "event_id": "bad id with spaces"},
])
def test_invalid_events_rejected(payload):
    with pytest.raises(ValidationError):
        EventIn.model_validate(payload)
