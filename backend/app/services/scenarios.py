"""Synthetic scenario generators.

SIMULATED DATA — NO REAL BANK INCIDENT. "SBI", "HDFC Bank" and "ICICI Bank"
appear only as fictional demo entities; every identifier is synthetic.

Each generator returns a list of steps ``{"offset": seconds, "title": str,
"narrative": str, "event": dict}`` where ``event`` is an ``EventIn`` payload
without a timestamp (the runner stamps ``base_time + offset``). Identifiers
may be raw synthetic ids (tokenized on ingestion) or existing tokens.

This module only depends on the standard library so scripts can import it.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

SIMULATION_BANNER = "SIMULATED DATA — NO REAL BANK INCIDENT"

# ---- flagship coordinated cross-channel attack (fixed synthetic identifiers) ----
DEMO = {
    "victim_customer": "CUSTOMER_10291",
    "victim_account": "SBI-DEMO-1042",
    "victim_bank": "SBI",
    "victim_device": "DEVICE-A1C3",
    "victim_ip": "100.72.14.21",
    "victim_city": "Mumbai",
    "attacker_device": "DEVICE-7F21",
    "attacker_ip": "100.99.203.7",
    "attacker_city": "Kolkata",
    "mule_hdfc_customer": "CUSTOMER_20777",
    "mule_hdfc_account": "HDFC-DEMO-7781",
    "mule_hdfc_device": "DEVICE-B7D0",
    "mule_hdfc_ip": "100.81.5.77",
    "mule_hdfc_city": "Pune",
    "mule_icici_customer": "CUSTOMER_30552",
    "mule_icici_account": "ICICI-DEMO-5520",
    "mule_icici_device": "DEVICE-C55E",
    "mule_icici_ip": "100.88.61.9",
    "mule_icici_city": "Hyderabad",
    "cloud_principal": "svc-payments-gateway",
    "cloud_resource": "iam-role/payments-admin",
    "baseline_low": 25_000,
    "baseline_high": 40_000,
    "amount": 185_000,
}

SCENARIOS = (
    "normal",
    "unusual_transaction",
    "account_takeover",
    "synthetic_identity",
    "kyc_manipulation",
    "coordinated_cross_channel_fraud",
)

SCENARIO_INFO = {
    "normal": "Ordinary customer activity — should NOT create a case.",
    "unusual_transaction": "Rapid high-value transfers to new beneficiaries from a known device.",
    "account_takeover": "New device + new IP + impossible travel + MFA reset + password change + transfer.",
    "synthetic_identity": "Several new identities onboarded from one device with weak KYC, paying one beneficiary.",
    "kyc_manipulation": "Re-verification with a manipulated selfie from a new device.",
    "coordinated_cross_channel_fraud": "Flagship demo: takeover → KYC anomaly → ₹1,85,000 transfer → device reuse "
                                        "across SBI/HDFC/ICICI → privileged cloud activity.",
}


@dataclass
class Party:
    customer: str
    account: str
    bank: str
    device: str
    ip: str
    city: str
    baseline: float = 30_000.0


@dataclass
class ScenarioContext:
    victim: Party
    mules: list[Party] = field(default_factory=list)
    attacker_device: str = "DEVICE-E0F1"
    attacker_ip: str = "100.99.1.1"
    attacker_city: str = "Kolkata"
    cloud_principal: str = "svc-payments-gateway"
    cloud_resource: str = "iam-role/payments-admin"
    rng: random.Random = field(default_factory=lambda: random.Random(7))
    tag: str = "live"


def _ev(event_type: str, p: Party | None = None, **kw: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {"event_type": event_type, "channel": kw.pop("channel", "mobile"), "metadata": {}}
    if p is not None:
        ev.update(customer_id=p.customer, account_id=p.account, device_id=p.device, ip_address=p.ip,
                  bank_name=p.bank)
        ev["metadata"]["city"] = p.city
    for key in ("customer_id", "account_id", "device_id", "ip_address", "bank_name", "amount"):
        if key in kw:
            ev[key] = kw.pop(key)
    ev["metadata"].update(kw)
    return ev


def _step(offset: float, title: str, narrative: str, event: dict[str, Any]) -> dict[str, Any]:
    return {"offset": offset, "title": title, "narrative": narrative, "event": event}


# ------------------------------------------------------------------ scenarios
def normal(ctx: ScenarioContext) -> list[dict[str, Any]]:
    v, r = ctx.victim, ctx.rng
    amt = round(v.baseline * r.uniform(0.7, 1.2), -1)
    return [
        _step(0, "NORMAL LOGIN", "Customer logs in from their usual device and network.",
              _ev("login", v, subtype="NORMAL_LOGIN")),
        _step(120, "TRANSACTION", "Routine payment to a regular merchant.",
              _ev("transaction", v, amount=amt, merchant="SYN-GROCERY-01", subtype="PAYMENT")),
    ]


def unusual_transaction(ctx: ScenarioContext) -> list[dict[str, Any]]:
    v, r = ctx.victim, ctx.rng
    steps = [_step(0, "LOGIN", "Login from the customer's usual device.", _ev("login", v, subtype="NORMAL_LOGIN"))]
    for i in range(3):
        amt = round(v.baseline * r.uniform(4.0, 6.0), -2)
        steps.append(_step(60 + i * 90, "HIGH-VALUE TRANSFER",
                           f"Transfer #{i + 1} to a never-seen beneficiary.",
                           _ev("transaction", v, amount=amt, beneficiary_id=f"SYN-BEN-{r.randint(10000, 99999)}",
                               subtype="HIGH_VALUE_TRANSFER")))
    return steps


def account_takeover(ctx: ScenarioContext) -> list[dict[str, Any]]:
    v, r = ctx.victim, ctx.rng
    atk = Party(v.customer, v.account, v.bank, ctx.attacker_device, ctx.attacker_ip, ctx.attacker_city)
    return [
        _step(0, "NEW DEVICE LOGIN", "Login from an unknown device.",
              _ev("login", Party(v.customer, v.account, v.bank, ctx.attacker_device, v.ip, v.city),
                  subtype="NEW_DEVICE_LOGIN", failed_attempts=3)),
        _step(60, "NEW IP / NETWORK", "Same device, new network far from home.",
              _ev("login", atk, subtype="NEW_IP_LOGIN")),
        _step(150, "MFA RESET", "MFA factor reset and password change.",
              _ev("mfa_reset", atk, subtype="MFA_RESET", password_changed=True, method="sms_new_number")),
        _step(300, "TRANSFER", "Transfer ~3× baseline to a new beneficiary.",
              _ev("transaction", atk, amount=round(v.baseline * r.uniform(2.8, 3.5), -2),
                  beneficiary_id=f"SYN-BEN-{r.randint(10000, 99999)}", subtype="TRANSFER")),
    ]


def synthetic_identity(ctx: ScenarioContext) -> list[dict[str, Any]]:
    r = ctx.rng
    banks = ["SBI", "HDFC Bank", "ICICI Bank"]
    prefix = {"SBI": "SBI", "HDFC Bank": "HDFC", "ICICI Bank": "ICICI"}
    ben = f"SYN-BEN-{r.randint(10000, 99999)}"
    steps = []
    for i, bank in enumerate(banks):
        ident = Party(f"CUSTOMER_9{r.randint(1000, 9999)}", f"{prefix[bank]}-SYN-{r.randint(50000, 59999)}", bank,
                      ctx.attacker_device, ctx.attacker_ip, ctx.attacker_city, baseline=5_000)
        t0 = i * 180
        steps += [
            _step(t0, "NEW IDENTITY KYC", f"Onboarding KYC for a new identity at {bank}.",
                  _ev("kyc_verification", ident, subtype="ONBOARDING_KYC", liveness_score=round(r.uniform(0.3, 0.45), 2),
                      face_match_score=round(r.uniform(0.5, 0.6), 2))),
            _step(t0 + 40, "FIRST LOGIN", "First login — same device as other new identities.",
                  _ev("login", ident, subtype="FIRST_LOGIN")),
            _step(t0 + 100, "TRANSFER", "Transfer to a shared beneficiary.",
                  _ev("transaction", ident, amount=round(r.uniform(40_000, 60_000), -2), beneficiary_id=ben,
                      subtype="TRANSFER")),
        ]
    return steps


def kyc_manipulation(ctx: ScenarioContext) -> list[dict[str, Any]]:
    v = ctx.victim
    atk = Party(v.customer, v.account, v.bank, ctx.attacker_device, v.ip, v.city)
    return [
        _step(0, "DEVICE CHANGE", "Customer registers a new device.",
              _ev("device_change", atk, subtype="DEVICE_REGISTRATION", previous_device_id=v.device)),
        _step(90, "KYC RE-VERIFICATION", "Selfie re-verification — prototype detector flags manipulation.",
              _ev("kyc_verification", atk, subtype="KYC_REVERIFICATION", demo_manipulation_score=0.86,
                  liveness_score=0.31, face_match_score=0.48)),
        _step(200, "LOGIN", "Login from the newly registered device.", _ev("login", atk, subtype="NEW_DEVICE_LOGIN")),
    ]


def coordinated_cross_channel_fraud(ctx: ScenarioContext) -> list[dict[str, Any]]:
    v = ctx.victim
    atk_home = Party(v.customer, v.account, v.bank, ctx.attacker_device, v.ip, v.city)
    atk = Party(v.customer, v.account, v.bank, ctx.attacker_device, ctx.attacker_ip, ctx.attacker_city)
    mule1, mule2 = ctx.mules[0], ctx.mules[1]
    amount = DEMO["amount"] if ctx.tag == "demo" else round(v.baseline * 6, -3)
    return [
        _step(0, "NORMAL LOGIN", f"{v.bank} customer logs in normally from their usual device.",
              _ev("login", v, subtype="NORMAL_LOGIN")),
        _step(60, "NEW DEVICE LOGIN", f"Login from unknown device {ctx.attacker_device}.",
              _ev("login", atk_home, subtype="NEW_DEVICE_LOGIN")),
        _step(120, "NEW IP / NETWORK", f"Same session moves to a new network ({ctx.attacker_city}).",
              _ev("login", atk, subtype="NEW_IP_LOGIN")),
        _step(180, "MFA RESET", "MFA reset to a new phone number + password change.",
              _ev("mfa_reset", atk, subtype="MFA_RESET", password_changed=True, method="sms_new_number")),
        _step(300, "KYC VERIFICATION", "Re-verification selfie — Prototype KYC detector returns manipulation 0.91.",
              _ev("kyc_verification", atk, subtype="KYC_REVERIFICATION", demo_manipulation_score=0.91,
                  liveness_score=0.34, face_match_score=0.52)),
        _step(420, "HIGH-VALUE TRANSACTION", f"₹{amount:,.0f} to a NEW beneficiary ({mule1.account}).",
              _ev("transaction", atk, amount=amount, beneficiary_account=mule1.account,
                  subtype="HIGH_VALUE_TRANSFER", purpose="unspecified")),
        _step(480, "DEVICE REUSE", f"{ctx.attacker_device} now logs into {mule1.account} ({mule1.bank}).",
              _ev("login", Party(mule1.customer, mule1.account, mule1.bank, ctx.attacker_device, ctx.attacker_ip,
                                 ctx.attacker_city), subtype="DEVICE_REUSE")),
        _step(540, "CROSS-BANK LINK", f"Same device/IP appears on {mule2.account} ({mule2.bank}).",
              _ev("login", Party(mule2.customer, mule2.account, mule2.bank, ctx.attacker_device, ctx.attacker_ip,
                                 ctx.attacker_city), subtype="CROSS_BANK_LINK")),
        _step(600, "CLOUD SECURITY ANOMALY", "PRIVILEGED_API_CALL from the attacker network in an unusual region.",
              _ev("cloud_event", None, channel="cloud", ip_address=ctx.attacker_ip, action="PRIVILEGED_API_CALL",
                  api="payments:UpdateLimits", principal=ctx.cloud_principal, resource=ctx.cloud_resource,
                  region="eu-central-1", privileged=True, new_access_key=True, subtype="PRIVILEGED_API_CALL",
                  mfa_used=False)),
    ]


GENERATORS = {
    "normal": normal,
    "unusual_transaction": unusual_transaction,
    "account_takeover": account_takeover,
    "synthetic_identity": synthetic_identity,
    "kyc_manipulation": kyc_manipulation,
    "coordinated_cross_channel_fraud": coordinated_cross_channel_fraud,
}


def demo_context() -> ScenarioContext:
    d = DEMO
    return ScenarioContext(
        victim=Party(d["victim_customer"], d["victim_account"], d["victim_bank"], d["victim_device"], d["victim_ip"],
                     d["victim_city"], baseline=(d["baseline_low"] + d["baseline_high"]) / 2),
        mules=[
            Party(d["mule_hdfc_customer"], d["mule_hdfc_account"], "HDFC Bank", d["mule_hdfc_device"],
                  d["mule_hdfc_ip"], d["mule_hdfc_city"]),
            Party(d["mule_icici_customer"], d["mule_icici_account"], "ICICI Bank", d["mule_icici_device"],
                  d["mule_icici_ip"], d["mule_icici_city"]),
        ],
        attacker_device=d["attacker_device"], attacker_ip=d["attacker_ip"], attacker_city=d["attacker_city"],
        cloud_principal=d["cloud_principal"], cloud_resource=d["cloud_resource"], tag="demo",
    )


def flagship_attack() -> list[dict[str, Any]]:
    """The scripted demo used by scripts/simulate_attack.py and the dashboard button."""
    return coordinated_cross_channel_fraud(demo_context())
