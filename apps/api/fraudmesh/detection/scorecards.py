"""Expert scorecards for signals that are deterministic facts rather than patterns
to learn (device integrity flags, MFA resets, KYC outcomes, sensitive cloud APIs).

They are labelled as scorecards everywhere in the UI — not presented as ML.
Each returns a ``DetectorResult`` with explicit, auditable reason codes.
"""

from __future__ import annotations

import time

import numpy as np

from fraudmesh.detection.base import DetectorResult, Reason


def _noisy_or(weights: list[float]) -> float:
    return 1 - float(np.prod([1 - w for w in weights])) if weights else 0.0


def device(ctx: dict) -> DetectorResult:
    t = time.perf_counter()
    d = ctx.get("device") or {}
    reasons: list[Reason] = []
    if ctx.get("is_new_device"):
        reasons.append(Reason("DEV_NEW", "First time this device is seen for the customer", 0.35))
    elif ctx.get("device_age_days", 999) < 1:
        reasons.append(Reason("DEV_RECENT", "Device first seen less than a day ago", 0.2))
    if d.get("emulator"):
        reasons.append(Reason("DEV_EMULATOR", "Emulator detected by device attestation", 0.6))
    if d.get("rooted"):
        reasons.append(Reason("DEV_ROOTED", "Rooted / jail-broken device", 0.35))
    if d.get("remote_access_tool"):
        reasons.append(Reason("DEV_RAT", "Remote-access tool active during session", 0.65))
    shared = ctx.get("device_shared_customers", 0)
    if shared:
        reasons.append(Reason("DEV_SHARED", f"Device also used by {shared} other customer(s)", min(0.8, 0.3 + 0.15 * shared)))
    churn = ctx.get("devices_24h", 0)
    if churn >= 3:
        reasons.append(Reason("DEV_CHURN", f"{churn} different devices in 24h", 0.4))
    risk = _noisy_or([r.weight for r in reasons])
    return DetectorResult("device-intel", "device", round(100 * risk, 2), 0.85 if d else 0.4, reasons, "device-scorecard-v1",
                          (time.perf_counter() - t) * 1000, {"device_known": not ctx.get("is_new_device")})


def identity(event_type: str, payload: dict, ctx: dict) -> DetectorResult | None:
    t = time.perf_counter()
    reasons: list[Reason] = []
    conf = 0.8
    if event_type == "LOGIN":
        fails = ctx.get("failed_logins_24h", 0)
        if not payload.get("success"):
            reasons.append(Reason("ID_LOGIN_FAILED", "Failed login attempt", 0.15))
        if fails >= 5:
            reasons.append(Reason("ID_MANY_FAILURES", f"{fails} failed logins in 24h", min(0.7, 0.2 + 0.05 * fails)))
        if payload.get("success") and fails >= 3:
            reasons.append(Reason("ID_SUCCESS_AFTER_FAILURES", "Successful login after repeated failures (possible credential stuffing hit)", 0.55))
        if ctx.get("is_new_device") and ctx.get("ip_new"):
            reasons.append(Reason("ID_NEW_DEVICE_AND_IP", "New device from a network never used by this customer", 0.45))
    elif event_type == "MFA":
        action = payload.get("action")
        if action in ("reset", "disabled", "factor_changed"):
            w = 0.45
            if ctx.get("mins_since_new_device_login") is not None and ctx["mins_since_new_device_login"] <= 30:
                w = 0.8
                reasons.append(Reason("ID_MFA_RESET_AFTER_NEW_DEVICE", f"MFA {action} {ctx['mins_since_new_device_login']:.0f} min after a new-device login", w))
            else:
                reasons.append(Reason("ID_MFA_CHANGE", f"MFA {action}", w))
        if action == "failure":
            reasons.append(Reason("ID_MFA_FAILURE", "MFA challenge failed", 0.25))
        if payload.get("channel_changed_to"):
            reasons.append(Reason("ID_MFA_CHANNEL", f"OTP channel moved to {payload['channel_changed_to']}", 0.4))
    elif event_type == "KYC":
        kr = payload.get("kyc_risk")
        if kr is not None:
            if kr >= 40:
                reasons.append(Reason("ID_KYC_RISK", f"KYC verification risk {kr:.0f}/100", kr / 100))
            for c in ctx.get("kyc_failed_checks", [])[:4]:
                reasons.append(Reason(f"KYC_{c['id'].upper()}", f"{c['name']}: {c['detail']}", 0.0))
        else:
            conf = 0.3
    elif event_type in ("BIOMETRIC", "DEEPFAKE"):
        if payload.get("liveness") == "FAILED":
            reasons.append(Reason("ID_LIVENESS_FAILED", "Liveness check failed", 0.7))
        fm = payload.get("face_match")
        if fm is not None and fm < 0.363:
            reasons.append(Reason("ID_FACE_MISMATCH", f"Face does not match enrolled template (similarity {fm:.2f})", 0.75))
    elif event_type == "BENEFICIARY":
        if ctx.get("mins_since_mfa_change") is not None and ctx["mins_since_mfa_change"] <= 60:
            reasons.append(Reason("ID_BENEF_AFTER_MFA", f"Beneficiary added {ctx['mins_since_mfa_change']:.0f} min after an MFA change", 0.55))
        if ctx.get("mins_since_new_device_login") is not None and ctx["mins_since_new_device_login"] <= 60:
            reasons.append(Reason("ID_BENEF_NEW_DEVICE", "Beneficiary added from a newly seen device", 0.35))
    else:
        return None
    if event_type == "KYC" and payload.get("kyc_risk") is not None:
        risk = max(payload["kyc_risk"] / 100, _noisy_or([r.weight for r in reasons if r.weight]))
    else:
        risk = _noisy_or([r.weight for r in reasons])
    return DetectorResult("identity-risk", "identity", round(100 * risk, 2), conf, reasons, "identity-scorecard-v1", (time.perf_counter() - t) * 1000)


SENSITIVE_CLOUD = {
    "iam:CreateAccessKey": 0.55, "iam:AttachUserPolicy": 0.6, "iam:PutUserPolicy": 0.6, "iam:CreateUser": 0.45,
    "sts:AssumeRole": 0.2, "secretsmanager:GetSecretValue": 0.5, "kms:Decrypt": 0.35, "s3:GetObject": 0.15,
    "s3:PutBucketPolicy": 0.6, "cloudtrail:StopLogging": 0.85, "ec2:ModifyInstanceAttribute": 0.3,
}


def cloud(payload: dict, ctx: dict) -> DetectorResult:
    t = time.perf_counter()
    reasons: list[Reason] = []
    act = payload.get("action", "")
    w = SENSITIVE_CLOUD.get(act)
    if w:
        reasons.append(Reason("CLOUD_SENSITIVE_API", f"Sensitive API call {act}", w))
    res = (payload.get("resource") or "").lower()
    if any(k in res for k in ("kyc", "customer", "export", "pii", "card", "otp")) and act.split(":")[-1].startswith(("Get", "List", "Copy", "Select")):
        reasons.append(Reason("CLOUD_SENSITIVE_DATA", f"Read of sensitive customer data ({payload.get('resource', '')[-60:]})", 0.45))
    if not payload.get("mfa_used", True):
        reasons.append(Reason("CLOUD_NO_MFA", "Console/API session without MFA", 0.35))
    if ctx.get("ip_risk", 0) >= 0.5:
        reasons.append(Reason("CLOUD_RISKY_IP", f"Call from {ctx.get('ip_category', 'risky')} network", ctx["ip_risk"] * 0.8))
    if ctx.get("principal_new_ip"):
        reasons.append(Reason("CLOUD_NEW_IP", "Principal never seen from this IP", 0.3))
    if payload.get("result") == "denied":
        reasons.append(Reason("CLOUD_DENIED", "Access denied (probing permissions)", 0.25))
    risk = _noisy_or([r.weight for r in reasons])
    return DetectorResult("cloud-security", "network", round(100 * risk, 2), 0.75, reasons, "cloud-scorecard-v1", (time.perf_counter() - t) * 1000)


def ip_reputation(ip: str, ctx: dict) -> DetectorResult:
    """Threat-intel reputation of the client IP for application events (login, MFA, payments)."""
    t = time.perf_counter()
    risk = float(ctx.get("ip_risk", 0.0))
    reasons = [Reason("NET_IP_REPUTATION", f"Client IP {ip} is listed as {ctx.get('ip_category', 'risky').replace('_', ' ')} (threat intel)", risk)]
    return DetectorResult("ip-reputation", "network", round(100 * risk, 2), 0.7, reasons, "threat-intel-v1", (time.perf_counter() - t) * 1000)
