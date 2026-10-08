"""Customer identity-verification workflow.

Stages: account → password → otp → mfa → device → biometric → kyc → deepfake → decision.
Every stage records its own evidence and confidence, and emits the corresponding
FraudMesh event (LOGIN / MFA / DEVICE / BIOMETRIC / KYC), so a verification attempt
is scored and correlated like any other activity — a deepfake selfie here can join
an account-takeover case already in progress.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.core.crypto import decrypt, decrypt_str, encrypt, encrypt_str, hmac_hex
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import Customer, KycRecord, VerificationSession
from fraudmesh.schemas.events import EventIn
from fraudmesh.services.auth import security as sec
from fraudmesh.services.auth import service as auth
from fraudmesh.services.events import pipeline
from fraudmesh.services.identity import media as media_svc
from fraudmesh.services.kyc import pipeline as kyc_pipeline

STAGES = ["account", "password", "otp", "mfa", "device", "biometric", "kyc", "deepfake", "decision"]


class VerificationError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set(vs: VerificationSession, stage: str, status: str, score: float | None, **details) -> None:
    stages = dict(vs.stages or {})
    stages[stage] = {"status": status, "at": _now(), "confidence": score, **details}
    vs.stages = stages
    order = [s for s in STAGES if stages.get(s, {}).get("status") not in ("PASSED", "FAILED", "WARN")]
    vs.current_stage = order[0] if order else "decision"
    vs.updated_at = datetime.now(timezone.utc)


def _require(vs: VerificationSession, stage: str) -> None:
    if vs.status != "IN_PROGRESS":
        raise VerificationError("verification already finalised", 409)
    if stage != "password" and (vs.stages or {}).get("password", {}).get("status") != "PASSED":
        raise VerificationError("password stage must pass first", 409)


async def _emit(db: AsyncSession, vs: VerificationSession, event_type: str, payload: dict, ip: str | None, extra: dict | None = None) -> dict:
    dev = (vs.stages or {}).get("device", {}).get("device")
    if dev is None and vs.device_id:
        dev = {"id": vs.device_id}
    ev = EventIn(event_type=event_type, customer_id=vs.customer_id, source="identity-verification", session_id=vs.id, ip=ip,
                 device=dev, payload=payload)
    res = await pipeline.process(db, ev, extra=extra)
    events = list((vs.scores or {}).get("events", []))
    events.append({"event_id": res["event_id"], "event_type": event_type, "risk_score": res["risk_score"], "case_id": res["case_id"], "action": res["action"]})
    vs.scores = {**(vs.scores or {}), "events": events}
    return res


async def start(db: AsyncSession, customer_id: str, ip: str | None) -> VerificationSession:
    c = await db.get(Customer, customer_id)
    if c is None:
        raise VerificationError("customer not found", 404)
    vs = VerificationSession(id=new_id("ver"), customer_id=customer_id, current_stage="password", stages={}, scores={}, ip=ip)
    _set(vs, "account", "PASSED", 1.0, customer=c.display_name, kyc_status=c.kyc_status, phone=c.phone_masked, email=c.email_masked)
    db.add(vs)
    await db.commit()
    return vs


async def password(db: AsyncSession, vs: VerificationSession, pw: str, ip: str | None) -> dict:
    _require(vs, "password")
    c = await db.get(Customer, vs.customer_id)
    ok = sec.verify_secret(c.password_hash if c else None, pw)
    fails = int((vs.stages or {}).get("password", {}).get("failures", 0)) + (0 if ok else 1)
    res = await _emit(db, vs, "LOGIN", {"success": ok, "method": "password", "failure_reason": None if ok else "bad_password"}, ip)
    _set(vs, "password", "PASSED" if ok else "FAILED", 1.0 if ok else 0.0, failures=fails, event_risk=res["risk_score"])
    await db.commit()
    return {"ok": ok, "risk": res["risk_score"], "case_id": res["case_id"]}


async def otp_send(db: AsyncSession, vs: VerificationSession) -> dict:
    _require(vs, "otp")
    c = await db.get(Customer, vs.customer_id)
    cid, code = await auth.create_otp(db, vs.customer_id, "verification", "sms", c.phone_masked)
    await auth.deliver_dev_outbox(vs.customer_id, "sms", c.phone_masked, code)
    _set(vs, "otp", "PENDING", None, challenge_id=cid, destination=c.phone_masked)
    await db.commit()
    return {"challenge_id": cid, "destination": c.phone_masked, "expires_in_s": 300}


async def otp_verify(db: AsyncSession, vs: VerificationSession, code: str) -> dict:
    _require(vs, "otp")
    ch = (vs.stages or {}).get("otp", {}).get("challenge_id")
    if not ch:
        raise VerificationError("no OTP sent")
    ok = await auth.verify_otp(db, ch, vs.customer_id, code)
    _set(vs, "otp", "PASSED" if ok else "FAILED", 1.0 if ok else 0.0, challenge_id=ch, destination=(vs.stages or {}).get("otp", {}).get("destination"))
    await db.commit()
    return {"ok": ok}


async def mfa_enroll(db: AsyncSession, vs: VerificationSession) -> dict:
    _require(vs, "mfa")
    c = await db.get(Customer, vs.customer_id)
    secret = sec.new_totp_secret()
    stages = dict(vs.stages or {})
    stages["mfa"] = {**stages.get("mfa", {}), "status": "PENDING", "pending_enc": base64.b64encode(encrypt_str(secret)).decode()}
    vs.stages = stages
    await db.commit()
    return {"otpauth_uri": sec.totp_uri(secret, f"{c.display_name} (customer)"), "enrolled": False}


async def mfa_verify(db: AsyncSession, vs: VerificationSession, code: str, ip: str | None) -> dict:
    _require(vs, "mfa")
    c = await db.get(Customer, vs.customer_id)
    pending = (vs.stages or {}).get("mfa", {}).get("pending_enc")
    secret = decrypt_str(base64.b64decode(pending)) if pending else (decrypt_str(c.totp_secret_enc) if c.totp_secret_enc else None)
    if not secret:
        raise VerificationError("no TOTP factor enrolled — call /mfa/enroll first")
    ok = sec.verify_totp(secret, code, None) is not None
    if ok and pending:
        c.totp_secret_enc = encrypt_str(secret)
        await _emit(db, vs, "MFA", {"action": "enrolled", "factor": "totp"}, ip)
    elif ok:
        await _emit(db, vs, "MFA", {"action": "success", "factor": "totp"}, ip)
    else:
        await _emit(db, vs, "MFA", {"action": "failure", "factor": "totp"}, ip)
    _set(vs, "mfa", "PASSED" if ok else "FAILED", 1.0 if ok else 0.0, enrolled_now=bool(ok and pending))
    await db.commit()
    return {"ok": ok}


async def device(db: AsyncSession, vs: VerificationSession, fingerprint: str, label: str, attrs: dict, ip: str | None) -> dict:
    _require(vs, "device")
    dev_id = f"vfp-{hmac_hex('device:' + fingerprint)[:16]}"
    vs.device_id = dev_id
    device_info = {"id": dev_id, "model": label[:80], "os": attrs.get("os"), "browser": attrs.get("browser"), "timezone": attrs.get("timezone"),
                   "emulator": bool(attrs.get("webdriver"))}
    stages = dict(vs.stages or {})
    stages["device"] = {**stages.get("device", {}), "device": device_info}
    vs.stages = stages
    res = await _emit(db, vs, "DEVICE", {"action": "attested"}, ip)
    known = not (res.get("detectors") and any(r["code"] == "DEV_NEW" for d in res["detectors"] for r in d["reason_codes"]))
    dev_risk = max((d["risk_score"] for d in res["detectors"] if d["domain"] == "device"), default=0.0)
    _set(vs, "device", "PASSED" if dev_risk < 40 else "WARN", round(1 - dev_risk / 100, 3), device=device_info, known=known,
         risk=dev_risk, reasons=[r["message"] for d in res["detectors"] for r in d["reason_codes"]][:5])
    await db.commit()
    return {"known": known, "risk": dev_risk}


async def biometric(db: AsyncSession, vs: VerificationSession, data: bytes, challenge: str | None, ip: str | None) -> dict:
    _require(vs, "biometric")
    out = await media_svc.analyze_media(db, data, customer_id=vs.customer_id, challenge=challenge)
    r = out["result"]
    emb = out.get("embedding")
    enrolled = await media_svc.enrolled_template(db, vs.customer_id) is not None
    live = r.get("liveness", {}).get("status")
    if emb is not None and not enrolled and r["verdict"] == "REAL_PERSON" and live != "FAILED":
        await media_svc.store_template(db, vs.customer_id, emb, "enrollment")  # first genuine capture becomes the template
    stages = dict(vs.stages or {})
    if emb is not None:
        stages["biometric"] = {**stages.get("biometric", {}), "embedding_enc": base64.b64encode(encrypt(np.asarray(emb, np.float32).tobytes())).decode()}
        vs.stages = stages
    match = r.get("identity_match", {})
    res = await _emit(db, vs, "BIOMETRIC", {"media_analysis_id": out["analysis_id"], "liveness": live, "face_match": match.get("similarity")}, ip,
                      extra={"deepfake": {**r, "analysis_id": out["analysis_id"]}})
    ok = r["verdict"] == "REAL_PERSON" and live != "FAILED" and match.get("matched", True)
    conf = (match.get("similarity") if match.get("available") else (r.get("real_probability") or 0)) or 0
    _set(vs, "biometric", "PASSED" if ok else "FAILED", round(float(conf), 3), analysis_id=out["analysis_id"], verdict=r["verdict"],
         liveness=live, face_match=match, deepfake_probability=r.get("deepfake_probability"), enrolled_now=bool(emb is not None and not enrolled and ok),
         event_risk=res["risk_score"], embedding_enc=(vs.stages or {}).get("biometric", {}).get("embedding_enc"))
    await db.commit()
    return {"analysis": r, "event": {"event_id": res["event_id"], "case_id": res["case_id"], "action": res["action"]}}


async def kyc(db: AsyncSession, vs: VerificationSession, document: bytes, ip: str | None) -> dict:
    _require(vs, "kyc")
    ref = None
    enc = (vs.stages or {}).get("biometric", {}).get("embedding_enc")
    if enc:
        ref = np.frombuffer(decrypt(base64.b64decode(enc)), dtype=np.float32)
    # the session's own (encrypted) selfie embedding is the face-match reference
    result = await asyncio.to_thread(kyc_pipeline.verify, document, None, ref, None, vs.customer_id)
    owner = None
    if result.get("doc_number_hmac"):
        owner = await db.scalar(select(KycRecord.customer_id).where(KycRecord.doc_number_hmac == result["doc_number_hmac"],
                                                                    KycRecord.customer_id != vs.customer_id).limit(1))
    result = kyc_pipeline.apply_reuse_check(result, owner, vs.customer_id)
    rec = KycRecord(id=new_id("kyc"), customer_id=vs.customer_id, doc_type=result["document_type"], doc_number_hmac=result.get("doc_number_hmac"),
                    fields_masked=result["fields"], checks=result["checks"], scores=result["scores"], decision=result["decision"])
    db.add(rec)
    await db.flush()
    result.pop("document_embedding", None)
    result["kyc_record_id"] = rec.id
    res = await _emit(db, vs, "KYC", {"kyc_record_id": rec.id}, ip, extra={"kyc": result, "doc_hmac": result.get("doc_number_hmac")})
    s = result["scores"]
    _set(vs, "kyc", {"APPROVE": "PASSED", "REVIEW": "WARN"}.get(result["decision"], "FAILED"), round(s["document_confidence"] * (1 - s["kyc_risk"] / 100), 3),
         kyc_record_id=rec.id, decision=result["decision"], scores=s, face_match=result.get("face_match"),
         failed_checks=[c for c in result["checks"] if c["status"] == "FAIL"], event_risk=res["risk_score"])
    await db.commit()
    return {"kyc": result, "event": {"event_id": res["event_id"], "case_id": res["case_id"], "action": res["action"]}}


def _noisy_or(xs: list[float]) -> float:
    p = 1.0
    for x in xs:
        p *= 1 - max(0.0, min(1.0, x))
    return 1 - p


async def decide(db: AsyncSession, vs: VerificationSession) -> dict:
    _require(vs, "decision")
    st = vs.stages or {}

    def conf(stage: str, default: float | None = None) -> float | None:
        s = st.get(stage, {})
        if s.get("status") in ("PASSED", "FAILED", "WARN"):
            return float(s.get("confidence") or 0.0)
        return default

    bio = st.get("biometric", {})
    kyc_s = st.get("kyc", {})
    deepfake_p = bio.get("deepfake_probability")
    kyc_df = (kyc_s.get("scores") or {}).get("deepfake_risk")
    deepfake_conf = None
    if deepfake_p is not None or kyc_df is not None:
        deepfake_conf = 1 - max(deepfake_p or 0.0, (kyc_df or 0.0) / 100)
    _set(vs, "deepfake", "PASSED" if (deepfake_conf or 1) >= 0.6 else "FAILED", deepfake_conf,
         sources={"selfie_deepfake_probability": deepfake_p, "kyc_deepfake_risk": kyc_df})
    confidences = {
        "identity": conf("password", 0.0) * (0.6 + 0.4 * (conf("otp") if conf("otp") is not None else 0.5)),
        "device": conf("device"),
        "mfa": conf("mfa"),
        "biometric": conf("biometric"),
        "deepfake": deepfake_conf,
        "kyc": conf("kyc"),
    }
    risks = [1 - v for v in confidences.values() if v is not None]
    missing = [k for k, v in confidences.items() if v is None]
    overall = 100 * _noisy_or([r * 0.9 for r in risks])
    case_ids = sorted({e["case_id"] for e in (vs.scores or {}).get("events", []) if e.get("case_id")})
    if (deepfake_conf is not None and deepfake_conf < 0.3) or overall >= 85:
        decision = "REJECT"
    elif overall >= 60 or missing:
        decision = "HOLD_FOR_REVIEW" if overall >= 60 else "STEP_UP"
    else:
        decision = "APPROVE"
    vs.decision = {"decision": decision, "overall_identity_risk": round(overall, 1), "confidences": {k: (round(v, 3) if v is not None else None) for k, v in confidences.items()},
                   "missing_stages": missing, "case_ids": case_ids, "decided_at": _now()}
    vs.status = "COMPLETED"
    _set(vs, "decision", "PASSED" if decision == "APPROVE" else "FAILED", round(1 - overall / 100, 3), decision=decision)
    await db.commit()
    return vs.decision
