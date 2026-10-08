"""Customer identity-verification workflow endpoints."""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.config import get_settings
from fraudmesh.core import ratelimit
from fraudmesh.core.ratelimit import client_ip
from fraudmesh.core.redis import redis
from fraudmesh.db.models import Customer, VerificationSession
from fraudmesh.db.session import get_db
from fraudmesh.services.deepfake.media import MediaError
from fraudmesh.services.identity import verification as ver
from fraudmesh.services.simulator.population import DEMO_PASSWORD, DEMO_VICTIM_ID

router = APIRouter(prefix="/identity", tags=["identity verification"])
_ID = r"^[A-Za-z0-9_.:\-]{1,64}$"


def _view(vs: VerificationSession) -> dict:
    stages = {k: {kk: vv for kk, vv in v.items() if kk not in ("pending_enc", "embedding_enc")} for k, v in (vs.stages or {}).items()}
    return {"id": vs.id, "customer_id": vs.customer_id, "status": vs.status, "current_stage": vs.current_stage, "stages": stages,
            "events": (vs.scores or {}).get("events", []), "decision": vs.decision, "created_at": vs.created_at, "updated_at": vs.updated_at,
            "stage_order": ver.STAGES}


async def _get(db: AsyncSession, sid: str) -> VerificationSession:
    vs = await db.get(VerificationSession, sid)
    if vs is None:
        raise HTTPException(404, "verification session not found")
    return vs


def _err(e: ver.VerificationError) -> HTTPException:
    return HTTPException(e.status, str(e))


@router.get("/customers")
async def customers(q: str | None = None, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    stmt = select(Customer).where(Customer.password_hash.is_not(None))
    if q:
        stmt = select(Customer).where(Customer.display_name.ilike(f"%{q[:40]}%"))
    rows = (await db.execute(stmt.limit(20))).scalars().all()
    demo = {"customer_id": DEMO_VICTIM_ID, "password": DEMO_PASSWORD} if get_settings().demo_mode else None
    return {"customers": [{"id": c.id, "name": c.display_name, "phone": c.phone_masked, "email": c.email_masked, "kyc_status": c.kyc_status,
                           "has_password": c.password_hash is not None, "has_totp": c.totp_secret_enc is not None} for c in rows],
            "demo_credentials": demo}


class StartRequest(BaseModel):
    customer_id: str = Field(pattern=_ID)


@router.post("/sessions")
async def start(body: StartRequest, request: Request, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    try:
        return _view(await ver.start(db, body.customer_id, client_ip(request)))
    except ver.VerificationError as e:
        raise _err(e)


@router.get("/sessions/{sid}")
async def get(sid: str, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    return _view(await _get(db, sid))


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class CodeRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class DeviceRequest(BaseModel):
    fingerprint: str = Field(min_length=8, max_length=256)
    label: str = Field(default="Browser", max_length=120)
    attributes: dict = Field(default_factory=dict)


async def _run(db, sid, fn, *args):
    vs = await _get(db, sid)
    try:
        out = await fn(db, vs, *args)
    except ver.VerificationError as e:
        raise _err(e)
    return {"result": out, "session": _view(vs)}


@router.post("/sessions/{sid}/password")
async def password(sid: str, body: PasswordRequest, request: Request, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "verify-pw", 20)
    return await _run(db, sid, ver.password, body.password, client_ip(request))


@router.post("/sessions/{sid}/otp/send")
async def otp_send(sid: str, request: Request, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "verify-otp", 10)
    return await _run(db, sid, ver.otp_send)


@router.post("/sessions/{sid}/otp/verify")
async def otp_verify(sid: str, body: CodeRequest, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    return await _run(db, sid, ver.otp_verify, body.code)


@router.post("/sessions/{sid}/mfa/enroll")
async def mfa_enroll(sid: str, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    return await _run(db, sid, ver.mfa_enroll)


@router.post("/sessions/{sid}/mfa/verify")
async def mfa_verify(sid: str, body: CodeRequest, request: Request, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    return await _run(db, sid, ver.mfa_verify, body.code, client_ip(request))


@router.post("/sessions/{sid}/device")
async def device(sid: str, body: DeviceRequest, request: Request, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    attrs = {k: str(v)[:80] for k, v in list(body.attributes.items())[:12]}
    return await _run(db, sid, ver.device, body.fingerprint, body.label, attrs, client_ip(request))


@router.post("/sessions/{sid}/biometric")
async def biometric(sid: str, request: Request, file: UploadFile | None = File(default=None), fixture: str | None = Form(default=None, max_length=80),
                    challenge: Literal["turn_head"] | None = Form(default=None),
                    cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "deepfake", 30)
    data = await _media(file, fixture)
    try:
        return await _run(db, sid, ver.biometric, data, challenge, client_ip(request))
    except MediaError as e:
        raise HTTPException(422, str(e))


@router.post("/sessions/{sid}/kyc")
async def kyc(sid: str, request: Request, file: UploadFile | None = File(default=None), fixture: str | None = Form(default=None, max_length=80),
              cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "kyc", 20)
    data = await _media(file, fixture)
    try:
        return await _run(db, sid, ver.kyc, data, client_ip(request))
    except MediaError as e:
        raise HTTPException(422, str(e))


@router.post("/sessions/{sid}/decision")
async def decision(sid: str, cu: CurrentUser = Depends(require("identity:verify")), db: AsyncSession = Depends(get_db)):
    return await _run(db, sid, ver.decide)


@router.get("/outbox/{customer_id}")
async def outbox(customer_id: str, cu: CurrentUser = Depends(require("identity:verify"))):
    """DEMO MODE ONLY — stands in for the SMS gateway so the OTP can be shown on screen."""
    if not get_settings().demo_mode:
        raise HTTPException(404, "not available")
    v = await redis().get(f"outbox:{customer_id}")
    return {"label": "DEMO SMS OUTBOX — no real message was sent", "message": json.loads(v) if v else None}


async def _media(file: UploadFile | None, fixture: str | None) -> bytes:
    if file is not None:
        data = await file.read(get_settings().max_upload_mb * 1024 * 1024 + 1)
        if len(data) > get_settings().max_upload_mb * 1024 * 1024:
            raise HTTPException(413, "file too large")
        return data
    if fixture:
        d = get_settings().fixture_dir
        manifest = json.loads((d / "manifest.json").read_text())
        if fixture not in manifest or fixture.startswith("_"):
            raise HTTPException(404, "unknown fixture")
        return (d / fixture).read_bytes()
    raise HTTPException(422, "upload a file or choose a demo fixture")
