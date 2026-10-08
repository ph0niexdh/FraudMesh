"""Deepfake analysis and KYC verification endpoints."""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.config import get_settings
from fraudmesh.core import ratelimit
from fraudmesh.db.models import KycRecord, MediaAnalysis
from fraudmesh.db.session import get_db
from fraudmesh.schemas.events import EventIn
from fraudmesh.services.audit import service as audit
from fraudmesh.services.deepfake import pipeline as deepfake
from fraudmesh.services.deepfake.media import MediaError
from fraudmesh.services.events import pipeline
from fraudmesh.services.identity import media as media_svc

router = APIRouter(tags=["deepfake & kyc"])

_ID = r"^[A-Za-z0-9_.:\-]{1,64}$"


async def _read(upload: UploadFile, max_mb: int) -> bytes:
    data = await upload.read(max_mb * 1024 * 1024 + 1)
    if len(data) > max_mb * 1024 * 1024:
        raise HTTPException(413, f"file too large (max {max_mb} MB)")
    if not data:
        raise HTTPException(422, "empty upload")
    return data


def _fixtures() -> dict:
    p = get_settings().fixture_dir / "manifest.json"
    return {k: v for k, v in json.loads(p.read_text()).items() if not k.startswith("_")} if p.exists() else {}


@router.get("/deepfake/status")
async def deepfake_status(cu: CurrentUser = Depends(require("dashboard:read"))):
    return deepfake.status()


@router.get("/deepfake/fixtures")
async def list_fixtures(cu: CurrentUser = Depends(require("media:analyze"))):
    src = json.loads((get_settings().fixture_dir / "manifest.json").read_text()).get("_source")
    return {"source": src, "label": "DEMO / TEST MEDIA", "fixtures": [{"name": k, **v} for k, v in _fixtures().items()]}


@router.get("/deepfake/fixtures/{name}")
async def get_fixture(name: str, cu: CurrentUser = Depends(require("media:analyze"))):
    if name not in _fixtures():  # whitelist: no path traversal possible
        raise HTTPException(404, "unknown fixture")
    path = get_settings().fixture_dir / name
    media_type = {"png": "image/png", "mp4": "video/mp4"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
    return Response(path.read_bytes(), media_type=media_type, headers={"Cache-Control": "private, max-age=3600"})


async def _emit(db: AsyncSession, event_type: str, customer_id: str, payload: dict, extra: dict, request: Request) -> dict:
    ev = EventIn(event_type=event_type, customer_id=customer_id, source="verification-api", payload=payload, ip=None)
    return await pipeline.process(db, ev, extra=extra)


@router.post("/deepfake/analyze")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    customer_id: str | None = Form(default=None, pattern=_ID),
    challenge: Literal["turn_head"] | None = Form(default=None),
    emit_event: bool = Form(default=False),
    cu: CurrentUser = Depends(require("media:analyze")),
    db: AsyncSession = Depends(get_db),
):
    await ratelimit.enforce(request, "deepfake", 30)
    data = await _read(file, get_settings().max_upload_mb)
    try:
        out = await media_svc.analyze_media(db, data, customer_id=customer_id, challenge=challenge)
    except MediaError as exc:
        raise HTTPException(422, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    res = out["result"]
    if emit_event and customer_id:
        ev = await _emit(db, "BIOMETRIC", customer_id, {"media_analysis_id": out["analysis_id"], "liveness": res["liveness"]["status"]},
                         {"deepfake": {**res, "analysis_id": out["analysis_id"]}}, request)
        res["event"] = {"event_id": ev["event_id"], "case_id": ev["case_id"], "action": ev["action"]}
    await audit.record(db, cu.actor, "deepfake.analyze", "media", out["analysis_id"],
                       new_state={"verdict": res["verdict"], "p": res.get("deepfake_probability"), "sha256": res["media"]["sha256"]})
    return res


class FixtureRequest(BaseModel):
    name: str = Field(max_length=80)
    customer_id: str | None = Field(default=None, pattern=_ID)
    challenge: Literal["turn_head"] | None = None


@router.post("/deepfake/analyze-fixture")
async def analyze_fixture(body: FixtureRequest, request: Request, cu: CurrentUser = Depends(require("media:analyze")), db: AsyncSession = Depends(get_db)):
    """Guaranteed demo path: analyse a controlled fixture through the identical pipeline."""
    if body.name not in _fixtures():
        raise HTTPException(404, "unknown fixture")
    await ratelimit.enforce(request, "deepfake", 30)
    data = (get_settings().fixture_dir / body.name).read_bytes()
    out = await media_svc.analyze_media(db, data, customer_id=body.customer_id, challenge=body.challenge)
    await audit.record(db, cu.actor, "deepfake.analyze", "media", out["analysis_id"], new_state={"fixture": body.name, "verdict": out["result"]["verdict"]})
    return out["result"]


@router.get("/deepfake/analyses")
async def list_analyses(limit: int = 50, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(MediaAnalysis).order_by(MediaAnalysis.created_at.desc()).limit(min(limit, 200)))).scalars().all()
    return [{"id": r.id, "created_at": r.created_at, "customer_id": r.customer_id, "media_type": r.media_type, "verdict": r.verdict,
             "deepfake_probability": r.deepfake_probability, "fixture": r.fixture_name, "confidence": r.result.get("confidence"),
             "risk_score": r.result.get("risk_score"), "liveness": (r.result.get("liveness") or {}).get("status"),
             "model": (r.result.get("model") or {}).get("version")} for r in rows]


@router.get("/deepfake/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    r = await db.get(MediaAnalysis, analysis_id)
    if r is None:
        raise HTTPException(404, "analysis not found")
    return {**r.result, "analysis_id": r.id, "fixture": r.fixture_name, "customer_id": r.customer_id, "created_at": r.created_at}


@router.post("/kyc/verify")
async def kyc_verify(
    request: Request,
    document: UploadFile = File(...),
    selfie: UploadFile | None = File(default=None),
    customer_id: str | None = Form(default=None, pattern=_ID),
    emit_event: bool = Form(default=False),
    cu: CurrentUser = Depends(require("media:analyze")),
    db: AsyncSession = Depends(get_db),
):
    await ratelimit.enforce(request, "kyc", 20)
    doc = await _read(document, 15)
    sel = await _read(selfie, get_settings().max_upload_mb) if selfie is not None else None
    try:
        out = await media_svc.verify_kyc(db, doc, sel, customer_id=customer_id)
    except MediaError as exc:
        raise HTTPException(422, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    res = out["result"]
    if emit_event and customer_id:
        payload = {"kyc_record_id": out["kyc_record_id"]}
        if res.get("selfie_analysis_id"):
            payload["media_analysis_id"] = res["selfie_analysis_id"]
        ev = await _emit(db, "KYC", customer_id, payload, {}, request)
        res["event"] = {"event_id": ev["event_id"], "case_id": ev["case_id"], "action": ev["action"]}
    await db.commit()
    await audit.record(db, cu.actor, "kyc.verify", "kyc_record", out["kyc_record_id"], new_state={"decision": res["decision"], "scores": res["scores"]})
    return res


class KycFixtureRequest(BaseModel):
    document: str = Field(max_length=80)
    selfie: str | None = Field(default=None, max_length=80)
    customer_id: str | None = Field(default=None, pattern=_ID)


@router.post("/kyc/verify-fixture")
async def kyc_fixture(body: KycFixtureRequest, request: Request, cu: CurrentUser = Depends(require("media:analyze")), db: AsyncSession = Depends(get_db)):
    fx = _fixtures()
    if body.document not in fx or (body.selfie and body.selfie not in fx):
        raise HTTPException(404, "unknown fixture")
    await ratelimit.enforce(request, "kyc", 20)
    d = get_settings().fixture_dir
    out = await media_svc.verify_kyc(db, (d / body.document).read_bytes(), (d / body.selfie).read_bytes() if body.selfie else None, customer_id=body.customer_id)
    await db.commit()
    await audit.record(db, cu.actor, "kyc.verify", "kyc_record", out["kyc_record_id"], new_state={"fixture": body.document, "decision": out["result"]["decision"]})
    return out["result"]


@router.get("/kyc/records")
async def kyc_records(limit: int = 50, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(KycRecord).order_by(KycRecord.created_at.desc()).limit(min(limit, 200)))).scalars().all()
    return [{"id": r.id, "created_at": r.created_at, "customer_id": r.customer_id, "doc_type": r.doc_type, "decision": r.decision,
             "scores": r.scores, "fields": r.fields_masked, "failed_checks": [c for c in r.checks if c["status"] == "FAIL"]} for r in rows]
