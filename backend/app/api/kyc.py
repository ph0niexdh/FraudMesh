"""Prototype KYC / Media Authenticity Detector upload endpoint.

Media is validated (size, declared type, magic bytes, decodability,
dimensions) and analysed in memory. Only a SHA-256 fingerprint and derived
features are kept; the raw image is discarded unless
FRAUDMESH_KYC_RETAIN_MEDIA=true (off by default).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.api.deps import broadcaster_dep, engine_dep
from app.config import get_settings
from app.detectors.kyc import DISCLAIMER, DISPLAY_NAME, KycValidationError, validate_media
from app.privacy.tokenizer import media_fingerprint
from app.schemas.events import EventIn, NormalizedEvent
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/api/kyc", tags=["kyc"])


@router.post("/analyze")
async def analyze_kyc(
    file: UploadFile = File(...),
    customer_id: str | None = Form(None, max_length=64),
    account_id: str | None = Form(None, max_length=64),
    device_id: str | None = Form(None, max_length=64),
    bank_name: str | None = Form(None, max_length=32),
    submit_event: bool = Form(False),
    engine: FraudMeshEngine = Depends(engine_dep),
    bc: Broadcaster = Depends(broadcaster_dep),
) -> dict:
    settings = get_settings()
    data = await file.read(settings.kyc_max_bytes + 1)
    await file.close()
    try:
        mime = validate_media(data, file.content_type, settings.kyc_max_bytes)
        features = await run_in_threadpool(engine.kyc.analyze_image, data)
    except KycValidationError as err:
        raise HTTPException(422, str(err)) from err
    digest = media_fingerprint(data)
    retained = False
    if settings.kyc_retain_media:
        media_dir = settings.data_dir / "kyc_media"
        media_dir.mkdir(exist_ok=True)
        (media_dir / f"{digest}.{'png' if mime == 'image/png' else 'jpg'}").write_bytes(data)
        retained = True
    del data  # raw media leaves scope here

    response: dict = {"display_name": DISPLAY_NAME, "disclaimer": DISCLAIMER, "media_sha256": digest,
                      "media_retained": retained, "features": features}
    if submit_event and (customer_id or account_id):
        ev = EventIn(event_id=f"kyc_{uuid.uuid4().hex[:12]}", event_type="kyc_verification", timestamp=utcnow(),
                     customer_id=customer_id, account_id=account_id, device_id=device_id, bank_name=bank_name,
                     metadata={"subtype": "KYC_UPLOAD", "media_sha256": digest, "media_retained": retained})
        result = await run_in_threadpool(engine.process_event, ev, image_features=features)
        await bc.publish(result["messages"])
        response.update(event_id=result["event"]["event_id"], case=result["case"],
                        detector_result=next(r for r in result["detector_results"] if r["channel"] == "kyc"))
    else:
        probe = NormalizedEvent(event_id="probe", event_type="kyc_verification", timestamp=utcnow())
        response["detector_result"] = engine.kyc.detect(probe, features).model_dump(mode="json")
    return response
