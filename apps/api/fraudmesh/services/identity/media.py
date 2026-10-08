"""Async façade over the CPU-bound deepfake and KYC pipelines.

* Inference runs in worker threads, capped by a semaphore so a burst of uploads
  cannot starve the event loop or exhaust memory.
* Results are persisted *without* raw media, crops or heatmaps — except for
  registered, non-PII demo fixtures — and face embeddings are stored encrypted.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core.crypto import decrypt, encrypt
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import FaceTemplate, KycRecord, MediaAnalysis
from fraudmesh.services.deepfake import pipeline as deepfake
from fraudmesh.services.kyc import pipeline as kyc
from fraudmesh.services.metrics.telemetry import telemetry

_sem = asyncio.Semaphore(2)
_VISUAL_KEYS = ("heatmap_png_b64", "face_crop_png_b64")


def fixture_name_for(sha256: str) -> str | None:
    """Demo fixtures are recognised by content hash, never by filename."""
    from hashlib import sha256 as h

    d = get_settings().fixture_dir
    manifest = d / "manifest.json"
    if not manifest.exists():
        return None
    for name in json.loads(manifest.read_text()):
        if name.startswith("_"):
            continue
        p = d / name
        if p.exists() and h(p.read_bytes()).hexdigest() == sha256:
            return name
    return None


async def enrolled_template(db: AsyncSession, customer_id: str | None) -> np.ndarray | None:
    if not customer_id:
        return None
    row = (await db.execute(select(FaceTemplate).where(FaceTemplate.customer_id == customer_id).order_by(FaceTemplate.created_at.desc()).limit(1))).scalar_one_or_none()
    if row is None:
        return None
    return np.frombuffer(decrypt(row.embedding_enc), dtype=np.float32)


async def store_template(db: AsyncSession, customer_id: str, embedding: list[float], source: str) -> str:
    row = FaceTemplate(id=new_id("face"), customer_id=customer_id, embedding_enc=encrypt(np.asarray(embedding, np.float32).tobytes()),
                       model_version=deepfake.engine().faces.embedder_version or "sface", source=source)
    db.add(row)
    await db.flush()
    return row.id


def _persistable(result: dict, keep_visuals: bool) -> dict:
    out = {k: v for k, v in result.items() if k != "embedding"}
    if not keep_visuals and out.get("explanation"):
        out["explanation"] = {k: v for k, v in out["explanation"].items() if k not in _VISUAL_KEYS}
        out["explanation"]["visuals_retained"] = False
    return out


async def analyze_media(db: AsyncSession, data: bytes, *, customer_id: str | None = None, challenge: str | None = None,
                        purpose: str = "analysis") -> dict[str, Any]:
    ref = await enrolled_template(db, customer_id)
    async with _sem:
        result = await asyncio.to_thread(deepfake.analyze_bytes, data, reference_embedding=ref, challenge=challenge, include_visuals=True)
    telemetry.observe_inference("deepfake-detector", result["latency_ms"])
    fixture = fixture_name_for(result["media"]["sha256"])
    row = MediaAnalysis(id=new_id("mda"), customer_id=customer_id, media_type=result["media"]["type"], media_sha256=result["media"]["sha256"],
                        fixture_name=fixture, verdict=result["verdict"], deepfake_probability=result.get("deepfake_probability") or 0.0,
                        result=_persistable(result, keep_visuals=fixture is not None))
    db.add(row)
    await db.flush()
    response = {k: v for k, v in result.items() if k != "embedding"}
    response["analysis_id"] = row.id
    response["fixture"] = fixture
    response["privacy"] = {"raw_media_stored": False, "visuals_stored": fixture is not None,
                           "note": "Only scores and evidence geometry are retained" + (" (demo fixture visuals retained)" if fixture else "")}
    return {"result": response, "embedding": result.get("embedding"), "analysis_id": row.id}


async def verify_kyc(db: AsyncSession, document: bytes, selfie: bytes | None, *, customer_id: str | None = None) -> dict[str, Any]:
    ref = await enrolled_template(db, customer_id)
    async with _sem:
        result = await asyncio.to_thread(kyc.verify, document, selfie, ref, None, customer_id)
    telemetry.observe_inference("kyc-engine", result["latency_ms"])
    owner = None
    if result.get("doc_number_hmac"):
        owner = await db.scalar(select(KycRecord.customer_id).where(KycRecord.doc_number_hmac == result["doc_number_hmac"],
                                                                    KycRecord.customer_id.is_not(None), KycRecord.customer_id != customer_id).limit(1))
    result = kyc.apply_reuse_check(result, owner, customer_id)
    selfie_analysis_id = None
    if result.get("selfie"):
        sel = result["selfie"]
        fixture = fixture_name_for(sel["media"]["sha256"])
        m = MediaAnalysis(id=new_id("mda"), customer_id=customer_id, media_type=sel["media"]["type"], media_sha256=sel["media"]["sha256"],
                          fixture_name=fixture, verdict=sel["verdict"], deepfake_probability=sel.get("deepfake_probability") or 0.0,
                          result=_persistable(sel, keep_visuals=fixture is not None))
        db.add(m)
        await db.flush()
        selfie_analysis_id = m.id
        sel["analysis_id"] = m.id
    rec = KycRecord(id=new_id("kyc"), customer_id=customer_id, doc_type=result["document_type"], doc_number_hmac=result.get("doc_number_hmac"),
                    fields_masked=result["fields"], checks=result["checks"], scores=result["scores"], decision=result["decision"])
    db.add(rec)
    await db.flush()
    doc_embedding = result.pop("document_embedding", None)
    result["kyc_record_id"] = rec.id
    result["selfie_analysis_id"] = selfie_analysis_id
    return {"result": result, "doc_embedding": doc_embedding, "kyc_record_id": rec.id}
