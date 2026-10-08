"""Model registry (Postgres) + live engine status."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import ModelRecord
from fraudmesh.services.behavior.detector import behavior_detector
from fraudmesh.services.deepfake import pipeline as deepfake
from fraudmesh.services.ids.detector import network_detector
from fraudmesh.services.kyc import ocr
from fraudmesh.services.metrics.telemetry import telemetry
from fraudmesh.services.transaction.detector import transaction_detector


def _card(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def _records() -> list[dict]:
    s = get_settings()
    a = s.artifact_dir
    out = []
    t = _card(a / "transaction" / "model_card.json")
    if t:
        out.append(dict(name="transaction-fraud", version=t["version"], model_type=t["model_type"], framework=t["framework"], domain="transaction",
                        training_date=t["trained_at"], dataset=t["dataset"]["source"], metrics={**t["metrics"], "comparison": t["comparison"],
                        "selection_rationale": t["selection_rationale"]}, artifact=f"ml/artifacts/transaction/{t['artifact']}",
                        artifact_sha256=t["artifact_sha256"], notes=t["limitations"]))
    b = _card(a / "behavior" / "model_card.json")
    if b:
        out.append(dict(name="behavior-anomaly", version=b["version"], model_type=b["model_type"], framework=b["framework"], domain="behavior",
                        training_date=b["trained_at"], dataset=b["dataset"]["source"], metrics={**b["metrics"], "comparison": b["comparison"],
                        "selection_rationale": b["selection_rationale"]}, artifact=f"ml/artifacts/behavior/{b['artifact']}",
                        artifact_sha256=b["artifact_sha256"], notes=b["limitations"]))
    i = _card(a / "ids" / "model_card.json")
    if i:
        out.append(dict(name="network-anomaly", version=i["version"], model_type=i["model_type"], framework=i["framework"], domain="network",
                        training_date=i["trained_at"], dataset=i["dataset"]["source"], metrics=i["metrics"], artifact=f"ml/artifacts/ids/{i['artifact']}",
                        artifact_sha256=i["artifact_sha256"], notes=i["limitations"]))
    f = _card(a / "fusion" / "fusion.json")
    if f:
        out.append(dict(name="risk-fusion", version=f["version"], model_type=f["model_type"], framework="numpy/scipy", domain="fusion",
                        training_date=f["trained_at"], dataset=f["dataset"]["source"], metrics={**f["metrics"], "weights": f["weights"],
                        "corroboration_weight": f["corroboration_weight"]}, artifact="ml/artifacts/fusion/fusion.json", artifact_sha256=None,
                        notes=f["limitations"]))
    manifest = _card(s.model_dir / "manifest.json") or {}
    for fname, meta in manifest.items():
        path = s.model_dir / fname
        name = {"effnb4_best.pth": "deepfake-detector", "meso4_best.pth": "deepfake-detector-lite",
                "face_detection_yunet_2023mar.onnx": "face-detector", "face_recognition_sface_2021dec.onnx": "face-embedder"}[fname]
        arch = {"effnb4_best.pth": "EfficientNet-B4 (DeepfakeBench)", "meso4_best.pth": "MesoNet-4 (DeepfakeBench)",
                "face_detection_yunet_2023mar.onnx": "YuNet", "face_recognition_sface_2021dec.onnx": "SFace"}[fname]
        out.append(dict(name=name, version=fname.rsplit(".", 1)[0], model_type=arch, framework="pytorch" if fname.endswith(".pth") else "onnx (OpenCV DNN)",
                        domain="deepfake" if "deepfake" in name else "identity", training_date=None,
                        dataset="FaceForensics++ c23" if fname.endswith(".pth") else "OpenCV Zoo pretrained",
                        metrics={"source": meta["url"], "license": meta["license"],
                                 "note": "Pretrained third-party model; FraudMesh did not retrain it. See DeepfakeBench for benchmark AUCs."},
                        artifact=f"ml/weights/{fname}", artifact_sha256=meta["sha256"] if path.exists() else None,
                        notes=meta["purpose"] + ("" if path.exists() else " — WEIGHTS NOT DOWNLOADED")))
    out.append(dict(name="kyc-ocr", version="rapidocr-onnx-1.2", model_type="PaddleOCR PP-OCR (det+rec)", framework="onnxruntime", domain="identity",
                    training_date=None, dataset="PaddleOCR pretrained", metrics={"note": "Pretrained OCR; MRZ validated with ICAO 9303 check digits"},
                    artifact="rapidocr_onnxruntime (bundled)", artifact_sha256=None, notes="Document text extraction"))
    return out


async def sync(db: AsyncSession) -> None:
    for r in _records():
        existing = (await db.execute(select(ModelRecord).where(ModelRecord.name == r["name"], ModelRecord.version == r["version"]))).scalar_one_or_none()
        if existing is None:
            for old in (await db.execute(select(ModelRecord).where(ModelRecord.name == r["name"], ModelRecord.status == "ACTIVE"))).scalars().all():
                old.status = "RETIRED"
            db.add(ModelRecord(id=new_id("mdl"), status="ACTIVE", **r))
        else:
            existing.metrics, existing.notes, existing.artifact_sha256 = r["metrics"], r["notes"], r["artifact_sha256"]
    await db.commit()


def _inf(name: str) -> dict:
    s = telemetry.inference.get(name)
    return s.summary() if s else {"count": 0, "p50_ms": None, "p95_ms": None, "last_at": None}


def engine_status(graph_ok: bool | None, policies_count: int) -> list[dict]:
    t = transaction_detector.status()
    b = behavior_detector.status()
    n = network_detector.status()
    df = deepfake.status() if deepfake._engine.loaded_at else {"status": "DEGRADED", "model_version": "loading", "error": "warming up"}
    oc = ocr.status()
    from fraudmesh.services.fusion import engine as fusion

    try:
        fv = fusion.params()["version"]
        fstate = "ONLINE"
    except Exception:
        fv, fstate = None, "OFFLINE"
    rows = [
        ("Transaction Model", "transaction", t.status, t.model_version, t.model_type, "transaction-model"),
        ("Behavior Model", "behavior", b.status, b.model_version, b.model_type, "behavior-model"),
        ("Deepfake Model", "deepfake", df["status"], df.get("model_version"), df.get("architecture") or "", "deepfake-detector"),
        ("KYC Model", "identity", oc["status"] if df["status"] != "OFFLINE" else "DEGRADED", "kyc-pipeline-v1", "PP-OCR + ICAO 9303 + SFace", "kyc-engine"),
        ("IDS", "network", n.status, n.model_version, n.model_type, "ids"),
        ("Graph Engine", "graph", "ONLINE" if graph_ok else "OFFLINE", "graph-propagation-v1", "Neo4j + controlled propagation", "graph-engine"),
        ("Risk Fusion", "fusion", fstate, fv, "Monotone logistic fusion", None),
        ("Policy Engine", "policy", "ONLINE" if policies_count else "DEGRADED", f"{policies_count} policies", "Rule evaluation", None),
    ]
    out = []
    for name, domain, status, version, mtype, key in rows:
        stats = _inf(key) if key else {"count": None, "p50_ms": None, "p95_ms": None, "last_at": None}
        if key == "graph-engine" and not stats["count"]:
            stats = _inf("graph-engine")
        out.append({"name": name, "domain": domain, "status": status, "model_version": version, "model_type": mtype,
                    "inferences": stats["count"], "latency_p50_ms": stats["p50_ms"], "latency_p95_ms": stats["p95_ms"],
                    "last_inference_at": stats["last_at"]})
    pipe = telemetry.stages.get("pipeline_total")
    for r in out:
        if r["name"] in ("Risk Fusion", "Policy Engine") and pipe:
            r["inferences"] = pipe.count
            r["last_inference_at"] = pipe.last_at
            corr = telemetry.stages.get("case_fusion")
            if corr and r["name"] == "Risk Fusion":
                r["latency_p50_ms"], r["latency_p95_ms"] = corr.summary()["p50_ms"], corr.summary()["p95_ms"]
    return out


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
