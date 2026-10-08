"""Deepfake analysis pipeline.

    input → media validation → face detection → frame extraction → preprocessing
          → deepfake classifier → artifact analysis → liveness → face consistency
          → confidence aggregation → deepfake risk score + verdict

The neural classifier is the primary signal. Forensic artifacts, liveness and
identity consistency are supporting evidence and are reported separately so an
investigator can see *why* the verdict was reached and how sure the system is.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from dataclasses import dataclass, field

import cv2
import numpy as np

from fraudmesh.config import get_settings
from fraudmesh.services.deepfake import artifacts as artifact_mod
from fraudmesh.services.deepfake import liveness as liveness_mod
from fraudmesh.services.deepfake.face import SFACE_COSINE_THRESHOLD, Face, FaceAnalyzer
from fraudmesh.services.deepfake.media import Media, MediaError, load
from fraudmesh.services.deepfake.models import DeepfakeModel, load_model

logger = logging.getLogger(__name__)

VERDICTS = ("REAL_PERSON", "SUSPICIOUS", "POSSIBLE_SPOOF", "DEEPFAKE_LIKELY", "HIGH_CONFIDENCE_DEEPFAKE", "INCONCLUSIVE")

DISCLAIMER = (
    "Automated deepfake detection is probabilistic. The classifier was trained on FaceForensics++ "
    "manipulations and can miss unseen generation methods or flag heavily filtered genuine media. "
    "Heatmaps show where the model looked, not proof of manipulation. Treat this as one signal for a human decision."
)


@dataclass
class _Engine:
    faces: FaceAnalyzer | None = None
    model: DeepfakeModel | None = None
    error: str | None = None
    loaded_at: float | None = None
    last_inference_at: float | None = None
    last_latency_ms: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_engine = _Engine()


def engine() -> _Engine:
    """Lazily load models once (thread-safe). Called at startup in a worker thread."""
    if _engine.loaded_at is None:
        with _engine.lock:
            if _engine.loaded_at is None:
                s = get_settings()
                try:
                    _engine.faces = FaceAnalyzer(s.model_dir)
                except Exception as exc:
                    _engine.error = f"face models unavailable: {exc}"
                _engine.model = load_model(s.model_dir, s.deepfake_model, s.torch_threads)
                if _engine.model is None:
                    _engine.error = (_engine.error or "") + " deepfake weights not found (run ml/deepfake/download_weights.py)"
                _engine.loaded_at = time.time()
    return _engine


def status() -> dict:
    e = engine()
    if e.model is not None and e.faces is not None:
        state = "ONLINE"
    elif e.faces is not None:
        state = "OFFLINE"
    else:
        state = "OFFLINE"
    card = e.model.card if e.model else None
    return {
        "status": state,
        "model_version": card.version if card else None,
        "architecture": card.architecture if card else None,
        "face_detector": e.faces.detector_version if e.faces else None,
        "face_embedder": e.faces.embedder_version if e.faces else None,
        "last_inference_at": e.last_inference_at,
        "last_latency_ms": e.last_latency_ms,
        "error": e.error,
        "card": card.__dict__ if card else None,
    }


def _verdict(p: float, conf: float, live: dict, artifacts: float) -> str:
    # A recaptured photo/screen looks "fake" to the classifier everywhere in the frame, but
    # the face is consistent with its surroundings (no blending seam). That is a
    # presentation attack, not a synthesised face.
    if live.get("status") == "FAILED" and live.get("spoof_probability", 0) >= 0.5 and artifacts < 0.2:
        return "POSSIBLE_SPOOF"
    if p >= 0.90 and conf >= 0.6:
        return "HIGH_CONFIDENCE_DEEPFAKE"
    if p >= 0.70:
        return "DEEPFAKE_LIKELY"
    if live.get("status") == "FAILED":
        return "POSSIBLE_SPOOF"
    if p >= 0.40 or artifacts >= 0.55:
        return "SUSPICIOUS"
    return "REAL_PERSON"


def _aggregate_frames(probs: list[float]) -> float:
    """Video-level probability: mean of the most suspicious half of frames.
    Manipulations are often intermittent; a plain mean dilutes them, a max is noisy."""
    if not probs:
        return 0.0
    s = sorted(probs, reverse=True)
    k = max(1, (len(s) + 1) // 2)
    return float(np.mean(s[:k]))


_REGION_NAMES = ("eyes", "nose", "mouth", "jaw/cheek boundary", "forehead/hairline")


def _regions(cam: np.ndarray, crop_box: tuple[int, int, int, int], face: Face) -> list[dict]:
    """Connected high-attention regions, labelled by nearest facial landmark zone."""
    mask = (cam >= 0.6).astype(np.uint8)
    n, labels, stats, cents = cv2.connectedComponentsWithStats(mask)
    x0, y0, cw, ch = crop_box
    sx, sy = cw / cam.shape[1], ch / cam.shape[0]
    lm = face.landmarks
    zones = {
        "eyes": (lm[0] + lm[1]) / 2,
        "nose": lm[2],
        "mouth": (lm[3] + lm[4]) / 2,
    }
    out = []
    for i in range(1, n):
        x, y, w, h, area = stats[i]
        if area < 120:
            continue
        cx, cy = x0 + cents[i][0] * sx, y0 + cents[i][1] * sy
        fx, fy, fw, fh = face.box
        if cy < fy + fh * 0.12:
            zone = "forehead/hairline"
        elif cx < fx + fw * 0.12 or cx > fx + fw * 0.88 or cy > fy + fh * 0.9:
            zone = "jaw/cheek boundary"
        else:
            zone = min(zones, key=lambda z: np.hypot(*(zones[z] - [cx, cy])))
        intensity = float(cam[labels == i].mean())
        out.append(
            {
                "box": [round(x0 + x * sx), round(y0 + y * sy), round(w * sx), round(h * sy)],
                "region": zone,
                "intensity": round(intensity, 3),
                "area_fraction": round(float(area) / cam.size, 3),
            }
        )
    out.sort(key=lambda r: -r["intensity"] * r["area_fraction"])
    return out[:5]


def _png_b64(img: np.ndarray) -> str:
    ok, buf = cv2.imencode(".png", img)
    return base64.b64encode(buf.tobytes()).decode() if ok else ""


def _overlay(crop_bgr: np.ndarray, cam: np.ndarray) -> np.ndarray:
    base = cv2.resize(crop_bgr, (cam.shape[1], cam.shape[0]))
    heat = cv2.applyColorMap((cam * 255).astype(np.uint8), cv2.COLORMAP_INFERNO)
    return cv2.addWeighted(base, 0.6, heat, 0.4, 0)


def analyze_bytes(
    data: bytes,
    *,
    reference_embedding: np.ndarray | None = None,
    challenge: str | None = None,
    include_visuals: bool = True,
    assess_liveness: bool = True,
) -> dict:
    """Run the full pipeline synchronously (call from a worker thread)."""
    s = get_settings()
    stages: dict[str, float] = {}
    t0 = time.perf_counter()

    def mark(name: str, start: float) -> float:
        now = time.perf_counter()
        stages[name] = round((now - start) * 1000, 1)
        return now

    eng = engine()
    if eng.faces is None or eng.model is None:
        raise RuntimeError(eng.error or "deepfake engine offline")

    t = time.perf_counter()
    media: Media = load(data, s.max_upload_mb * 1024 * 1024, s.deepfake_max_frames)
    t = mark("media_validation_and_frame_extraction", t)

    frame_faces: list[Face | None] = []
    for fr in media.frames:
        found = eng.faces.detect(fr)
        frame_faces.append(found[0] if found else None)
    t = mark("face_detection", t)

    usable = [(i, fr, fc) for i, (fr, fc) in enumerate(zip(media.frames, frame_faces)) if fc is not None]
    base = {
        "media": {
            "type": media.kind,
            "container": media.container,
            "sha256": media.sha256,
            "width": media.width,
            "height": media.height,
            "duration_s": media.duration_s,
            "fps": media.fps,
            "frames_total": media.total_frames,
            "frames_sampled": len(media.frames),
        },
        "model": {
            "name": eng.model.card.name,
            "version": eng.model.card.version,
            "architecture": eng.model.card.architecture,
            "training_data": eng.model.card.training_data,
            "face_detector": eng.faces.detector_version,
            "face_embedder": eng.faces.embedder_version,
        },
        "disclaimer": DISCLAIMER,
    }
    if not usable:
        return {
            **base,
            "verdict": "INCONCLUSIVE",
            "deepfake_probability": None,
            "real_probability": None,
            "confidence": 0.0,
            "risk_score": 35.0,
            "faces_detected": 0,
            "frames": [],
            "reason_codes": [{"code": "NO_FACE", "message": "No face detected — cannot assess manipulation", "weight": 0.35}],
            "stages_ms": stages,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }

    crops, crop_boxes = [], []
    for _, fr, fc in usable:
        c, box = FaceAnalyzer.crop(fr, fc)
        crops.append(cv2.cvtColor(c, cv2.COLOR_BGR2RGB))
        crop_boxes.append(box)
    t = mark("preprocessing", t)

    preds = eng.model.predict(crops)
    t = mark("deepfake_classifier", t)

    frame_rows = []
    for (i, fr, fc), pred in zip(usable, preds):
        frame_rows.append(
            {
                "index": i,
                "t": media.frame_times[i],
                "deepfake_probability": round(pred.deepfake_probability, 4),
                "face": fc.to_dict(),
            }
        )
    probs = [p.deepfake_probability for p in preds]
    p_fake = _aggregate_frames(probs)

    art_results = [artifact_mod.analyze(fr, fc) for _, fr, fc in usable[:4]]
    art_ok = [a for a in art_results if a.get("available")]
    artifact_agg = float(np.mean([a["aggregate"] for a in art_ok])) if art_ok else 0.0
    artifact_checks = art_ok[0]["checks"] if art_ok else {}
    if len(art_ok) > 1:  # average each check across analysed frames
        for k in artifact_checks:
            artifact_checks[k] = {**artifact_checks[k], "score": round(float(np.mean([a["checks"][k]["score"] for a in art_ok if k in a["checks"]])), 3)}
    t = mark("artifact_analysis", t)

    if assess_liveness:
        img_live = [liveness_mod.passive_image(fr, fc) for _, fr, fc in usable[:3]]
        temporal = liveness_mod.temporal(media.frames, frame_faces) if media.kind == "video" else None
        live = liveness_mod.evaluate(img_live, temporal, challenge)
        live["image_signals"] = img_live[0]["signals"] if img_live else {}
        if temporal:
            live["temporal"] = temporal
    else:  # e.g. the portrait printed on an identity document is a photo by definition
        live = {"status": "NOT_APPLICABLE", "mode": "document", "liveness_score": None, "spoof_probability": 0.0, "reasons": []}
    t = mark("liveness_analysis", t)

    embeddings = [eng.faces.embed(fr, fc) for _, fr, fc in usable]
    embeddings = [e for e in embeddings if e is not None]
    consistency: dict = {"available": False}
    if len(embeddings) >= 2:
        sims = [FaceAnalyzer.similarity(embeddings[0], e) for e in embeddings[1:]]
        consistency = {
            "available": True,
            "min_similarity": round(min(sims), 3),
            "mean_similarity": round(float(np.mean(sims)), 3),
            "stable_identity": min(sims) >= SFACE_COSINE_THRESHOLD,
        }
    identity: dict = {"available": False}
    if reference_embedding is not None and embeddings:
        sim = FaceAnalyzer.similarity(reference_embedding, np.mean(embeddings, axis=0))
        identity = {
            "available": True,
            "similarity": round(sim, 3),
            "threshold": SFACE_COSINE_THRESHOLD,
            "matched": sim >= SFACE_COSINE_THRESHOLD,
        }
    t = mark("face_consistency", t)

    # ---------------- confidence aggregation
    quality = float(np.mean([fc.quality.get("score", 0.5) for _, _, fc in usable]))
    margin = float(np.mean([min(1.0, abs(p.logit_margin) / 4.0) for p in preds]))  # decisiveness
    spread = float(np.std(probs)) if len(probs) > 1 else 0.0
    coverage = min(1.0, len(usable) / max(1, min(4, len(media.frames))))
    confidence = float(np.clip(0.45 * margin + 0.35 * quality + 0.2 * coverage - 0.5 * spread, 0.05, 0.99))

    verdict = _verdict(p_fake, confidence, live, artifact_agg)
    risk = 100 * float(np.clip(0.85 * p_fake + 0.15 * artifact_agg, 0, 1))
    if live["status"] == "FAILED":
        risk = max(risk, 100 * 0.8 * live["spoof_probability"])
    if consistency.get("available") and not consistency["stable_identity"]:
        risk = min(100.0, risk + 10)

    reasons: list[dict] = []
    reasons.append(
        {
            "code": "DF_CLASSIFIER",
            "message": f"{eng.model.card.architecture} deepfake probability {p_fake:.2f} across {len(probs)} face frame(s)",
            "weight": round(p_fake, 3),
        }
    )
    for name, chk in sorted(artifact_checks.items(), key=lambda kv: -kv[1]["score"]):
        if chk["score"] >= 0.4:
            reasons.append({"code": f"ARTIFACT_{name.upper()}", "message": chk["description"], "weight": chk["score"]})
    if live["status"] == "FAILED":
        reasons.append({"code": "LIVENESS_FAILED", "message": "; ".join(live["reasons"]) or "presentation attack cues", "weight": live["spoof_probability"]})
    if consistency.get("available") and not consistency["stable_identity"]:
        reasons.append({"code": "IDENTITY_FLICKER", "message": "Face identity is not stable across frames", "weight": 0.5})
    if identity.get("available") and not identity["matched"]:
        reasons.append({"code": "FACE_MISMATCH", "message": f"Face does not match reference (similarity {identity['similarity']:.2f})", "weight": 0.6})

    result = {
        **base,
        "verdict": verdict,
        "deepfake_probability": round(p_fake, 4),
        "real_probability": round(1 - p_fake, 4),
        "confidence": round(confidence, 3),
        "risk_score": round(risk, 1),
        "faces_detected": len(usable),
        "frames": frame_rows,
        "suspicious_frames": [r["index"] for r in frame_rows if r["deepfake_probability"] >= 0.7],
        "artifacts": {"aggregate": round(artifact_agg, 3), "checks": artifact_checks, "kind": "forensic heuristics (supporting evidence)"},
        "liveness": live,
        "face_consistency": consistency,
        "identity_match": identity,
        "confidence_factors": {
            "decisiveness": round(margin, 3),
            "face_quality": round(quality, 3),
            "frame_coverage": round(coverage, 3),
            "frame_disagreement": round(spread, 3),
        },
        "reason_codes": reasons,
    }

    if include_visuals:
        k = int(np.argmax(probs))
        _, fr, fc = usable[k]
        crop_bgr = cv2.cvtColor(crops[k], cv2.COLOR_RGB2BGR)
        cam = eng.model.gradcam(crops[k])
        result["explanation"] = {
            "method": "Grad-CAM on the classifier's final convolutional features (fake-vs-real logit)",
            "frame_index": usable[k][0],
            "suspicious_regions": _regions(cam, crop_boxes[k], fc),
            "heatmap_png_b64": _png_b64(_overlay(crop_bgr, cam)),
            "face_crop_png_b64": _png_b64(cv2.resize(crop_bgr, (256, 256))),
            "caveat": "Highlights regions that most influenced the score; it is not a manipulation mask.",
        }
        t = mark("explainability", t)

    result["embedding"] = np.mean(embeddings, axis=0).tolist() if embeddings else None  # stripped before persistence/response
    result["stages_ms"] = stages
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    eng.last_inference_at = time.time()
    eng.last_latency_ms = result["latency_ms"]
    return result


__all__ = ["analyze_bytes", "status", "engine", "MediaError", "VERDICTS"]
