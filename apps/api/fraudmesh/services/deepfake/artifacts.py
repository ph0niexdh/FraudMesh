"""Classical image-forensics signals that support (never replace) the neural classifier.

Face-swap / reenactment pipelines generate the inner face at a different resolution
and blend it into the original frame. That leaves measurable *inconsistencies between
the inner face and its surroundings*. Each check compares the inner-face region with a
ring of surrounding context from the same image, so global properties (camera, JPEG
quality, lighting) cancel out:

* ``frequency``  – high-frequency spectral energy (resampled faces lose HF detail)
* ``noise``      – sensor-noise residual level (blending replaces native noise)
* ``sharpness``  – Laplacian variance
* ``color``      – chroma statistics in Lab space
* ``boundary``   – gradient discontinuity along the blend boundary
* ``compression``– error-level difference after re-compression

Every score is in [0, 1] where 0 = consistent. These are heuristics with known false
positives (make-up, beauty filters, strong lighting) and are reported as such.
"""

from __future__ import annotations

import cv2
import numpy as np

from fraudmesh.services.deepfake.face import Face

ARTIFACT_DESCRIPTIONS = {
    "frequency": "High-frequency energy mismatch between face and surroundings (resampling / upscaling)",
    "noise": "Sensor-noise residual mismatch (face region does not share the camera's noise pattern)",
    "sharpness": "Focus/sharpness mismatch between face and surroundings",
    "color": "Colour-statistics mismatch between inner face and surrounding skin",
    "boundary": "Gradient discontinuity along the facial blending boundary",
    "compression": "Error-level (re-compression) mismatch between face and surroundings",
}


def _masks(shape: tuple[int, int], face: Face) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """inner-face mask, surrounding ring mask, boundary band mask."""
    h, w = shape
    x, y, bw, bh = face.box
    cx, cy = x + bw / 2, y + bh * 0.55
    inner = np.zeros((h, w), np.uint8)
    cv2.ellipse(inner, (int(cx), int(cy)), (int(bw * 0.36), int(bh * 0.42)), 0, 0, 360, 255, -1)
    outer = np.zeros((h, w), np.uint8)
    cv2.ellipse(outer, (int(cx), int(cy)), (int(bw * 0.75), int(bh * 0.80)), 0, 0, 360, 255, -1)
    mid = np.zeros((h, w), np.uint8)
    cv2.ellipse(mid, (int(cx), int(cy)), (int(bw * 0.52), int(bh * 0.60)), 0, 0, 360, 255, -1)
    ring = cv2.subtract(outer, mid)
    band_outer = np.zeros((h, w), np.uint8)
    cv2.ellipse(band_outer, (int(cx), int(cy)), (int(bw * 0.50), int(bh * 0.58)), 0, 0, 360, 255, -1)
    band_inner = np.zeros((h, w), np.uint8)
    cv2.ellipse(band_inner, (int(cx), int(cy)), (int(bw * 0.40), int(bh * 0.47)), 0, 0, 360, 255, -1)
    band = cv2.subtract(band_outer, band_inner)
    return inner > 0, ring > 0, band > 0


def _ratio_score(a: float, b: float, tolerance: float, span: float) -> tuple[float, float]:
    """Map |log(a/b)| to [0,1]: below ``tolerance`` = 0, saturating at tolerance+span."""
    r = (a + 1e-6) / (b + 1e-6)
    dev = abs(np.log(r))
    return float(np.clip((dev - tolerance) / span, 0, 1)), float(r)


def _hf_energy(gray: np.ndarray, mask: np.ndarray) -> float:
    lap = cv2.Laplacian(gray, cv2.CV_32F, ksize=3)
    return float(np.mean(np.abs(lap[mask]))) if mask.any() else 0.0


def analyze(bgr: np.ndarray, face: Face) -> dict:
    h, w = bgr.shape[:2]
    # Work at a bounded resolution so scores are comparable across inputs.
    scale = min(1.0, 900 / max(h, w))
    if scale < 1.0:
        bgr = cv2.resize(bgr, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        face = Face(box=tuple(np.array(face.box) * scale), landmarks=face.landmarks * scale, score=face.score, raw=face.raw)
    inner, ring, band = _masks(bgr.shape[:2], face)
    if inner.sum() < 400 or ring.sum() < 400:
        return {"available": False, "reason": "face too small for forensic analysis"}

    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    scores: dict[str, dict] = {}

    # 1. frequency: Laplacian energy (proxy for HF spectrum) inner vs ring
    s, r = _ratio_score(_hf_energy(gray, inner), _hf_energy(gray, ring), 0.35, 0.9)
    scores["frequency"] = {"score": s, "ratio": round(r, 3)}

    # 2. noise residual: image - median filtered
    resid = gray - cv2.medianBlur(gray.astype(np.uint8), 3).astype(np.float32)
    s, r = _ratio_score(float(resid[inner].std()), float(resid[ring].std()), 0.30, 0.9)
    scores["noise"] = {"score": s, "ratio": round(r, 3)}

    # 3. sharpness: local Laplacian variance
    lap = cv2.Laplacian(gray, cv2.CV_32F)
    s, r = _ratio_score(float(lap[inner].var()), float(lap[ring].var()), 0.6, 1.6)
    scores["sharpness"] = {"score": s, "ratio": round(r, 3)}

    # 4. colour: chroma distance in Lab (a*, b*) relative to ring spread
    lab = cv2.cvtColor(bgr, cv2.COLOR_BGR2LAB).astype(np.float32)
    ab_in = lab[..., 1:][inner]
    ab_ring = lab[..., 1:][ring]
    dist = float(np.linalg.norm(ab_in.mean(0) - ab_ring.mean(0)))
    spread = float(ab_ring.std(0).mean() + 1.0)
    scores["color"] = {"score": float(np.clip((dist / spread - 1.0) / 2.0, 0, 1)), "distance": round(dist, 2)}

    # 5. blending boundary: gradient magnitude on the band vs inside/outside
    gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0)
    gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1)
    mag = cv2.magnitude(gx, gy)
    band_g = float(np.median(mag[band]))
    ref_g = float(np.median(np.concatenate([mag[inner], mag[ring]])))
    s, r = _ratio_score(band_g, ref_g, 0.45, 1.0)
    scores["boundary"] = {"score": s, "ratio": round(r, 3)}

    # 6. error level analysis at JPEG q=90
    ok, enc = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, 90])
    if ok:
        ela = np.abs(bgr.astype(np.float32) - cv2.imdecode(enc, cv2.IMREAD_COLOR).astype(np.float32)).mean(2)
        s, r = _ratio_score(float(ela[inner].mean()), float(ela[ring].mean()), 0.35, 1.0)
        scores["compression"] = {"score": s, "ratio": round(r, 3)}

    weights = {"frequency": 0.25, "noise": 0.25, "sharpness": 0.15, "color": 0.1, "boundary": 0.1, "compression": 0.15}
    agg = sum(weights[k] * v["score"] for k, v in scores.items()) / sum(weights[k] for k in scores)
    for k, v in scores.items():
        v["score"] = round(v["score"], 3)
        v["description"] = ARTIFACT_DESCRIPTIONS[k]
    return {"available": True, "aggregate": round(float(agg), 3), "checks": scores}
