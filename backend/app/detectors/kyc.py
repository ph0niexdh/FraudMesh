"""Prototype KYC / Media Authenticity Detector  (DEMO — NOT a deepfake model).

This component exposes a clean detector interface so a validated model (e.g.
an EfficientNet-B0 trained on a deepfake benchmark) can be dropped in later.
Today it combines:

* OpenCV image-quality analysis (blur, exposure, contrast, resolution)
* Haar-cascade face detection
* simple manipulation indicators (JPEG error-level analysis, block-noise
  inconsistency, face/background sharpness mismatch)
* for scripted scenarios, a *controlled scenario value*
  (``metadata.demo_manipulation_score``) that is explicitly labelled as such.

It must not be described as production-grade deepfake detection.
"""
from __future__ import annotations

import math
from typing import Any

import cv2
import numpy as np

from app.detectors.base import DetectorStats, Timer, clamp01, make_result
from app.schemas.events import DetectorResult, NormalizedEvent

DISPLAY_NAME = "Prototype KYC / Media Authenticity Detector"
DISCLAIMER = ("Heuristic prototype. Not a validated deepfake detector; scores are indicative only and "
              "must be reviewed by a human investigator.")

ALLOWED_MIME = {"image/jpeg": b"\xff\xd8\xff", "image/png": b"\x89PNG\r\n\x1a\n"}
MAX_DIMENSION = 6000


class KycValidationError(ValueError):
    pass


def validate_media(data: bytes, content_type: str | None, max_bytes: int) -> str:
    """Validate size, declared type and magic bytes. Returns the detected MIME type."""
    if not data:
        raise KycValidationError("empty file")
    if len(data) > max_bytes:
        raise KycValidationError(f"file exceeds {max_bytes // 1024} KiB limit")
    detected = next((mime for mime, magic in ALLOWED_MIME.items() if data.startswith(magic)), None)
    if detected is None:
        raise KycValidationError("only JPEG and PNG images are accepted")
    if content_type and content_type not in ALLOWED_MIME:
        raise KycValidationError(f"content type {content_type} not allowed")
    if content_type and content_type != detected:
        raise KycValidationError("declared content type does not match file contents")
    return detected


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


class KycDetector:
    name = "kyc_media_demo"
    channel = "kyc"
    version_label = "demo-heuristic-v1"
    display_name = DISPLAY_NAME

    def __init__(self) -> None:
        self.stats = DetectorStats(self.name)
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml" if hasattr(cv2, "data") else ""
        self._face = cv2.CascadeClassifier(path) if path else None
        if self._face is not None and self._face.empty():
            self._face = None

    @property
    def face_detection_available(self) -> bool:
        return self._face is not None

    # ---------------------------------------------------------------- images
    def analyze_image(self, data: bytes) -> dict[str, Any]:
        """Extract quality + manipulation indicators from image bytes (in memory only)."""
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise KycValidationError("image could not be decoded")
        h, w = img.shape[:2]
        if h > MAX_DIMENSION or w > MAX_DIMENSION:
            raise KycValidationError("image dimensions too large")
        scale = 1024 / max(h, w) if max(h, w) > 1024 else 1.0
        if scale != 1.0:
            img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        blur_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        brightness = float(gray.mean())
        contrast = float(gray.std())

        faces: list[tuple[int, int, int, int]] = []
        if self._face is not None:
            detected = self._face.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
            faces = [tuple(int(v) for v in f) for f in detected] if len(detected) else []

        # Error-level analysis: re-encode at a known quality and measure the residual.
        ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 90])
        recompressed = cv2.imdecode(enc, cv2.IMREAD_COLOR) if ok else img
        ela = cv2.absdiff(img, recompressed).astype(np.float32).mean(axis=2)
        ela_mean = float(ela.mean())
        # block-wise ELA and noise inconsistency (spliced regions tend to differ)
        bh, bw = max(1, gray.shape[0] // 8), max(1, gray.shape[1] // 8)
        ela_blocks, noise_blocks = [], []
        lap = cv2.Laplacian(gray, cv2.CV_64F)
        for i in range(8):
            for j in range(8):
                ela_blocks.append(float(ela[i * bh:(i + 1) * bh, j * bw:(j + 1) * bw].mean()))
                noise_blocks.append(float(lap[i * bh:(i + 1) * bh, j * bw:(j + 1) * bw].std()))
        ela_cv = float(np.std(ela_blocks) / (np.mean(ela_blocks) + 1e-6))
        noise_cv = float(np.std(noise_blocks) / (np.mean(noise_blocks) + 1e-6))

        sharp_mismatch = 0.0
        if faces:
            x, y, fw, fh = max(faces, key=lambda f: f[2] * f[3])
            face_sharp = float(cv2.Laplacian(gray[y:y + fh, x:x + fw], cv2.CV_64F).var())
            sharp_mismatch = abs(math.log((face_sharp + 1) / (blur_var + 1)))

        return {
            "width": int(w), "height": int(h),
            "blur_variance": round(blur_var, 2),
            "brightness": round(brightness, 2),
            "contrast": round(contrast, 2),
            "faces_detected": len(faces),
            "face_detection_available": self.face_detection_available,
            "ela_mean": round(ela_mean, 4),
            "ela_block_cv": round(ela_cv, 4),
            "noise_block_cv": round(noise_cv, 4),
            "face_background_sharpness_mismatch": round(sharp_mismatch, 4),
        }

    @staticmethod
    def score_features(f: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
        signals: list[dict[str, Any]] = []

        def add(name: str, label: str, weight: float, value: Any) -> None:
            signals.append({"name": name, "label": label, "weight": round(weight, 4), "value": value})

        z = -2.2
        if f.get("blur_variance", 999) < 60:
            z += 0.8
            add("low_image_quality", "Image is blurry (low Laplacian variance)", 0.8, f["blur_variance"])
        if not (40 <= f.get("brightness", 128) <= 220):
            z += 0.4
            add("exposure_anomaly", "Under/over-exposed capture", 0.4, f["brightness"])
        if f.get("face_detection_available") and f.get("faces_detected", 1) == 0:
            z += 1.0
            add("no_face_detected", "No face detected in identity image", 1.0, 0)
        if f.get("faces_detected", 0) > 1:
            z += 0.9
            add("multiple_faces", "Multiple faces in identity image", 0.9, f["faces_detected"])
        if f.get("ela_block_cv", 0) > 0.9:
            w = min(1.6, (f["ela_block_cv"] - 0.9) * 2 + 0.6)
            z += w
            add("ela_inconsistency", "Inconsistent JPEG error levels (possible splice)", w, f["ela_block_cv"])
        if f.get("noise_block_cv", 0) > 1.1:
            w = min(1.2, (f["noise_block_cv"] - 1.1) + 0.5)
            z += w
            add("noise_inconsistency", "Inconsistent sensor-noise pattern across regions", w, f["noise_block_cv"])
        if f.get("face_background_sharpness_mismatch", 0) > 1.5:
            z += 0.9
            add("face_sharpness_mismatch", "Face sharpness inconsistent with background", 0.9,
                f["face_background_sharpness_mismatch"])
        if f.get("liveness_score") is not None and f["liveness_score"] < 0.5:
            w = (0.5 - f["liveness_score"]) * 4
            z += w
            add("liveness_failed", "Low liveness score", w, f["liveness_score"])
        if f.get("face_match_score") is not None and f["face_match_score"] < 0.6:
            w = (0.6 - f["face_match_score"]) * 4
            z += w
            add("face_mismatch", "Selfie does not match document photo", w, f["face_match_score"])
        return clamp01(_sigmoid(z)), signals

    # ---------------------------------------------------------------- events
    def detect(self, event: NormalizedEvent, image_features: dict[str, Any] | None = None) -> DetectorResult:
        with Timer() as t:
            md = event.metadata
            feats: dict[str, Any] = dict(image_features or md.get("kyc_features") or {})
            for k in ("liveness_score", "face_match_score"):
                if md.get(k) is not None:
                    feats[k] = float(md[k])
            score, signals = self.score_features(feats)
            mode = "image_heuristics" if image_features or md.get("kyc_features") else "metadata_heuristics"
            controlled = md.get("demo_manipulation_score")
            if controlled is not None:
                score = clamp01(float(controlled))
                mode = "controlled_scenario_value"
                signals.append({
                    "name": "kyc_manipulation", "label": "Media manipulation / deepfake-risk indicator",
                    "weight": round(score, 4), "value": score,
                })
            elif score >= 0.5:
                signals.append({"name": "kyc_manipulation", "label": "Media manipulation / deepfake-risk indicator",
                                "weight": round(score, 4), "value": round(score, 4)})
            confidence = 0.35 if mode == "controlled_scenario_value" else (0.5 if feats else 0.25)
        self.stats.record(t.ms)
        return make_result(
            detector=self.name, channel=self.channel, score=score, confidence=confidence,
            signal_details=signals, model_version=self.version_label, latency_ms=t.ms,
            details={
                "display_name": DISPLAY_NAME,
                "disclaimer": DISCLAIMER,
                "mode": mode,
                "manipulation_score": round(score, 4),
                "features": feats,
            },
        )
