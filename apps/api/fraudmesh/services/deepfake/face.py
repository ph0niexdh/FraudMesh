"""Face detection, quality, alignment and embeddings.

* Detection: YuNet (OpenCV Zoo, ``face_detection_yunet_2023mar.onnx``, MIT) — box,
  5 landmarks, confidence.
* Embeddings: SFace (OpenCV Zoo, ``face_recognition_sface_2021dec.onnx``, Apache-2.0)
  — 128-d, cosine similarity; OpenCV's published same-identity threshold is 0.363.

Only embeddings leave this module for storage; raw crops stay in memory.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

import cv2
import numpy as np

try:  # silence OpenCV DNN backend notices
    cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_ERROR)
except AttributeError:  # pragma: no cover
    pass

SFACE_COSINE_THRESHOLD = 0.363  # OpenCV Zoo reference threshold for SFace
CROP_SCALE = 1.3  # DeepfakeBench crops faces with a 1.3x margin


@dataclass
class Face:
    box: tuple[float, float, float, float]  # x, y, w, h in image pixels
    landmarks: np.ndarray  # (5, 2): right eye, left eye, nose tip, right mouth, left mouth
    score: float
    raw: np.ndarray  # YuNet row (needed by SFace alignCrop)
    quality: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        x, y, w, h = self.box
        return {
            "box": [round(float(x), 1), round(float(y), 1), round(float(w), 1), round(float(h), 1)],
            "detection_score": round(float(self.score), 3),
            "landmarks": [[round(float(a), 1), round(float(b), 1)] for a, b in self.landmarks],
            "quality": self.quality,
        }


class FaceAnalyzer:
    def __init__(self, model_dir: Path):
        det_path = model_dir / "face_detection_yunet_2023mar.onnx"
        rec_path = model_dir / "face_recognition_sface_2021dec.onnx"
        if not det_path.exists():
            raise FileNotFoundError(det_path)
        self._det = cv2.FaceDetectorYN.create(str(det_path), "", (320, 320), 0.6, 0.3, 5000)
        self._rec = cv2.FaceRecognizerSF.create(str(rec_path), "") if rec_path.exists() else None
        self._lock = threading.Lock()
        self.detector_version = "yunet-2023mar"
        self.embedder_version = "sface-2021dec" if self._rec else None

    # ------------------------------------------------------------------ detection
    def detect(self, bgr: np.ndarray) -> list[Face]:
        h, w = bgr.shape[:2]
        scale = 1.0
        img = bgr
        if max(h, w) > 1280:  # bound compute; coordinates are scaled back
            scale = 1280 / max(h, w)
            img = cv2.resize(bgr, (int(w * scale), int(h * scale)))
        with self._lock:
            self._det.setInputSize((img.shape[1], img.shape[0]))
            _, faces = self._det.detect(img)
        out: list[Face] = []
        if faces is None:
            return out
        for row in faces:
            row = row.copy()
            row[:14] /= scale
            out.append(Face(box=tuple(row[:4]), landmarks=row[4:14].reshape(5, 2), score=float(row[14]), raw=row))
        out.sort(key=lambda f: f.box[2] * f.box[3], reverse=True)
        for f in out:
            f.quality = self.quality(bgr, f)
        return out

    @staticmethod
    def crop(bgr: np.ndarray, face: Face, scale: float = CROP_SCALE) -> tuple[np.ndarray, tuple[int, int, int, int]]:
        """Square crop around the face with a margin (DeepfakeBench-style)."""
        h, w = bgr.shape[:2]
        x, y, bw, bh = face.box
        cx, cy = x + bw / 2, y + bh / 2
        side = max(bw, bh) * scale
        x0, y0 = int(max(0, cx - side / 2)), int(max(0, cy - side / 2))
        x1, y1 = int(min(w, cx + side / 2)), int(min(h, cy + side / 2))
        return bgr[y0:y1, x0:x1].copy(), (x0, y0, x1 - x0, y1 - y0)

    # ------------------------------------------------------------------ quality
    @staticmethod
    def pose(face: Face) -> dict:
        re, le, nose, rm, lm = face.landmarks
        eye_mid = (re + le) / 2
        inter = np.linalg.norm(le - re) + 1e-6
        yaw = float((nose[0] - eye_mid[0]) / inter)  # ~0 frontal; ±0.5 strongly turned
        roll = float(np.degrees(np.arctan2(le[1] - re[1], le[0] - re[0])))
        mouth_mid = (rm + lm) / 2
        pitch = float((nose[1] - eye_mid[1]) / (np.linalg.norm(mouth_mid - eye_mid) + 1e-6))
        return {"yaw": round(yaw, 3), "roll_deg": round(roll, 1), "pitch_ratio": round(pitch, 3)}

    def quality(self, bgr: np.ndarray, face: Face) -> dict:
        crop, _ = self.crop(bgr, face, 1.0)
        if crop.size == 0:
            return {"usable": False}
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
        sharp = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        bright = float(gray.mean())
        contrast = float(gray.std())
        size = float(min(face.box[2], face.box[3]))
        p = self.pose(face)
        issues = []
        if size < 80:
            issues.append("face_too_small")
        if sharp < 40:
            issues.append("blurry")
        if bright < 50:
            issues.append("too_dark")
        if bright > 215:
            issues.append("overexposed")
        if abs(p["yaw"]) > 0.35 or abs(p["roll_deg"]) > 25:
            issues.append("non_frontal")
        score = 1.0
        score *= min(1.0, size / 160)
        score *= min(1.0, sharp / 120)
        score *= 1.0 if 50 <= bright <= 215 else 0.6
        score *= 1.0 if abs(p["yaw"]) <= 0.35 else 0.7
        return {
            "usable": not ({"face_too_small", "blurry"} & set(issues)),
            "score": round(float(score), 3),
            "sharpness": round(sharp, 1),
            "brightness": round(bright, 1),
            "contrast": round(contrast, 1),
            "face_px": round(size, 1),
            "pose": p,
            "issues": issues,
        }

    # ------------------------------------------------------------------ embeddings
    def embed(self, bgr: np.ndarray, face: Face) -> np.ndarray | None:
        if self._rec is None:
            return None
        with self._lock:
            aligned = self._rec.alignCrop(bgr, face.raw)
            feat = self._rec.feature(aligned)
        v = feat.flatten().astype(np.float32)
        return v / (np.linalg.norm(v) + 1e-9)

    @staticmethod
    def similarity(a: np.ndarray, b: np.ndarray) -> float:
        return float(np.dot(a / (np.linalg.norm(a) + 1e-9), b / (np.linalg.norm(b) + 1e-9)))
