"""OCR engine wrapper.

RapidOCR runs the PaddleOCR (PP-OCR) detection + recognition models through ONNX
Runtime; the models ship inside the wheel, so it works offline and without the
PaddlePaddle runtime.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import numpy as np

_lock = threading.Lock()
_engine = None
_error: str | None = None
ENGINE_NAME = "PaddleOCR PP-OCR (via RapidOCR / ONNX Runtime)"


@dataclass
class OcrLine:
    text: str
    confidence: float
    box: list[list[float]]  # 4 points

    @property
    def x(self) -> float:
        return min(p[0] for p in self.box)

    @property
    def y(self) -> float:
        return min(p[1] for p in self.box)


def _get():
    global _engine, _error
    if _engine is None and _error is None:
        with _lock:
            if _engine is None and _error is None:
                try:
                    from rapidocr_onnxruntime import RapidOCR

                    _engine = RapidOCR()
                except Exception as exc:  # pragma: no cover
                    _error = f"OCR unavailable: {exc}"
    return _engine


def status() -> dict:
    eng = _get()
    return {"status": "ONLINE" if eng else "OFFLINE", "engine": ENGINE_NAME, "error": _error}


def read(bgr: np.ndarray) -> tuple[list[OcrLine], float]:
    eng = _get()
    if eng is None:
        raise RuntimeError(_error or "OCR unavailable")
    t = time.perf_counter()
    with _lock:
        result, _ = eng(bgr)
    lines = [OcrLine(text=str(txt), confidence=float(conf), box=[[float(a), float(b)] for a, b in box]) for box, txt, conf in (result or [])]
    lines.sort(key=lambda l: (round(l.y / 12), l.x))
    return lines, (time.perf_counter() - t) * 1000
