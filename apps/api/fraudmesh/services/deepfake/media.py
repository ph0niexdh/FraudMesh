"""Media validation and frame extraction.

Type is decided from magic bytes (never from the filename or client content-type),
sizes and dimensions are bounded, and videos are decoded from a private temp file
that is deleted immediately afterwards.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass

import cv2
import numpy as np

MAX_PIXELS = 40_000_000
MAX_VIDEO_SECONDS = 30


class MediaError(ValueError):
    pass


@dataclass
class Media:
    kind: str  # image | video
    container: str
    sha256: str
    frames: list[np.ndarray]  # BGR
    frame_times: list[float]
    width: int
    height: int
    duration_s: float | None
    fps: float | None
    total_frames: int


def sniff(data: bytes) -> tuple[str, str]:
    if data[:3] == b"\xff\xd8\xff":
        return "image", "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image", "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image", "webp"
    if data[4:8] == b"ftyp":
        return "video", "mp4"
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return "video", "webm"
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "video", "avi"
    raise MediaError("unsupported media type (accepted: JPEG, PNG, WebP, MP4/MOV, WebM, AVI)")


def load(data: bytes, max_bytes: int, max_frames: int) -> Media:
    if not data:
        raise MediaError("empty upload")
    if len(data) > max_bytes:
        raise MediaError(f"file too large (max {max_bytes // (1024 * 1024)} MB)")
    kind, container = sniff(data)
    digest = hashlib.sha256(data).hexdigest()
    if kind == "image":
        arr = np.frombuffer(data, np.uint8)
        # check declared size before full decode (decompression-bomb guard)
        header = cv2.imdecode(arr, cv2.IMREAD_REDUCED_GRAYSCALE_8)
        if header is None:
            raise MediaError("image could not be decoded")
        if header.shape[0] * header.shape[1] * 64 > MAX_PIXELS:
            raise MediaError("image dimensions too large")
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise MediaError("image could not be decoded")
        return Media("image", container, digest, [img], [0.0], img.shape[1], img.shape[0], None, None, 1)

    fd, path = tempfile.mkstemp(suffix=f".{container}")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            raise MediaError("video could not be decoded")
        fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        frames_all: list[np.ndarray] = []
        if total <= 0:  # some WebM streams report no count: decode sequentially (bounded)
            while len(frames_all) < 900:
                ok, fr = cap.read()
                if not ok:
                    break
                frames_all.append(fr)
            total = len(frames_all)
        duration = total / fps if fps > 0 else None
        if duration and duration > MAX_VIDEO_SECONDS:
            raise MediaError(f"video too long (max {MAX_VIDEO_SECONDS}s)")
        if total == 0:
            raise MediaError("video has no frames")
        idxs = sorted(set(np.linspace(0, total - 1, num=min(max_frames, total)).astype(int).tolist()))
        frames, times = [], []
        for i in idxs:
            if frames_all:
                fr = frames_all[i]
            else:
                cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                ok, fr = cap.read()
                if not ok:
                    continue
            if fr.shape[0] * fr.shape[1] > MAX_PIXELS:
                raise MediaError("video resolution too large")
            frames.append(fr)
            times.append(round(i / fps, 3) if fps > 0 else float(i))
        cap.release()
        if not frames:
            raise MediaError("no decodable frames")
        h, w = frames[0].shape[:2]
        return Media("video", container, digest, frames, times, w, h, duration, fps or None, total)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
