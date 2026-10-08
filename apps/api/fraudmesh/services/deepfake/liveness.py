"""Presentation-attack (liveness) signals.

Three tiers, reported separately so their strength is never overstated:

1. **Passive, single image** – screen-replay / print cues: moiré periodicity, specular
   glare, display-bezel edges. A single image can *fail* liveness but cannot prove it,
   so the best outcome is INCONCLUSIVE.
2. **Passive, multi-frame** – a live face shows *non-rigid* motion (eyes, mouth move
   relative to the head); a photo or a looped frame moves rigidly or not at all.
3. **Active challenge** – the user is asked to turn their head; the yaw trajectory
   from the landmarks must show the requested movement.
"""

from __future__ import annotations

import cv2
import numpy as np

from fraudmesh.services.deepfake.face import Face, FaceAnalyzer


def _moire_score(gray_face: np.ndarray) -> float:
    """Isolated periodic peaks in the mid/high-frequency spectrum (screen pixel grid
    beating against the camera sensor). Natural faces, JPEG blocking and video
    compression give a smooth spectrum: max/p99 ≈ 2-3. Screen recaptures: ≫ 5."""
    g = cv2.resize(gray_face, (256, 256)).astype(np.float32)
    g = g - cv2.GaussianBlur(g, (0, 0), 3)  # keep mid/high frequencies
    spec = np.abs(np.fft.fftshift(np.fft.fft2(g)))
    yy, xx = np.mgrid[-128:128, -128:128]
    rad = np.sqrt(xx**2 + yy**2)
    vals = spec[(rad > 20) & (rad < 110)]
    isolation = float(vals.max() / (np.percentile(vals, 99) + 1e-6))
    return float(np.clip((isolation - 4.0) / 8.0, 0, 1))


def _glare_score(bgr_face: np.ndarray) -> float:
    hsv = cv2.cvtColor(bgr_face, cv2.COLOR_BGR2HSV)
    spec = (hsv[..., 2] > 245) & (hsv[..., 1] < 30)
    frac = float(spec.mean())
    return float(np.clip((frac - 0.01) / 0.06, 0, 1))


def _bezel_score(bgr: np.ndarray, face: Face) -> float:
    """Long straight edges framing the face (phone/monitor/photo border)."""
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 80, 200)
    x, y, w, h = face.box
    min_len = int(max(w, h) * 1.2)
    lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=120, minLineLength=min_len, maxLineGap=6)
    if lines is None:
        return 0.0
    cx, cy = x + w / 2, y + h / 2
    framing = 0
    for x1, y1, x2, y2 in np.asarray(lines).reshape(-1, 4):
        horizontal = abs(y2 - y1) < 0.05 * abs(x2 - x1 + 1e-6)
        vertical = abs(x2 - x1) < 0.05 * abs(y2 - y1 + 1e-6)
        if not (horizontal or vertical):
            continue
        # line must lie outside the face but close to it, spanning across it
        if horizontal and min(x1, x2) < cx < max(x1, x2) and h * 0.6 < abs((y1 + y2) / 2 - cy) < h * 1.6:
            framing += 1
        if vertical and min(y1, y2) < cy < max(y1, y2) and w * 0.6 < abs((x1 + x2) / 2 - cx) < w * 1.6:
            framing += 1
    return float(np.clip(framing / 3.0, 0, 1))


def passive_image(bgr: np.ndarray, face: Face) -> dict:
    crop, _ = FaceAnalyzer.crop(bgr, face, 1.0)
    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
    signals = {
        "moire": round(_moire_score(gray), 3),
        "specular_glare": round(_glare_score(crop), 3),
        "display_bezel": round(_bezel_score(bgr, face), 3),
    }
    spoof = float(np.clip(0.5 * signals["moire"] + 0.25 * signals["specular_glare"] + 0.35 * signals["display_bezel"], 0, 1))
    return {"signals": signals, "spoof_probability": round(spoof, 3)}


def temporal(frames: list[np.ndarray], faces: list[Face | None]) -> dict:
    tracked = [(f, fc) for f, fc in zip(frames, faces) if fc is not None]
    if len(tracked) < 3:
        return {"available": False, "reason": "fewer than 3 frames with a face"}
    norm = []
    yaws = []
    for _, fc in tracked:
        x, y, w, h = fc.box
        norm.append(((fc.landmarks - [x, y]) / [w, h]).flatten())
        yaws.append(FaceAnalyzer.pose(fc)["yaw"])
    norm = np.array(norm)
    nonrigid = float(norm.std(0).mean())  # landmark motion relative to the face box
    centers = np.array([[fc.box[0] + fc.box[2] / 2, fc.box[1] + fc.box[3] / 2] for _, fc in tracked])
    widths = np.array([fc.box[2] for _, fc in tracked])
    rigid = float((np.linalg.norm(np.diff(centers, axis=0), axis=1) / widths[1:]).mean())
    diffs = [float(np.abs(a.astype(np.int16) - b.astype(np.int16)).mean()) for (a, _), (b, _) in zip(tracked, tracked[1:])]
    duplicate_frac = float(np.mean([d < 0.5 for d in diffs]))
    return {
        "available": True,
        "frames_with_face": len(tracked),
        "nonrigid_motion": round(nonrigid, 4),
        "rigid_motion": round(rigid, 4),
        "duplicate_frame_fraction": round(duplicate_frac, 3),
        "yaw_range": round(float(max(yaws) - min(yaws)), 3),
        "yaw_track": [round(v, 3) for v in yaws],
    }


def evaluate(image_signals: list[dict], temporal_signals: dict | None, challenge: str | None) -> dict:
    spoof_img = max((s["spoof_probability"] for s in image_signals), default=0.0)
    reasons: list[str] = []
    mode = "passive_image"
    live_evidence = 0.0
    spoof = spoof_img
    if spoof_img >= 0.5:
        reasons.append("screen/print replay cues detected (moiré, glare or display bezel)")

    if temporal_signals and temporal_signals.get("available"):
        mode = "passive_video"
        nr = temporal_signals["nonrigid_motion"]
        dup = temporal_signals["duplicate_frame_fraction"]
        if dup > 0.6:
            spoof = max(spoof, 0.85)
            reasons.append("frames are near-identical (static image or injected loop)")
        elif nr < 0.004:
            spoof = max(spoof, 0.6)
            reasons.append("face moves only rigidly — consistent with a held-up photo or screen")
        else:
            live_evidence = float(np.clip((nr - 0.004) / 0.01, 0, 1))
        if challenge:
            mode = "active_challenge"
            yaw_range = temporal_signals["yaw_range"]
            if yaw_range >= 0.22:
                live_evidence = max(live_evidence, 0.9)
                reasons.append(f"head-turn challenge completed (yaw range {yaw_range:.2f})")
            else:
                spoof = max(spoof, 0.55)
                reasons.append(f"head-turn challenge not completed (yaw range {yaw_range:.2f} < 0.22)")

    if spoof >= 0.5:
        status = "FAILED"
    elif mode == "passive_image":
        status = "INCONCLUSIVE"
        reasons.append("single image: liveness cannot be confirmed without motion or a challenge")
    elif live_evidence >= 0.5:
        status = "PASSED"
    else:
        status = "INCONCLUSIVE"
    liveness_score = float(np.clip(live_evidence * (1 - spoof), 0, 1))
    return {
        "status": status,
        "mode": mode,
        "liveness_score": round(liveness_score, 3),
        "spoof_probability": round(float(spoof), 3),
        "reasons": reasons,
    }
