"""Build the controlled demo/test media fixtures (deterministic).

Source face: NASA official portrait bundled with scikit-image as ``skimage.data.astronaut()``
(public domain, NASA). No other people's images are used.

Outputs (tests/fixtures/media):
  real_portrait.png          genuine image
  deepfake_faceswap.png      face-swap-style manipulation (re-synthesised inner face, resampled,
                             colour-shifted and alpha-blended — the artefact family that
                             FaceForensics++-trained detectors respond to; cf. Self-Blended Images, CVPR 2022)
  replay_attack.png          the genuine portrait re-captured from a screen (moiré, glare, bezel)
  real_selfie.mp4            short clip with natural-looking head motion (synthetic motion of the genuine image)
  deepfake_selfie.mp4        the same clip with per-frame manipulation (temporal flicker)
  id_document_genuine.png    SPECIMEN identity card (fictitious identity, valid check digits)
  id_document_tampered.png   SPECIMEN card with edited date of birth and a swapped photo

All documents are watermarked SPECIMEN / NOT A VALID DOCUMENT.
"""

from __future__ import annotations

import json
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from skimage import data

OUT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "media"
YUNET = Path(__file__).resolve().parents[1] / "weights" / "face_detection_yunet_2023mar.onnx"


def detect(img: np.ndarray) -> np.ndarray:
    det = cv2.FaceDetectorYN.create(str(YUNET), "", (img.shape[1], img.shape[0]), 0.6)
    _, faces = det.detect(img)
    return faces[0]


def manipulate(real: np.ndarray, face: np.ndarray, seed: int, shrink: float = 0.4) -> np.ndarray:
    rng = np.random.default_rng(seed)
    h, w = real.shape[:2]
    x, y, bw, bh = [float(v) for v in face[:4]]
    src = real.copy()
    hsv = cv2.cvtColor(src, cv2.COLOR_BGR2HSV).astype(np.float32)
    hsv[..., 0] = (hsv[..., 0] + rng.uniform(-4, 4)) % 180
    hsv[..., 1] *= rng.uniform(0.85, 1.15)
    hsv[..., 2] *= rng.uniform(0.9, 1.1)
    src = cv2.cvtColor(np.clip(hsv, 0, 255).astype(np.uint8), cv2.COLOR_HSV2BGR)
    small = cv2.resize(src, None, fx=shrink, fy=shrink, interpolation=cv2.INTER_AREA)
    src = cv2.resize(small, (w, h), interpolation=cv2.INTER_LINEAR)
    src = cv2.GaussianBlur(src, (3, 3), 0.8)
    m = cv2.getRotationMatrix2D((x + bw / 2, y + bh / 2), rng.uniform(-3, 3), rng.uniform(1.0, 1.05))
    m[:, 2] += rng.uniform(-3, 3, 2)
    src = cv2.warpAffine(src, m, (w, h), borderMode=cv2.BORDER_REFLECT)
    mask = np.zeros((h, w), np.uint8)
    hull = np.array(
        [[x + bw * 0.12, y + bh * 0.18], [x + bw * 0.88, y + bh * 0.18], [x + bw * 0.92, y + bh * 0.7],
         [x + bw * 0.5, y + bh * 1.02], [x + bw * 0.08, y + bh * 0.7]], np.int32)
    cv2.fillConvexPoly(mask, cv2.convexHull(hull), 255)
    alpha = cv2.GaussianBlur(mask, (15, 15), 5).astype(np.float32)[..., None] / 255.0
    return (src * alpha + real * (1 - alpha)).astype(np.uint8)


def replay(real: np.ndarray) -> np.ndarray:
    h, w = real.shape[:2]
    canvas = np.full((int(h * 1.25), int(w * 1.25), 3), 28, np.uint8)  # dark room
    screen = real.astype(np.float32)
    yy, xx = np.mgrid[0:h, 0:w]
    moire = 14 * np.sin(2 * np.pi * (xx * 0.21 + yy * 0.17)) + 10 * np.sin(2 * np.pi * (xx * 0.19 - yy * 0.23))
    screen = np.clip(screen * 0.92 + moire[..., None] + 12, 0, 255)
    glare = np.exp(-(((xx - w * 0.68) / (w * 0.10)) ** 2 + ((yy - h * 0.30) / (h * 0.07)) ** 2))
    screen = np.clip(screen + 255 * glare[..., None], 0, 255).astype(np.uint8)
    oy, ox = (canvas.shape[0] - h) // 2, (canvas.shape[1] - w) // 2
    cv2.rectangle(canvas, (ox - 18, oy - 18), (ox + w + 18, oy + h + 18), (10, 10, 10), -1)  # bezel
    cv2.rectangle(canvas, (ox - 18, oy - 18), (ox + w + 18, oy + h + 18), (200, 200, 200), 2)
    canvas[oy : oy + h, ox : ox + w] = screen
    src = np.float32([[0, 0], [canvas.shape[1], 0], [canvas.shape[1], canvas.shape[0]], [0, canvas.shape[0]]])
    dst = np.float32([[30, 18], [canvas.shape[1] - 12, 0], [canvas.shape[1] - 30, canvas.shape[0] - 10], [8, canvas.shape[0] - 26]])
    return cv2.warpPerspective(canvas, cv2.getPerspectiveTransform(src, dst), (canvas.shape[1], canvas.shape[0]), borderValue=(28, 28, 28))


def video(frames: list[np.ndarray], path: Path, fps: int = 8) -> None:
    h, w = frames[0].shape[:2]
    vw = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h))
    for f in frames:
        vw.write(f)
    vw.release()


def head_motion(real: np.ndarray, face: np.ndarray, n: int = 16) -> list[np.ndarray]:
    """Small yaw-like perspective sway + translation (synthetic motion for pipeline tests)."""
    h, w = real.shape[:2]
    frames = []
    for i in range(n):
        a = np.sin(2 * np.pi * i / n)
        sx = 0.06 * a
        src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
        dst = np.float32([[w * max(0, sx), h * 0.02 * a], [w - w * max(0, -sx), -h * 0.02 * a], [w - w * max(0, -sx), h + h * 0.02 * a], [w * max(0, sx), h - h * 0.02 * a]])
        m = cv2.getPerspectiveTransform(src, dst)
        fr = cv2.warpPerspective(real, m, (w, h), borderMode=cv2.BORDER_REFLECT)
        noise = np.random.default_rng(i).normal(0, 2.0, fr.shape)
        frames.append(np.clip(fr + noise, 0, 255).astype(np.uint8))
    return frames


# ---------------------------------------------------------------- specimen ID documents
def _check_digit(s: str) -> str:
    """ICAO 9303 check digit (weights 7,3,1; A-Z = 10-35, '<' = 0)."""
    total = 0
    for i, ch in enumerate(s):
        if ch.isdigit():
            v = int(ch)
        elif ch.isalpha():
            v = ord(ch.upper()) - 55
        else:
            v = 0
        total += v * (7, 3, 1)[i % 3]
    return str(total % 10)


def id_card(face_img: np.ndarray, fields: dict, mrz_fields: dict, path: Path) -> None:
    W, H = 1012, 638
    card = Image.new("RGB", (W, H), (236, 241, 247))
    d = ImageDraw.Draw(card)
    f_title = ImageFont.load_default(size=30)
    f_lbl = ImageFont.load_default(size=17)
    f_val = ImageFont.load_default(size=27)
    f_mrz = ImageFont.load_default(size=30)
    d.rectangle([0, 0, W, 70], fill=(22, 52, 107))
    d.text((28, 18), "REPUBLIC OF DEMONSTRATIA  ·  IDENTITY CARD", font=f_title, fill=(255, 255, 255))
    face = cv2.cvtColor(face_img, cv2.COLOR_BGR2RGB)
    fh, fw = face.shape[:2]
    side = min(fh, fw)
    face = cv2.resize(face[(fh - side) // 2 : (fh + side) // 2, (fw - side) // 2 : (fw + side) // 2], (250, 300))
    card.paste(Image.fromarray(face), (34, 100))
    y = 100
    for label, key in (("SURNAME", "surname"), ("GIVEN NAMES", "given_names"), ("DATE OF BIRTH", "dob"),
                       ("DOCUMENT NO.", "document_number"), ("DATE OF EXPIRY", "expiry"), ("NATIONALITY", "nationality")):
        d.text((320, y), label, font=f_lbl, fill=(90, 100, 120))
        d.text((320, y + 18), fields[key], font=f_val, fill=(15, 20, 30))
        y += 62
    # watermark
    wm = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(wm).text((520, 120), "SPECIMEN", font=ImageFont.load_default(size=64), fill=(200, 30, 30, 70))
    card = Image.alpha_composite(card.convert("RGBA"), wm).convert("RGB")
    d = ImageDraw.Draw(card)
    d.text((660, 400), "NOT A VALID DOCUMENT", font=f_lbl, fill=(200, 30, 30))
    # TD1-style MRZ (3 lines x 30 chars)
    doc = mrz_fields["document_number"].ljust(9, "<")
    l1 = f"IDDMO{doc}{_check_digit(doc)}".ljust(30, "<")
    dob, exp = mrz_fields["dob"], mrz_fields["expiry"]
    l2 = f"{dob}{_check_digit(dob)}{mrz_fields['sex']}{exp}{_check_digit(exp)}DMO".ljust(29, "<")
    composite = l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
    l2 = l2 + _check_digit(composite)
    name = f"{mrz_fields['surname']}<<{mrz_fields['given'].replace(' ', '<')}".ljust(30, "<")[:30]
    d.rectangle([0, H - 150, W, H], fill=(250, 250, 250))
    for i, line in enumerate((l1, l2, name)):
        d.text((40, H - 140 + i * 44), line, font=f_mrz, fill=(10, 10, 10))
    card.save(path)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    real = cv2.cvtColor(data.astronaut(), cv2.COLOR_RGB2BGR)
    face = detect(real)
    cv2.imwrite(str(OUT / "real_portrait.png"), real)
    fake = manipulate(real, face, seed=0)
    cv2.imwrite(str(OUT / "deepfake_faceswap.png"), fake)
    cv2.imwrite(str(OUT / "replay_attack.png"), replay(real))

    motion = head_motion(real, face)
    video(motion, OUT / "real_selfie.mp4")
    fake_frames = []
    for i, fr in enumerate(motion):
        fc = detect(fr)
        fake_frames.append(manipulate(fr, fc, seed=100 + i, shrink=0.35 + 0.1 * (i % 3)))
    video(fake_frames, OUT / "deepfake_selfie.mp4")

    genuine = {
        "surname": "DEMO-SUBJECT", "given_names": "AVA", "dob": "1984-03-12", "document_number": "DM4827193",
        "expiry": "2031-08-30", "nationality": "DEMONSTRATIA",
    }
    mrz = {"document_number": "DM4827193", "dob": "840312", "expiry": "310830", "sex": "F", "surname": "DEMO", "given": "AVA"}
    id_card(real, genuine, mrz, OUT / "id_document_genuine.png")
    # Tampered: printed DOB edited (MRZ unchanged → check mismatch) and the photo swapped for a manipulated face
    tampered = {**genuine, "dob": "1979-03-12"}
    id_card(fake, tampered, mrz, OUT / "id_document_tampered.png")

    manifest = {
        "real_portrait.png": {"label": "genuine", "kind": "image"},
        "deepfake_faceswap.png": {"label": "manipulated", "kind": "image"},
        "replay_attack.png": {"label": "presentation_attack", "kind": "image"},
        "real_selfie.mp4": {"label": "genuine", "kind": "video"},
        "deepfake_selfie.mp4": {"label": "manipulated", "kind": "video"},
        "id_document_genuine.png": {"label": "genuine_document", "kind": "document"},
        "id_document_tampered.png": {"label": "tampered_document", "kind": "document"},
        "_source": "skimage.data.astronaut() — NASA official portrait, public domain. Documents are fictitious SPECIMENs.",
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("fixtures written to", OUT)


if __name__ == "__main__":
    main()
