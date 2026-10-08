"""Deepfake and KYC pipelines on the controlled fixtures (real pretrained models)."""

from __future__ import annotations

import cv2
import numpy as np
import pytest

from fraudmesh.services.deepfake import pipeline
from fraudmesh.services.deepfake.media import MediaError
from fraudmesh.services.kyc import pipeline as kyc

from .conftest import fixture_bytes

pytestmark = pytest.mark.slow


def test_real_portrait_is_real():
    r = pipeline.analyze_bytes(fixture_bytes("real_portrait.png"), include_visuals=False)
    assert r["verdict"] == "REAL_PERSON"
    assert r["deepfake_probability"] < 0.4
    assert r["model"]["architecture"].startswith("EfficientNet-B4")
    assert "embedding" in r and len(r["embedding"]) == 128


def test_face_swap_is_flagged_with_evidence():
    r = pipeline.analyze_bytes(fixture_bytes("deepfake_faceswap.png"), include_visuals=True)
    assert r["verdict"] in ("DEEPFAKE_LIKELY", "HIGH_CONFIDENCE_DEEPFAKE")
    assert r["deepfake_probability"] >= 0.7
    assert r["explanation"]["suspicious_regions"] and r["explanation"]["heatmap_png_b64"]
    assert r["artifacts"]["aggregate"] > 0.2
    assert "not proof" in r["explanation"]["caveat"] or "not a manipulation mask" in r["explanation"]["caveat"]
    assert r["disclaimer"]


def test_screen_replay_is_presentation_attack():
    r = pipeline.analyze_bytes(fixture_bytes("replay_attack.png"), include_visuals=False)
    assert r["verdict"] == "POSSIBLE_SPOOF"
    assert r["liveness"]["status"] == "FAILED"


def test_video_frame_level_scores():
    r = pipeline.analyze_bytes(fixture_bytes("deepfake_selfie.mp4"), include_visuals=False)
    assert r["media"]["type"] == "video" and len(r["frames"]) >= 3
    assert r["deepfake_probability"] >= 0.7 and r["suspicious_frames"]
    real = pipeline.analyze_bytes(fixture_bytes("real_selfie.mp4"), include_visuals=False)
    assert real["deepfake_probability"] < 0.3


def test_no_face_is_inconclusive_not_real():
    img = np.full((300, 300, 3), 180, np.uint8)
    ok, buf = cv2.imencode(".png", img)
    r = pipeline.analyze_bytes(buf.tobytes())
    assert r["verdict"] == "INCONCLUSIVE" and r["deepfake_probability"] is None


def test_media_validation_rejects_garbage():
    with pytest.raises(MediaError):
        pipeline.analyze_bytes(b"MZ\x90\x00 not an image at all")
    with pytest.raises(MediaError):
        pipeline.analyze_bytes(b"")


def test_kyc_genuine_document_and_selfie_approved():
    r = kyc.verify(fixture_bytes("id_document_genuine.png"), fixture_bytes("real_portrait.png"))
    assert r["document_type"] == "NATIONAL_ID" and r["mrz"]["valid"]
    assert r["face_match"]["matched"]
    assert r["decision"] == "APPROVE", r["checks"]
    assert "*" in r["fields"]["document_number"]  # masked


def test_kyc_tampered_document_rejected_with_reasons():
    r = kyc.verify(fixture_bytes("id_document_tampered.png"), fixture_bytes("deepfake_faceswap.png"))
    failed = {c["id"] for c in r["checks"] if c["status"] == "FAIL"}
    assert {"dob_consistency", "portrait_manipulation", "selfie_deepfake"} <= failed
    assert r["decision"] == "REJECT" and r["scores"]["overall_identity_risk"] > 90


def test_kyc_document_reuse_check():
    r = kyc.verify(fixture_bytes("id_document_genuine.png"))
    r = kyc.apply_reuse_check(r, "cust_someone_else", "cust_me")
    assert any(c["id"] == "document_reuse" and c["status"] == "FAIL" for c in r["checks"])
