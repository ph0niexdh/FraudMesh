"""KYC document verification.

    upload → file validation → OCR → document classification → field extraction
           → face extraction → face match → deepfake analysis → consistency checks → KYC risk

The function is synchronous/CPU-bound (run it in a worker thread). Database-backed
checks (document number re-use across customers) are supplied by the caller.
"""

from __future__ import annotations

import re
import time
from datetime import date

import cv2
import numpy as np

from fraudmesh.core.crypto import hmac_hex
from fraudmesh.core.privacy import mask_document
from fraudmesh.services.deepfake import pipeline as deepfake
from fraudmesh.services.deepfake.face import SFACE_COSINE_THRESHOLD, FaceAnalyzer
from fraudmesh.services.deepfake.media import MediaError, sniff
from fraudmesh.services.kyc import mrz as mrz_mod
from fraudmesh.services.kyc import ocr

LABELS = {
    "surname": ("SURNAME", "LAST NAME"),
    "given_names": ("GIVEN NAMES", "GIVEN NAME", "FIRST NAME"),
    "date_of_birth": ("DATE OF BIRTH", "DOB", "BIRTH"),
    "document_number": ("DOCUMENT NO", "DOCUMENT NUMBER", "ID NO", "CARD NO", "PASSPORT NO"),
    "date_of_expiry": ("DATE OF EXPIRY", "EXPIRY", "VALID UNTIL", "EXPIRES"),
    "nationality": ("NATIONALITY",),
}
DOC_TYPES = (
    ("PASSPORT", ("PASSPORT",)),
    ("NATIONAL_ID", ("IDENTITY CARD", "NATIONAL ID", "ID CARD")),
    ("DRIVING_LICENCE", ("DRIVING LICENCE", "DRIVER LICENSE", "DRIVING LICENSE")),
)
_SEVERITY_WEIGHT = {"critical": 45.0, "high": 25.0, "medium": 12.0, "low": 5.0}


def _norm(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", s.upper())


def classify(text_lines: list[str], mrz: dict | None) -> tuple[str, float]:
    joined = _norm(" ".join(text_lines))
    for doc_type, keys in DOC_TYPES:
        if any(_norm(k) in joined for k in keys):
            return doc_type, 0.9 if mrz else 0.75
    if mrz:
        return ("PASSPORT" if mrz["format"] == "TD3" else "NATIONAL_ID"), 0.7
    return "UNKNOWN", 0.2


def extract_fields(lines: list[ocr.OcrLine]) -> dict[str, dict]:
    """Label/value pairing: the value is the nearest OCR line directly below (or right of) a label."""
    out: dict[str, dict] = {}
    for field, labels in LABELS.items():
        nlabels = [_norm(l) for l in labels]
        for i, line in enumerate(lines):
            if not any(nl == _norm(line.text) or (len(nl) > 4 and nl in _norm(line.text)) for nl in nlabels):
                continue
            below = [
                l for l in lines
                if l is not line and 0 < l.y - line.y < 60 and abs(l.x - line.x) < 40
            ]
            if below:
                val = min(below, key=lambda l: l.y - line.y)
                out[field] = {"value": val.text.strip(), "confidence": round(val.confidence, 3)}
                break
    return out


def _parse_date(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().replace("/", "-").replace(".", "-")
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s) or None
    if m:
        try:
            return date(int(m[1]), int(m[2]), int(m[3])).isoformat()
        except ValueError:
            return None
    m = re.fullmatch(r"(\d{2})-(\d{2})-(\d{4})", s)
    if m:
        try:
            return date(int(m[3]), int(m[2]), int(m[1])).isoformat()
        except ValueError:
            return None
    return None


def _check(cid: str, name: str, status: str, severity: str, detail: str) -> dict:
    return {"id": cid, "name": name, "status": status, "severity": severity, "detail": detail}


def verify(
    document: bytes,
    selfie: bytes | None = None,
    reference_embedding: np.ndarray | None = None,
    duplicate_owner_lookup=None,
    customer_id: str | None = None,
) -> dict:
    t0 = time.perf_counter()
    stages: dict[str, float] = {}

    def mark(name: str, t: float) -> float:
        now = time.perf_counter()
        stages[name] = round((now - t) * 1000, 1)
        return now

    t = time.perf_counter()
    kind, container = sniff(document)
    if kind != "image":
        raise MediaError("identity document must be an image (JPEG, PNG or WebP)")
    if len(document) > 15 * 1024 * 1024:
        raise MediaError("document image too large (max 15 MB)")
    img = cv2.imdecode(np.frombuffer(document, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise MediaError("document could not be decoded")
    if max(img.shape[:2]) > 2400:
        s = 2400 / max(img.shape[:2])
        img = cv2.resize(img, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
    t = mark("file_validation", t)

    lines, _ = ocr.read(img)
    texts = [l.text for l in lines]
    t = mark("ocr", t)

    mrz = mrz_mod.parse(texts)
    doc_type, type_conf = classify(texts, mrz)
    t = mark("document_classification", t)

    printed = extract_fields(lines)
    t = mark("field_extraction", t)

    eng = deepfake.engine()
    doc_faces = eng.faces.detect(img) if eng.faces else []
    doc_face = doc_faces[0] if doc_faces else None
    doc_embedding = eng.faces.embed(img, doc_face) if (eng.faces and doc_face) else None
    t = mark("face_extraction", t)

    # deepfake / manipulation analysis of the document portrait (no liveness: it is a photo)
    doc_portrait_analysis = None
    if doc_face is not None:
        crop, _ = FaceAnalyzer.crop(img, doc_face, 1.6)
        ok, enc = cv2.imencode(".png", crop)
        if ok:
            doc_portrait_analysis = deepfake.analyze_bytes(enc.tobytes(), include_visuals=False, assess_liveness=False)
            doc_portrait_analysis.pop("embedding", None)

    selfie_analysis = None
    if selfie:
        selfie_analysis = deepfake.analyze_bytes(selfie, include_visuals=True)
    t = mark("deepfake_analysis", t)

    # face match: document portrait ↔ selfie (preferred) or ↔ enrolled template
    face_match: dict = {"available": False}
    probe = None
    probe_source = None
    if selfie_analysis and selfie_analysis.get("embedding"):
        probe, probe_source = np.array(selfie_analysis["embedding"], np.float32), "selfie"
    elif reference_embedding is not None:
        probe, probe_source = reference_embedding, "enrolled_template"
    if doc_embedding is not None and probe is not None:
        sim = FaceAnalyzer.similarity(doc_embedding, probe)
        face_match = {"available": True, "similarity": round(sim, 3), "threshold": SFACE_COSINE_THRESHOLD,
                      "matched": sim >= SFACE_COSINE_THRESHOLD, "compared_with": probe_source}
    t = mark("face_match", t)

    # ---------------- consistency checks
    checks: list[dict] = []
    p_dob = _parse_date(printed.get("date_of_birth", {}).get("value"))
    p_exp = _parse_date(printed.get("date_of_expiry", {}).get("value"))
    p_num = (printed.get("document_number", {}).get("value") or "").replace(" ", "").upper()

    if mrz is None:
        checks.append(_check("mrz_present", "Machine-readable zone", "FAIL", "medium", "No MRZ could be read"))
    else:
        bad = [k for k, ok in mrz["check_digits"].items() if not ok]
        checks.append(_check("mrz_check_digits", "MRZ check digits (ICAO 9303)", "PASS" if not bad else "FAIL",
                             "critical", "all check digits valid" if not bad else f"invalid: {', '.join(bad)}"))
        if p_dob:
            same = p_dob == mrz["date_of_birth"]
            checks.append(_check("dob_consistency", "Printed DOB matches MRZ", "PASS" if same else "FAIL", "critical",
                                 "consistent" if same else f"printed {p_dob} ≠ MRZ {mrz['date_of_birth']}"))
        if p_num:
            same = _norm(p_num) == _norm(mrz["document_number"])
            checks.append(_check("number_consistency", "Printed number matches MRZ", "PASS" if same else "FAIL", "critical",
                                 "consistent" if same else "document number differs between visual zone and MRZ"))
        sname = _norm(printed.get("surname", {}).get("value", ""))
        if sname and mrz["surname"]:
            ok = _norm(mrz["surname"]) in sname or sname in _norm(mrz["surname"])
            checks.append(_check("name_consistency", "Printed name matches MRZ", "PASS" if ok else "WARN", "medium",
                                 "consistent" if ok else "surname differs between visual zone and MRZ"))

    expiry = p_exp or (mrz or {}).get("date_of_expiry")
    if expiry:
        valid = expiry >= date.today().isoformat()
        checks.append(_check("not_expired", "Document not expired", "PASS" if valid else "FAIL", "high", f"expires {expiry}"))
    dob = (mrz or {}).get("date_of_birth") or p_dob
    if dob:
        age = (date.today() - date.fromisoformat(dob)).days / 365.25
        ok = 18 <= age <= 110
        checks.append(_check("age_plausible", "Age plausible (18-110)", "PASS" if ok else "FAIL", "high", f"age {age:.0f}"))

    if doc_face is None:
        checks.append(_check("portrait_present", "Document portrait found", "FAIL", "high", "no face detected on document"))
    else:
        checks.append(_check("portrait_present", "Document portrait found", "PASS", "high", f"detection score {doc_face.score:.2f}"))
    if doc_portrait_analysis and doc_portrait_analysis.get("deepfake_probability") is not None:
        p = doc_portrait_analysis["deepfake_probability"]
        status = "FAIL" if p >= 0.7 else ("WARN" if p >= 0.4 else "PASS")
        checks.append(_check("portrait_manipulation", "Document portrait not manipulated", status, "critical",
                             f"deepfake probability {p:.2f} ({doc_portrait_analysis['model']['architecture']})"))
    if face_match.get("available"):
        checks.append(_check("face_match", f"Document portrait matches {face_match['compared_with'].replace('_', ' ')}",
                             "PASS" if face_match["matched"] else "FAIL", "critical",
                             f"cosine similarity {face_match['similarity']:.2f} (threshold {SFACE_COSINE_THRESHOLD})"))
    if selfie_analysis and selfie_analysis.get("deepfake_probability") is not None:
        p = selfie_analysis["deepfake_probability"]
        status = "FAIL" if p >= 0.7 else ("WARN" if p >= 0.4 else "PASS")
        checks.append(_check("selfie_deepfake", "Selfie is not a deepfake", status, "critical", f"{selfie_analysis['verdict']} (p={p:.2f})"))
        if selfie_analysis["liveness"]["status"] == "FAILED":
            checks.append(_check("selfie_liveness", "Selfie liveness", "FAIL", "high", "; ".join(selfie_analysis["liveness"]["reasons"])))

    doc_hmac = hmac_hex(f"doc:{_norm((mrz or {}).get('document_number') or p_num)}") if (mrz or p_num) else None
    if doc_hmac and duplicate_owner_lookup is not None:
        owner = duplicate_owner_lookup(doc_hmac)
        if owner and owner != customer_id:
            checks.append(_check("document_reuse", "Document not registered to another customer", "FAIL", "critical",
                                 "this document number was already used by a different customer (possible synthetic identity)"))
        else:
            checks.append(_check("document_reuse", "Document not registered to another customer", "PASS", "critical", "no conflicting registration"))

    if "SPECIMEN" in _norm(" ".join(texts)):
        checks.append(_check("specimen_marker", "Specimen marking", "WARN", "low", "document carries a SPECIMEN marking (test document)"))
    t = mark("consistency_checks", t)

    # ---------------- scores
    ocr_conf = float(np.mean([l.confidence for l in lines])) if lines else 0.0
    field_cov = len(printed) / len(LABELS)
    mrz_ok = 1.0 if (mrz and mrz["valid"]) else (0.5 if mrz else 0.3)
    document_confidence = float(np.clip(ocr_conf * (0.4 + 0.6 * field_cov) * (0.5 + 0.5 * mrz_ok) * (0.6 + 0.4 * type_conf), 0, 1))

    kyc_risk = 0.0
    for c in checks:
        if c["status"] == "FAIL":
            kyc_risk += _SEVERITY_WEIGHT[c["severity"]]
        elif c["status"] == "WARN":
            kyc_risk += _SEVERITY_WEIGHT[c["severity"]] * 0.35
    kyc_risk = float(min(100.0, kyc_risk + (1 - document_confidence) * 15))

    deepfake_risk = max(
        (selfie_analysis or {}).get("risk_score") or 0.0,
        (doc_portrait_analysis or {}).get("risk_score") or 0.0,
    )
    match_score = face_match.get("similarity")
    identity_confidence = float(np.clip(
        (0.35 + 0.65 * max(0.0, (match_score - 0.2) / 0.5) if match_score is not None else 0.5)
        * (1 - deepfake_risk / 100) * (0.5 + 0.5 * document_confidence), 0, 1))
    # noisy-OR: independent failure modes compound
    overall = 100 * (1 - (1 - kyc_risk / 100) * (1 - deepfake_risk / 100))
    decision = "APPROVE" if overall < 35 else ("REVIEW" if overall < 65 else "REJECT")

    fields_masked = {
        "surname": (mrz or {}).get("surname") or printed.get("surname", {}).get("value"),
        "given_names": (mrz or {}).get("given_names") or printed.get("given_names", {}).get("value"),
        "document_number": mask_document((mrz or {}).get("document_number") or p_num),
        "date_of_birth": (dob[:4] + "-**-**") if dob else None,
        "date_of_expiry": expiry,
        "nationality": (mrz or {}).get("nationality") or printed.get("nationality", {}).get("value"),
        "sex": (mrz or {}).get("sex"),
    }
    if selfie_analysis:
        selfie_analysis.pop("embedding", None)
    return {
        "document_type": doc_type,
        "document_type_confidence": round(type_conf, 2),
        "fields": fields_masked,
        "mrz": {"present": mrz is not None, "format": (mrz or {}).get("format"), "valid": (mrz or {}).get("valid"),
                "check_digits": (mrz or {}).get("check_digits")},
        "ocr": {"engine": ocr.ENGINE_NAME, "lines": len(lines), "mean_confidence": round(ocr_conf, 3)},
        "document_portrait": {"found": doc_face is not None, "analysis": _slim(doc_portrait_analysis)},
        "selfie": selfie_analysis,
        "face_match": face_match,
        "checks": checks,
        "scores": {
            "kyc_risk": round(kyc_risk, 1),
            "deepfake_risk": round(deepfake_risk, 1),
            "document_confidence": round(document_confidence, 3),
            "identity_confidence": round(identity_confidence, 3),
            "overall_identity_risk": round(overall, 1),
        },
        "decision": decision,
        "doc_number_hmac": doc_hmac,
        "document_embedding": doc_embedding.tolist() if doc_embedding is not None else None,
        "stages_ms": stages,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def _slim(a: dict | None) -> dict | None:
    if not a:
        return None
    return {k: a.get(k) for k in ("verdict", "deepfake_probability", "confidence", "risk_score", "artifacts", "reason_codes")}
