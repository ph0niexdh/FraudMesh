"""ICAO Doc 9303 machine-readable-zone parsing with check-digit validation.

Supports TD1 (ID cards, 3x30) and TD3 (passports, 2x44). OCR confusions are
corrected *by field type* (digits-only fields map O→0, I→1, ...; alpha fields map
0→O, 1→I ...), which is how production MRZ readers handle them.
"""

from __future__ import annotations

import re
from datetime import date

_TO_DIGIT = str.maketrans({"O": "0", "Q": "0", "D": "0", "I": "1", "L": "1", "Z": "2", "S": "5", "B": "8", "G": "6"})
_TO_ALPHA = str.maketrans({"0": "O", "1": "I", "2": "Z", "5": "S", "8": "B", "6": "G"})


def check_digit(s: str) -> str:
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


def _clean(line: str) -> str:
    line = line.upper().replace(" ", "").replace("«", "<")
    return re.sub(r"[^A-Z0-9<]", "<", line)


def _digits(s: str) -> str:
    return s.translate(_TO_DIGIT)


def _alpha(s: str) -> str:
    return s.translate(_TO_ALPHA)


def _yymmdd(s: str, future: bool) -> str | None:
    if not re.fullmatch(r"\d{6}", s):
        return None
    yy, mm, dd = int(s[:2]), int(s[2:4]), int(s[4:6])
    century = 2000 if (future or yy <= date.today().year % 100) else 1900
    try:
        return date(century + yy, mm, dd).isoformat()
    except ValueError:
        return None


def find_mrz_lines(lines: list[str]) -> list[str]:
    cands = [_clean(l) for l in lines if l.count("<") >= 2 and len(l.replace(" ", "")) >= 18]
    return cands


def parse(lines: list[str]) -> dict | None:
    mrz = find_mrz_lines(lines)
    if len(mrz) >= 3 and mrz[0][:1] in {"I", "A", "C"}:
        return _parse_td1(mrz[:3])
    if len(mrz) >= 2 and mrz[0].startswith("P"):
        return _parse_td3(mrz[:2])
    return None


def _result(fmt, doc_type, issuer, number, number_cd, dob, dob_cd, sex, expiry, exp_cd, nationality, names, composite_ok):
    checks = {
        "document_number": check_digit(number) == number_cd,
        "date_of_birth": check_digit(dob) == dob_cd,
        "date_of_expiry": check_digit(expiry) == exp_cd,
        "composite": composite_ok,
    }
    surname, _, given = names.partition("<<")
    return {
        "format": fmt,
        "document_code": doc_type,
        "issuer": issuer,
        "document_number": number.replace("<", ""),
        "date_of_birth": _yymmdd(dob, future=False),
        "sex": sex,
        "date_of_expiry": _yymmdd(expiry, future=True),
        "nationality": nationality,
        "surname": surname.replace("<", " ").strip(),
        "given_names": given.replace("<", " ").strip(),
        "check_digits": checks,
        "valid": all(checks.values()),
    }


def _parse_td1(l: list[str]) -> dict:
    l1, l2, l3 = (x.ljust(30, "<")[:30] for x in l)
    doc_type, issuer = l1[0:2], _alpha(l1[2:5])
    number, number_cd = l1[5:14], _digits(l1[14])
    dob, dob_cd = _digits(l2[0:6]), _digits(l2[6])
    sex = l2[7]
    expiry, exp_cd = _digits(l2[8:14]), _digits(l2[14])
    nationality = _alpha(l2[15:18])
    composite = l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
    composite_ok = check_digit(composite) == _digits(l2[29])
    return _result("TD1", doc_type, issuer, number, number_cd, dob, dob_cd, sex, expiry, exp_cd, nationality, _alpha(l3), composite_ok)


def _parse_td3(l: list[str]) -> dict:
    l1, l2 = (x.ljust(44, "<")[:44] for x in l)
    doc_type, issuer, names = l1[0:2], _alpha(l1[2:5]), _alpha(l1[5:44])
    number, number_cd = l2[0:9], _digits(l2[9])
    nationality = _alpha(l2[10:13])
    dob, dob_cd = _digits(l2[13:19]), _digits(l2[19])
    sex = l2[20]
    expiry, exp_cd = _digits(l2[21:27]), _digits(l2[27])
    composite = l2[0:10] + l2[13:20] + l2[21:43]
    composite_ok = check_digit(composite) == _digits(l2[43])
    return _result("TD3", doc_type, issuer, number, number_cd, dob, dob_cd, sex, expiry, exp_cd, nationality, names, composite_ok)
