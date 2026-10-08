"""Authentication, MFA, refresh rotation, lockout and RBAC."""

from __future__ import annotations

import time

import pyotp
import pytest
from sqlalchemy import select

from fraudmesh.core.ids import new_id
from fraudmesh.db.models import AuditLog, OtpChallenge, User
from fraudmesh.db.session import sessionmaker
from fraudmesh.services.auth import security as sec
from fraudmesh.services.auth import service as auth_service

from .conftest import PASSWORD, login_as


async def _make_user(email: str, role: str = "ANALYST") -> None:
    async with sessionmaker()() as db:
        db.add(User(id=new_id("usr"), email=email, display_name=email, role=role, password_hash=sec.hash_secret(PASSWORD)))
        await db.commit()


def test_argon2id_hashes_and_verifies():
    h = sec.hash_secret("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert sec.verify_secret(h, "correct horse battery staple")
    assert not sec.verify_secret(h, "wrong")
    assert not sec.verify_secret(None, "anything")


def test_jwt_type_confusion_rejected():
    mfa_token = sec.issue_token("usr_x", "mfa", 60)
    with pytest.raises(Exception):
        sec.decode_token(mfa_token, "access")


def test_totp_replay_protection():
    secret = sec.new_totp_secret()
    code = pyotp.TOTP(secret).now()
    step = sec.verify_totp(secret, code, None)
    assert step is not None
    assert sec.verify_totp(secret, code, step) is None  # same code cannot be reused


def test_rbac_matrix():
    assert sec.has_permission("ADMIN", "policies:write")
    assert not sec.has_permission("ANALYST", "policies:write")
    assert sec.has_permission("AUDITOR", "audit:read")
    assert not sec.has_permission("AUDITOR", "cases:act")
    assert not sec.has_permission("NOT_A_ROLE", "cases:read")


async def test_login_success_and_me(client):
    headers = await login_as(client, "investigator@fraudmesh.local")
    r = await client.get("/api/auth/me", headers=headers)
    assert r.status_code == 200
    assert r.json()["role"] == "INVESTIGATOR"
    assert "cases:act" in r.json()["permissions"]


async def test_bad_password_rejected_and_audited(client):
    r = await client.post("/api/auth/login", json={"email": "analyst@fraudmesh.local", "password": "nope"})
    assert r.status_code == 401
    async with sessionmaker()() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.action == "auth.login.failed"))).scalars().all()
        assert rows
        # audit rows never contain the attempted password
        assert all("nope" not in str(r.new_state) for r in rows)


async def test_lockout_after_repeated_failures(client):
    email = "lockme@fraudmesh.local"
    await _make_user(email)
    for _ in range(5):
        await client.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
    r = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 423  # locked even with the right password


async def test_refresh_rotation_and_reuse_detection(client):
    email = "rotate@fraudmesh.local"
    await _make_user(email)
    r = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200
    first_refresh = client.cookies.get("fm_refresh")
    csrf = client.cookies.get("fm_csrf")

    # CSRF header required
    r = await client.post("/api/auth/refresh")
    assert r.status_code == 403

    r = await client.post("/api/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    new_access = r.json()["access_token"]
    assert client.cookies.get("fm_refresh") != first_refresh

    # Replay the rotated (old) refresh token ⇒ whole family revoked
    client.cookies.set("fm_refresh", first_refresh, path="/api/auth")
    r = await client.post("/api/auth/refresh", headers={"X-CSRF-Token": client.cookies.get("fm_csrf")})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "refresh_reuse"
    # and the access token issued from that family no longer works
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 401
    client.cookies.clear()


async def test_totp_enrollment_and_mfa_login(client):
    email = "mfa@fraudmesh.local"
    await _make_user(email, "INVESTIGATOR")
    headers = await login_as(client, email)
    r = await client.post("/api/auth/mfa/enroll", headers=headers)
    uri = r.json()["otpauth_uri"]
    secret = pyotp.parse_uri(uri).secret
    r = await client.post("/api/auth/mfa/enroll/confirm", headers=headers, json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text

    async with sessionmaker()() as db:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        assert user.mfa_enabled
        assert user.totp_secret_enc and secret.encode() not in user.totp_secret_enc  # encrypted at rest

    r = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    body = r.json()
    assert body["status"] == "MFA_REQUIRED"
    bad = await client.post("/api/auth/mfa", json={"mfa_token": body["mfa_token"], "code": "000000"})
    assert bad.status_code == 401
    # next time-step code (the enrollment code's step is consumed)
    code = pyotp.TOTP(secret).at(time.time() + 30)
    ok = await client.post("/api/auth/mfa", json={"mfa_token": body["mfa_token"], "code": code})
    assert ok.status_code == 200, ok.text
    assert ok.json()["mfa_verified"] is True
    client.cookies.clear()


async def test_otp_is_hashed_and_single_use(app):
    async with sessionmaker()() as db:
        cid, code = await auth_service.create_otp(db, "cust_test", "verification", "sms", "+91 ******1234")
        row = await db.get(OtpChallenge, cid)
        assert code not in row.code_hash and row.code_hash.startswith("$argon2id$")
        assert not await auth_service.verify_otp(db, cid, "cust_test", "999999" if code != "999999" else "111111")
        assert await auth_service.verify_otp(db, cid, "cust_test", code)
        assert not await auth_service.verify_otp(db, cid, "cust_test", code)  # consumed


async def test_unauthenticated_requests_rejected(client):
    assert (await client.get("/api/auth/me")).status_code == 401
    assert (await client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"})).status_code == 401


async def test_security_headers_present(client):
    r = await client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "x-request-id" in r.headers
