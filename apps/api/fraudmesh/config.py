"""Runtime configuration.

Every secret and connection string comes from the environment (prefix ``FM_``).
Development defaults exist so the stack runs locally, but ``FM_ENV=production``
refuses to start with them.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]

_DEV_JWT_SECRET = "dev-only-jwt-secret-change-me-0123456789abcdef"
_DEV_DATA_KEY = "ZGV2LW9ubHktZGF0YS1rZXktY2hhbmdlLW1lLTAxMjM="  # 32 bytes, base64


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FM_", env_file=".env", extra="ignore")

    env: str = "development"  # development | test | production
    demo_mode: bool = True  # enables synthetic data seeding + DEMO labels + OTP dev outbox
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://fraudmesh:fraudmesh@127.0.0.1:5432/fraudmesh"
    redis_url: str = "redis://127.0.0.1:6379/0"
    neo4j_uri: str = "bolt://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "fraudmesh-dev"

    jwt_secret: str = _DEV_JWT_SECRET
    jwt_issuer: str = "fraudmesh"
    access_token_ttl_s: int = 900
    refresh_token_ttl_s: int = 60 * 60 * 24 * 7
    mfa_token_ttl_s: int = 300
    # base64 32-byte key used for AES-GCM encryption of TOTP secrets, PII and face templates
    data_key: str = _DEV_DATA_KEY
    # HMAC key for deterministic, non-reversible lookups (e.g. document numbers)
    hmac_key: str = "dev-only-hmac-key-change-me"

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"])
    cookie_secure: bool = False
    # X-Forwarded-For is honoured only when the direct peer is one of these (e.g. the nginx container).
    trusted_proxies: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Sensitive operations (policy edits, user admin, demo reset) require an MFA-verified session.
    # Defaults to on in production; off in local demo so the stack works without an authenticator app.
    enforce_mfa_sensitive: bool | None = None

    login_max_failures: int = 5
    lockout_seconds: int = 900
    rate_limit_per_minute: int = 240
    auth_rate_limit_per_minute: int = 20

    model_dir: Path = REPO_ROOT / "ml" / "weights"
    artifact_dir: Path = REPO_ROOT / "ml" / "artifacts"
    fixture_dir: Path = REPO_ROOT / "tests" / "fixtures" / "media"
    # "auto" picks the EfficientNet-B4 detector when its weights exist, otherwise Meso4.
    deepfake_model: str = "auto"
    deepfake_max_frames: int = 8
    torch_threads: int = 4
    max_upload_mb: int = 25

    # Initial operator accounts are created on first start with this password (demo only;
    # in production create users via the admin API and set FM_BOOTSTRAP_PASSWORD to something strong).
    bootstrap_password: str = "FraudMesh-Demo-2026!"

    timezone: str = "Asia/Kolkata"
    seed: int = 1337

    @property
    def mfa_required_for_sensitive(self) -> bool:
        return self.enforce_mfa_sensitive if self.enforce_mfa_sensitive is not None else self.env == "production"

    @model_validator(mode="after")
    def _refuse_dev_secrets_in_production(self) -> "Settings":
        if self.env == "production":
            if self.jwt_secret == _DEV_JWT_SECRET or self.data_key == _DEV_DATA_KEY:
                raise ValueError("FM_JWT_SECRET and FM_DATA_KEY must be set in production")
            if not self.cookie_secure:
                raise ValueError("FM_COOKIE_SECURE must be true in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
