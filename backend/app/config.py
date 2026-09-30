"""Runtime configuration loaded from environment variables.

Nothing secret is hard-coded here. If no tokenization secret is supplied, a
random one is generated on first start and stored next to the SQLite database
(``data/.token_secret``, git-ignored) so tokens stay stable across restarts.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    app_env: str = field(default_factory=lambda: os.getenv("FRAUDMESH_ENV", "development"))
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("FRAUDMESH_DATA_DIR", REPO_ROOT / "data")))
    models_dir: Path = field(default_factory=lambda: Path(os.getenv("FRAUDMESH_MODELS_DIR", REPO_ROOT / "models")))
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))
    token_secret: str = field(default_factory=lambda: os.getenv("FRAUDMESH_TOKEN_SECRET", ""))
    admin_token: str = field(default_factory=lambda: os.getenv("FRAUDMESH_ADMIN_TOKEN", ""))
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.getenv("FRAUDMESH_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
            if o.strip()
        ]
    )
    auto_seed: bool = field(default_factory=lambda: _bool("FRAUDMESH_AUTO_SEED", True))
    log_level: str = field(default_factory=lambda: os.getenv("FRAUDMESH_LOG_LEVEL", "INFO"))
    rate_limit_per_minute: int = field(default_factory=lambda: _int("FRAUDMESH_RATE_LIMIT_PER_MINUTE", 600))
    kyc_rate_limit_per_minute: int = field(default_factory=lambda: _int("FRAUDMESH_KYC_RATE_LIMIT_PER_MINUTE", 20))
    kyc_max_bytes: int = field(default_factory=lambda: _int("FRAUDMESH_KYC_MAX_BYTES", 5 * 1024 * 1024))
    kyc_retain_media: bool = field(default_factory=lambda: _bool("FRAUDMESH_KYC_RETAIN_MEDIA", False))
    show_synthetic_labels: bool = field(default_factory=lambda: _bool("FRAUDMESH_SHOW_SYNTHETIC_LABELS", True))
    max_batch_size: int = field(default_factory=lambda: _int("FRAUDMESH_MAX_BATCH_SIZE", 500))

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        if not self.database_url:
            self.database_url = f"sqlite:///{(self.data_dir / 'fraudmesh.db').as_posix()}"
        if not self.token_secret:
            self.token_secret = self._load_or_create_secret()

    def _load_or_create_secret(self) -> str:
        path = self.data_dir / ".token_secret"
        if path.exists():
            return path.read_text().strip()
        value = secrets.token_hex(32)
        path.write_text(value)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return value

    @property
    def admin_auth_enabled(self) -> bool:
        return bool(self.admin_token)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Used by tests to re-read the environment."""
    global _settings
    _settings = None
