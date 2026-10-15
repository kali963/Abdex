"""Application settings. All configuration comes from environment variables (NFR-ARC-06).

No secrets are stored in the repository: SECRET_KEY and integration credentials must be
provided by the environment / secret store. In development a random key is generated per
process, which simply logs everybody out on restart.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'var' / 'abdex.db'}")
    )
    storage_dir: Path = field(default_factory=lambda: Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "var" / "storage"))))
    # Admin interface lives on a separate host in production (FR-ACL-04). Empty = same host.
    admin_host: str = field(default_factory=lambda: os.getenv("ADMIN_HOST", ""))
    secure_cookies: bool = field(default_factory=lambda: _bool("SECURE_COOKIES", False))
    require_2fa_privileged: bool = field(default_factory=lambda: _bool("REQUIRE_2FA_PRIVILEGED", False))
    run_background_worker: bool = field(default_factory=lambda: _bool("RUN_BACKGROUND_WORKER", True))
    seed_demo_data: bool = field(default_factory=lambda: _bool("SEED_DEMO_DATA", True))
    default_locale: str = field(default_factory=lambda: os.getenv("DEFAULT_LOCALE", "ru"))
    default_timezone: str = field(default_factory=lambda: os.getenv("DEFAULT_TIMEZONE", "Asia/Almaty"))
    max_upload_mb: int = field(default_factory=lambda: _int("MAX_UPLOAD_MB", 15))
    # SEC-AUT-07
    user_idle_timeout_min: int = field(default_factory=lambda: _int("USER_IDLE_TIMEOUT_MIN", 8 * 60))
    admin_idle_timeout_min: int = field(default_factory=lambda: _int("ADMIN_IDLE_TIMEOUT_MIN", 30))
    session_absolute_days: int = field(default_factory=lambda: _int("SESSION_ABSOLUTE_DAYS", 30))
    # SEC-AUT-10: cooling-off period for new bank details
    iban_cooldown_hours: int = field(default_factory=lambda: _int("IBAN_COOLDOWN_HOURS", 24))
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_dev(self) -> bool:
        return self.app_env in {"development", "test"}


def load_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        if s.is_production:
            raise RuntimeError("SECRET_KEY must be set in production")
        object.__setattr__(s, "secret_key", secrets.token_urlsafe(48))
    if s.is_production:
        # Hard rules that cannot be relaxed in production.
        object.__setattr__(s, "require_2fa_privileged", True)
        object.__setattr__(s, "secure_cookies", True)
        object.__setattr__(s, "seed_demo_data", _bool("SEED_DEMO_DATA", False))
    return s


settings = load_settings()
