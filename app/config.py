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


# Serverless hosting (Vercel): the filesystem is read-only except /tmp and there are no
# long-running processes, so defaults change. Persistent data needs DATABASE_URL (PostgreSQL).
ON_VERCEL = bool(os.getenv("VERCEL"))
if ON_VERCEL:
    os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/abdex.db")
    os.environ.setdefault("STORAGE_DIR", "/tmp/abdex-storage")  # noqa: S108 — only writable, per-instance dir on Vercel
    os.environ.setdefault("RUN_BACKGROUND_WORKER", "false")
    os.environ.setdefault("AUTO_MIGRATE", "true")
    os.environ.setdefault("SECURE_COOKIES", "true")  # Vercel always serves HTTPS
    os.environ.setdefault("TRUST_PROXY", "true")  # Vercel's edge sets X-Forwarded-For itself


def _normalize_db_url(url: str) -> str:
    """Hosted PostgreSQL providers (Neon, Vercel Postgres) give postgres:// URLs."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


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
        default_factory=lambda: _normalize_db_url(os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'var' / 'abdex.db'}"))
    )
    # Apply Alembic migrations on startup (serverless deploys have no separate migration step).
    auto_migrate: bool = field(default_factory=lambda: _bool("AUTO_MIGRATE", False))
    storage_dir: Path = field(default_factory=lambda: Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "var" / "storage"))))
    # Admin interface lives on a separate host in production (FR-ACL-04). Empty = same host.
    admin_host: str = field(default_factory=lambda: os.getenv("ADMIN_HOST", ""))
    secure_cookies: bool = field(default_factory=lambda: _bool("SECURE_COOKIES", False))
    # Take the client IP from X-Forwarded-For only behind a proxy that overwrites it; otherwise
    # anyone could spoof their IP and bypass per-IP rate limits (SEC-AUT-03, SEC-APP-06).
    trust_proxy: bool = field(default_factory=lambda: _bool("TRUST_PROXY", False))
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
    # Secret Telegram sends in X-Telegram-Bot-Api-Secret-Token (set via setWebhook secret_token)
    telegram_webhook_secret: str = field(default_factory=lambda: os.getenv("TELEGRAM_WEBHOOK_SECRET", ""))
    metrics_token: str = field(default_factory=lambda: os.getenv("METRICS_TOKEN", ""))  # NFR-OBS-01
    # GOV-DS-02: server-side verification of NCA RK signatures (NCANode); empty = development signer
    eds_ncanode_url: str = field(default_factory=lambda: os.getenv("EDS_NCANODE_URL", ""))
    # FR-LOC-04: official rates feed, e.g. https://nationalbank.kz/rss/get_rates.cfm (empty: simulator in development,
    # manual rates in production)
    fx_rates_url: str = field(default_factory=lambda: os.getenv("FX_RATES_URL", ""))
    # FR-BIL-06: hosted-checkout payment provider; empty URL = development simulator
    payment_provider_url: str = field(default_factory=lambda: os.getenv("PAYMENT_PROVIDER_URL", ""))
    payment_provider_key: str = field(default_factory=lambda: os.getenv("PAYMENT_PROVIDER_KEY", ""))
    payment_webhook_secret: str = field(default_factory=lambda: os.getenv("PAYMENT_WEBHOOK_SECRET", ""))
    public_base_url: str = field(default_factory=lambda: os.getenv("PUBLIC_BASE_URL", "http://localhost:8000"))

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
        if ON_VERCEL and os.getenv("VERCEL_PROJECT_ID"):
            # Demo deploy without SECRET_KEY: instances must share a key or logins break between them.
            # Not secret — set SECRET_KEY in the Vercel project settings for anything beyond a demo.
            import hashlib
            import logging

            logging.getLogger("abdex").warning("SECRET_KEY is not set; using a derived demo key")
            object.__setattr__(s, "secret_key", hashlib.sha256(
                ("abdex-demo:" + os.environ["VERCEL_PROJECT_ID"]).encode()).hexdigest())
        else:
            object.__setattr__(s, "secret_key", secrets.token_urlsafe(48))
    for name in ("eds_ncanode_url", "payment_provider_url", "fx_rates_url"):  # external endpoints: http(s) only
        value = getattr(s, name)
        if value and not value.startswith(("https://", "http://")):
            raise RuntimeError(f"{name.upper()} must be an http(s) URL")
    if s.is_production:
        # Hard rules that cannot be relaxed in production.
        object.__setattr__(s, "require_2fa_privileged", True)
        object.__setattr__(s, "secure_cookies", True)
        object.__setattr__(s, "seed_demo_data", _bool("SEED_DEMO_DATA", False))
    return s


settings = load_settings()
