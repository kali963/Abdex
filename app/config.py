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


def _secret(name: str) -> str:
    from app.core.secrets import secret  # files of the secret store first (GOV-R-07)

    return secret(name)


def _normalize_db_url(url: str) -> str:
    """Accept plain postgres:// / postgresql:// URLs (the driver is psycopg 3)."""
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
    secret_key: str = field(default_factory=lambda: _secret("SECRET_KEY"))
    database_url: str = field(
        default_factory=lambda: _normalize_db_url(os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'var' / 'abdex.db'}"))
    )
    # Apply Alembic migrations on startup (serverless deploys have no separate migration step).
    auto_migrate: bool = field(default_factory=lambda: _bool("AUTO_MIGRATE", False))
    storage_dir: Path = field(default_factory=lambda: Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "var" / "storage"))))
    # Admin interface lives on a separate host in production (FR-ACL-04). Empty = same host.
    admin_host: str = field(default_factory=lambda: os.getenv("ADMIN_HOST", ""))
    # SEC-AZ-06: the admin interface answers only from these networks (office, VPN), e.g. "10.8.0.0/24,203.0.113.7"
    admin_networks: str = field(default_factory=lambda: os.getenv("ADMIN_ALLOWED_NETWORKS", ""))
    secure_cookies: bool = field(default_factory=lambda: _bool("SECURE_COOKIES", False))
    # Take the client IP from X-Forwarded-For only behind a proxy that overwrites it; otherwise
    # anyone could spoof their IP and bypass per-IP rate limits (SEC-AUT-03, SEC-APP-06).
    trust_proxy: bool = field(default_factory=lambda: _bool("TRUST_PROXY", False))
    # how many reverse proxies in front of the app append to X-Forwarded-For; the client address is that many
    # entries from the right (the left part of the header is whatever the client sent)
    trusted_proxy_hops: int = field(default_factory=lambda: max(1, int(os.getenv("TRUSTED_PROXY_HOPS", "1") or 1)))
    require_2fa_privileged: bool = field(default_factory=lambda: _bool("REQUIRE_2FA_PRIVILEGED", False))
    run_background_worker: bool = field(default_factory=lambda: _bool("RUN_BACKGROUND_WORKER", True))
    default_locale: str = field(default_factory=lambda: os.getenv("DEFAULT_LOCALE", "ru"))
    default_timezone: str = field(default_factory=lambda: os.getenv("DEFAULT_TIMEZONE", "Asia/Almaty"))
    max_upload_mb: int = field(default_factory=lambda: _int("MAX_UPLOAD_MB", 15))
    # SEC-AUT-07
    user_idle_timeout_min: int = field(default_factory=lambda: _int("USER_IDLE_TIMEOUT_MIN", 8 * 60))
    admin_idle_timeout_min: int = field(default_factory=lambda: _int("ADMIN_IDLE_TIMEOUT_MIN", 30))
    session_absolute_days: int = field(default_factory=lambda: _int("SESSION_ABSOLUTE_DAYS", 30))
    # SEC-AUT-10: cooling-off period for new bank details
    iban_cooldown_hours: int = field(default_factory=lambda: _int("IBAN_COOLDOWN_HOURS", 24))
    telegram_bot_token: str = field(default_factory=lambda: _secret("TELEGRAM_BOT_TOKEN"))
    # Secret Telegram sends in X-Telegram-Bot-Api-Secret-Token (set via setWebhook secret_token)
    telegram_webhook_secret: str = field(default_factory=lambda: _secret("TELEGRAM_WEBHOOK_SECRET"))
    metrics_token: str = field(default_factory=lambda: _secret("METRICS_TOKEN"))  # NFR-OBS-01
    # GOV-DS-02: server-side verification of NCA RK signatures (NCANode); empty = development signer
    eds_ncanode_url: str = field(default_factory=lambda: os.getenv("EDS_NCANODE_URL", ""))
    # FR-LOC-04: official rates feed, e.g. https://nationalbank.kz/rss/get_rates.cfm (empty: simulator in development,
    # manual rates in production)
    fx_rates_url: str = field(default_factory=lambda: os.getenv("FX_RATES_URL", ""))
    # FR-BIL-06: hosted-checkout payment provider; empty URL = development simulator
    payment_provider_url: str = field(default_factory=lambda: os.getenv("PAYMENT_PROVIDER_URL", ""))
    payment_provider_key: str = field(default_factory=lambda: _secret("PAYMENT_PROVIDER_KEY"))
    payment_webhook_secret: str = field(default_factory=lambda: _secret("PAYMENT_WEBHOOK_SECRET"))
    public_base_url: str = field(default_factory=lambda: os.getenv("PUBLIC_BASE_URL", "http://localhost:8000"))

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_dev(self) -> bool:
        return self.app_env in {"development", "test"}


def _dev_secret_key(storage_dir: Path) -> str:
    """Development without SECRET_KEY: one random key shared by every process (several web workers, the
    background worker) through a file in the storage directory. A key per process would make a session
    created by one process unknown to the others — random logouts and "form expired" errors."""
    import time

    path = storage_dir / ".dev-secret-key"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            for _ in range(50):  # another process may be writing it right now
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value
                time.sleep(0.05)
        else:
            value = secrets.token_urlsafe(48)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(value)
            return value
    except OSError:
        pass
    return secrets.token_urlsafe(48)


def load_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        if s.is_production:
            raise RuntimeError("SECRET_KEY must be set in production")
        object.__setattr__(s, "secret_key", _dev_secret_key(s.storage_dir))
    for name in ("eds_ncanode_url", "payment_provider_url", "fx_rates_url"):  # external endpoints: http(s) only
        value = getattr(s, name)
        if value and not value.startswith(("https://", "http://")):
            raise RuntimeError(f"{name.upper()} must be an http(s) URL")
    if s.is_production:
        # Hard rules that cannot be relaxed in production.
        object.__setattr__(s, "require_2fa_privileged", True)
        object.__setattr__(s, "secure_cookies", True)
    return s


settings = load_settings()
