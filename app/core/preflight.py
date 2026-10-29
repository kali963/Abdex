"""Launch readiness check (OPS): what must be configured before real users come.

``python -m app.cli preflight`` prints the whole report. In production the application refuses to start while
an ERROR remains (``enforce()`` at start-up) — a misconfigured site that silently drops login codes or accepts
fake signatures is worse than one that does not start. WARNINGS are things to fix soon or to decide on
consciously.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

ERROR, WARN, OK = "ERROR", "WARN", "OK"


@dataclass
class Item:
    level: str
    code: str
    text: str


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def check_env() -> list[Item]:
    """Checks that need no database."""
    from app.config import settings
    from app.modules.integrations.adapters import sms_provider

    out: list[Item] = []
    add = lambda level, code, text: out.append(Item(level, code, text))  # noqa: E731
    prod = settings.is_production

    add(OK if prod else WARN, "app_env", f"APP_ENV={settings.app_env}" + ("" if prod else " — для боя нужно production"))
    if len(settings.secret_key) < 32 or not _env("SECRET_KEY"):
        add(ERROR, "secret_key", "SECRET_KEY: задайте случайную строку не короче 32 символов")
    else:
        add(OK, "secret_key", "SECRET_KEY задан")
    if not settings.database_url.startswith("postgresql"):
        add(ERROR, "database", "DATABASE_URL: в бою нужна PostgreSQL")
    else:
        add(OK, "database", "PostgreSQL")
    try:
        from app.core.crypto import keyring, reset_keyring

        reset_keyring()
        keyring()
        if not (_env("FIELD_ENCRYPTION_KEYS_FILE") or _env("FIELD_ENCRYPTION_KEYS")):
            add(ERROR, "field_keys", "FIELD_ENCRYPTION_KEYS_FILE: ключи шифрования ИИН/IBAN/телефонов не заданы")
        else:
            add(OK, "field_keys", "ключи шифрования персональных данных заданы")
    except Exception as exc:  # noqa: BLE001
        add(ERROR, "field_keys", f"ключи шифрования не читаются: {type(exc).__name__}")
    if not _env("FIELD_INDEX_KEY"):
        add(WARN, "index_key", "FIELD_INDEX_KEY не задан — ключ поиска выводится из первого ключа шифрования")

    base = urlsplit(settings.public_base_url)
    if base.scheme != "https" or base.hostname in (None, "localhost", "127.0.0.1"):
        add(ERROR, "public_url", "PUBLIC_BASE_URL: публичный адрес сайта с https:// (ссылки в SMS, письмах, QR)")
    else:
        add(OK, "public_url", f"PUBLIC_BASE_URL={settings.public_base_url}")

    provider = sms_provider()
    if not provider:
        add(ERROR, "sms", "SMS не подключены (MOBIZON_API_KEY, SMSC_LOGIN или SMS_GATEWAY_URL): без них никто не "
                          "зарегистрируется и не войдёт")
    else:
        add(OK, "sms", f"SMS: {provider}")
    if not _env("SMTP_HOST"):
        add(WARN, "smtp", "SMTP_HOST не задан — письма (счета, восстановление пароля по e-mail) не уходят")
    if not settings.trust_proxy:
        add(WARN, "proxy", "TRUST_PROXY=false: за обратным прокси все клиенты будут с одного адреса (лимиты, журнал)")
    if not _env("REDIS_URL"):
        add(WARN if int(_env("WEB_CONCURRENCY") or "1") <= 1 else ERROR, "redis",
            "REDIS_URL не задан — лимиты попыток считаются в каждом процессе отдельно")
    if settings.run_background_worker and prod:
        add(WARN, "worker", "RUN_BACKGROUND_WORKER=true в веб-процессе: в бою фоновые задачи — отдельный контейнер")
    if not _env("CLAMAV_HOST"):
        add(WARN if not prod else ERROR, "antivirus", "CLAMAV_HOST не задан — загружаемые файлы не проверяются антивирусом")
    if not settings.admin_host:  # FR-ACL-04: a separate admin subdomain
        add(ERROR if prod else WARN, "admin_host", "ADMIN_HOST не задан — админка должна быть на отдельном поддомене")
    if not settings.admin_networks:  # SEC-AZ-06
        add(WARN, "admin_networks", "ADMIN_ALLOWED_NETWORKS не задан — админка открыта из любой сети (задайте сеть офиса или VPN)")
    if not settings.metrics_token:
        add(WARN, "metrics", "METRICS_TOKEN не задан — /metrics недоступен для мониторинга")
    from app.core.secrets import has

    if not has("AUDIT_ARCHIVE_KEY"):  # SEC-LOG-04
        add(ERROR if prod else WARN, "audit_key", "AUDIT_ARCHIVE_KEY не задан — архив журнала безопасности нечем подписать")
    if prod and not _env("AUDIT_ARCHIVE_DIR"):
        add(WARN, "audit_dir", "AUDIT_ARCHIVE_DIR не задан — архив журнала лежит рядом с файлами, а не в отдельном томе")
    if not has("VAPID_PRIVATE_KEY"):
        add(WARN, "vapid", "VAPID_PRIVATE_KEY не задан — push-уведомления в браузере выключены")
    return out


def check_db(db) -> list[Item]:
    """Checks that depend on switched-on features and data."""
    from sqlalchemy import func, select

    from app.config import settings
    from app.modules.accounts.models import STAFF_ADMIN, User
    from app.modules.platform.service import flag_enabled

    out: list[Item] = []
    add = lambda level, code, text: out.append(Item(level, code, text))  # noqa: E731
    admins = db.execute(select(func.count(User.id)).where(User.staff_role == STAFF_ADMIN, User.is_blocked.is_(False),
                                                          User.is_deleted.is_(False))).scalar_one()
    if not admins:
        add(ERROR, "admin", "нет ни одного администратора: задайте INITIAL_ADMIN_* в .env.production и перезапустите "
                            "приложение (или python -m app.cli create-staff --role admin ...)")
    else:
        add(OK, "admin", f"администраторов: {admins}")
    if flag_enabled(db, "online_payments"):
        if not (settings.payment_provider_url and settings.payment_webhook_secret):
            add(ERROR, "payments", "онлайн-оплата включена, но PAYMENT_PROVIDER_URL / PAYMENT_WEBHOOK_SECRET не заданы")
    if any(flag_enabled(db, f) for f in ("qualified_signature", "auth.eds_login", "auth.egov_mobile", "eds.egov_mobile")):
        if not settings.eds_ncanode_url:
            add(ERROR, "eds", "ЭЦП включена, но EDS_NCANODE_URL не задан (docs/eds-setup.md)")
        else:
            add(OK, "eds", "проверка ЭЦП: NCANode")
    if flag_enabled(db, "gov.esf") and not _env("ESF_GATEWAY_URL"):
        add(ERROR, "esf", "отправка ЭСФ включена, но ESF_GATEWAY_URL не задан")
    for flag, name in (("gov.etd", "ЭТТН"), ("gov.services", "госреестры")):
        if flag_enabled(db, flag):
            add(WARN, flag, f"флаг {flag} включён, но адаптер «{name}» пока без боевого подключения — проверки уйдут "
                            "модератору вручную")
    out += _check_clock(db)
    return out


def _check_clock(db) -> list[Item]:
    """SEC-LOG-07: the journal's time stamps are trustworthy only with synchronised clocks (chrony/NTP on the
    server): the application and the database must agree."""
    import time

    from sqlalchemy import text

    if db.get_bind().dialect.name != "postgresql":
        return []
    skew = abs(float(db.execute(text("SELECT extract(epoch from clock_timestamp())")).scalar()) - time.time())
    if skew > 2:
        return [Item(ERROR, "clock", f"часы приложения и базы расходятся на {skew:.1f} с: включите синхронизацию "
                                     "времени (chrony) на сервере")]
    return [Item(OK, "clock", f"часы синхронизированы (расхождение {skew:.2f} с)")]


def report(db=None) -> list[Item]:
    items = check_env()
    if db is not None:
        items += check_db(db)
    return items


def enforce() -> None:
    """Production start-up: refuse to run with configuration ERRORs (database-free checks only, so a fresh
    installation can still start and get its first administrator)."""
    from app.config import settings

    if not settings.is_production:
        return
    errors = [i for i in check_env() if i.level == ERROR]
    if errors:
        raise RuntimeError("Production configuration is not ready:\n" + "\n".join(f"- {i.text}" for i in errors)
                           + "\nRun `python -m app.cli preflight` for the full report.")
