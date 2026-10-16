"""Operational commands.

    python -m app.cli rotate-keys            re-encrypt personal-data fields with the newest key (SEC-DAT-03)
    python -m app.cli anonymize --confirm    anonymise a COPY of the database for development / testing (SEC-DAT-09)

A production database is marked at start-up (``platform.data_origin = production``). A non-production
instance refuses to start on a database with that mark until ``anonymize`` has been run on the copy, so a
production copy cannot be used in other environments without anonymisation — technically, not by rule.
"""
from __future__ import annotations

import secrets
import sys

from sqlalchemy import text

from app.config import settings
from app.core import crypto

ENCRYPTED = {"drivers": ("iin", "phone", "license_number"), "bank_accounts": ("iban",)}


def _system(conn) -> None:
    """Operational commands work on all companies' rows: row-level security bypass for this transaction."""
    if conn.dialect.name == "postgresql":
        conn.execute(text("SELECT set_config('app.rls_bypass', 'on', true)"))


def rotate_keys() -> dict[str, int]:
    from app.db import engine

    version = crypto.current_version()
    counts: dict[str, int] = {}
    with engine.begin() as conn:
        _system(conn)
        for table, cols in ENCRYPTED.items():
            n = 0
            for row in conn.execute(text(f"SELECT id, {', '.join(cols)} FROM {table}")).mappings():  # noqa: S608 — fixed names
                changes = {}
                for col in cols:
                    raw = row[col]
                    if raw and crypto.key_version(raw) != version:
                        changes[col] = crypto.encrypt(crypto.decrypt(raw, f"{table}.{col}"), f"{table}.{col}")
                if changes:
                    sets = ", ".join(f"{c} = :{c}" for c in changes)
                    conn.execute(text(f"UPDATE {table} SET {sets} WHERE id = :id"), {**changes, "id": row["id"]})  # noqa: S608
                    n += 1
            counts[table] = n
    return counts


def _fake_iin(n: int) -> str:
    from app.demo import make_bin

    return make_bin(f"{900101300000 + n:012d}"[:11])


def anonymize() -> dict[str, int]:
    """Irreversibly replaces personal data in the current database. Never run it on production."""
    if settings.is_production:
        raise SystemExit("refusing to anonymise a production instance")
    from app.db import engine

    pg = engine.dialect.name == "postgresql"
    counts: dict[str, int] = {}
    with engine.begin() as conn:
        _system(conn)
        if pg:  # append-only guards are lifted only inside this transaction on the copy
            for t in ("checkpoints", "messages", "audit_log", "integration_calls", "signatures"):
                conn.execute(text(f"ALTER TABLE {t} DISABLE TRIGGER USER"))
        users = list(conn.execute(text("SELECT id, staff_role FROM users")).mappings())
        for i, u in enumerate(users, start=1):
            conn.execute(text("UPDATE users SET full_name = :n, phone = :p, email = :e, password_hash = NULL, "
                              "totp_secret = NULL, totp_enabled = :f, sms_2fa_enabled = :f WHERE id = :id"),
                         {"n": f"Пользователь {i}", "p": f"+7999{i:07d}", "e": f"user{i}@example.invalid" if u["staff_role"] else None,
                          "f": False, "id": u["id"]})
        counts["users"] = len(users)
        drivers = list(conn.execute(text("SELECT id FROM drivers")).mappings())
        for i, d in enumerate(drivers, start=1):
            iin = _fake_iin(i)
            conn.execute(text("UPDATE drivers SET full_name = :n, iin = :iin, iin_index = :ix, phone = '', "
                              "license_number = '' WHERE id = :id"),
                         {"n": f"Водитель {i}", "iin": crypto.encrypt(iin, "drivers.iin"),
                          "ix": crypto.blind_index(iin, "iin"), "id": d["id"]})
        counts["drivers"] = len(drivers)
        banks = list(conn.execute(text("SELECT id FROM bank_accounts")).mappings())
        for b in banks:
            iban = "KZ" + "".join(secrets.choice("0123456789") for _ in range(18))
            conn.execute(text("UPDATE bank_accounts SET iban = :i, iban_index = :ix WHERE id = :id"),
                         {"i": crypto.encrypt(iban, "bank_accounts.iban"), "ix": crypto.blind_index(iban, "iban"),
                          "id": b["id"]})
        counts["bank_accounts"] = len(banks)
        conn.execute(text("UPDATE companies SET contact_phone = '', contact_email = '', legal_address = '', "
                          "actual_address = ''"))
        conn.execute(text("UPDATE order_points SET address = '', contact_name = '', contact_phone = ''"))
        conn.execute(text("UPDATE checkpoints SET lat = NULL, lng = NULL, note = ''"))
        conn.execute(text("UPDATE messages SET body = '…'"))
        conn.execute(text("UPDATE audit_log SET ip = '', device = '', details = '{}'"))
        conn.execute(text("UPDATE signatures SET ip = ''"))
        for t in ("user_sessions", "otp_codes", "device_events", "outbox", "notifications", "channel_links",
                  "support_access_grants", "biometric_checks", "api_keys", "webhook_deliveries", "webhook_endpoints"):
            conn.execute(text(f"DELETE FROM {t}"))  # noqa: S608 — fixed names
        if pg:
            for t in ("checkpoints", "messages", "audit_log", "integration_calls", "signatures"):
                conn.execute(text(f"ALTER TABLE {t} ENABLE TRIGGER USER"))
    # Uploaded scans and photos may contain personal data: the copy keeps generated documents only.
    from sqlalchemy import select

    from app.core.storage import storage
    from app.db import SessionLocal
    from app.modules.documents.models import Document, StoredFile
    from app.modules.platform.service import set_setting

    db = SessionLocal()
    try:
        keep = set(db.execute(select(Document.file_id).where(Document.is_generated.is_(True))).scalars())
        removed = 0
        for f in db.execute(select(StoredFile).where(StoredFile.is_deleted.is_(False))).scalars().all():
            if f.id not in keep:
                storage.delete(f.storage_key)
                f.is_deleted = True
                removed += 1
        counts["files"] = removed
        set_setting(db, "platform.data_origin", "anonymized", "SEC-DAT-09: origin of the data in this database")
        db.commit()
    finally:
        db.close()
    return counts


def check_data_origin(db) -> None:
    """Called at start-up. Marks a production database; stops other environments on an unanonymised copy."""
    from app.modules.platform.service import get_setting, set_setting

    origin = get_setting(db, "platform.data_origin", None)
    if settings.is_production:
        if origin != "production":
            set_setting(db, "platform.data_origin", "production", "SEC-DAT-09: origin of the data in this database")
        return
    if origin == "production":
        raise RuntimeError("This database is a copy of production and has not been anonymised. "
                           "Run `python -m app.cli anonymize --confirm` on the copy first (SEC-DAT-09).")
    if origin is None:
        set_setting(db, "platform.data_origin", settings.app_env, "SEC-DAT-09: origin of the data in this database")


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("rotate-keys", "anonymize"):
        print(__doc__)
        return 2
    if argv[0] == "rotate-keys":
        print(rotate_keys())
        return 0
    if "--confirm" not in argv:
        print("anonymize is irreversible: add --confirm")
        return 2
    print(anonymize())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
