"""Operational commands.

    python -m app.cli preflight              launch readiness report; exit code 1 while an ERROR remains
    python -m app.cli create-staff --phone +7701... --name "Имя Фамилия" --role admin [--email a@b.kz]
                                             create a platform employee (or give an existing user the role);
                                             roles: admin, manager, moderator, finance, auditor; a one-time
                                             password is printed — change it and set up 2FA at first login
    python -m app.cli audit-verify           check the security journal archive (SEC-LOG-04); exit code 1 if tampered
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


def preflight() -> int:
    from app.bootstrap import ensure_initialized
    from app.core.preflight import ERROR, OK, report
    from app.db import SessionLocal

    db = None
    try:
        ensure_initialized()
        db = SessionLocal()
        items = report(db)
    except Exception as exc:  # noqa: BLE001 — the database itself may be what is missing
        from app.core.preflight import Item, check_env

        items = check_env() + [Item(ERROR, "db", f"база данных недоступна: {type(exc).__name__}: {str(exc)[:200]}")]
    finally:
        if db is not None:
            db.close()
    marks = {OK: "  ok ", "WARN": " warn", ERROR: "ERROR"}
    for i in items:
        print(f"[{marks[i.level]}] {i.text}")
    errors = sum(1 for i in items if i.level == ERROR)
    print(f"\n{errors} error(s), {sum(1 for i in items if i.level == 'WARN')} warning(s)")
    return 1 if errors else 0


def _arg(argv: list[str], name: str) -> str:
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return ""


def create_staff(phone: str, name: str, role: str, email: str = "") -> str:
    """Creates a staff member (or grants the role to an existing user); returns the one-time password, or ""
    when an existing user keeps their own password."""
    from sqlalchemy import select

    from app.bootstrap import ensure_initialized
    from app.core.audit import audit
    from app.core.security import hash_password
    from app.db import SessionLocal
    from app.modules.accounts.models import STAFF_ROLES, User
    from app.modules.accounts.service import normalize_phone

    if role not in STAFF_ROLES:
        raise SystemExit(f"role must be one of: {', '.join(STAFF_ROLES)}")
    phone = normalize_phone(phone)
    if len(phone) != 12:
        raise SystemExit("phone: +7XXXXXXXXXX")
    ensure_initialized()
    db = SessionLocal()
    try:
        _system(db.connection())
        user = db.execute(select(User).where(User.phone == phone)).scalar_one_or_none()
        password = ""
        if user is None:
            if not name.strip():
                raise SystemExit("--name is required for a new user")
            password = secrets.token_urlsafe(12)
            user = User(phone=phone, full_name=name.strip(), email=(email or "").strip().lower() or None,
                        password_hash=hash_password(password), phone_verified=True)
            db.add(user)
            db.flush()
        user.staff_role = role
        audit(db, "admin.staff_granted", object_type="user", object_id=user.id, details={"role": role, "via": "cli"})
        db.commit()
        return password
    finally:
        db.close()


def main(argv: list[str]) -> int:
    if argv and argv[0] == "preflight":
        return preflight()
    if argv and argv[0] == "audit-verify":
        from app.core.audit_archive import export, verify
        from app.db import SessionLocal

        db = SessionLocal()
        try:
            _system(db.connection())
            export(db)  # bring the archive up to date first
            db.commit()
            res = verify(db)
        finally:
            db.close()
        print(f"records: {res['records']} in {res['files']} file(s), {res['first']} … {res['last']}")
        for p in res["problems"]:
            print("PROBLEM:", p)
        print("archive intact" if res["ok"] else "ARCHIVE DOES NOT MATCH")
        return 0 if res["ok"] else 1
    if argv and argv[0] == "create-staff":
        password = create_staff(_arg(argv, "--phone"), _arg(argv, "--name"), _arg(argv, "--role"),
                                _arg(argv, "--email"))
        print("staff member ready." + (f" One-time password: {password}" if password else
                                       " Existing user: signs in with their own password."))
        print("At first login: change the password and enable the authenticator app (2FA is required for staff).")
        return 0
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
