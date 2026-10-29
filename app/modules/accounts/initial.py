"""The first accounts of a new installation, created at start-up from the server settings.

    INITIAL_ADMIN_PHONE, INITIAL_ADMIN_NAME, INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD
        the platform administrator (staff role ``admin``); at the first sign-in the admin interface requires
        the authenticator app (2FA) before anything else;
    INITIAL_USER_PHONE, INITIAL_USER_NAME, INITIAL_USER_EMAIL, INITIAL_USER_PASSWORD,
    INITIAL_USER_TYPE (client | carrier), INITIAL_USER_COMPANY, INITIAL_USER_BIN
        one ordinary user — the owner of a client or carrier company.

Passwords are secrets: ``deploy/secrets/initial_admin_password`` / ``initial_user_password`` (Docker secrets,
created by generate-secrets.sh) or the variables. An account is created only once — when no user has that
phone yet; later starts never change it (a changed password stays changed). An existing user with the phone is
never promoted to administrator automatically. Nothing is created while the settings are empty.
"""
from __future__ import annotations

import logging
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.secrets import secret
from app.core.security import hash_password

log = logging.getLogger("abdex.accounts")


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _check(db: Session, prefix: str) -> tuple[str, str, str | None, str] | None:
    from app.modules.accounts.models import User
    from app.modules.accounts.service import EMAIL_RE, normalize_phone, password_problems

    raw_phone = _env(f"{prefix}_PHONE")
    if not raw_phone:
        return None
    phone = normalize_phone(raw_phone)
    name = _env(f"{prefix}_NAME")
    email = _env(f"{prefix}_EMAIL").lower() or None
    password = secret(f"{prefix}_PASSWORD")
    problems = []
    if len(phone) != 12:
        problems.append("phone must be +7XXXXXXXXXX")
    if not name:
        problems.append(f"{prefix}_NAME is empty")
    if email and not EMAIL_RE.match(email):
        problems.append("e-mail is not valid")
    if not password:
        problems.append(f"{prefix}_PASSWORD is empty")
    else:
        problems += password_problems(password, identifiers=(phone[-10:], email or ""))
    if problems:
        log.error("%s: account not created — %s", prefix, ", ".join(problems))
        return None
    if db.execute(select(User.id).where(User.phone == phone)).first():
        return None  # created earlier (or registered by that person): never touched again
    if email and db.execute(select(User.id).where(User.email == email)).first():
        log.error("%s: account not created — e-mail %s belongs to another user", prefix, email)
        return None
    return phone, name, email, password


def _admin(db: Session) -> bool:
    from app.modules.accounts.models import STAFF_ADMIN, User

    data = _check(db, "INITIAL_ADMIN")
    if data is None:
        return False
    phone, name, email, password = data
    user = User(phone=phone, full_name=name, email=email, password_hash=hash_password(password),
                phone_verified=True, email_verified=bool(email), staff_role=STAFF_ADMIN)
    db.add(user)
    db.flush()
    audit(db, "admin.staff_granted", object_type="user", object_id=user.id, role="system",
          details={"role": STAFF_ADMIN, "via": "initial_settings"})
    log.info("initial administrator created")
    return True


def _user(db: Session) -> bool:
    from app.modules.accounts.models import (
        COMPANY_CARRIER,
        COMPANY_CLIENT,
        ROLE_FLEET_OWNER,
        ROLE_OWNER,
        Company,
        Membership,
        User,
    )
    from app.modules.accounts.service import validate_bin

    kind = _env("INITIAL_USER_TYPE").lower() or COMPANY_CLIENT
    company_name, bin_iin = _env("INITIAL_USER_COMPANY"), _env("INITIAL_USER_BIN")
    if _env("INITIAL_USER_PHONE"):
        problems = []
        if kind not in (COMPANY_CLIENT, COMPANY_CARRIER):
            problems.append("INITIAL_USER_TYPE must be client or carrier")
        if not company_name:
            problems.append("INITIAL_USER_COMPANY is empty")
        if not validate_bin(bin_iin):
            problems.append("INITIAL_USER_BIN is not a valid BIN/IIN")
        if problems:
            log.error("INITIAL_USER: account not created — %s", ", ".join(problems))
            return False
    data = _check(db, "INITIAL_USER")
    if data is None:
        return False
    phone, name, email, password = data
    user = User(phone=phone, full_name=name, email=email, password_hash=hash_password(password),
                phone_verified=True, email_verified=bool(email))
    db.add(user)
    db.flush()
    company = Company(kind=kind, name=company_name, bin_iin=bin_iin, contact_phone=phone,
                      contact_email=email or "")
    db.add(company)
    db.flush()
    db.add(Membership(user_id=user.id, company_id=company.id,
                      role=ROLE_OWNER if kind == COMPANY_CLIENT else ROLE_FLEET_OWNER))
    audit(db, "user.register", object_type="user", object_id=user.id, role="system", company_id=company.id,
          details={"via": "initial_settings"})
    log.info("initial user created")
    return True


def ensure_initial_accounts(db: Session) -> int:
    """Called at start-up; returns how many accounts were created."""
    created = int(_admin(db)) + int(_user(db))
    if created:
        db.commit()
    return created
