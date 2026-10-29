"""Registration, authentication, sessions, OTP, 2FA, invitations, bank details (M1, section 34)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.core import ratelimit
from app.core.audit import audit
from app.core.i18n import LOCALES
from app.core.context import get_ctx
from app.core.errors import AppError, Forbidden, NotFound, ValidationFailed
from app.core.security import (
    generate_otp_code,
    hash_password,
    hash_token,
    password_problems,
    token,
    verify_password,
    verify_totp,
)
from app.db import utcnow
from app.modules.accounts.models import (
    COMPANY_CARRIER,
    COMPANY_CLIENT,
    OWNER_ROLES,
    ROLE_DRIVER,
    ROLE_FLEET_OWNER,
    ROLE_OWNER,
    BankAccount,
    Company,
    Consent,
    Invitation,
    Membership,
    OtpCode,
    User,
    UserSession,
)
from app.modules.integrations.adapters import email as email_adapter
from app.modules.integrations.adapters import sms as sms_adapter

PHONE_RE = re.compile(r"^\+7\d{10}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CONSENT_TEXT_VERSION = "2026-07"
OTP_TTL = timedelta(minutes=5)  # SEC-AUT-04
OTP_MAX_ATTEMPTS = 5


def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 11 and digits[0] in "78":
        digits = "7" + digits[1:]
    elif len(digits) == 10:
        digits = "7" + digits
    return "+" + digits


def validate_bin(value: str) -> bool:
    """BIN/IIN: 12 digits with the official control digit algorithm."""
    if not re.fullmatch(r"\d{12}", value or ""):
        return False
    d = [int(c) for c in value]
    return bin_control_digit(value[:11]) == d[11]


def bin_control_digit(first11: str) -> int | None:
    d = [int(c) for c in first11]
    s = sum(d[i] * (i + 1) for i in range(11)) % 11
    if s == 10:
        weights = (3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2)
        s = sum(d[i] * weights[i] for i in range(11)) % 11
        if s == 10:
            return None
    return s


def make_bin(prefix11: str) -> str:
    """A valid BIN/IIN starting with the given digits (used for anonymised copies and tests)."""
    for i in range(10):
        candidate = prefix11[:10] + str(i)
        cd = bin_control_digit(candidate)
        if cd is not None:
            return candidate + str(cd)
    raise ValueError("cannot build BIN")


# ------------------------------------------------------------------------ OTP (SEC-AUT-04)


def send_otp(db: Session, target: str, purpose: str, *, channel: str = "sms", context: str = "") -> None:
    ratelimit.hit("otp_send", target)
    db.execute(update(OtpCode).where(OtpCode.target == target, OtpCode.purpose == purpose, OtpCode.used_at.is_(None))
               .values(used_at=utcnow()))
    code = generate_otp_code(6)
    db.add(OtpCode(target=target, purpose=purpose, code_hash=hash_token(code), expires_at=utcnow() + OTP_TTL,
                   context=context))
    db.flush()
    text = f"AbdEX: код {code}. Никому не сообщайте его."
    (email_adapter if channel == "email" else sms_adapter).send(target, text)


def check_otp(db: Session, target: str, purpose: str, code: str, *, context: str = "") -> bool:
    ratelimit.hit("otp_check", target)
    row = db.execute(
        select(OtpCode).where(OtpCode.target == target, OtpCode.purpose == purpose, OtpCode.used_at.is_(None))
        .order_by(OtpCode.created_at.desc())
    ).scalars().first()
    if row is None or row.expires_at < utcnow() or row.attempts >= OTP_MAX_ATTEMPTS:
        return False
    if context and row.context != context:
        return False
    row.attempts += 1
    if row.code_hash != hash_token((code or "").strip()):
        db.flush()
        return False
    row.used_at = utcnow()
    db.flush()
    return True


# ------------------------------------------------------------------------ registration


@dataclass
class RegistrationData:
    full_name: str
    phone: str
    email: str
    password: str
    account_type: str  # client / carrier / driver
    company_name: str = ""
    bin_iin: str = ""
    consent_registration: bool = False
    locale: str = "ru"


def register(db: Session, data: RegistrationData) -> User:
    ratelimit.hit("register", get_ctx().ip or "local")
    errors: dict[str, str] = {}
    phone = normalize_phone(data.phone)
    email = (data.email or "").strip().lower() or None
    if not data.full_name.strip():
        errors["full_name"] = "error.required"
    if not PHONE_RE.match(phone):
        errors["phone"] = "error.phone_format"
    if email and not EMAIL_RE.match(email):
        errors["email"] = "error.email_format"
    for p in password_problems(data.password, identifiers=(phone[-10:], email or "")):
        errors.setdefault("password", f"error.{p}")
    if data.account_type not in ("client", "carrier", "driver"):
        errors["account_type"] = "error.required"
    if data.account_type in ("client", "carrier"):
        if not data.company_name.strip():
            errors["company_name"] = "error.required"
        if not validate_bin(data.bin_iin.strip()):
            errors["bin_iin"] = "error.bin_invalid"
    if not data.consent_registration:
        errors["consent_registration"] = "error.consent_required"
    if not errors:
        if db.execute(select(User.id).where(User.phone == phone)).first():
            errors["phone"] = "error.phone_taken"
        if email and db.execute(select(User.id).where(User.email == email)).first():
            errors["email"] = "error.email_taken"
    if errors:
        raise ValidationFailed(errors)

    user = User(phone=phone, email=email, full_name=data.full_name.strip(), password_hash=hash_password(data.password),
                locale=data.locale if data.locale in LOCALES else "ru")
    db.add(user)
    db.flush()
    db.add(Consent(user_id=user.id, purpose="registration", text_version=CONSENT_TEXT_VERSION, ip=get_ctx().ip))
    if data.account_type == "driver":
        # FR-AUTH-05: a driver registers without a company; a personal "self-employed" profile is created
        company = Company(kind=COMPANY_CARRIER, name=data.full_name.strip(), bin_iin=data.bin_iin.strip() or "",
                          legal_form="ФЛ", is_self_employed_driver=True, contact_phone=phone)
        db.add(company)
        db.flush()
        db.add(Membership(user_id=user.id, company_id=company.id, role=ROLE_DRIVER))
        from app.modules.fleet.models import Driver

        db.add(Driver(company_id=company.id, user_id=user.id, full_name=user.full_name, iin=data.bin_iin.strip(),
                      phone=phone))
    else:
        kind = COMPANY_CLIENT if data.account_type == "client" else COMPANY_CARRIER
        company = Company(kind=kind, name=data.company_name.strip(), bin_iin=data.bin_iin.strip(),
                          contact_phone=phone, contact_email=email or "", locale=user.locale)
        db.add(company)
        db.flush()
        db.add(Membership(user_id=user.id, company_id=company.id,
                          role=ROLE_OWNER if kind == COMPANY_CLIENT else ROLE_FLEET_OWNER))
        from app.modules.fleet.service import detect_duplicates

        detect_duplicates(db, company_id=company.id, bin_iin=company.bin_iin)
    audit(db, "user.register", object_type="user", object_id=user.id, user_id=user.id, company_id=company.id)
    db.flush()
    from app.modules.platform.antifraud import track

    track(db, "register", user_id=user.id, company_id=company.id if company else None)  # SEC-FRD-02/03
    send_otp(db, phone, "verify_phone")
    return user


# ------------------------------------------------------------------------ login (SEC-AUT-03)


def authenticate(db: Session, login: str, password: str) -> User:
    ip = get_ctx().ip or "local"
    ratelimit.hit("login", ip)
    login = (login or "").strip()
    if "@" in login:
        user = db.execute(select(User).where(User.email == login.lower())).scalar_one_or_none()
    else:
        user = db.execute(select(User).where(User.phone == normalize_phone(login))).scalar_one_or_none()
    key = str(user.id) if user else login
    if not ratelimit.hit("login_account", key, raise_exc=False):
        audit(db, "auth.login_throttled", object_type="user", object_id=key, result="denied")
        raise AppError("too_many_attempts", status_code=429)
    now = utcnow()
    if user and user.locked_until and user.locked_until > now:
        raise AppError("account_temporarily_locked", status_code=429)
    password_ok = verify_password(user.password_hash if user else None, password)  # same cost for unknown logins
    if not user or not password_ok or user.is_deleted:
        if user:
            user.failed_logins += 1
            if user.failed_logins >= 10:
                user.locked_until = now + timedelta(minutes=15)
                # alert the account owner (SEC-AUT-03)
                sms_adapter.send(user.phone, "AbdEX: зафиксирована серия неудачных попыток входа в ваш аккаунт.")
        audit(db, "auth.login_failed", object_type="user", object_id=user.id if user else "", result="denied",
              user_id=user.id if user else None)
        raise AppError("invalid_credentials", status_code=401)
    if user.is_blocked:
        audit(db, "auth.login_blocked", object_type="user", object_id=user.id, result="denied", user_id=user.id)
        raise Forbidden("account_blocked")
    user.failed_logins = 0
    user.locked_until = None
    return user


def requires_second_factor(db: Session, user: User) -> bool:
    return user.has_2fa


def must_enroll_2fa(db: Session, user: User, *, totp: bool | None = None, sms: bool | None = None) -> bool:
    """SEC-AUT-05: mandatory for platform staff and company owners.
    Staff need an authenticator app (SMS is only a reserve channel for them); company owners may use SMS.
    `totp` / `sms` let callers ask "would 2FA still be sufficient after this change"."""
    totp = user.totp_enabled if totp is None else totp
    sms = user.sms_2fa_enabled if sms is None else sms
    if not settings.require_2fa_privileged:
        return False
    if user.staff_role:
        return not totp
    if totp or sms:
        return False
    roles = db.execute(select(Membership.role).where(Membership.user_id == user.id, Membership.is_active.is_(True)))
    return any(r in OWNER_ROLES for r in roles.scalars())


def start_login_sms(db: Session, user: User) -> None:
    send_otp(db, user.phone, "login_2fa")


def set_sms_2fa(db: Session, user: User, enabled: bool) -> None:
    user.sms_2fa_enabled = enabled
    audit(db, "auth.2fa_sms_enabled" if enabled else "auth.2fa_sms_disabled", object_type="user", object_id=user.id,
          user_id=user.id)
    from app.modules.notifications.service import notify_user

    notify_user(db, user.id, "security.2fa_changed", {}, link="/account/security", critical=True)


def create_session(db: Session, user: User, *, mfa_passed: bool, is_admin: bool = False) -> tuple[str, UserSession]:
    """SEC-AUT-06: a fresh session identifier after every login."""
    ctx = get_ctx()
    raw = token(32)
    now = utcnow()
    known_device = db.execute(
        select(UserSession.id).where(UserSession.user_id == user.id, UserSession.device_id == ctx.device_id)
    ).first() if ctx.device_id else None
    had_sessions = db.execute(select(UserSession.id).where(UserSession.user_id == user.id)).first() is not None
    company_id = default_company_id(db, user)
    sess = UserSession(user_id=user.id, token_hash=hash_token(raw), csrf_token=token(24), active_company_id=company_id,
                       mfa_passed=mfa_passed, is_admin=is_admin, last_seen_at=now,
                       expires_at=now + timedelta(days=settings.session_absolute_days), ip=ctx.ip,
                       user_agent=ctx.user_agent[:300], device_id=ctx.device_id)
    db.add(sess)
    user.last_login_at = now
    db.flush()
    audit(db, "auth.login", object_type="user", object_id=user.id, user_id=user.id, company_id=company_id)
    from app.modules.platform.antifraud import track

    track(db, "login", user_id=user.id, company_id=company_id)  # SEC-FRD-02
    from app.modules.fleet.reverify import on_login

    on_login(db, user.id, ctx.device_id or "")  # FR-KYC-09: a driver on a new device
    if not known_device and had_sessions and ctx.device_id:
        # SEC-AUT-11 / FR-NTF-05: security notifications cannot be disabled
        from app.modules.notifications.service import notify_user

        notify_user(db, user.id, "security.new_device", {"ip": ctx.ip}, link="/account/sessions", critical=True)
    return raw, sess


def default_company_id(db: Session, user: User):
    m = db.execute(select(Membership).where(Membership.user_id == user.id, Membership.is_active.is_(True))
                   .order_by(Membership.created_at)).scalars().first()
    return m.company_id if m else None


def load_session(db: Session, raw: str | None) -> UserSession | None:
    if not raw:
        return None
    sess = db.execute(select(UserSession).where(UserSession.token_hash == hash_token(raw))).scalar_one_or_none()
    if sess is None or sess.revoked_at is not None:
        return None
    now = utcnow()
    idle = timedelta(minutes=settings.admin_idle_timeout_min if sess.is_admin else settings.user_idle_timeout_min)
    if sess.expires_at < now or sess.last_seen_at + idle < now:
        sess.revoked_at = now
        db.commit()
        return None
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    return sess


def revoke_session(db: Session, sess: UserSession) -> None:
    sess.revoked_at = utcnow()
    audit(db, "auth.logout", object_type="session", object_id=sess.id, user_id=sess.user_id)


def revoke_all_sessions(db: Session, user_id, *, except_id=None) -> int:
    q = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_id:
        q = q.where(UserSession.id != except_id)
    res = db.execute(q.values(revoked_at=utcnow()))
    audit(db, "auth.sessions_revoked", object_type="user", object_id=user_id, user_id=user_id)
    return res.rowcount or 0


def verify_totp_code(user: User, code: str) -> bool:
    if not user.totp_enabled and not user.totp_secret:
        return False
    step = verify_totp(user.totp_secret, code, last_step=user.totp_last_step or 0)
    if step is None:
        return False
    user.totp_last_step = step
    return True


MAX_2FA_FAILURES = 5


def verify_second_factor(db: Session, user: User, code: str) -> bool:
    """Every guess counts, whatever factor it is checked against: the limit is per account, so a correct
    authenticator code cannot be brute-forced behind the SMS limit (SEC-AUT-03)."""
    if not ratelimit.hit("2fa", str(user.id), raise_exc=False):
        audit(db, "auth.2fa_throttled", object_type="user", object_id=user.id, result="denied", user_id=user.id)
        raise AppError("too_many_attempts", status_code=429)
    ok = user.totp_enabled and verify_totp_code(user, code)
    if not ok:
        ok = check_otp(db, user.phone, "login_2fa", code)  # SMS code (primary for SMS-2FA users, reserve for TOTP)
    audit(db, "auth.2fa_check", object_type="user", object_id=user.id, result="ok" if ok else "denied",
          user_id=user.id)
    return ok


def change_password(db: Session, user: User, current: str, new: str) -> None:
    if not verify_password(user.password_hash, current):
        raise ValidationFailed({"current_password": "error.invalid_password"})
    problems = password_problems(new, identifiers=(user.phone[-10:], user.email or ""))
    if problems:
        raise ValidationFailed({"new_password": f"error.{problems[0]}"})
    user.password_hash = hash_password(new)
    audit(db, "auth.password_changed", object_type="user", object_id=user.id, user_id=user.id)
    from app.modules.notifications.service import notify_user

    notify_user(db, user.id, "security.password_changed", {}, link="/account/security", critical=True)


def start_password_reset(db: Session, login: str) -> list:
    """SEC-AUT-09: the response never reveals whether the account exists — neither by its text nor by its
    timing: the messages are returned as callables that the caller sends after the response."""
    ratelimit.hit("password_reset", get_ctx().ip or "local")
    login = (login or "").strip()
    user = None
    if "@" in login:
        user = db.execute(select(User).where(User.email == login.lower())).scalar_one_or_none()
    elif login:
        user = db.execute(select(User).where(User.phone == normalize_phone(login))).scalar_one_or_none()
    if user is None or user.is_deleted:
        return []
    raw = token(24)
    db.add(OtpCode(target=str(user.id), purpose="password_reset", code_hash=hash_token(raw),
                   expires_at=utcnow() + timedelta(minutes=30)))
    from app.config import settings

    link = f"{settings.public_base_url.rstrip('/')}/reset-password?u={user.id}&t={raw}"  # opened from SMS / e-mail
    sends = []
    if user.email:
        sends.append(lambda: email_adapter.send(user.email, f"AbdEX: ссылка для восстановления пароля (30 минут): {link}"))
    sends.append(lambda: sms_adapter.send(user.phone, f"AbdEX: ссылка для восстановления пароля: {link}"))
    audit(db, "auth.password_reset_requested", object_type="user", object_id=user.id, user_id=user.id)
    return sends


def finish_password_reset(db: Session, user_id: str, raw: str, new_password: str) -> None:
    row = db.execute(select(OtpCode).where(OtpCode.target == user_id, OtpCode.purpose == "password_reset",
                                           OtpCode.used_at.is_(None))
                     .order_by(OtpCode.created_at.desc())).scalars().first()
    if row is None or row.expires_at < utcnow() or row.code_hash != hash_token(raw or ""):
        raise AppError("reset_link_invalid")
    import uuid as _uuid

    user = db.get(User, _uuid.UUID(user_id))
    if user is None:
        raise AppError("reset_link_invalid")
    problems = password_problems(new_password, identifiers=(user.phone[-10:], user.email or ""))
    if problems:
        raise ValidationFailed({"password": f"error.{problems[0]}"})
    row.used_at = utcnow()
    user.password_hash = hash_password(new_password)
    user.failed_logins = 0
    user.locked_until = None
    revoke_all_sessions(db, user.id)
    audit(db, "auth.password_reset_done", object_type="user", object_id=user.id, user_id=user.id)


# ------------------------------------------------------------------------ memberships / invitations


def memberships(db: Session, user_id) -> list[tuple[Membership, Company]]:
    rows = db.execute(
        select(Membership, Company).join(Company, Company.id == Membership.company_id)
        .where(Membership.user_id == user_id, Membership.is_active.is_(True)).order_by(Company.name)
    ).all()
    return [(m, c) for m, c in rows]


def role_in(db: Session, user_id, company_id) -> str | None:
    m = db.execute(select(Membership).where(Membership.user_id == user_id, Membership.company_id == company_id,
                                            Membership.is_active.is_(True))).scalar_one_or_none()
    return m.role if m else None


def create_invitation(db: Session, company: Company, role: str, note: str = "") -> str:
    from app.modules.accounts.permissions import roles_in_scope

    valid_roles = roles_in_scope("client" if company.kind == COMPANY_CLIENT else "carrier")  # FR-ACL-06
    if role not in valid_roles:
        raise ValidationFailed({"role": "error.invalid_role"})
    raw = token(18)
    db.add(Invitation(company_id=company.id, role=role, token_hash=hash_token(raw), note=note[:200],
                      expires_at=utcnow() + timedelta(days=3), created_by=get_ctx().user_id))
    audit(db, "company.invite_created", object_type="company", object_id=company.id, details={"role": role})
    return raw


def accept_invitation(db: Session, user: User, raw: str) -> Company:
    inv = db.execute(select(Invitation).where(Invitation.token_hash == hash_token(raw or ""))).scalar_one_or_none()
    if inv is None or inv.used_at or inv.revoked_at or inv.expires_at < utcnow():
        raise AppError("invitation_invalid")
    existing = db.execute(select(Membership).where(Membership.user_id == user.id,
                                                   Membership.company_id == inv.company_id)).scalar_one_or_none()
    if existing:
        existing.is_active = True
        existing.role = inv.role
    else:
        db.add(Membership(user_id=user.id, company_id=inv.company_id, role=inv.role))
    inv.used_at = utcnow()
    inv.used_by = user.id
    company = db.get(Company, inv.company_id)
    if inv.role == ROLE_DRIVER:
        # FR-AUTH-05: a self-registered driver joins a fleet
        from app.modules.fleet.models import Driver

        drv = db.execute(select(Driver).where(Driver.user_id == user.id)).scalars().first()
        if drv is None:
            db.add(Driver(company_id=company.id, user_id=user.id, full_name=user.full_name, iin="", phone=user.phone))
        else:
            db.add(Driver(company_id=company.id, user_id=user.id, full_name=drv.full_name, iin=drv.iin,
                          phone=user.phone, license_number=drv.license_number,
                          license_categories=drv.license_categories, license_until=drv.license_until))
    audit(db, "company.invite_accepted", object_type="company", object_id=company.id, user_id=user.id)
    return company


def deactivate_member(db: Session, company: Company, membership_id) -> None:
    """FR-AUTH-04: disabling an employee keeps their action history."""
    m = db.get(Membership, membership_id)
    if m is None or m.company_id != company.id:
        raise NotFound()
    if m.role in OWNER_ROLES:
        owners = db.execute(select(Membership).where(Membership.company_id == company.id,
                                                     Membership.role.in_(OWNER_ROLES),
                                                     Membership.is_active.is_(True))).scalars().all()
        if len(owners) <= 1:
            raise AppError("last_owner")
    m.is_active = False
    db.execute(update(UserSession).where(UserSession.user_id == m.user_id,
                                         UserSession.active_company_id == company.id,
                                         UserSession.revoked_at.is_(None)).values(revoked_at=utcnow()))
    audit(db, "company.member_disabled", object_type="membership", object_id=m.id)


# ------------------------------------------------------------------------ bank details (SEC-AUT-10)


IBAN_RE = re.compile(r"^KZ\d{2}[0-9A-Z]{16}$")


def request_bank_change(db: Session, company: Company, user: User, iban: str, bank_name: str, bik: str) -> BankAccount:
    iban = iban.replace(" ", "").upper()
    if not IBAN_RE.match(iban):
        raise ValidationFailed({"iban": "error.iban_format"})
    acc = BankAccount(company_id=company.id, iban=iban, bank_name=bank_name.strip(), bik=bik.strip().upper(),
                      status="pending", created_by=user.id)
    db.add(acc)
    db.flush()
    send_otp(db, user.phone, "bank_change", context=str(acc.id))
    from app.modules.platform.antifraud import track

    track(db, "bank_change", user_id=user.id, company_id=company.id)  # SEC-FRD-03
    audit(db, "company.bank_change_requested", object_type="bank_account", object_id=acc.id)
    return acc


def confirm_bank_change(db: Session, company: Company, user: User, account_id, code: str) -> BankAccount:
    acc = db.get(BankAccount, account_id)
    if acc is None or acc.company_id != company.id or acc.status != "pending":
        raise NotFound()
    if not check_otp(db, user.phone, "bank_change", code, context=str(acc.id)):
        raise ValidationFailed({"code": "error.code_invalid"})
    now = utcnow()
    for old in db.execute(select(BankAccount).where(BankAccount.company_id == company.id,
                                                    BankAccount.status == "active")).scalars():
        old.status = "superseded"
    acc.status = "active"
    acc.confirmed_at = now
    acc.effective_at = now + timedelta(hours=settings.iban_cooldown_hours)
    audit(db, "company.bank_changed", object_type="bank_account", object_id=acc.id)
    from app.modules.notifications.service import notify_company_owners
    from app.modules.fleet.service import detect_duplicates

    notify_company_owners(db, company.id, "security.bank_changed", {"iban_tail": acc.iban[-4:]},
                          link="/company", critical=True)
    detect_duplicates(db, company_id=company.id, iban=acc.iban)
    return acc


def active_bank_account(db: Session, company_id) -> BankAccount | None:
    return db.execute(select(BankAccount).where(BankAccount.company_id == company_id, BankAccount.status == "active")
                      ).scalars().first()


def record_consent(db: Session, user_id, purpose: str) -> None:
    db.add(Consent(user_id=user_id, purpose=purpose, text_version=CONSENT_TEXT_VERSION, ip=get_ctx().ip))
    audit(db, "consent.granted", object_type="consent", object_id=purpose, user_id=user_id)


def revoke_consent(db: Session, user_id, purpose: str) -> None:
    if purpose == "registration":
        raise AppError("consent_registration_required")
    for c in db.execute(select(Consent).where(Consent.user_id == user_id, Consent.purpose == purpose,
                                              Consent.revoked_at.is_(None))).scalars():
        c.revoked_at = utcnow()
    if purpose == "biometrics":  # SEC-DAT-10: images still kept are deleted together with the consent
        from app.modules.fleet.biometrics import purge_images

        purge_images(db, user_id=user_id)
    audit(db, "consent.revoked", object_type="consent", object_id=purpose, user_id=user_id)


def has_consent(db: Session, user_id, purpose: str) -> bool:
    return db.execute(select(Consent.id).where(Consent.user_id == user_id, Consent.purpose == purpose,
                                               Consent.revoked_at.is_(None))).first() is not None


# ------------------------------------------------------------------------ deletion (FR-AUTH-10, SEC-DAT-07)


def anonymize_user(db: Session, user: User, *, reason: str, by_staff: bool = False) -> None:
    """Soft delete: personal data is wiped, the deal history stays with an anonymous author.
    Refused while the user is the last active owner of a company (ownership must move first)."""
    for m in db.execute(select(Membership).where(Membership.user_id == user.id, Membership.is_active.is_(True))).scalars():
        if m.role in OWNER_ROLES:
            others = db.execute(select(Membership.id).where(Membership.company_id == m.company_id,
                                                            Membership.role.in_(OWNER_ROLES),
                                                            Membership.is_active.is_(True),
                                                            Membership.user_id != user.id)).first()
            company = db.get(Company, m.company_id)
            if others is None and not (company and company.is_self_employed_driver):
                raise AppError("last_owner_delete")
    from app.modules.fleet.models import Driver

    tag = user.id.hex[:12]
    user.full_name = "Удалённый пользователь"
    user.phone = f"+del{tag}"
    user.email = None
    user.password_hash = None
    user.totp_secret = None
    user.totp_enabled = False
    user.sms_2fa_enabled = False
    user.iin, user.eds_linked_at = "", None
    user.is_blocked = True
    user.is_deleted = True
    user.anonymized_at = utcnow()
    for m in db.execute(select(Membership).where(Membership.user_id == user.id)).scalars():
        m.is_active = False
    for d in db.execute(select(Driver).where(Driver.user_id == user.id)).scalars():
        d.full_name, d.phone, d.iin, d.license_number = "Удалённый водитель", "", "", ""
    for c in db.execute(select(Consent).where(Consent.user_id == user.id, Consent.revoked_at.is_(None))).scalars():
        c.revoked_at = utcnow()
    db.execute(update(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
               .values(revoked_at=utcnow()))
    audit(db, "user.anonymized", object_type="user", object_id=user.id, reason=reason[:300],
          details={"by_staff": by_staff})
