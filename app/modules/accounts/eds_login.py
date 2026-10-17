"""Login with a qualified e-signature (FR-AUTH-09) — an additional way in, alongside phone + password.

* The user first binds the EDS in the security settings: signs a one-time challenge with the certificate; the
  server verifies the signature (chain, validity, revocation) and stores the certificate's IIN — encrypted,
  with a blind index for the lookup (NFR-DB-08).
* Login: the browser asks for a fresh challenge, signs it locally (NCALayer; the key never leaves the
  device), and the server verifies the signature and finds the user by the IIN in the certificate.
* Challenges live five minutes and are single-use (replay protection); only their hash is stored.
* The second factor policy still applies after an EDS login (SEC-AUT-05), as after a password login.
* Switched by the ``auth.eds_login`` flag: available once the state signature services are connected.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, Conflict, Forbidden
from app.db import utcnow
from app.modules.accounts.models import OtpCode, User

PURPOSE = "eds_challenge"
TTL = timedelta(minutes=5)


def enabled(db: Session) -> bool:
    from app.modules.platform.service import flag_enabled

    return flag_enabled(db, "auth.eds_login")


def _hash(challenge: str) -> str:
    return hashlib.sha256(challenge.encode()).hexdigest()


def new_challenge(db: Session) -> str:
    ratelimit.hit("eds_challenge", get_ctx().ip or "local")
    challenge = f"AbdEX login {utcnow():%Y-%m-%dT%H:%M:%SZ} {secrets.token_hex(24)}"
    db.add(OtpCode(target=f"eds:{_hash(challenge)[:48]}", purpose=PURPOSE, code_hash=_hash(challenge),
                   expires_at=utcnow() + TTL))
    db.flush()
    return challenge


def consume(db: Session, challenge: str) -> None:
    row = db.execute(select(OtpCode).where(OtpCode.target == f"eds:{_hash(challenge or '')[:48]}",
                                           OtpCode.purpose == PURPOSE).with_for_update()).scalar_one_or_none()
    if row is None or row.used_at is not None or row.expires_at < utcnow() or row.code_hash != _hash(challenge):
        raise AppError("eds_challenge", status_code=400)
    row.used_at = utcnow()


def _verify(db: Session, package: str, challenge: str) -> dict:
    """Returns the signer data of a valid signature over the challenge; the owner check does not apply here —
    the certificate itself names the person."""
    from app.modules.documents import eds
    from app.modules.platform.service import get_setting

    if not package or len(package) > 200_000:
        raise AppError("eds_invalid", status_code=422, checks="package")
    consume(db, challenge)
    revoked = set(get_setting(db, "eds.revoked_serials", []) or [])
    res = eds.verifier().verify(package, challenge.encode(), signed_at=utcnow(), expected_bin="", revoked=revoked)
    checks = {k: v for k, v in res.checks.items() if k != "owner"}
    if not checks or not all(checks.values()):
        failed = [k for k, v in checks.items() if not v] or [res.error or "invalid"]
        audit(db, "auth.eds_rejected", object_type="user", object_id="", result="denied", details={"checks": failed})
        raise AppError("eds_invalid", status_code=422, checks=", ".join(failed))
    iin = str(res.signer.get("iin", ""))
    if not re.fullmatch(r"\d{12}", iin):
        raise AppError("eds_invalid", status_code=422, checks="iin")
    return res.signer


def link(db: Session, user: User, package: str, challenge: str) -> User:
    from app.core.crypto import blind_index

    if not enabled(db):
        raise Forbidden("eds_login_off")
    signer = _verify(db, package, challenge)
    other = db.execute(select(User.id).where(User.iin_index == blind_index(signer["iin"], "iin"),
                                             User.id != user.id)).first()
    if other:
        audit(db, "auth.eds_link_conflict", object_type="user", object_id=user.id, result="denied")
        raise Conflict("eds_iin_taken")
    user.iin, user.eds_linked_at = signer["iin"], utcnow()
    audit(db, "auth.eds_linked", object_type="user", object_id=user.id, details={"serial": signer.get("serial", "")})
    return user


def unlink(db: Session, user: User) -> None:
    user.iin, user.eds_linked_at = "", None
    audit(db, "auth.eds_unlinked", object_type="user", object_id=user.id)


def authenticate(db: Session, package: str, challenge: str) -> User:
    from app.core.crypto import blind_index

    if not enabled(db):
        raise Forbidden("eds_login_off")
    ratelimit.hit("login", get_ctx().ip or "local")
    signer = _verify(db, package, challenge)
    user = db.execute(select(User).where(User.iin_index == blind_index(signer["iin"], "iin"),
                                         User.is_deleted.is_(False))).scalar_one_or_none()
    if user is None or not user.eds_linked_at:
        audit(db, "auth.login_failed", object_type="user", object_id="", result="denied", details={"method": "eds"})
        raise AppError("eds_not_linked", status_code=401)
    if user.is_blocked:
        audit(db, "auth.login_blocked", object_type="user", object_id=user.id, result="denied", user_id=user.id)
        raise Forbidden("account_blocked")
    if user.locked_until and user.locked_until > utcnow():
        raise AppError("account_temporarily_locked", status_code=429)
    user.failed_logins = 0
    audit(db, "auth.login_eds", object_type="user", object_id=user.id, user_id=user.id,
          details={"serial": signer.get("serial", "")})
    return user


def dev_iin(user: User) -> str:
    """Test IIN for the development CA (never a real person's)."""
    if user.iin:
        return user.iin
    return "99" + f"{int(hashlib.sha256(str(user.id).encode()).hexdigest(), 16) % 10**10:010d}"
