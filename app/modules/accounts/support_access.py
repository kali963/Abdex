"""Support works "as the user" (FR-ADM-05).

* Only with the user's consent (a time-limited grant the user gives and can revoke), or by regulation:
  a platform administrator states the regulation basis explicitly.
* A separate short session names the staff member; it is never extended, and a banner is shown on every page.
* Every request made in it is written to the audit journal; sensitive actions (password, 2FA, bank details,
  signing, API keys, consents, account deletion) are refused outright.
* The user is notified when the session starts (security notification, cannot be disabled).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.security import hash_token, token
from app.db import utcnow
from app.modules.accounts.models import STAFF_ADMIN, SupportAccessGrant, User, UserSession

MAX_GRANT_HOURS = 72
# A support session may only read, plus the few helping actions below (allow-list): filling in orders and fleet
# cards, the support thread and the deal chat. Everything with legal or security weight — accepting bids,
# cancelling, signing, money, API keys, notifications channels, company details, account security — is refused.
ALLOWED_WRITE_PREFIXES = ("/orders/new", "/orders/import", "/fleet/vehicles", "/fleet/drivers", "/support",
                          "/notifications", "/impersonation/end", "/logout")
ALLOWED_WRITE_PATTERNS = (r"^/orders/[0-9a-f-]{36}/(edit|template|submit)$", r"^/deals/[0-9a-f-]{36}/chat$")
FORBIDDEN_PREFIXES = ("/account/password", "/account/2fa", "/account/delete", "/account/sessions",
                      "/account/consents", "/account/support-access", "/company/bank", "/company/api-keys",
                      "/company/webhooks", "/company/members", "/company/invite")  # kept for reference / tests
FORBIDDEN_SUFFIXES = ("/sign", "/sign-code", "/sign-eds", "/egov/start", "/accept")


def active_grant(db: Session, user_id) -> SupportAccessGrant | None:
    return db.execute(select(SupportAccessGrant).where(
        SupportAccessGrant.user_id == user_id, SupportAccessGrant.revoked_at.is_(None),
        SupportAccessGrant.valid_until > utcnow()).order_by(SupportAccessGrant.valid_until.desc())).scalars().first()


def grant(db: Session, user: User, hours: int, ticket_number: str = "") -> SupportAccessGrant:
    if not 1 <= hours <= MAX_GRANT_HOURS:
        raise ValidationFailed({"hours": "error.number"})
    g = SupportAccessGrant(user_id=user.id, valid_until=utcnow() + timedelta(hours=hours),
                           ticket_number=ticket_number.strip()[:30], created_by=user.id)
    db.add(g)
    db.flush()
    audit(db, "support_access.granted", object_type="user", object_id=user.id, details={"hours": hours})
    return g


def revoke_grants(db: Session, user: User) -> None:
    now = utcnow()
    for g in db.execute(select(SupportAccessGrant).where(SupportAccessGrant.user_id == user.id,
                                                         SupportAccessGrant.revoked_at.is_(None))).scalars():
        g.revoked_at = now
    # an active support session ends together with the consent
    for s in db.execute(select(UserSession).where(UserSession.user_id == user.id,
                                                  UserSession.impersonator_id.is_not(None),
                                                  UserSession.revoked_at.is_(None))).scalars():
        s.revoked_at = now
    audit(db, "support_access.revoked", object_type="user", object_id=user.id)


def start(db: Session, staff: User, target: User, *, reason: str, by_regulation: bool) -> tuple[str, UserSession]:
    from app.modules.accounts.service import default_company_id
    from app.modules.notifications.service import notify_user
    from app.modules.platform.service import get_setting

    ratelimit.hit("impersonate", str(staff.id))
    if target.is_staff or target.is_blocked or target.anonymized_at or target.is_deleted or target.id == staff.id:
        raise NotFound()
    if len(reason.strip()) < 10:
        raise ValidationFailed({"reason": "error.reason_required"})
    consent = active_grant(db, target.id)
    if consent is None:
        if not by_regulation or staff.staff_role != STAFF_ADMIN:
            raise Forbidden("impersonation_needs_consent")
    minutes = int(get_setting(db, "impersonation.minutes", 30))
    now = utcnow()
    until = min(now + timedelta(minutes=minutes), consent.valid_until) if consent else now + timedelta(minutes=minutes)
    ctx = get_ctx()
    raw = token(32)
    sess = UserSession(user_id=target.id, token_hash=hash_token(raw), csrf_token=token(24),
                       active_company_id=default_company_id(db, target), mfa_passed=True, is_admin=False,
                       last_seen_at=now, expires_at=until, ip=ctx.ip, user_agent=ctx.user_agent[:300],
                       device_id=ctx.device_id, impersonator_id=staff.id,
                       impersonation_reason=("[regulation] " if consent is None else "") + reason.strip()[:280])
    db.add(sess)
    db.flush()
    audit(db, "impersonation.started", object_type="user", object_id=target.id, user_id=staff.id, role=staff.staff_role,
          reason=reason, details={"basis": "consent" if consent else "regulation", "until": until.isoformat(),
                                  "session": str(sess.id)})
    notify_user(db, target.id, "security.support_session", {"until": until.strftime("%H:%M UTC")},
                link="/account/sessions", critical=True)
    return raw, sess


def end(db: Session, sess: UserSession) -> None:
    if sess.impersonator_id is None:
        return
    sess.revoked_at = utcnow()
    audit(db, "impersonation.ended", object_type="user", object_id=sess.user_id, user_id=sess.impersonator_id,
          details={"session": str(sess.id)})


def is_forbidden(path: str, method: str) -> bool:
    import re

    if method in ("GET", "HEAD", "OPTIONS"):
        return False
    if path.endswith(FORBIDDEN_SUFFIXES) or path.startswith(FORBIDDEN_PREFIXES):
        return True
    return not (path.startswith(ALLOWED_WRITE_PREFIXES) or any(re.match(p, path) for p in ALLOWED_WRITE_PATTERNS))
