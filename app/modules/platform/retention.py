"""Retention by data category (SEC-DAT-06).

Periods are the platform setting ``retention.policies`` (days per category; 0 switches a category off).
The daily worker job deletes or blanks expired rows and writes one audit record with the counts per category.

Legal journals are not in this list on purpose: the audit log, status history, snapshots, accruals, payments,
signatures and checkpoints are append-only and are kept for the statutory period (SEC-LOG-04, section 4);
personal data of deleted accounts is anonymised at deletion time (FR-AUTH-10).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, delete, or_, update
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.db import utcnow

DEFAULT_POLICIES = {
    "otp_codes": 7,              # one-time codes (hashes) — only needed for the check
    "sessions": 180,             # ended or expired sessions
    "notifications": 365,        # read in-app notifications
    "outbox": 90,                # delivered messages: the body (event text) is blanked, the delivery record stays
    "device_events": 180,        # device / IP marks used by antifraud
    "product_events": 400,       # anonymous interface funnel events
    "idempotency_keys": 30,
    "webhook_deliveries": 90,    # delivered / failed deliveries
    "invitations": 90,           # used, revoked or expired invitations
    "support_grants": 365,       # finished support access grants
    "track_points": 90,          # telematics positions (FR-TRK-05): geodata is kept only as long as needed
}


def policies(db: Session) -> dict[str, int]:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "retention.policies", None)
    merged = {**DEFAULT_POLICIES, **(value if isinstance(value, dict) else {})}
    return {k: max(0, int(v or 0)) for k, v in merged.items() if k in DEFAULT_POLICIES}


def run(db: Session) -> dict[str, int]:
    from app.modules.accounts.models import Invitation, OtpCode, SupportAccessGrant, UserSession
    from app.modules.notifications.models import Notification, OutboxMessage
    from app.modules.platform.models import DeviceEvent, IdempotencyKey, ProductEvent
    from app.modules.deals.models import TrackPoint
    from app.modules.webhooks.models import WebhookDelivery

    now = utcnow()
    p = policies(db)
    before = lambda days: now - timedelta(days=days)  # noqa: E731
    jobs = {
        "otp_codes": lambda c: delete(OtpCode).where(OtpCode.created_at < c),
        "sessions": lambda c: delete(UserSession).where(
            UserSession.last_seen_at < c, or_(UserSession.revoked_at.is_not(None), UserSession.expires_at < now)),
        "notifications": lambda c: delete(Notification).where(Notification.read_at.is_not(None),
                                                              Notification.created_at < c),
        "outbox": lambda c: update(OutboxMessage).where(
            OutboxMessage.created_at < c, OutboxMessage.status.in_(("sent", "failed", "digested")),
            OutboxMessage.body != "").values(body="", recipient=""),
        "device_events": lambda c: delete(DeviceEvent).where(DeviceEvent.created_at < c),
        "product_events": lambda c: delete(ProductEvent).where(ProductEvent.created_at < c),
        "idempotency_keys": lambda c: delete(IdempotencyKey).where(IdempotencyKey.created_at < c),
        "webhook_deliveries": lambda c: delete(WebhookDelivery).where(
            WebhookDelivery.created_at < c, WebhookDelivery.status.in_(("delivered", "failed"))),
        "invitations": lambda c: delete(Invitation).where(Invitation.created_at < c, or_(
            Invitation.used_at.is_not(None), Invitation.revoked_at.is_not(None), Invitation.expires_at < now)),
        "track_points": lambda c: delete(TrackPoint).where(TrackPoint.at < c),
        "support_grants": lambda c: delete(SupportAccessGrant).where(SupportAccessGrant.created_at < c, or_(
            SupportAccessGrant.revoked_at.is_not(None), and_(SupportAccessGrant.valid_until < now))),
    }
    counts: dict[str, int] = {}
    from app.modules.fleet.biometrics import purge_images

    counts["biometric_images"] = purge_images(db, now=now)  # SEC-DAT-10: own short period, in hours
    for category, days in p.items():
        if not days:
            continue
        res = db.execute(jobs[category](before(days)).execution_options(synchronize_session=False))
        counts[category] = res.rowcount or 0
    audit(db, "retention.purged", object_type="retention", object_id=now.date().isoformat(), role="system",
          # pairs, not a dict: category names such as "otp_codes" would be masked as sensitive keys
          details={"purged": [[k, v] for k, v in counts.items()], "days": [[k, v] for k, v in p.items()]})
    db.commit()
    return counts
