"""Unified notification service (M8).

- FR-NTF-01 queue with retries, dedup, delivery journal (OutboxMessage)
- FR-NTF-03 RU/KK templates by user locale
- FR-NTF-05 security notifications cannot be disabled
- FR-NTF-06 messages carry only the event and a link — no personal data or document content
- Matrix "event × role × channel" (appendix 57.2) is a platform setting editable without release
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.i18n import translate
from app.db import utcnow
from app.modules.accounts.models import (
    OWNER_ROLES,
    ROLE_DRIVER,
    STAFF_MANAGER,
    Membership,
    User,
)
from app.modules.integrations.adapters import CHANNELS
from app.modules.integrations.base import IntegrationUnavailable
from app.modules.notifications.models import ChannelLink, Notification, NotificationPrefs, OutboxMessage

log = logging.getLogger("abdex.notifications")

ALL = ["web", "telegram", "email", "sms", "push"]

# Appendix 57.2 — base matrix. Overridden by platform setting "notifications.matrix".
DEFAULT_MATRIX: dict[str, dict[str, list[str]]] = {
    "order.published": {"client": ["web"], "carrier": ["web", "telegram", "push"], "manager": ["web"]},
    "bid.received": {"client": ["web", "telegram", "email"]},
    "bid.accepted": {"client": ["web"], "carrier": ["web", "telegram", "push"], "driver": ["push"], "manager": ["web"]},
    "deal.terms_changed": {"client": ALL, "carrier": ALL, "driver": ["push"], "manager": ["web"]},
    "deal.executor_changed": {"client": ALL, "carrier": ["web"], "driver": ["push"], "manager": ["web"]},
    "document.uploaded": {"client": ["web", "email"], "carrier": ["web"]},
    "trip.checkpoint": {"client": ["web", "push"], "carrier": ["web"]},
    "dispute.opened": {"client": ALL, "carrier": ALL, "manager": ALL},
    "fee.invoiced": {"client": ["web", "email"], "manager": ["web"]},
    "order.status": {"client": ["web"], "carrier": ["web"], "driver": ["web"]},
    "chat.message": {"client": ["web"], "carrier": ["web"], "driver": ["web", "push"]},
}


# FR-NTF-04: categories a user can switch per channel. Security events are not listed: they cannot be disabled.
USER_CATEGORIES = ("order.matching", "order.invited", "bid.received", "bid.accepted", "order.status",
                   "trip.checkpoint", "chat.message", "document.uploaded", "deal.terms_changed", "fee.invoiced")
USER_CHANNELS = ("telegram", "email", "sms", "push")


def prefs_for(db: Session, user_id) -> NotificationPrefs:
    p = db.execute(select(NotificationPrefs).where(NotificationPrefs.user_id == user_id)).scalar_one_or_none()
    return p or NotificationPrefs(user_id=user_id, quiet_enabled=False, quiet_from="22:00", quiet_to="08:00",
                                  digest="off", digest_hour=9)


def _hm(value: str, default: time) -> time:
    try:
        h, m = (int(x) for x in value.split(":"))
        return time(h, m)
    except (ValueError, AttributeError):
        return default


def quiet_until(prefs: NotificationPrefs, tz_name: str, now: datetime | None = None) -> datetime | None:
    """End of the current quiet window in UTC, or None when outside it. Windows may cross midnight."""
    if not prefs.quiet_enabled:
        return None
    now = now or utcnow()
    tz = ZoneInfo(tz_name or "Asia/Almaty")
    local = now.astimezone(tz)
    start, end = _hm(prefs.quiet_from, time(22)), _hm(prefs.quiet_to, time(8))
    t = local.time()
    if start == end:
        return None
    inside = (start <= t < end) if start < end else (t >= start or t < end)
    if not inside:
        return None
    end_dt = datetime.combine(local.date(), end, tzinfo=tz)
    if end_dt <= local:
        end_dt += timedelta(days=1)
    return end_dt.astimezone(ZoneInfo("UTC"))


def _matrix(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    return get_setting(db, "notifications.matrix", None) or DEFAULT_MATRIX


def _render(user: User, event: str, params: dict) -> str:
    return translate(f"ntf.{event}", user.locale, **params)


def notify_user(db: Session, user_id, event: str, params: dict | None = None, *, link: str = "",
                channels: list[str] | None = None, critical: bool = False, dedup: str | None = None) -> None:
    user = db.get(User, user_id)
    if user is None or user.is_deleted:
        return
    params = params or {}
    channels = list(ALL if critical else (channels or ["web"]))
    disabled: set[str] = set()
    links = {cl.channel: cl for cl in db.execute(select(ChannelLink).where(ChannelLink.user_id == user.id)).scalars()}
    for cl in links.values():
        disabled |= {f"{cl.channel}:{e}" for e in cl.disabled_events.split(",") if e}
    if "web" in channels:
        db.add(Notification(user_id=user.id, event=event, params=json.dumps(params, ensure_ascii=False, default=str),
                            link=link))
    body = _render(user, event, params) + (f"\n{link}" if link else "")
    base_key = dedup or f"{event}:{link}:{utcnow().strftime('%Y%m%d%H%M%S%f')}"
    prefs = prefs_for(db, user.id)
    deliver_at = None if critical else quiet_until(prefs, user.timezone)
    to_digest = not critical and prefs.digest in ("hourly", "daily")
    for ch in channels:
        if ch == "web":
            continue
        if not critical and f"{ch}:{event}" in disabled:
            continue
        recipient = {"sms": user.phone, "email": user.email or "", "push": str(user.id),
                     "telegram": links["telegram"].address if "telegram" in links else ""}.get(ch, "")
        if not recipient:
            continue
        msg = OutboxMessage(channel=ch, user_id=user.id, recipient=recipient, event=event, body=body,
                            dedup_key=f"{base_key}:{ch}:{user.id}"[:200], next_attempt_at=deliver_at or utcnow(),
                            status="digest" if to_digest else "queued")
        try:
            with db.begin_nested():
                db.add(msg)
                db.flush()
        except IntegrityError:
            log.info("duplicate notification suppressed: %s", msg.dedup_key)


def _company_users(db: Session, company_id, roles) -> list:
    return list(db.execute(select(Membership.user_id).where(Membership.company_id == company_id,
                                                            Membership.role.in_(roles),
                                                            Membership.is_active.is_(True))).scalars())


def notify_company_owners(db: Session, company_id, event: str, params: dict | None = None, *, link: str = "",
                          critical: bool = False, dedup: str | None = None) -> None:
    for uid in _company_users(db, company_id, OWNER_ROLES):
        notify_user(db, uid, event, params, link=link, critical=critical, channels=["web", "email"],
                    dedup=f"{dedup}:{uid}" if dedup else None)


def _staff_link(link: str) -> str:
    """Platform staff open deals and orders only through the audited admin interface."""
    for prefix in ("/deals/", "/orders/"):
        if link.startswith(prefix):
            return "/admin" + link
    return "/admin/finance" if link.startswith("/finance") else link


def notify_event(db: Session, event: str, *, params: dict | None = None, link: str = "", client_company_id=None,
                 carrier_company_id=None, driver_user_id=None, include_managers: bool = False,
                 dedup: str | None = None) -> None:
    """Route by the event × role × channel matrix."""
    matrix = _matrix(db).get(event, {})
    targets: list[tuple[object, list[str]]] = []
    from app.modules.accounts.permissions import roles_in_scope

    if client_company_id and matrix.get("client"):
        targets += [(u, matrix["client"]) for u in _company_users(db, client_company_id, roles_in_scope("client"))]
    if carrier_company_id and matrix.get("carrier"):
        roles = tuple(r for r in roles_in_scope("carrier") if r != ROLE_DRIVER)
        targets += [(u, matrix["carrier"]) for u in _company_users(db, carrier_company_id, roles)]
    if driver_user_id and matrix.get("driver"):
        targets.append((driver_user_id, matrix["driver"]))
    if include_managers and matrix.get("manager"):
        mgrs = db.execute(select(User.id).where(User.staff_role == STAFF_MANAGER, User.is_blocked.is_(False))).scalars()
        targets += [(u, matrix["manager"]) for u in mgrs]
    staff_ids = set(db.execute(select(User.id).where(User.staff_role.is_not(None))).scalars()) if include_managers else set()
    seen = set()
    for uid, chans in targets:
        if uid in seen:
            continue
        seen.add(uid)
        notify_user(db, uid, event, params, link=_staff_link(link) if uid in staff_ids else link, channels=chans, dedup=f"{dedup}:{uid}" if dedup else None)


def unread_count(db: Session, user_id) -> int:
    from sqlalchemy import func

    return db.execute(select(func.count(Notification.id)).where(Notification.user_id == user_id,
                                                                Notification.read_at.is_(None))).scalar_one()


def process_outbox(db: Session, limit: int = 100) -> int:
    """Delivery worker: retries with growing pause, journal per message."""
    now = utcnow()
    rows = db.execute(select(OutboxMessage).where(OutboxMessage.status == "queued",
                                                  OutboxMessage.next_attempt_at <= now)
                      .order_by(OutboxMessage.created_at).limit(limit)
                      .with_for_update(skip_locked=True)).scalars().all()  # several workers never send one twice
    for msg in rows:
        adapter = CHANNELS.get(msg.channel)
        msg.attempts += 1
        try:
            if adapter is None:
                raise IntegrationUnavailable(msg.channel)
            adapter.send(msg.recipient, msg.body)
            msg.status = "sent"
            msg.sent_at = utcnow()
        except Exception as exc:  # noqa: BLE001
            msg.last_error = str(exc)[:300]
            if msg.attempts >= 5:
                msg.status = "failed"
            else:
                msg.next_attempt_at = utcnow() + timedelta(seconds=30 * 2 ** msg.attempts)
    db.commit()
    return len(rows)


def process_digests(db: Session, now: datetime | None = None) -> int:
    """FR-NTF-04: one summary per user and channel instead of a stream; respects quiet hours."""
    now = now or utcnow()
    rows = db.execute(select(OutboxMessage).where(OutboxMessage.status == "digest")
                      .order_by(OutboxMessage.created_at)).scalars().all()
    by_user: dict = {}
    for m in rows:
        by_user.setdefault(m.user_id, []).append(m)
    sent = 0
    for user_id, msgs in by_user.items():
        user = db.get(User, user_id)
        if user is None:
            continue
        prefs = db.execute(select(NotificationPrefs).where(NotificationPrefs.user_id == user_id)).scalar_one_or_none()
        if prefs is None or prefs.digest == "off":
            for m in msgs:  # digest switched off meanwhile: deliver as usual
                m.status, m.next_attempt_at = "queued", now
            continue
        last = prefs.digest_sent_at
        if prefs.digest == "hourly":
            due = last is None or now - last >= timedelta(hours=1)
        else:
            local = now.astimezone(ZoneInfo(user.timezone or "Asia/Almaty"))
            due = local.hour >= prefs.digest_hour and (
                last is None or last.astimezone(local.tzinfo).date() < local.date())
        if not due:
            continue
        by_channel: dict = {}
        for m in msgs:
            by_channel.setdefault((m.channel, m.recipient), []).append(m)
        for (channel, recipient), items in by_channel.items():
            lines = [translate("ntf.digest_head", user.locale, count=len(items))]
            lines += ["• " + i.body.splitlines()[0] for i in items[:20]]
            if len(items) > 20:
                lines.append(translate("ntf.digest_more", user.locale, count=len(items) - 20))
            db.add(OutboxMessage(channel=channel, user_id=user_id, recipient=recipient, event="digest",
                                 body="\n".join(lines), dedup_key=f"digest:{user_id}:{channel}:{now.isoformat()}"[:200],
                                 next_attempt_at=quiet_until(prefs, user.timezone, now) or now))
            for i in items:
                i.status = "digested"
            sent += 1
        prefs.digest_sent_at = now
    db.commit()
    return sent
