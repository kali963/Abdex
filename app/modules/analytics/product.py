"""Product analytics of interface funnels without excess personal data (FR-BI-07).

An event is a step name, a role and an anonymous id: a keyed hash of the device cookie, truncated, so the
same visitor is counted once per funnel step but cannot be traced back to a person or an account.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.context import get_ctx
from app.modules.platform.models import ProductEvent

FUNNELS = {
    "registration": ("register_view", "register_done", "phone_verified"),
    "order": ("order_form_view", "order_created", "order_published", "bid_accepted"),  # client side
    "bid": ("market_card_view", "bid_placed"),  # carrier side
}
STEPS = {s for steps in FUNNELS.values() for s in steps}


def anon_id() -> str:
    ctx = get_ctx()
    raw = ctx.device_id or ctx.request_id or "-"
    return hmac.new(settings.secret_key.encode(), f"product:{raw}".encode(), hashlib.sha256).hexdigest()[:16]


def track(db: Session, step: str, *, role: str | None = None) -> None:
    if step not in STEPS:
        return
    db.add(ProductEvent(name=step, anon_id=anon_id(), role=(role if role is not None else get_ctx().role or "")[:20]))


def funnels(db: Session, date_from: date, date_to: date) -> dict:
    start = datetime.combine(date_from, time.min, tzinfo=timezone.utc)
    end = datetime.combine(date_to, time.max, tzinfo=timezone.utc)
    counts = dict(db.execute(select(ProductEvent.name, func.count(func.distinct(ProductEvent.anon_id)))
                             .where(ProductEvent.created_at >= start, ProductEvent.created_at <= end)
                             .group_by(ProductEvent.name)).all())
    out = {}
    for name, steps in FUNNELS.items():
        rows = []
        first = counts.get(steps[0], 0)
        prev = None
        for s in steps:
            n = counts.get(s, 0)
            rows.append({"step": s, "count": n, "from_start": round(n * 100 / first) if first else 0,
                         "from_prev": round(n * 100 / prev) if prev else (100 if n else 0)})
            prev = n
        out[name] = rows
    return out


def default_period() -> tuple[date, date]:
    today = datetime.now(timezone.utc).date()
    return today - timedelta(days=30), today
