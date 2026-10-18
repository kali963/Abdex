"""Participant rating (FR-RAT-01/02) and breakdown accounting after acceptance (FR-BID-08).

The rating is never stored as an editable number. It is computed from:

* objective events in `rating_events` (completed deals, breakdowns, late deliveries, rejected documents,
  lost disputes) — written by the system when the event happens;
* subjective reviews from counterparties (`ratings`, FR-DEAL-07);
* corrections — separate events with an author and a reason (FR-RAT-02).

The formula and its weights are the platform setting ``rating.formula`` (changed without a release) and are
shown to users on /rating in plain words.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.timeutil import local_today
from app.core import events
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import ValidationFailed
from app.db import utcnow
from app.modules.rating.models import (
    KIND_BREAKDOWN,
    KIND_COMPLETED,
    KIND_CORRECTION,
    KIND_DISPUTE_LOST,
    KIND_DOC_REJECTED,
    KIND_LATE,
    RatingEvent,
)

DEFAULT_FORMULA = {
    "w_reviews": 0.6,        # share of counterparty reviews
    "w_reliability": 0.4,    # share of objective reliability
    "neutral_review": 4.0,   # used while a participant has no reviews yet
    "window_days": 365,      # objective events older than this are not counted
    "penalty": {KIND_BREAKDOWN: 3.0, KIND_LATE: 1.0, KIND_DOC_REJECTED: 0.5, KIND_DISPUTE_LOST: 2.0},
}
DEFAULT_BREAKDOWN_LIMIT = {"count": 3, "days": 90, "restrict_days": 30}
PENALTY_KINDS = (KIND_BREAKDOWN, KIND_LATE, KIND_DOC_REJECTED, KIND_DISPUTE_LOST)


def formula(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "rating.formula", None)
    merged = {**DEFAULT_FORMULA, **(value if isinstance(value, dict) else {})}
    merged["penalty"] = {**DEFAULT_FORMULA["penalty"], **(merged.get("penalty") or {})}
    return merged


def breakdown_limit(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "rating.breakdown_limit", None)
    return {**DEFAULT_BREAKDOWN_LIMIT, **(value if isinstance(value, dict) else {})}


def record(db: Session, company_id, kind: str, *, deal_id=None, reason: str = "") -> RatingEvent | None:
    """Objective event, idempotent per (company, kind, deal)."""
    if deal_id is not None:
        exists = db.execute(select(RatingEvent.id).where(RatingEvent.company_id == company_id,
                                                         RatingEvent.kind == kind, RatingEvent.deal_id == deal_id)
                            ).first()
        if exists:
            return None
    ev = RatingEvent(company_id=company_id, kind=kind, deal_id=deal_id, reason=reason[:500],
                     created_by=get_ctx().user_id)
    try:
        with db.begin_nested():
            db.add(ev)
            db.flush()
    except IntegrityError:
        return None
    if kind == KIND_BREAKDOWN:
        _enforce_breakdown_limit(db, company_id)
    return ev


def correct(db: Session, company_id, delta: float, reason: str) -> RatingEvent:
    """FR-RAT-02: the rating is never edited; a correction is its own event with author and reason."""
    errors = {}
    if not reason.strip():
        errors["reason"] = "error.reason_required"
    if not -1.0 <= delta <= 1.0 or delta == 0:
        errors["delta"] = "error.rating_delta"
    if errors:
        raise ValidationFailed(errors)
    ev = RatingEvent(company_id=company_id, kind=KIND_CORRECTION, delta=round(delta * 100), reason=reason[:500],
                     created_by=get_ctx().user_id)
    db.add(ev)
    db.flush()
    audit(db, "rating.corrected", object_type="company", object_id=company_id, reason=reason,
          details={"delta": delta})
    return ev


def breakdowns(db: Session, company_id, days: int) -> int:
    since = utcnow() - timedelta(days=days)
    return db.execute(select(func.count(RatingEvent.id)).where(
        RatingEvent.company_id == company_id, RatingEvent.kind == KIND_BREAKDOWN, RatingEvent.created_at >= since)
    ).scalar_one()


def _enforce_breakdown_limit(db: Session, company_id) -> None:
    """FR-BID-08: temporary restriction of access when breakdowns exceed the threshold."""
    from app.modules.notifications.service import notify_company_owners
    from app.modules.platform.models import Restriction

    limit = breakdown_limit(db)
    count = breakdowns(db, company_id, int(limit["days"]))
    if count < int(limit["count"]):
        return
    today = local_today()
    active = db.execute(select(Restriction).where(Restriction.company_id == company_id, Restriction.kind == "no_bids",
                                                  Restriction.lifted_at.is_(None))).scalars().all()
    if any(r.until is None or r.until >= today for r in active):
        return
    until = today + timedelta(days=int(limit["restrict_days"]))
    reason = f"breakdowns:{count}/{limit['days']}d"
    db.add(Restriction(company_id=company_id, kind="no_bids", reason=reason, until=until))
    db.flush()
    audit(db, "rating.breakdown_restriction", object_type="company", object_id=company_id, reason=reason,
          details={"until": until.isoformat()}, role="system")
    notify_company_owners(db, company_id, "account.breakdown_restricted",
                          {"count": count, "until": until.strftime("%d.%m.%Y")}, link="/rating", critical=True,
                          dedup=f"breakdown_restriction:{company_id}:{today}")


def compute(db: Session, company_id) -> dict:
    """Rating with every component, so the user sees how it was obtained (FR-RAT-01)."""
    from app.modules.deals.models import Rating

    f = formula(db)
    since = utcnow() - timedelta(days=int(f["window_days"]))
    counts = dict(db.execute(
        select(RatingEvent.kind, func.count(RatingEvent.id))
        .where(RatingEvent.company_id == company_id, RatingEvent.created_at >= since,
               RatingEvent.kind != KIND_CORRECTION).group_by(RatingEvent.kind)).all())
    corrections = db.execute(select(func.coalesce(func.sum(RatingEvent.delta), 0)).where(
        RatingEvent.company_id == company_id, RatingEvent.kind == KIND_CORRECTION)).scalar_one() / 100
    reviews_avg, reviews_n = db.execute(select(func.avg(Rating.score), func.count(Rating.id))
                                        .where(Rating.to_company_id == company_id)).one()
    completed = counts.get(KIND_COMPLETED, 0)
    penalty_points = sum(float(f["penalty"].get(k, 0)) * counts.get(k, 0) for k in PENALTY_KINDS)
    reliability = completed / (completed + penalty_points) if (completed + penalty_points) else 1.0
    reviews = float(reviews_avg) if reviews_n else float(f["neutral_review"])
    raw = float(f["w_reviews"]) * reviews + float(f["w_reliability"]) * 5 * reliability + corrections
    value = round(min(5.0, max(0.0, raw)), 2)
    is_new = completed == 0 and not reviews_n and not penalty_points
    return {"value": None if is_new else value, "is_new": is_new, "reviews_avg": round(reviews, 2),
            "reviews_n": reviews_n, "completed": completed, "counts": {k: counts.get(k, 0) for k in PENALTY_KINDS},
            "reliability": round(reliability * 100), "corrections": round(corrections, 2), "formula": f}


def history(db: Session, company_id, limit: int = 100) -> list[RatingEvent]:
    return list(db.execute(select(RatingEvent).where(RatingEvent.company_id == company_id)
                           .order_by(RatingEvent.created_at.desc()).limit(limit)).scalars())


# ------------------------------------------------------------------ event hooks (objective events)


@events.subscribe("order.status_changed")
def _on_status(db: Session, order, frm, to, rollback=False, **_):
    from app.modules.deals.models import Deal
    from app.modules.orders import flow

    if rollback or to != flow.COMPLETED:
        return
    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    if deal is None:
        return
    record(db, deal.carrier_company_id, KIND_COMPLETED, deal_id=deal.id)
    record(db, deal.client_company_id, KIND_COMPLETED, deal_id=deal.id)


def on_unloaded_late(db: Session, deal, order, at=None) -> None:
    """Judged by when the unloading happened (an offline checkpoint syncs later), not by when it reached us."""
    if order.unload_to and (at or utcnow()) > order.unload_to:
        record(db, deal.carrier_company_id, KIND_LATE, deal_id=deal.id)


def on_dispute_resolved(db: Session, deal, *, outcome: str, fault: str) -> None:
    """Fault is decided by the manager: carrier / client / none. A cancelled deal through the carrier's fault
    after acceptance is a breakdown (FR-BID-08)."""
    from app.modules.orders import flow

    if fault == "carrier":
        record(db, deal.carrier_company_id, KIND_DISPUTE_LOST, deal_id=deal.id)
        if outcome == flow.CANCELLED:
            record(db, deal.carrier_company_id, KIND_BREAKDOWN, deal_id=deal.id, reason="dispute")
    elif fault == "client":
        record(db, deal.client_company_id, KIND_DISPUTE_LOST, deal_id=deal.id)


def on_document_rejected(db: Session, deal, company_id) -> None:
    record(db, company_id, KIND_DOC_REJECTED, deal_id=deal.id)
