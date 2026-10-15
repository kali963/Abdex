"""Order/deal status machine — the core of the system (section 6, FR-FLOW-01..05).

Transitions are declared in one table below and executed by `transition()` only.
Direct writes of `Order.status` from other modules are forbidden; tests check the table.
Any transition not in the table raises Conflict (HTTP 409), never a silent change.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import events
from app.core.context import get_ctx
from app.core.errors import Conflict, Forbidden, ValidationFailed
from app.db import utcnow
from app.modules.orders.models import Order, StatusHistory

DRAFT = "draft"
MODERATION = "moderation"
PUBLISHED = "published"
BIDDING = "bidding"
ASSIGNED = "assigned"
DOCS_SIGNED = "docs_signed"
LOADING = "loading"
IN_TRANSIT = "in_transit"
UNLOADED = "unloaded"
CLOSED_DOCS = "closed_docs"
FEE_INVOICED = "fee_invoiced"
COMPLETED = "completed"
DISPUTE = "dispute"
CANCELLED = "cancelled"

ALL_STATUSES = (DRAFT, MODERATION, PUBLISHED, BIDDING, ASSIGNED, DOCS_SIGNED, LOADING, IN_TRANSIT, UNLOADED,
                CLOSED_DOCS, FEE_INVOICED, COMPLETED, DISPUTE, CANCELLED)

# Statuses where the order is visible on the carrier marketplace.
OPEN_FOR_BIDS = (PUBLISHED, BIDDING)
# Statuses where a deal exists.
DEAL_STATUSES = (ASSIGNED, DOCS_SIGNED, LOADING, IN_TRANSIT, UNLOADED, CLOSED_DOCS, FEE_INVOICED, COMPLETED, DISPUTE)
ACTIVE_TRIP = (DOCS_SIGNED, LOADING, IN_TRANSIT)
FINAL = (COMPLETED, CANCELLED)

# Actors
CLIENT = "client"
CARRIER = "carrier"
DRIVER = "driver"
MANAGER = "manager"
FINANCE = "finance"
SYSTEM = "system"


@dataclass(frozen=True)
class Rule:
    actors: frozenset[str]
    reason_required: bool = False


def _r(*actors: str, reason: bool = False) -> Rule:
    return Rule(frozenset(actors), reason)


TRANSITIONS: dict[tuple[str, str], Rule] = {
    (DRAFT, MODERATION): _r(CLIENT),
    (MODERATION, PUBLISHED): _r(SYSTEM, MANAGER),
    (MODERATION, DRAFT): _r(SYSTEM, MANAGER, reason=True),
    (PUBLISHED, BIDDING): _r(SYSTEM),
    (BIDDING, ASSIGNED): _r(SYSTEM),  # executed by the bids service on acceptance (creates snapshot)
    (BIDDING, CANCELLED): _r(SYSTEM, CLIENT),  # deadline expired / client cancels before assignment
    (ASSIGNED, DOCS_SIGNED): _r(SYSTEM),  # contract signed by both sides
    (DOCS_SIGNED, LOADING): _r(DRIVER, CARRIER),
    (LOADING, IN_TRANSIT): _r(DRIVER, CARRIER),
    (IN_TRANSIT, UNLOADED): _r(DRIVER, CARRIER, CLIENT),
    (UNLOADED, CLOSED_DOCS): _r(SYSTEM, CLIENT, CARRIER),
    (CLOSED_DOCS, FEE_INVOICED): _r(SYSTEM),
    (FEE_INVOICED, COMPLETED): _r(FINANCE, SYSTEM),
    (ASSIGNED, DISPUTE): _r(CLIENT, CARRIER, reason=True),
    (IN_TRANSIT, DISPUTE): _r(CLIENT, CARRIER, reason=True),
    (UNLOADED, DISPUTE): _r(CLIENT, CARRIER, reason=True),
    (DISPUTE, CLOSED_DOCS): _r(MANAGER, reason=True),
    (DISPUTE, CANCELLED): _r(MANAGER, reason=True),
    (DRAFT, CANCELLED): _r(CLIENT),
    (PUBLISHED, CANCELLED): _r(CLIENT),
}


def allowed_targets(status: str, actor: str) -> list[str]:
    return [to for (frm, to), rule in TRANSITIONS.items() if frm == status and actor in rule.actors]


def can(status: str, to: str, actor: str) -> bool:
    rule = TRANSITIONS.get((status, to))
    return bool(rule and actor in rule.actors)


def lock_order(db: Session, order_id) -> Order:
    """SELECT ... FOR UPDATE (no-op on SQLite, which serialises writers anyway)."""
    order = db.execute(select(Order).where(Order.id == order_id).with_for_update()).scalar_one_or_none()
    if order is None:
        raise Conflict("order_missing")
    return order


def transition(db: Session, order: Order, to: str, *, actor: str, reason: str = "", user_id=None) -> StatusHistory:
    frm = order.status
    rule = TRANSITIONS.get((frm, to))
    if rule is None:
        raise Conflict("invalid_transition", frm=frm, to=to)
    if actor not in rule.actors:
        raise Forbidden("transition_not_allowed_for_role")
    if rule.reason_required and not reason.strip():
        raise ValidationFailed({"reason": "error.reason_required"})
    return _apply(db, order, frm, to, actor=actor, reason=reason, user_id=user_id, rollback=False)


def rollback(db: Session, order: Order, to: str, *, reason: str, user_id) -> StatusHistory:
    """FR-FLOW-03: only a platform manager, with a reason; both sides are notified."""
    if not reason.strip():
        raise ValidationFailed({"reason": "error.reason_required"})
    frm = order.status
    if to not in ALL_STATUSES or to == frm:
        raise Conflict("invalid_transition", frm=frm, to=to)
    history = db.execute(
        select(StatusHistory.from_status).where(StatusHistory.order_id == order.id)
    ).scalars().all()
    if to not in history:
        raise Conflict("rollback_target_not_in_history")
    return _apply(db, order, frm, to, actor=MANAGER, reason=reason, user_id=user_id, rollback=True)


def _apply(db, order, frm, to, *, actor, reason, user_id, rollback) -> StatusHistory:
    ctx = get_ctx()
    now = utcnow()
    order.status = to
    if to == PUBLISHED and order.published_at is None:
        order.published_at = now
    if to == ASSIGNED:
        order.assigned_at = now
    entry = StatusHistory(
        order_id=order.id, from_status=frm, to_status=to, reason=reason[:500], actor_user_id=user_id or ctx.user_id,
        actor_role=actor, ip=ctx.ip, device=ctx.user_agent[:300], is_rollback=rollback,
        created_by=user_id or ctx.user_id,
    )
    db.add(entry)
    db.flush()
    events.emit("order.status_changed", db=db, order=order, frm=frm, to=to, actor=actor, reason=reason,
                rollback=rollback)
    return entry
