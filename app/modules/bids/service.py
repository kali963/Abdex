"""Bids, negotiation and acceptance (M4)."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.i18n import parse_local_input
from app.core.money import to_minor
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.bids.models import Bid, BidEvent
from app.modules.chat.leaks import mask_contacts
from app.modules.fleet.models import Driver, Vehicle
from app.modules.orders import flow
from app.modules.orders.models import Order
from app.modules.orders.service import carrier_can_see

OPEN_BID = ("active", "countered", "needs_confirmation")


def _event(db: Session, bid: Bid, kind: str, price: int | None = None, comment: str = "") -> None:
    ctx = get_ctx()
    db.add(BidEvent(bid_id=bid.id, kind=kind, price_minor=price, actor_user_id=ctx.user_id,
                    actor_company_id=ctx.company_id, comment=comment[:500], created_by=ctx.user_id))


def place_bid(db: Session, order_id, carrier: Company, form: dict) -> Bid:
    """FR-BID-01. Requires verification level L1+ (section 8)."""
    ratelimit.hit("bid", str(carrier.id))
    order = flow.lock_order(db, order_id)
    if not carrier_can_see(db, order, carrier):
        raise NotFound()
    if carrier.verification_level < 1:
        raise Forbidden("verification_required")
    if carrier.is_blocked:
        raise Forbidden("company_blocked")
    from app.modules.platform.service import has_restriction

    if has_restriction(db, carrier.id, ("block", "no_bids")):
        raise Forbidden("company_restricted_bids")  # FR-BID-08 / FR-RAT-04
    errors = {}
    try:
        price = to_minor(form.get("price", ""), order.currency)
        if price <= 0:
            raise ValueError
    except ValueError:
        errors["price"] = "error.number"
        price = 0
    if carrier.deal_limit_minor is not None and price > carrier.deal_limit_minor:
        errors["price"] = "error.over_deal_limit"
    vehicle_id = form.get("vehicle_id") or None
    driver_id = form.get("driver_id") or None
    vehicle = db.get(Vehicle, _uuid(vehicle_id)) if vehicle_id else None
    driver = db.get(Driver, _uuid(driver_id)) if driver_id else None
    if vehicle_id and (vehicle is None or vehicle.company_id != carrier.id):
        errors["vehicle_id"] = "error.invalid_choice"
    if driver_id and (driver is None or driver.company_id != carrier.id):
        errors["driver_id"] = "error.invalid_choice"
    if order.adr_class and ((vehicle and not vehicle.adr_allowed) or (driver and not driver.adr_permit)):
        errors["vehicle_id"] = "error.adr_required"
    if not errors and (vehicle or driver):
        from app.modules.fleet.schedule import conflicts

        errors.update({k: "error.executor_busy" for k in conflicts(
            db, order, vehicle_id=vehicle.id if vehicle else None, driver_id=driver.id if driver else None)})
    if errors:
        raise ValidationFailed(errors)
    comment, leaked = mask_contacts(form.get("comment", ""))
    existing = db.execute(select(Bid).where(Bid.order_id == order.id, Bid.carrier_company_id == carrier.id)
                          ).scalar_one_or_none()
    if existing and existing.status in OPEN_BID:
        existing.price_minor = price
        existing.vehicle_id = vehicle.id if vehicle else None
        existing.driver_id = driver.id if driver else None
        existing.comment = comment
        existing.status = "active"
        existing.order_version = order.version
        existing.counter_price_minor = None
        _event(db, existing, "price_changed", price)
        bid = existing
    elif existing:
        raise Conflict("bid_closed")
    else:
        bid = Bid(order_id=order.id, carrier_company_id=carrier.id, price_minor=price, currency=order.currency,
                  payment_terms=form.get("payment_terms") or order.payment_terms,
                  vehicle_id=vehicle.id if vehicle else None, driver_id=driver.id if driver else None,
                  ready_at=parse_local_input(form.get("ready_at")), valid_until=parse_local_input(form.get("valid_until")),
                  comment=comment, order_version=order.version, created_by=get_ctx().user_id)
        db.add(bid)
        try:
            with db.begin_nested():
                db.flush()
        except IntegrityError as exc:
            raise Conflict("bid_exists") from exc
        _event(db, bid, "created", price)
    if leaked:
        from app.modules.platform.service import raise_alert

        raise_alert(db, "contact_leak_attempt", severity="low", company_id=carrier.id,
                    details={"order": str(order.id), "where": "bid_comment"})
    if order.status == flow.PUBLISHED:
        flow.transition(db, order, flow.BIDDING, actor=flow.SYSTEM, reason="first bid received")
    from app.modules.notifications.service import notify_event

    notify_event(db, "bid.received", params={"number": order.number}, link=f"/orders/{order.id}",
                 client_company_id=order.client_company_id, dedup=f"bid:{bid.id}:{bid.price_minor}")
    audit(db, "bid.placed", object_type="bid", object_id=bid.id, details={"order": str(order.id)})
    return bid


def _uuid(value):
    import uuid

    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def order_bids(db: Session, order_id) -> list[Bid]:
    return list(db.execute(select(Bid).where(Bid.order_id == order_id).order_by(Bid.price_minor)).scalars())


def counter_offer(db: Session, bid: Bid, price_raw: str, comment: str = "") -> None:
    """FR-BID-03: client counter-offer, history kept."""
    order = flow.lock_order(db, bid.order_id)
    if order.status not in flow.OPEN_FOR_BIDS or bid.status not in OPEN_BID:
        raise Conflict("bid_closed")
    try:
        price = to_minor(price_raw, bid.currency)
    except ValueError:
        raise ValidationFailed({"counter_price": "error.number"})
    bid.counter_price_minor = price
    bid.status = "countered"
    _event(db, bid, "counter", price, comment)
    from app.modules.notifications.service import notify_event

    notify_event(db, "order.status", params={"number": order.number, "status": "counter"},
                 link=f"/market/{order.id}", carrier_company_id=bid.carrier_company_id)


def respond_counter(db: Session, bid: Bid, accept: bool) -> None:
    if bid.status != "countered" or bid.counter_price_minor is None:
        raise Conflict("no_counter")
    if accept:
        bid.price_minor = bid.counter_price_minor
        _event(db, bid, "counter_accepted", bid.price_minor)
    else:
        _event(db, bid, "counter_declined", bid.price_minor)
    bid.counter_price_minor = None
    bid.status = "active"


def withdraw(db: Session, bid: Bid) -> None:
    if bid.status not in OPEN_BID:
        raise Conflict("bid_closed")
    bid.status = "withdrawn"
    _event(db, bid, "withdrawn")


def confirm_actual(db: Session, bid: Bid) -> None:
    """FR-ORD-07: carrier confirms the price is still valid for the new order version."""
    order = db.get(Order, bid.order_id)
    if bid.status != "needs_confirmation":
        raise Conflict("nothing_to_confirm")
    bid.status = "active"
    bid.order_version = order.version
    _event(db, bid, "confirmed_version", bid.price_minor, f"v{order.version}")


def request_reconfirmation(db: Session, order: Order) -> None:
    from app.modules.notifications.service import notify_event

    for bid in db.execute(select(Bid).where(Bid.order_id == order.id, Bid.status.in_(("active", "countered")))).scalars():
        bid.status = "needs_confirmation"
        _event(db, bid, "order_changed", None, f"v{order.version}")
        notify_event(db, "order.status", params={"number": order.number, "status": "changed"},
                     link=f"/market/{order.id}", carrier_company_id=bid.carrier_company_id,
                     dedup=f"reconfirm:{bid.id}:{order.version}")


def accept(db: Session, bid_id, client: Company, *, idempotency_key: str | None = None):
    """FR-BID-06/07: atomic acceptance. Row lock on the order + unique(deal.order_id) +
    idempotency key make a double assignment impossible."""
    from app.modules.deals.service import create_deal_from_bid
    from app.modules.platform.service import idempotent_lookup, idempotent_store

    ctx = get_ctx()
    prev = idempotent_lookup(db, ctx.user_id, idempotency_key, "bid.accept")
    if prev:
        from app.modules.deals.models import Deal

        return db.get(Deal, _uuid(prev))
    bid = db.get(Bid, bid_id)
    if bid is None:
        raise NotFound()
    order = flow.lock_order(db, bid.order_id)
    if order.client_company_id != client.id:
        raise NotFound()
    if order.status != flow.BIDDING:
        raise Conflict("order_not_accepting")
    if bid.status not in ("active",):
        raise Conflict("bid_not_acceptable")
    if bid.valid_until and bid.valid_until < utcnow():
        bid.status = "expired"
        raise Conflict("bid_expired")
    if bid.vehicle_id or bid.driver_id:
        from app.modules.fleet.schedule import conflicts

        if conflicts(db, order, vehicle_id=bid.vehicle_id, driver_id=bid.driver_id):
            raise Conflict("executor_busy")  # the carrier booked the same vehicle/driver elsewhere meanwhile
    try:
        with db.begin_nested():
            deal = create_deal_from_bid(db, order, bid)
    except IntegrityError as exc:
        raise Conflict("already_assigned") from exc
    for other in db.execute(select(Bid).where(Bid.order_id == order.id, Bid.id != bid.id,
                                              Bid.status.in_(OPEN_BID))).scalars():
        other.status = "rejected"
        _event(db, other, "rejected")
    bid.status = "accepted"
    _event(db, bid, "accepted", bid.price_minor)
    idempotent_store(db, ctx.user_id, idempotency_key, "bid.accept", str(deal.id))
    audit(db, "bid.accepted", object_type="deal", object_id=deal.id, details={"bid": str(bid.id)})
    return deal


def bid_history(db: Session, bid_id) -> list[BidEvent]:
    return list(db.execute(select(BidEvent).where(BidEvent.bid_id == bid_id).order_by(BidEvent.created_at)).scalars())


def carrier_history_with(db: Session, carrier_id, client_id) -> int:
    from app.modules.deals.models import Deal

    return db.execute(select(func.count(Deal.id)).where(Deal.carrier_company_id == carrier_id,
                                                        Deal.client_company_id == client_id)).scalar_one()
