"""Vehicle and driver occupancy for carriers (FR-PLAN-04).

A vehicle or driver is busy from the order's loading start until its unloading deadline for every deal
that is assigned and not yet unloaded. Assigning the same vehicle or driver to an overlapping trip is
refused at the moment of the bid and of the executor change, so double booking cannot happen silently.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.modules.deals.models import Deal
from app.modules.fleet.models import Driver, Vehicle
from app.modules.orders import flow
from app.modules.orders.models import Order

BUSY_STATUSES = (flow.ASSIGNED, flow.DOCS_SIGNED, flow.LOADING, flow.IN_TRANSIT)


@dataclass
class Busy:
    deal: Deal
    order: Order
    start: datetime
    end: datetime


def interval(order: Order) -> tuple[datetime | None, datetime | None]:
    start = order.load_from
    if start is None:
        return None, None
    end = order.unload_to or order.unload_from or order.load_to
    if end is None or end < start:
        end = start + timedelta(hours=max(order.duration_hours or 0, 24))
    return start, end


def _busy(db: Session, *, vehicle_id=None, driver_id=None, company_id=None, exclude_deal_id=None) -> list[Busy]:
    stmt = select(Deal, Order).join(Order, Order.id == Deal.order_id).where(Order.status.in_(BUSY_STATUSES))
    conds = []
    if vehicle_id:
        conds.append(Deal.vehicle_id == vehicle_id)
    if driver_id:
        conds.append(Deal.driver_id == driver_id)
    if company_id:
        conds.append(Deal.carrier_company_id == company_id)
    if not conds:
        return []
    stmt = stmt.where(or_(*conds))
    if exclude_deal_id:
        stmt = stmt.where(Deal.id != exclude_deal_id)
    out = []
    for deal, order in db.execute(stmt).all():
        start, end = interval(order)
        if start is not None:
            out.append(Busy(deal, order, start, end))
    return out


def conflicts(db: Session, order: Order, *, vehicle_id=None, driver_id=None, exclude_deal_id=None) -> dict:
    """Field → clashing deal number for the vehicle/driver over the order's interval."""
    start, end = interval(order)
    if start is None:
        return {}
    found = {}
    for field, kw in (("vehicle_id", {"vehicle_id": vehicle_id}), ("driver_id", {"driver_id": driver_id})):
        if not next(iter(kw.values())):
            continue
        for b in _busy(db, exclude_deal_id=exclude_deal_id, **kw):
            if b.deal.order_id != order.id and b.start < end and start < b.end:
                found[field] = b.deal.number
                break
    return found


def ensure_free(db: Session, order: Order, *, vehicle_id=None, driver_id=None, exclude_deal_id=None) -> None:
    clash = conflicts(db, order, vehicle_id=vehicle_id, driver_id=driver_id, exclude_deal_id=exclude_deal_id)
    if clash:
        raise ValidationFailed({k: "error.executor_busy" for k in clash})


def board(db: Session, company_id, start: date, days: int = 14) -> dict:
    """Occupancy board: one row per vehicle and driver, one cell per day."""
    day_list = [start + timedelta(days=i) for i in range(days)]
    vehicles = list(db.execute(select(Vehicle).where(Vehicle.company_id == company_id, Vehicle.is_deleted.is_(False))
                               .order_by(Vehicle.plate)).scalars())
    drivers = list(db.execute(select(Driver).where(Driver.company_id == company_id, Driver.is_deleted.is_(False))
                              .order_by(Driver.full_name)).scalars())
    busy = _busy(db, company_id=company_id)
    from app.core.context import get_ctx

    tz = ZoneInfo(get_ctx().timezone or "Asia/Almaty")

    def cells(match) -> list:
        row = []
        for d in day_list:
            lo = datetime.combine(d, datetime.min.time(), tzinfo=tz)
            hi = lo + timedelta(days=1)
            hit = next((b for b in busy if match(b) and b.start < hi and lo < b.end), None)
            row.append(hit)
        return row

    return {"days": day_list,
            "vehicles": [(v, cells(lambda b, v=v: b.deal.vehicle_id == v.id)) for v in vehicles],
            "drivers": [(d, cells(lambda b, d=d: b.deal.driver_id == d.id)) for d in drivers],
            "unassigned": [b for b in busy if not b.deal.vehicle_id or not b.deal.driver_id]}
