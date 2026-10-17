"""API sandbox (FR-API-05).

A test key (``abxtest_…``) is issued and revoked like a live key, but every call it makes runs against the
sandbox: orders, bids and deals are test objects stored separately (``sandbox_objects``), with the same shapes
and validation as the live API. Nothing reaches the real market, other companies, billing or documents.

* the test market always has a few sample orders, so a carrier integration can place bids;
* a published test order receives two test bids at once, so a client integration can accept one;
* ``POST /api/v1/sandbox/orders/{id}/advance`` moves a test deal along the real status model and fires the
  same webhook events — to the company's sandbox webhook endpoints only (payload ``"livemode": false``);
* ``POST /api/v1/sandbox/reset`` deletes the company's test data.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.errors import Conflict, NotFound, ValidationFailed
from app.db import utcnow
from app.modules.orders import flow
from app.modules.platform.models import SandboxObject

NS = uuid.UUID("5f0c6d1e-8a51-4c1b-9d55-6a6e7a0b0d01")
CURRENCIES = ("KZT", "USD", "CNY", "RUB")
DEAL_PATH = (flow.ASSIGNED, flow.DOCS_SIGNED, flow.LOADING, flow.IN_TRANSIT, flow.UNLOADED, flow.CLOSED_DOCS,
             flow.COMPLETED)
MAX_OBJECTS = 2000

MARKET = (  # cargo, from, to, weight, body, rate (KZT)
    ("Тестовый груз: мука в мешках", "Костанай", "Алматы", 20000, "tent", 480000),
    ("Тестовый груз: бытовая техника", "Алматы", "Астана", 8000, "tent", 350000),
    ("Тестовый груз: замороженная продукция", "Шымкент", "Караганда", 18000, "refrigerator", 620000),
)


def _iso(dt):
    return dt.isoformat() if dt else None


def market() -> list[dict]:
    """Fixed sample orders; ids are stable so integrations can be scripted against them."""
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    out = []
    for i, (cargo, a, b, w, body, rate) in enumerate(MARKET, start=1):
        out.append({"id": str(uuid.uuid5(NS, f"market-{i}")), "number": f"TEST-M-{i:04d}", "status": "bidding",
                    "version": 1, "cargo_name": cargo, "weight_kg": w, "body_type": body, "desired_rate_minor": rate * 100,
                    "currency": "KZT", "load_from": _iso(now + timedelta(days=i + 1)), "distance_km": 0,
                    "points": [{"kind": "load", "city": a, "address": None}, {"kind": "unload", "city": b, "address": None}],
                    "created_at": _iso(now - timedelta(days=1))})
    return out


def _count(db: Session, company_id) -> int:
    return db.execute(select(func.count(SandboxObject.id)).where(SandboxObject.company_id == company_id)).scalar_one()


def _add(db: Session, company_id, kind: str, data: dict, *, status: str, parent_id=None, prefix: str) -> SandboxObject:
    if _count(db, company_id) >= MAX_OBJECTS:
        raise Conflict("sandbox_full")
    n = db.execute(select(func.count(SandboxObject.id)).where(SandboxObject.company_id == company_id,
                                                              SandboxObject.kind == kind)).scalar_one() + 1
    obj = SandboxObject(company_id=company_id, kind=kind, parent_id=parent_id, number=f"TEST-{prefix}-{n:06d}",
                        status=status)
    db.add(obj)
    db.flush()
    obj.data = json.dumps({**data, "id": str(obj.id), "number": obj.number, "status": status,
                           "created_at": _iso(obj.created_at)}, ensure_ascii=False, default=str)
    return obj


def out(obj: SandboxObject) -> dict:
    d = json.loads(obj.data)
    d["status"] = obj.status
    return d


def _set_status(obj: SandboxObject, status: str) -> None:
    obj.status = status
    d = json.loads(obj.data)
    d["status"] = status
    obj.data = json.dumps(d, ensure_ascii=False)


def _get(db: Session, company_id, oid, kind: str) -> SandboxObject:
    obj = db.get(SandboxObject, oid)
    if obj is None or obj.company_id != company_id or obj.kind != kind:
        raise NotFound()
    return obj


# ------------------------------------------------------------------ client side


def create_order(db: Session, company_id, body) -> dict:
    """Same validation as the live API (schema) plus the business checks of the order form."""
    errors = {}
    if body.points[0].kind != "load":
        errors["points"] = "error.points_required"
    if body.points[-1].kind != "unload":
        errors["points"] = "error.points_required"
    load_from = body.load_from if body.load_from.tzinfo else body.load_from.replace(tzinfo=utcnow().tzinfo)
    if load_from < utcnow() - timedelta(minutes=5):
        errors["load_from"] = "error.date_in_past"
    if body.unload_to and body.unload_to < body.load_from:
        errors["unload_to"] = "error.unload_before_load"
    if body.currency not in CURRENCIES:
        errors["currency"] = "error.invalid_choice"
    if body.adr_class and not body.un_number:
        errors["un_number"] = "error.un_required"
    if errors:
        raise ValidationFailed(errors)
    data = {"version": 1, "cargo_name": body.cargo_name, "weight_kg": body.weight_kg, "body_type": body.body_type,
            "desired_rate_minor": body.desired_rate_minor, "currency": body.currency, "load_from": _iso(load_from),
            "distance_km": 0, "points": [{"kind": p.kind, "city": p.city, "address": p.address} for p in body.points]}
    order = _add(db, company_id, "order", data, status=flow.DRAFT, prefix="ЗК")
    if body.publish:
        publish(db, order)
    return out(order)


def publish(db: Session, order: SandboxObject) -> None:
    """A published test order gets two test bids right away."""
    _set_status(order, flow.BIDDING)
    base = json.loads(order.data).get("desired_rate_minor") or 30_000_000
    for i, k in enumerate((0.97, 1.04), start=1):
        _add(db, order.company_id, "bid", {"order_id": str(order.id), "carrier": f"Тестовый перевозчик {i}",
                                            "price_minor": int(round(base * k / 100) * 100), "currency": "KZT"},
             status="active", parent_id=order.id, prefix="ПР")


def list_orders(db: Session, company_id, *, cursor=None, limit: int = 50, status: str | None = None):
    q = select(SandboxObject).where(SandboxObject.company_id == company_id, SandboxObject.kind == "order")
    if status:
        q = q.where(SandboxObject.status == status)
    if cursor:
        q = q.where(SandboxObject.id < cursor)
    rows = list(db.execute(q.order_by(SandboxObject.id.desc()).limit(limit + 1)).scalars())
    return [out(o) for o in rows[:limit]], (str(rows[limit - 1].id) if len(rows) > limit else None)


def get_order(db: Session, company_id, oid) -> dict:
    return out(_get(db, company_id, oid, "order"))


def order_bids(db: Session, company_id, oid) -> list[dict]:
    order = _get(db, company_id, oid, "order")
    return [out(b) for b in db.execute(select(SandboxObject).where(SandboxObject.parent_id == order.id,
                                                                   SandboxObject.kind == "bid")
                                       .order_by(SandboxObject.created_at)).scalars()]


def accept(db: Session, company_id, oid, bid_id) -> dict:
    from app.modules.webhooks.service import enqueue_sandbox

    order = _get(db, company_id, oid, "order")
    bid = _get(db, company_id, bid_id, "bid")
    if bid.parent_id != order.id:
        raise NotFound()
    if order.status != flow.BIDDING:
        raise Conflict("order_not_accepting")
    if bid.status != "active":
        raise Conflict("bid_not_acceptable")
    for other in db.execute(select(SandboxObject).where(SandboxObject.parent_id == order.id,
                                                        SandboxObject.kind == "bid")).scalars():
        _set_status(other, "accepted" if other.id == bid.id else "rejected")
    _set_status(order, flow.ASSIGNED)
    b = json.loads(bid.data)
    deal = _add(db, company_id, "deal", {"order_id": str(order.id), "bid_id": str(bid.id), "carrier": b["carrier"],
                                         "price_minor": b["price_minor"], "currency": b["currency"]},
                status=flow.ASSIGNED, parent_id=order.id, prefix="СД")
    enqueue_sandbox(db, company_id, "deal.created", {"deal_id": str(deal.id), "deal_number": deal.number,
                                                     "order_id": str(order.id), "order_number": order.number,
                                                     "from": flow.BIDDING, "to": flow.ASSIGNED})
    return out(deal)


def advance(db: Session, company_id, oid, to: str) -> dict:
    """Moves the test deal one or more steps along the real status model, firing an event per step."""
    from app.modules.webhooks.service import enqueue_sandbox

    order = _get(db, company_id, oid, "order")
    deal = db.execute(select(SandboxObject).where(SandboxObject.parent_id == order.id,
                                                  SandboxObject.kind == "deal")).scalar_one_or_none()
    if deal is None:
        raise Conflict("order_not_open")
    if to not in DEAL_PATH or DEAL_PATH.index(to) <= DEAL_PATH.index(deal.status):
        raise ValidationFailed({"to": "error.invalid_transition"})
    for step in DEAL_PATH[DEAL_PATH.index(deal.status) + 1:DEAL_PATH.index(to) + 1]:
        frm = deal.status
        _set_status(deal, step)
        _set_status(order, step)
        enqueue_sandbox(db, company_id, "deal.status_changed", {
            "deal_id": str(deal.id), "deal_number": deal.number, "order_id": str(order.id),
            "order_number": order.number, "from": frm, "to": step})
    return out(deal)


# ------------------------------------------------------------------ carrier side


def place_bid(db: Session, company_id, market_order_id: str, price_minor: int, comment: str) -> dict:
    if market_order_id not in {o["id"] for o in market()}:
        raise NotFound()
    exists = db.execute(select(SandboxObject.id).where(SandboxObject.company_id == company_id,
                                                       SandboxObject.kind == "bid",
                                                       SandboxObject.parent_id == uuid.UUID(market_order_id))).first()
    if exists:
        raise Conflict("bid_exists")
    bid = _add(db, company_id, "bid", {"order_id": market_order_id, "price_minor": price_minor, "currency": "KZT",
                                       "comment": comment[:1000]}, status="active",
               parent_id=uuid.UUID(market_order_id), prefix="ПР")
    return out(bid)


def reset(db: Session, company_id) -> int:
    n = _count(db, company_id)
    db.execute(delete(SandboxObject).where(SandboxObject.company_id == company_id))
    return n
