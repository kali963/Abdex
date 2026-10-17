"""Carrier auto-matching for an order (FR-BID-04).

Each candidate gets six partial scores in 0…1, combined with weights from the platform setting
``matching.weights`` (changed without a release):

* body     — an approved vehicle with the required body type and enough capacity (0.5 if capacity is short);
* geo      — the carrier has worked from or to the loading city before;
* history  — the carrier has driven this exact route; extra if it already worked with this client;
* rating   — participant rating / 5 (FR-RAT-01), 0.6 for newcomers;
* level    — verification level / 3;
* load     — free capacity: 1 − active trips / vehicles.

Rules that make an order invisible to a carrier (closed pool, black list, ADR, restrictions) are applied first,
so the list never suggests a carrier who could not bid anyway.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from app.modules.accounts.models import COMPANY_CARRIER, Company
from app.modules.deals.models import Deal
from app.modules.fleet.models import Vehicle
from app.modules.orders import flow
from app.modules.orders.models import Order, OrderPoint
from app.modules.orders.service import carrier_can_see

DEFAULT_WEIGHTS = {"body": 25, "geo": 20, "history": 15, "rating": 20, "level": 10, "load": 10}
MAX_CANDIDATES = 500


@dataclass
class Match:
    company: Company
    score: int
    parts: dict = field(default_factory=dict)
    rating: float | None = None


def weights(db: Session) -> dict[str, float]:
    from app.modules.platform.service import flag_enabled, get_setting

    if flag_enabled(db, "matching.ai"):  # FR-BID-09: weights learned from the clients' past choices
        learned = get_setting(db, "matching.learned", None) or {}
        if isinstance(learned, dict) and learned.get("weights") and learned.get("samples", 0) >= MIN_SAMPLES:
            return {k: max(0.0, float(learned["weights"].get(k, 0) or 0)) for k in DEFAULT_WEIGHTS}
    value = get_setting(db, "matching.weights", None)
    merged = {**DEFAULT_WEIGHTS, **(value if isinstance(value, dict) else {})}
    return {k: max(0.0, float(merged.get(k, 0) or 0)) for k in DEFAULT_WEIGHTS}


def _city(point: OrderPoint | None) -> str:
    return (point.city if point else "").strip().lower()


def _route_counts(db: Session, carrier_ids: list, origin: str, destination: str) -> tuple[dict, dict]:
    """How many deals each carrier had touching the origin city, and on exactly this route."""
    first = aliased(OrderPoint)
    last = aliased(OrderPoint)
    max_seq = (select(OrderPoint.order_id, func.max(OrderPoint.seq).label("seq")).group_by(OrderPoint.order_id)
               .subquery())
    rows = db.execute(
        select(Deal.carrier_company_id, func.lower(first.city), func.lower(last.city))
        .join(first, (first.order_id == Deal.order_id) & (first.seq == 0))
        .join(max_seq, max_seq.c.order_id == Deal.order_id)
        .join(last, (last.order_id == Deal.order_id) & (last.seq == max_seq.c.seq))
        .where(Deal.carrier_company_id.in_(carrier_ids))
    ).all()
    geo: dict = {}
    route: dict = {}
    for cid, frm, to in rows:
        frm, to = (frm or "").strip(), (to or "").strip()
        if origin and origin in (frm, to):
            geo[cid] = geo.get(cid, 0) + 1
        if origin and destination and frm == origin and to == destination:
            route[cid] = route.get(cid, 0) + 1
    return geo, route


def rank(db: Session, order: Order, *, limit: int = 10) -> list[Match]:
    from app.modules.platform.service import has_restriction

    w = weights(db)
    total_w = sum(w.values()) or 1.0
    carriers = list(db.execute(
        select(Company).where(Company.kind == COMPANY_CARRIER, Company.is_blocked.is_(False),
                              Company.is_deleted.is_(False), Company.verification_level >= 1)
        .order_by(Company.verification_level.desc(), Company.created_at).limit(MAX_CANDIDATES)).scalars())
    from app.modules.fleet.level3 import required_for

    min_level = 3 if required_for(db, order) else 1  # section 8: valuable / international cargo — L3 only
    carriers = [c for c in carriers if carrier_can_see(db, order, c) and c.verification_level >= min_level
                and not has_restriction(db, c.id, ("block", "no_bids"))]
    if not carriers:
        return []
    result = []
    for c, parts, r in features(db, order, carriers):
        score = round(100 * sum(w[k] * parts[k] for k in w) / total_w)
        result.append(Match(company=c, score=score, parts={k: round(v * 100) for k, v in parts.items()},
                            rating=r))
    result.sort(key=lambda m: (-m.score, m.company.name))
    return result[:limit]


def features(db: Session, order: Order, carriers: list) -> list[tuple]:
    """The six partial scores (0…1) of each carrier for the order: [(company, parts, rating)]."""
    from app.modules.rating.service import compute

    ids = [c.id for c in carriers]
    vehicles: dict = {}
    for v in db.execute(select(Vehicle).where(Vehicle.company_id.in_(ids), Vehicle.is_deleted.is_(False),
                                              Vehicle.status != "rejected")).scalars():
        vehicles.setdefault(v.company_id, []).append(v)
    active = dict(db.execute(
        select(Deal.carrier_company_id, func.count(Deal.id)).join(Order, Order.id == Deal.order_id)
        .where(Deal.carrier_company_id.in_(ids), Order.status.in_((flow.ASSIGNED,) + flow.ACTIVE_TRIP))
        .group_by(Deal.carrier_company_id)).all())
    with_client = dict(db.execute(
        select(Deal.carrier_company_id, func.count(Deal.id))
        .where(Deal.carrier_company_id.in_(ids), Deal.client_company_id == order.client_company_id)
        .group_by(Deal.carrier_company_id)).all())
    geo, route = _route_counts(db, ids, _city(order.origin), _city(order.destination))
    need = max(order.weight_kg or 0, order.min_capacity_kg or 0)
    out = []
    for c in carriers:
        fleet = vehicles.get(c.id, [])
        same_body = [v for v in fleet if v.body_type == order.body_type]
        if any(v.capacity_kg >= need and v.status == "approved" for v in same_body):
            body = 1.0
        elif same_body:
            body = 0.5
        else:
            body = 0.0
        r = compute(db, c.id)
        parts = {
            "body": body,
            "geo": min(1.0, geo.get(c.id, 0) / 3),
            "history": min(1.0, route.get(c.id, 0) / 2 + (0.5 if with_client.get(c.id) else 0)),
            "rating": (r["value"] / 5) if r["value"] is not None else 0.6,
            "level": min(1.0, c.verification_level / 3),
            "load": max(0.0, 1 - active.get(c.id, 0) / len(fleet)) if fleet else 0.0,
        }
        out.append((c, parts, r["value"]))
    return out


# ------------------------------------------------------------------ FR-BID-09: learned weights ("AI matching")

MIN_SAMPLES = 30


def learn(db: Session, *, days: int = 365, max_orders: int = 400) -> dict:
    """Fit a logistic regression on past choices: for every order that became a deal, each carrier who bid is
    a sample (features = the six partial scores, label = was this bid accepted). The positive coefficients,
    scaled to 100, become the matching weights. Plain Python, no external ML service; the model is a handful of
    numbers stored in the setting ``matching.learned`` and switched on by the ``matching.ai`` flag."""
    import math
    from datetime import timedelta

    from app.core import rls
    from app.db import utcnow
    from app.modules.bids.models import Bid
    from app.modules.platform.service import set_setting

    keys = list(DEFAULT_WEIGHTS)
    xs, ys = [], []
    with rls.system(db):
        deals = db.execute(select(Deal).where(Deal.created_at >= utcnow() - timedelta(days=days))
                           .order_by(Deal.created_at.desc()).limit(max_orders)).scalars().all()
        for deal in deals:
            order = db.get(Order, deal.order_id)
            bids = db.execute(select(Bid).where(Bid.order_id == order.id)).scalars().all()
            carriers = [db.get(Company, b.carrier_company_id) for b in bids]
            carriers = [c for c in carriers if c is not None]
            if len(carriers) < 2:
                continue  # a single bidder says nothing about preferences
            for c, parts, _ in features(db, order, carriers):
                xs.append([parts[k] for k in keys])
                ys.append(1.0 if c.id == deal.carrier_company_id else 0.0)
    n = len(ys)
    result = {"samples": n, "weights": None, "at": utcnow().isoformat(timespec="seconds")}
    if n >= MIN_SAMPLES and 0 < sum(ys) < n:
        w = [0.0] * len(keys)
        b = 0.0
        lr, l2 = 0.5, 0.01
        for _ in range(400):
            gw, gb = [0.0] * len(keys), 0.0
            for x, y in zip(xs, ys, strict=True):
                z = b + sum(wi * xi for wi, xi in zip(w, x, strict=True))
                p = 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))
                err = p - y
                gb += err
                for i, xi in enumerate(x):
                    gw[i] += err * xi
            b -= lr * gb / n
            w = [wi - lr * (g / n + l2 * wi) for wi, g in zip(w, gw, strict=True)]
        positive = {k: max(0.0, wi) for k, wi in zip(keys, w, strict=True)}
        total = sum(positive.values())
        if total > 0:
            result["weights"] = {k: round(100 * v / total, 1) for k, v in positive.items()}
            result["coefficients"] = {k: round(wi, 3) for k, wi in zip(keys, w, strict=True)}
    set_setting(db, "matching.learned", result)
    db.commit()
    return result


def invited_ids(db: Session, order_id) -> set:
    from app.modules.orders.models import OrderInvite

    return set(db.execute(select(OrderInvite.carrier_company_id).where(OrderInvite.order_id == order_id)).scalars())


def invite(db: Session, order: Order, carrier: Company) -> None:
    """Notify a recommended carrier about the order. Only carriers who could see and bid on it can be invited."""
    from sqlalchemy.exc import IntegrityError

    from app.core import ratelimit
    from app.core.audit import audit
    from app.core.context import get_ctx
    from app.core.errors import Conflict, NotFound
    from app.modules.accounts.models import ROLE_DISPATCHER, ROLE_FLEET_OWNER
    from app.modules.notifications.service import _company_users, notify_user
    from app.modules.orders.models import OrderInvite
    from app.modules.platform.service import has_restriction

    if order.status not in flow.OPEN_FOR_BIDS:
        raise Conflict("order_not_open")
    from app.modules.fleet.level3 import required_for

    if (carrier.kind != COMPANY_CARRIER or carrier.verification_level < (3 if required_for(db, order) else 1)
            or carrier.is_blocked
            or not carrier_can_see(db, order, carrier) or has_restriction(db, carrier.id, ("block", "no_bids"))):
        raise NotFound()
    ratelimit.hit("invite", str(order.client_company_id))
    try:
        with db.begin_nested():
            db.add(OrderInvite(order_id=order.id, carrier_company_id=carrier.id, created_by=get_ctx().user_id))
            db.flush()
    except IntegrityError as exc:
        raise Conflict("already_invited") from exc
    for uid in _company_users(db, carrier.id, (ROLE_FLEET_OWNER, ROLE_DISPATCHER)):
        notify_user(db, uid, "order.invited", {"number": order.number}, link=f"/market/{order.id}",
                    channels=["web", "telegram", "push"], dedup=f"invite:{order.id}:{uid}")
    audit(db, "order.carrier_invited", object_type="order", object_id=order.id, details={"carrier": str(carrier.id)})
