"""Orders (M3): form validation, moderation, versioning, marketplace, archive search."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, Forbidden, NotFound, ValidationFailed
from app.core.i18n import parse_local_input
from app.core.money import to_minor
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.integrations.adapters import routing
from app.modules.integrations.base import IntegrationUnavailable
from app.modules.orders import flow
from app.modules.orders.models import Order, OrderPoint, OrderTemplate, OrderVersion, PoolMember, SavedSearch
from app.modules.platform.service import get_setting, next_number

POINT_KINDS = ("load", "stop", "unload")
PAYMENT_TERMS = ("prepay", "on_unload", "deferred")


@dataclass
class PointInput:
    kind: str
    city: str
    address: str = ""
    region: str = ""
    contact_name: str = ""
    contact_phone: str = ""


def parse_order_form(form: dict, *, preliminary: bool = False) -> tuple[dict, list[PointInput]]:
    """Server-side validation for every field (NFR-FE-02). Messages say what to fix."""
    errors: dict[str, str] = {}
    g = lambda k, d="": (form.get(k) or d).strip() if isinstance(form.get(k, d), str) else form.get(k, d)  # noqa: E731

    def as_int(key: str, *, required: bool = False, minimum: int = 0) -> int:
        raw = g(key)
        if not raw:
            if required:
                errors[key] = "error.required"
            return 0
        try:
            val = int(float(str(raw).replace(",", ".").replace(" ", "")))
        except ValueError:
            errors[key] = "error.number"
            return 0
        if val < minimum:
            errors[key] = "error.number_min"
        return val

    def as_bool(key: str) -> bool:
        return str(form.get(key, "")).lower() in ("1", "on", "true", "yes")

    data: dict = {
        "cargo_name": g("cargo_name"), "cargo_type": g("cargo_type", "general"), "packaging": g("packaging"),
        "body_type": g("body_type", "tent"), "temperature_mode": g("temperature_mode"),
        "special_conditions": g("special_conditions"), "adr_class": g("adr_class"), "un_number": g("un_number"),
        "countries": g("countries"), "border_crossing": g("border_crossing"),
        "payment_terms": g("payment_terms", "on_unload"), "downtime_terms": g("downtime_terms"),
        "currency": g("currency", "KZT") or "KZT", "visibility": g("visibility", "public") or "public",
        "needs_tail_lift": as_bool("needs_tail_lift"), "needs_straps": as_bool("needs_straps"),
        "is_international": as_bool("is_international"), "needs_cmr": as_bool("needs_cmr"),
        "needs_tir": as_bool("needs_tir"), "vat_included": as_bool("vat_included"),
    }
    full = not preliminary
    data["weight_kg"] = as_int("weight_kg", required=full, minimum=1 if full else 0)
    data["volume_m3"] = as_int("volume_m3")
    data["places"] = as_int("places")
    data["min_capacity_kg"] = as_int("min_capacity_kg")
    data["payment_delay_days"] = as_int("payment_delay_days")
    for key in ("desired_rate", "cargo_value"):
        raw = g(key)
        try:
            data[f"{key}_minor"] = to_minor(raw, data["currency"]) if raw else 0
        except ValueError:
            errors[key] = "error.number"
            data[f"{key}_minor"] = 0
    if full and not data["cargo_name"]:
        errors["cargo_name"] = "error.required"
    if data["payment_terms"] not in PAYMENT_TERMS:
        errors["payment_terms"] = "error.required"
    if data["payment_terms"] == "deferred" and data["payment_delay_days"] <= 0:
        errors["payment_delay_days"] = "error.delay_required"
    for key in ("load_from", "load_to", "unload_from", "unload_to", "bidding_deadline"):
        data[key] = parse_local_input(g(key))
    if full and not data["load_from"]:
        errors["load_from"] = "error.required"
    if data["load_from"] and data["load_to"] and data["load_to"] < data["load_from"]:
        errors["load_to"] = "error.date_order"
    if data["unload_from"] and data["load_from"] and data["unload_from"] < data["load_from"]:
        errors["unload_from"] = "error.unload_before_load"
    if full and data["load_from"] and data["load_from"] < utcnow() - timedelta(hours=1):
        errors["load_from"] = "error.date_in_past"
    # FR-ORD-02: ADR class requires UN number
    if data["adr_class"] and not data["un_number"]:
        errors["un_number"] = "error.un_required"
    # FR-ORD-03: required fields depend on direction
    if data["is_international"]:
        if not data["countries"]:
            errors["countries"] = "error.required"
        if not data["border_crossing"]:
            errors["border_crossing"] = "error.required"

    points: list[PointInput] = []
    cities = form.get("point_city") or []
    if isinstance(cities, str):
        cities = [cities]
    kinds = form.get("point_kind") or []
    addrs = form.get("point_address") or []
    names = form.get("point_contact_name") or []
    phones = form.get("point_contact_phone") or []
    for i, city in enumerate(cities):
        city = (city or "").strip()
        if not city:
            continue
        kind = kinds[i] if i < len(kinds) and kinds[i] in POINT_KINDS else "stop"
        points.append(PointInput(kind=kind, city=city, address=(addrs[i] if i < len(addrs) else "").strip(),
                                 contact_name=(names[i] if i < len(names) else "").strip(),
                                 contact_phone=(phones[i] if i < len(phones) else "").strip()))
    if points:
        points[0].kind = "load"
        if len(points) > 1:
            points[-1].kind = "unload"
    if full and len(points) < 2:
        errors["points"] = "error.points_required"
    if errors:
        raise ValidationFailed(errors)
    return data, points


def _apply(order: Order, data: dict, points: list[PointInput]) -> None:
    for k, v in data.items():
        setattr(order, k, v)
    order.points.clear()
    for i, p in enumerate(points):
        order.points.append(OrderPoint(seq=i, kind=p.kind, city=p.city, address=p.address,
                                       contact_name=p.contact_name, contact_phone=p.contact_phone))
    order.search_text = " ".join([order.number, order.cargo_name, *[p.city for p in points],
                                  *[p.address for p in points]]).lower()


def _calc_route(order: Order) -> None:
    try:
        res = routing.route([p.city for p in order.points])
    except IntegrationUnavailable:
        res = None
    if res:
        order.distance_km = res["distance_km"]
        order.duration_hours = res["duration_hours"]
        order.route_source = res["source"]


def _snapshot(order: Order) -> str:
    cols = {c.key: getattr(order, c.key) for c in Order.__table__.columns}
    cols["points"] = [{"kind": p.kind, "city": p.city, "address": p.address} for p in order.points]
    return json.dumps(cols, ensure_ascii=False, default=str)


def create_order(db: Session, company: Company, form: dict, *, preliminary: bool = False) -> Order:
    ratelimit.hit("order_create", str(company.id))
    if company.kind != "client":
        raise Forbidden()
    _check_restrictions(db, company)
    data, points = parse_order_form(form, preliminary=preliminary)
    order = Order(number=next_number(db, "order", "AX"), client_company_id=company.id, status=flow.DRAFT,
                  is_preliminary=preliminary, created_by=get_ctx().user_id)
    db.add(order)
    _apply(order, data, points)
    _calc_route(order)
    db.flush()
    audit(db, "order.created", object_type="order", object_id=order.id)
    return order


def update_order(db: Session, order: Order, form: dict, *, note: str = "") -> Order:
    """FR-ORD-07: editing a published order creates a new version; bidders must reconfirm."""
    if order.status not in (flow.DRAFT, flow.PUBLISHED, flow.BIDDING):
        raise AppError("order_not_editable", status_code=409)
    data, points = parse_order_form(form, preliminary=order.is_preliminary and order.status == flow.DRAFT)
    _apply(order, data, points)
    _calc_route(order)
    order.updated_by = get_ctx().user_id
    if order.status in flow.OPEN_FOR_BIDS:
        order.version += 1
        db.add(OrderVersion(order_id=order.id, version=order.version, data=_snapshot(order), change_note=note[:300],
                            created_by=get_ctx().user_id))
        from app.modules.bids.service import request_reconfirmation

        request_reconfirmation(db, order)
    db.flush()
    audit(db, "order.updated", object_type="order", object_id=order.id, details={"version": order.version})
    return order


def submit(db: Session, order: Order) -> Order:
    """Draft -> moderation -> automatic checks -> published or back to draft with reason."""
    if order.is_preliminary:
        # FR-PLAN-02: a preliminary order must be completed first
        parse_order_form(_order_as_form(order))
        order.is_preliminary = False
    flow.transition(db, order, flow.MODERATION, actor=flow.CLIENT)
    problems = auto_moderation_problems(db, order)
    if problems:
        if get_setting(db, "moderation.manual_on_warning", True):
            order.moderation_note = "; ".join(problems)
            return order  # stays in moderation for a manager
    flow.transition(db, order, flow.PUBLISHED, actor=flow.SYSTEM, reason="auto checks passed")
    if order.bidding_deadline is None:
        hours = int(get_setting(db, "orders.default_bidding_hours", 24))
        order.bidding_deadline = utcnow() + timedelta(hours=hours)
    db.add(OrderVersion(order_id=order.id, version=order.version, data=_snapshot(order), change_note="published",
                        created_by=get_ctx().user_id))
    return order


def auto_moderation_problems(db: Session, order: Order) -> list[str]:
    """FR-ORD-10: unrealistic terms and rates below the direction threshold."""
    problems = []
    if order.distance_km and order.load_from and order.unload_to:
        hours = (order.unload_to - order.load_from).total_seconds() / 3600
        if hours > 0 and order.distance_km / hours > 90:
            problems.append("unrealistic_transit_time")
    min_rate_per_km = int(get_setting(db, "moderation.min_rate_per_km_minor", 15000))
    if order.desired_rate_minor and order.distance_km and order.currency == "KZT":
        if order.desired_rate_minor / max(order.distance_km, 1) < min_rate_per_km:
            problems.append("rate_below_threshold")
    return problems


def _order_as_form(order: Order) -> dict:
    from app.core.i18n import to_local_input
    from app.core.money import from_minor

    form = {c: str(getattr(order, c) or "") for c in (
        "cargo_name", "cargo_type", "packaging", "body_type", "temperature_mode", "special_conditions", "adr_class",
        "un_number", "countries", "border_crossing", "payment_terms", "downtime_terms", "currency", "visibility",
        "weight_kg", "volume_m3", "places", "min_capacity_kg", "payment_delay_days")}
    for b in ("needs_tail_lift", "needs_straps", "is_international", "needs_cmr", "needs_tir", "vat_included"):
        form[b] = "on" if getattr(order, b) else ""
    form["desired_rate"] = str(from_minor(order.desired_rate_minor, order.currency)) if order.desired_rate_minor else ""
    form["cargo_value"] = str(from_minor(order.cargo_value_minor, order.currency)) if order.cargo_value_minor else ""
    for k in ("load_from", "load_to", "unload_from", "unload_to", "bidding_deadline"):
        form[k] = to_local_input(getattr(order, k))
    form["point_city"] = [p.city for p in order.points]
    form["point_kind"] = [p.kind for p in order.points]
    form["point_address"] = [p.address for p in order.points]
    form["point_contact_name"] = [p.contact_name for p in order.points]
    form["point_contact_phone"] = [p.contact_phone for p in order.points]
    return form


order_as_form = _order_as_form


def cancel(db: Session, order: Order, reason: str) -> None:
    flow.transition(db, order, flow.CANCELLED, actor=flow.CLIENT, reason=reason)
    from app.modules.bids.models import Bid

    for bid in db.execute(select(Bid).where(Bid.order_id == order.id, Bid.status.in_(
            ("active", "countered", "needs_confirmation")))).scalars():
        bid.status = "rejected"


def _check_restrictions(db: Session, company: Company) -> None:
    """FR-BIL-05 / FR-RAT-04: blocked companies or companies with debt cannot create orders."""
    from app.modules.platform.models import Restriction

    if company.is_blocked:
        raise Forbidden("company_blocked")
    active = db.execute(select(Restriction).where(Restriction.company_id == company.id,
                                                  Restriction.kind.in_(("block", "no_new_orders")),
                                                  Restriction.lifted_at.is_(None))).scalars().all()
    today = utcnow().date()
    if any(r.until is None or r.until >= today for r in active):
        raise Forbidden("company_restricted")


def get_for_client(db: Session, order_id, company_id) -> Order:
    order = db.get(Order, order_id)
    if order is None or order.client_company_id != company_id or order.is_deleted:
        raise NotFound()  # SEC-AZ-02: unknown and foreign look the same
    return order


def client_orders(db: Session, company_id, *, status: str | None = None, q: str = "", limit: int = 50,
                  cursor: str | None = None) -> list[Order]:
    stmt = select(Order).where(Order.client_company_id == company_id, Order.is_deleted.is_(False))
    if status:
        stmt = stmt.where(Order.status == status)
    if q:
        stmt = stmt.where(Order.search_text.contains(q.lower()))
    if cursor:
        stmt = stmt.where(Order.id < cursor)
    return list(db.execute(stmt.order_by(Order.id.desc()).limit(limit)).scalars())


def carrier_can_see(db: Session, order: Order, carrier: Company) -> bool:
    if order.status not in flow.OPEN_FOR_BIDS or order.is_deleted:
        return False
    if order.visibility == "pool":
        return db.execute(select(PoolMember.id).where(PoolMember.owner_company_id == order.client_company_id,
                                                      PoolMember.other_company_id == carrier.id,
                                                      PoolMember.kind == "trusted")).first() is not None
    blocked = db.execute(select(PoolMember.id).where(PoolMember.owner_company_id == order.client_company_id,
                                                     PoolMember.other_company_id == carrier.id,
                                                     PoolMember.kind == "blocked")).first()
    if blocked:
        return False
    if order.adr_class:
        return carrier_has_adr(db, carrier.id)
    return True


def carrier_has_adr(db: Session, carrier_id) -> bool:
    from app.modules.fleet.models import Driver, Vehicle

    v = db.execute(select(Vehicle.id).where(Vehicle.company_id == carrier_id, Vehicle.adr_allowed.is_(True))).first()
    d = db.execute(select(Driver.id).where(Driver.company_id == carrier_id, Driver.adr_permit.is_(True))).first()
    return bool(v and d)


def marketplace(db: Session, carrier: Company, filters: dict, *, limit: int = 50) -> list[Order]:
    """FR-ORD-08: marketplace with filters; ADR and closed-pool rules applied server-side."""
    stmt = select(Order).where(Order.status.in_(flow.OPEN_FOR_BIDS), Order.is_deleted.is_(False))
    pool_ok = exists().where(and_(PoolMember.owner_company_id == Order.client_company_id,
                                  PoolMember.other_company_id == carrier.id, PoolMember.kind == "trusted"))
    blocked = exists().where(and_(PoolMember.owner_company_id == Order.client_company_id,
                                  PoolMember.other_company_id == carrier.id, PoolMember.kind == "blocked"))
    stmt = stmt.where(or_(Order.visibility == "public", pool_ok)).where(~blocked)
    if not carrier_has_adr(db, carrier.id):
        stmt = stmt.where(Order.adr_class == "")
    if filters.get("from_city"):
        sub = select(OrderPoint.order_id).where(OrderPoint.kind == "load",
                                                func.lower(OrderPoint.city) == filters["from_city"].lower())
        stmt = stmt.where(Order.id.in_(sub))
    if filters.get("to_city"):
        sub = select(OrderPoint.order_id).where(OrderPoint.kind == "unload",
                                                func.lower(OrderPoint.city) == filters["to_city"].lower())
        stmt = stmt.where(Order.id.in_(sub))
    if filters.get("body_type"):
        stmt = stmt.where(Order.body_type == filters["body_type"])
    if filters.get("max_weight"):
        try:
            stmt = stmt.where(Order.weight_kg <= int(filters["max_weight"]))
        except ValueError:
            pass
    if filters.get("min_rate"):
        try:
            stmt = stmt.where(Order.desired_rate_minor >= to_minor(filters["min_rate"]))
        except ValueError:
            pass
    if filters.get("date_from"):
        dt = parse_local_input(filters["date_from"] + "T00:00")
        if dt:
            stmt = stmt.where(Order.load_from >= dt)
    if filters.get("date_to"):
        dt = parse_local_input(filters["date_to"] + "T23:59")
        if dt:
            stmt = stmt.where(Order.load_from <= dt)
    return list(db.execute(stmt.order_by(Order.published_at.desc()).limit(limit)).scalars())


def save_template(db: Session, company: Company, order: Order, name: str) -> OrderTemplate:
    tpl = OrderTemplate(company_id=company.id, name=name.strip() or order.number,
                        data=json.dumps(_order_as_form(order), ensure_ascii=False))
    db.add(tpl)
    return tpl


def repeat_order(db: Session, company: Company, source: Order) -> Order:
    """FR-ORD-05: repeat a past order in one click (dates must be re-entered)."""
    form = _order_as_form(source)
    for k in ("load_from", "load_to", "unload_from", "unload_to", "bidding_deadline"):
        form[k] = ""
    return create_order(db, company, form, preliminary=True)


def expire_bidding(db: Session) -> int:
    """FR-FLOW-04: timer transition; idempotent (only rows still in bidding are touched)."""
    now = utcnow()
    count = 0
    rows = db.execute(select(Order).where(Order.status.in_(flow.OPEN_FOR_BIDS), Order.bidding_deadline.is_not(None),
                                          Order.bidding_deadline < now)).scalars().all()
    for order in rows:
        order = flow.lock_order(db, order.id)
        if order.status == flow.BIDDING:
            flow.transition(db, order, flow.CANCELLED, actor=flow.SYSTEM, reason="bidding deadline expired")
            count += 1
        elif order.status == flow.PUBLISHED:
            # no bids at all: extend once and escalate to a manager (FR-NTF-07)
            from app.modules.notifications.service import notify_event

            order.bidding_deadline = now + timedelta(hours=int(get_setting(db, "orders.default_bidding_hours", 24)))
            notify_event(db, "order.status", params={"number": order.number, "status": "no_bids"},
                         link=f"/orders/{order.id}", client_company_id=order.client_company_id,
                         include_managers=True, dedup=f"nobids:{order.id}:{order.bidding_deadline:%Y%m%d%H}")
    db.commit()
    return count


def notify_saved_searches(db: Session, order: Order) -> None:
    from app.modules.notifications.service import notify_user

    for s in db.execute(select(SavedSearch).where(SavedSearch.notify.is_(True))).scalars():
        filters = json.loads(s.filters or "{}")
        carrier = db.get(Company, s.company_id)
        if carrier is None or not carrier_can_see(db, order, carrier):
            continue
        origin = order.origin.city.lower() if order.origin else ""
        dest = order.destination.city.lower() if order.destination else ""
        if filters.get("from_city") and filters["from_city"].lower() != origin:
            continue
        if filters.get("to_city") and filters["to_city"].lower() != dest:
            continue
        if filters.get("body_type") and filters["body_type"] != order.body_type:
            continue
        notify_user(db, s.user_id, "order.matching", {"number": order.number, "route": f"{origin} → {dest}"},
                    link=f"/market/{order.id}", channels=["web", "telegram", "push"],
                    dedup=f"match:{order.id}:{s.user_id}")
