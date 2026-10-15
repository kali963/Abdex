"""Order series for regular routes (FR-ORD-05, Ц2).

A series copies a source order onto chosen weekdays. The background worker creates each order
``lead_days`` before its loading date; ``last_load_date`` makes generation idempotent, so a restarted
or repeated worker run never creates the same order twice.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, NotFound, ValidationFailed
from app.core.i18n import to_local_input
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.orders import service as orders
from app.modules.orders.models import Order, OrderSeries

log = logging.getLogger("abdex.series")
MAX_LEAD_DAYS = 30
MAX_PER_RUN = 60  # safety net per series and run


def _parse_date(raw) -> date | None:
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def parse_form(form) -> dict:
    errors = {}
    getlist = getattr(form, "getlist", None)
    raw_days = getlist("weekdays") if getlist else form.get("weekdays", [])
    if isinstance(raw_days, str):
        raw_days = raw_days.split(",")
    days = sorted({int(d) for d in raw_days if str(d).strip().isdigit() and 1 <= int(d) <= 7})
    if not days:
        errors["weekdays"] = "error.required"
    start = _parse_date(form.get("start_date"))
    if start is None:
        errors["start_date"] = "error.date"
    end = _parse_date(form.get("end_date"))
    if form.get("end_date") and end is None:
        errors["end_date"] = "error.date"
    if start and end and end < start:
        errors["end_date"] = "error.date_order"
    try:
        lead = int(form.get("lead_days") or 3)
        if not 0 <= lead <= MAX_LEAD_DAYS:
            raise ValueError
    except ValueError:
        errors["lead_days"] = "error.number"
        lead = 3
    name = str(form.get("name") or "").strip()[:200]
    if errors:
        raise ValidationFailed(errors)
    return {"weekdays": ",".join(map(str, days)), "start_date": start, "end_date": end, "lead_days": lead,
            "name": name, "auto_submit": bool(form.get("auto_submit"))}


def create_series(db: Session, company: Company, source: Order, form) -> OrderSeries:
    if source.client_company_id != company.id:
        raise NotFound()
    if source.load_from is None or not source.points:
        raise ValidationFailed({"source": "error.series_source"})
    data = parse_form(form)
    if data["start_date"] < utcnow().date():
        raise ValidationFailed({"start_date": "error.date_past"})
    s = OrderSeries(company_id=company.id, source_order_id=source.id, name=data["name"] or source.number,
                    weekdays=data["weekdays"], start_date=data["start_date"], end_date=data["end_date"],
                    lead_days=data["lead_days"], auto_submit=data["auto_submit"], created_by=get_ctx().user_id)
    db.add(s)
    db.flush()
    audit(db, "order.series_created", object_type="order_series", object_id=s.id,
          details={"source": str(source.id), "weekdays": s.weekdays})
    return s


def company_series(db: Session, company_id) -> list[OrderSeries]:
    return list(db.execute(select(OrderSeries).where(OrderSeries.company_id == company_id,
                                                     OrderSeries.is_deleted.is_(False))
                           .order_by(OrderSeries.created_at.desc())).scalars())


def upcoming_dates(s: OrderSeries, *, today: date | None = None, count: int = 5) -> list[date]:
    today = today or utcnow().date()
    days = {int(d) for d in s.weekdays.split(",") if d}
    d = max(s.start_date, today, (s.last_load_date + timedelta(days=1)) if s.last_load_date else s.start_date)
    out = []
    for _ in range(366):
        if s.end_date and d > s.end_date:
            break
        if d.isoweekday() in days:
            out.append(d)
            if len(out) >= count:
                break
        d += timedelta(days=1)
    return out


def _form_for(source: Order, load_day: date) -> dict:
    form = orders.order_as_form(source)
    tz = ZoneInfo(get_ctx().timezone or "Asia/Almaty")
    shift = timedelta(days=(load_day - source.load_from.astimezone(tz).date()).days)
    for k in ("load_from", "load_to", "unload_from", "unload_to"):
        value = getattr(source, k)
        form[k] = to_local_input(value + shift) if value else ""
    form["bidding_deadline"] = ""
    return form


def generate_due(db: Session, *, today: date | None = None) -> int:
    """Worker job: create orders whose loading date falls within the series lead time."""
    today = today or utcnow().date()
    created = 0
    ids = list(db.execute(select(OrderSeries.id).where(OrderSeries.active.is_(True),
                                                       OrderSeries.is_deleted.is_(False))).scalars())
    for sid in ids:
        s = db.execute(select(OrderSeries).where(OrderSeries.id == sid).with_for_update()).scalar_one()
        source = db.get(Order, s.source_order_id)
        company = db.get(Company, s.company_id)
        if source is None or company is None or source.load_from is None:
            s.active = False
            continue
        horizon = today + timedelta(days=s.lead_days)
        n = 0
        for d in upcoming_dates(s, today=today, count=MAX_PER_RUN):
            if d > horizon:
                break
            try:
                with db.begin_nested():
                    order = orders.create_order(db, company, _form_for(source, d), rate_limited=False)
                    if s.auto_submit:
                        orders.submit(db, order)
            except AppError as exc:  # restricted company, invalid source: stop the series, tell the owner
                log.info("series %s stopped: %s", s.id, exc.code)
                s.active = False
                from app.modules.notifications.service import notify_company_owners

                notify_company_owners(db, company.id, "series.stopped", {"name": s.name}, link="/orders/series",
                                      dedup=f"series_stop:{s.id}:{today}")
                break
            s.last_load_date = d
            s.created_count += 1
            n += 1
        created += n
    db.commit()
    return created
