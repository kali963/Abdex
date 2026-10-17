"""KPI and analytics (M15, FR-PVD-08).

Definition fixed here and in docs/metrics.md (FR-PVD-08 note):
  "Order processing time" = interval between the status transition into `published`
  and the transition into `assigned` (executor appointed), taken from status_history.
  Reported as median and mean, split by route type (domestic / international).
All KPI values are computed by the system; there is no manual input.
"""
from __future__ import annotations

import csv
import io
import json
import statistics
from datetime import date, datetime, time, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.export import row as safe_row
from app.db import utcnow
from app.modules.accounts.models import Company, Membership, ROLE_DRIVER
from app.modules.billing.models import Accrual
from app.modules.bids.models import Bid
from app.modules.deals.models import Deal, Rating
from app.modules.documents.models import Document
from app.modules.fleet.models import Driver
from app.modules.orders import flow
from app.modules.orders.models import Order, StatusHistory
from app.modules.platform.fx import deal_kzt
from app.modules.platform.models import KpiSnapshot

KPI_TARGETS = {  # month -> targets from the development plan
    8: {"processing_minutes": 30, "auto_documents": 250},
    16: {"processing_minutes": 15, "auto_documents": 800},
    24: {"processing_minutes": 10, "auto_documents": 2000},
}


def _range(date_from: date | None, date_to: date | None):
    start = datetime.combine(date_from, time.min, tzinfo=timezone.utc) if date_from else datetime(2000, 1, 1, tzinfo=timezone.utc)
    end = datetime.combine(date_to, time.max, tzinfo=timezone.utc) if date_to else utcnow()
    return start, end


def processing_times(db: Session, date_from: date | None = None, date_to: date | None = None) -> dict:
    start, end = _range(date_from, date_to)
    pub = {r.order_id: r.created_at for r in db.execute(
        select(StatusHistory).where(StatusHistory.to_status == flow.PUBLISHED, StatusHistory.is_rollback.is_(False))
    ).scalars()}
    out: dict[str, list[float]] = {"domestic": [], "international": []}
    rows = db.execute(select(StatusHistory, Order.is_international).join(Order, Order.id == StatusHistory.order_id)
                      .where(StatusHistory.to_status == flow.ASSIGNED, StatusHistory.created_at >= start,
                             StatusHistory.created_at <= end)).all()
    for h, intl in rows:
        if h.order_id in pub:
            minutes = (h.created_at - pub[h.order_id]).total_seconds() / 60
            out["international" if intl else "domestic"].append(max(0.0, minutes))

    def stats(values):
        if not values:
            return {"count": 0, "median": None, "mean": None}
        return {"count": len(values), "median": round(statistics.median(values), 1),
                "mean": round(statistics.fmean(values), 1)}

    all_values = out["domestic"] + out["international"]
    return {"all": stats(all_values), "domestic": stats(out["domestic"]), "international": stats(out["international"])}


def kpi(db: Session, date_from: date | None = None, date_to: date | None = None) -> dict:
    start, end = _range(date_from, date_to)

    def count(model, *conds):
        return db.execute(select(func.count(model.id)).where(model.created_at >= start, model.created_at <= end,
                                                             *conds)).scalar_one()

    drivers = db.execute(select(func.count(func.distinct(Driver.iin_index))).where(
        Driver.created_at >= start, Driver.created_at <= end, Driver.is_deleted.is_(False))).scalar_one()
    driver_members = db.execute(select(func.count(Membership.id)).where(
        Membership.role == ROLE_DRIVER, Membership.created_at >= start, Membership.created_at <= end)).scalar_one()
    return {
        "clients": count(Company, Company.kind == "client", Company.is_deleted.is_(False)),
        "carriers": count(Company, Company.kind == "carrier", Company.is_self_employed_driver.is_(False),
                          Company.is_deleted.is_(False)),
        "drivers": max(drivers, driver_members),
        "orders": count(Order, Order.is_deleted.is_(False)),
        "deals": count(Deal),
        "auto_documents": count(Document, Document.is_generated.is_(True)),
        "processing": processing_times(db, date_from, date_to),
    }


def fix_snapshot(db: Session, report_date: date) -> KpiSnapshot:
    """FR-BI-02: values fixed at a reporting date (append-only)."""
    values = kpi(db, None, report_date)
    snap = KpiSnapshot(report_date=report_date, values=json.dumps(values, ensure_ascii=False, default=str))
    db.add(snap)
    return snap


def operations(db: Session) -> dict:
    """FR-BI-01: operational dashboard."""
    by_status = dict(db.execute(select(Order.status, func.count(Order.id)).where(Order.is_deleted.is_(False))
                                .group_by(Order.status)).all())
    total_orders = db.execute(select(func.count(Order.id)).where(Order.status != flow.DRAFT)).scalar_one()
    with_bids = db.execute(select(func.count(func.distinct(Bid.order_id)))).scalar_one()
    deals = db.execute(select(func.count(Deal.id))).scalar_one()
    from app.modules.platform.models import AntifraudAlert
    from app.modules.fleet.models import VerificationRequest

    return {
        "by_status": by_status,
        "funnel": {"orders": total_orders, "with_bids": with_bids, "deals": deals,
                   "conv_bid": round(with_bids * 100 / total_orders, 1) if total_orders else 0,
                   "conv_deal": round(deals * 100 / total_orders, 1) if total_orders else 0},
        "processing": processing_times(db),
        "open_alerts": db.execute(select(func.count(AntifraudAlert.id)).where(AntifraudAlert.status == "open")).scalar_one(),
        "moderation_queue": db.execute(select(func.count(VerificationRequest.id))
                                       .where(VerificationRequest.status == "pending")).scalar_one(),
        "disputes": by_status.get(flow.DISPUTE, 0),
        "revenue_minor": db.execute(select(func.coalesce(func.sum(Accrual.amount_minor), 0))).scalar_one(),
    }


def client_analytics(db: Session, company_id) -> dict:
    """FR-BI-03."""
    rows = db.execute(select(Deal, Order).join(Order, Order.id == Deal.order_id)
                      .where(Deal.client_company_id == company_id)).all()
    spend = sum(deal_kzt(d) or 0 for d, o in rows)  # FR-LOC-04: tenge at the deal's own rate
    km = sum(o.distance_km for _, o in rows)
    directions: dict[str, int] = {}
    carriers: dict = {}
    on_time = late = 0
    for d, o in rows:
        key = f"{o.origin.city if o.origin else '?'} → {o.destination.city if o.destination else '?'}"
        directions[key] = directions.get(key, 0) + 1
        carriers[d.carrier_company_id] = carriers.get(d.carrier_company_id, 0) + 1
        unl = db.execute(select(StatusHistory.created_at).where(StatusHistory.order_id == o.id,
                                                                StatusHistory.to_status == flow.UNLOADED)).scalar()
        if unl and o.unload_to:
            if unl <= o.unload_to:
                on_time += 1
            else:
                late += 1
    names = {c.id: c.name for c in db.execute(select(Company).where(Company.id.in_(list(carriers) or [None]))).scalars()}
    return {"deals": len(rows), "spend_minor": spend, "km": km,
            "cost_per_km_minor": int(spend / km) if km else 0,
            "directions": sorted(directions.items(), key=lambda x: -x[1])[:10],
            "carriers": sorted(((names.get(k, "?"), v) for k, v in carriers.items()), key=lambda x: -x[1])[:10],
            "on_time": on_time, "late": late}


def carrier_analytics(db: Session, company_id) -> dict:
    """FR-BI-04."""
    rows = db.execute(select(Deal, Order).join(Order, Order.id == Deal.order_id)
                      .where(Deal.carrier_company_id == company_id)).all()
    income = sum(deal_kzt(d) or 0 for d, _ in rows)  # FR-LOC-04
    directions: dict[str, int] = {}
    for d, o in rows:
        key = f"{o.origin.city if o.origin else '?'} → {o.destination.city if o.destination else '?'}"
        directions[key] = directions.get(key, 0) + (deal_kzt(d) or 0)
    avg = db.execute(select(func.avg(Rating.score)).where(Rating.to_company_id == company_id)).scalar_one()
    bids_total = db.execute(select(func.count(Bid.id)).where(Bid.carrier_company_id == company_id)).scalar_one()
    rejected = db.execute(select(func.count(Bid.id)).where(Bid.carrier_company_id == company_id,
                                                           Bid.status == "rejected")).scalar_one()
    return {"deals": len(rows), "income_minor": income, "rating": round(float(avg), 2) if avg else None,
            "directions": sorted(directions.items(), key=lambda x: -x[1])[:10], "bids": bids_total,
            "bids_rejected": rejected, "win_rate": round(len(rows) * 100 / bids_total, 1) if bids_total else 0}


def to_csv(rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    for r in rows:
        w.writerow(safe_row(r))
    return ("﻿" + buf.getvalue()).encode("utf-8")


def to_xlsx(rows: list[list], title: str = "Отчет") -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = title[:30]
    for r in rows:
        ws.append(safe_row(r))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
