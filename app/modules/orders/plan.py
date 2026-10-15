"""Shipment plan for a period: upload from a file and plan / fact / deviation (FR-PLAN-03).

A plan line is a direction (from city → to city) with the planned number of trips and tonnage.
Fact is computed from the company's orders in the period that reached a deal (assigned or later):
plans never store fact numbers, so nobody can edit them by hand.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import date, datetime, time, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, NotFound, ValidationFailed
from app.modules.accounts.models import Company
from app.modules.orders import flow
from app.modules.orders.importer import read_rows
from app.modules.orders.models import Order, ShipmentPlan, ShipmentPlanLine

COLUMNS = ("from_city", "to_city", "trips", "weight_kg")
MAX_LINES = 300
FACT_STATUSES = flow.DEAL_STATUSES  # a deal exists: assigned or later (dispute included)


@dataclass
class LineResult:
    line: ShipmentPlanLine
    fact_trips: int
    fact_weight: int

    @property
    def deviation(self) -> int:
        return self.fact_trips - self.line.trips

    @property
    def percent(self) -> int:
        return round(self.fact_trips * 100 / self.line.trips) if self.line.trips else 0


def _int(value) -> int:
    text = str(value if value is not None else "").replace(" ", "").replace(",", ".")
    if not text:
        return 0
    n = float(text)
    if n < 0 or n > 10_000_000:
        raise ValueError
    return int(round(n))


def upload(db: Session, company: Company, *, name: str, period_from: date | None, period_to: date | None,
           filename: str, data: bytes) -> tuple[ShipmentPlan | None, list[tuple[int, str, str]]]:
    """All or nothing, like the order import: returns (plan, []) or (None, errors by row and column)."""
    errors = {}
    if period_from is None:
        errors["period_from"] = "error.date"
    if period_to is None or (period_from and period_to and period_to < period_from):
        errors["period_to"] = "error.date_order"
    if errors:
        raise ValidationFailed(errors)
    rows = read_rows(filename, data)
    if not rows:
        raise AppError("import_empty")
    if len(rows) > MAX_LINES:
        raise AppError("import_too_many", limit=MAX_LINES)
    missing = [c for c in ("from_city", "to_city", "trips") if c not in rows[0]]
    if missing:
        raise AppError("import_missing_columns", columns=", ".join(missing))
    problems: list[tuple[int, str, str]] = []
    lines = []
    for i, row in enumerate(rows, start=2):
        frm, to = str(row.get("from_city") or "").strip(), str(row.get("to_city") or "").strip()
        if not frm:
            problems.append((i, "from_city", "error.required"))
        if not to:
            problems.append((i, "to_city", "error.required"))
        try:
            trips = _int(row.get("trips"))
            if trips <= 0:
                raise ValueError
        except ValueError:
            problems.append((i, "trips", "error.number"))
            trips = 0
        try:
            weight = _int(row.get("weight_kg"))
        except ValueError:
            problems.append((i, "weight_kg", "error.number"))
            weight = 0
        lines.append((frm[:100], to[:100], trips, weight))
    if problems:
        return None, problems
    plan = ShipmentPlan(company_id=company.id, name=(name or "").strip()[:200] or f"{period_from:%m.%Y}",
                        period_from=period_from, period_to=period_to, created_by=get_ctx().user_id)
    db.add(plan)
    db.flush()
    for frm, to, trips, weight in lines:
        db.add(ShipmentPlanLine(plan_id=plan.id, from_city=frm, to_city=to, trips=trips, weight_kg=weight))
    db.flush()
    audit(db, "plan.uploaded", object_type="shipment_plan", object_id=plan.id, details={"lines": len(lines)})
    return plan, []


def company_plans(db: Session, company_id) -> list[ShipmentPlan]:
    return list(db.execute(select(ShipmentPlan).where(ShipmentPlan.company_id == company_id,
                                                      ShipmentPlan.is_deleted.is_(False))
                           .order_by(ShipmentPlan.period_from.desc())).scalars())


def get_plan(db: Session, company_id, plan_id) -> ShipmentPlan:
    plan = db.get(ShipmentPlan, plan_id)
    if plan is None or plan.company_id != company_id or plan.is_deleted:
        raise NotFound()
    return plan


def plan_vs_fact(db: Session, plan: ShipmentPlan) -> dict:
    start = datetime.combine(plan.period_from, time.min, tzinfo=timezone.utc)
    end = datetime.combine(plan.period_to, time.max, tzinfo=timezone.utc)
    orders = db.execute(select(Order).where(Order.client_company_id == plan.company_id, Order.load_from >= start,
                                            Order.load_from <= end, Order.status.in_(FACT_STATUSES))).scalars().all()
    fact: dict[tuple[str, str], list[int]] = {}
    for o in orders:
        key = ((o.origin.city if o.origin else "").strip().lower(), (o.destination.city if o.destination else "").strip().lower())
        f = fact.setdefault(key, [0, 0])
        f[0] += 1
        f[1] += o.weight_kg or 0
    lines = list(db.execute(select(ShipmentPlanLine).where(ShipmentPlanLine.plan_id == plan.id)
                            .order_by(ShipmentPlanLine.from_city, ShipmentPlanLine.to_city)).scalars())
    results = []
    planned_keys = set()
    for ln in lines:
        key = (ln.from_city.strip().lower(), ln.to_city.strip().lower())
        planned_keys.add(key)
        trips, weight = fact.get(key, [0, 0])
        results.append(LineResult(ln, trips, weight))
    unplanned = [(k, v) for k, v in fact.items() if k not in planned_keys]
    total_plan = sum(r.line.trips for r in results)
    total_fact = sum(r.fact_trips for r in results)
    return {"lines": results, "unplanned": unplanned, "total_plan": total_plan, "total_fact": total_fact,
            "total_deviation": total_fact - total_plan,
            "percent": round(total_fact * 100 / total_plan) if total_plan else 0}


def template_xlsx() -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "plan"
    ws.append(list(COLUMNS))
    ws.append(["Алматы", "Астана", 12, 240000])
    ws.append(["Алматы", "Шымкент", 8, 150000])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
