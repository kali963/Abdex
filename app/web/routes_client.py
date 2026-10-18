"""Client (shipper) cabinet: orders, bids comparison, acceptance, shipment plan, carrier pool."""
from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import local_today
from app.core.errors import NotFound, ValidationFailed
from app.db import get_db
from app.modules.accounts.models import Company
from app.modules.bids import service as bids
from app.modules.bids.models import Bid
from app.modules.deals.models import Deal
from app.modules.fleet.service import company_stats
from app.modules.orders import flow
from app.modules.orders import service as orders
from app.modules.orders.models import Order, OrderTemplate, OrderVersion, PoolMember
from app.modules.platform.service import dictionary, localized_setting
from app.web.deps import Principal, csrf_protect, parse_uuid, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


def _form_ctx(db: Session) -> dict:
    return {"body_types": dictionary(db, "body_types"), "cargo_types": dictionary(db, "cargo_types"),
            "adr_classes": dictionary(db, "adr_classes"), "currencies": dictionary(db, "currencies"),
            "crossings": dictionary(db, "border_crossings"), "countries": dictionary(db, "countries")}


async def _form_dict(request: Request) -> dict:
    form = await request.form()
    data: dict = {}
    for key in form.keys():
        values = form.getlist(key)
        data[key] = values if key.startswith("point_") else values[-1]
    return data


@router.get("/orders")
def orders_list(request: Request, status: str = "", q: str = "", db: Session = Depends(get_db),
                me: Principal = Depends(require("order.view"))):
    items = orders.client_orders(db, me.company.id, status=status or None, q=q.strip(), limit=200)
    return render(request, "client/orders.html", {"items": items, "status": status, "q": q,
                                                  "statuses": flow.ALL_STATUSES})


@router.get("/orders/new")
def order_new(request: Request, template: str = "", db: Session = Depends(get_db),
              me: Principal = Depends(require("order.create"))):
    form: dict = {"payment_terms": "on_unload", "currency": "KZT", "vat_included": "on",
                  "point_city": ["", ""], "point_kind": ["load", "unload"]}
    if template:
        tpl = db.get(OrderTemplate, parse_uuid(template))
        if tpl is None or tpl.company_id != me.company.id:
            raise NotFound()
        form = json.loads(tpl.data)
    templates_ = list(db.execute(select(OrderTemplate).where(OrderTemplate.company_id == me.company.id)).scalars())
    from app.modules.analytics.product import track

    track(db, "order_form_view")
    db.commit()
    return render(request, "client/order_form.html", {**_form_ctx(db), "form": form, "templates": templates_,
                                                      "role_text": localized_setting(db, "platform.role_explanation")})


@router.post("/orders/new")
async def order_create(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    data = await _form_dict(request)
    preliminary = data.get("action") == "preliminary"
    # NFR-FE-07: a repeated submission (same form token) never creates a duplicate order
    from app.modules.platform.service import idempotent_lookup, idempotent_store

    key = str(data.get("form_token", ""))[:80]
    prev = idempotent_lookup(db, me.user.id, key, "order.create")
    if prev:
        return redirect(f"/orders/{prev}")
    try:
        order = orders.create_order(db, db.get(Company, me.company.id), data, preliminary=preliminary)
        idempotent_store(db, me.user.id, key, "order.create", str(order.id))
        if data.get("action") == "publish":
            orders.submit(db, order)
            orders.notify_saved_searches(db, order) if order.status == flow.PUBLISHED else None
    except ValidationFailed as exc:
        db.rollback()
        return render(request, "client/order_form.html", {**_form_ctx(db), "form": data, "errors": exc.fields,
                                                          "role_text": localized_setting(db, "platform.role_explanation")},
                      status_code=422)
    db.commit()
    return redirect(f"/orders/{order.id}", flash=("success", "msg.order_saved"))


@router.get("/orders/import")
def import_page(request: Request, me: Principal = Depends(require("order.create"))):
    from app.modules.orders.importer import COLUMNS, MAX_ROWS, REQUIRED

    return render(request, "client/import.html", {"columns": COLUMNS, "required": REQUIRED, "max_rows": MAX_ROWS})


@router.get("/orders/import/template.xlsx")
def import_template(me: Principal = Depends(require("order.create"))):
    from fastapi.responses import Response

    from app.modules.orders.importer import template_xlsx

    return Response(template_xlsx(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="abdex-orders-template.xlsx"'})


@router.post("/orders/import")
async def import_run(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    """FR-ORD-06: all rows validated first; any error -> nothing is created, report by row."""
    from app.core.audit import audit
    from app.modules.orders.importer import COLUMNS, MAX_ROWS, REQUIRED, import_orders

    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise ValidationFailed({"file": "error.required"})
    result = import_orders(db, db.get(Company, me.company.id), upload.filename or "", await upload.read())
    ctx = {"columns": COLUMNS, "required": REQUIRED, "max_rows": MAX_ROWS, "result": result}
    if result.errors:
        db.rollback()
        return render(request, "client/import.html", ctx, status_code=422)
    audit(db, "order.imported", object_type="company", object_id=me.company.id, details={"count": len(result.created)})
    db.commit()
    return render(request, "client/import.html", ctx)


@router.get("/orders/{oid}")
def order_view(oid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.view"))):
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    bid_rows = []
    for b in bids.order_bids(db, order.id):
        carrier = db.get(Company, b.carrier_company_id)
        bid_rows.append({"bid": b, "carrier": carrier, "stats": company_stats(db, carrier.id),
                         "history_with_me": bids.carrier_history_with(db, carrier.id, me.company.id),
                         "events": bids.bid_history(db, b.id)})
    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    versions = list(db.execute(select(OrderVersion).where(OrderVersion.order_id == order.id)
                               .order_by(OrderVersion.version)).scalars())
    from app.modules.bids import matching
    from app.modules.deals.service import history

    open_for_bids = order.status in flow.OPEN_FOR_BIDS
    matches = matching.rank(db, order, limit=8) if open_for_bids else []
    bidders = {row["carrier"].id for row in bid_rows}
    return render(request, "client/order_view.html", {
        "order": order, "bids": bid_rows, "deal": deal, "versions": versions, "history": history(db, order.id),
        "matches": [m for m in matches if m.company.id not in bidders],
        "invited": matching.invited_ids(db, order.id) if open_for_bids else set(),
        "today": local_today(),
        "can_edit": order.status in (flow.DRAFT, flow.PUBLISHED, flow.BIDDING),
        "can_cancel": flow.can(order.status, flow.CANCELLED, flow.CLIENT),
        "can_submit": order.status == flow.DRAFT, "role_text": localized_setting(db, "platform.role_explanation"),
        "body_types": {i.code: i.name_ru for i in dictionary(db, "body_types")}})


@router.get("/orders/{oid}/edit")
def order_edit(oid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    return render(request, "client/order_form.html", {**_form_ctx(db), "form": orders.order_as_form(order),
                                                      "order": order})


@router.post("/orders/{oid}/edit")
async def order_update(oid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("order.create"))):
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    data = await _form_dict(request)
    try:
        orders.update_order(db, order, data, note=str(data.get("change_note", "")))
        if data.get("action") == "publish" and order.status == flow.DRAFT:
            orders.submit(db, order)
    except ValidationFailed as exc:
        db.rollback()
        return render(request, "client/order_form.html", {**_form_ctx(db), "form": data, "errors": exc.fields,
                                                          "order": order}, status_code=422)
    db.commit()
    return redirect(f"/orders/{order.id}", flash=("success", "msg.order_saved"))


@router.post("/orders/{oid}/submit")
def order_submit(oid: str, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    order = flow.lock_order(db, parse_uuid(oid))
    if order.client_company_id != me.company.id:
        raise NotFound()
    orders.submit(db, order)
    if order.status == flow.PUBLISHED:
        orders.notify_saved_searches(db, order)
    db.commit()
    key = "msg.order_published" if order.status == flow.PUBLISHED else "msg.order_on_moderation"
    return redirect(f"/orders/{order.id}", flash=("success", key))


@router.post("/orders/{oid}/cancel")
async def order_cancel(oid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("order.create"))):
    form = await request.form()
    order = flow.lock_order(db, parse_uuid(oid))
    if order.client_company_id != me.company.id:
        raise NotFound()
    orders.cancel(db, order, str(form.get("reason", "")))
    db.commit()
    return redirect(f"/orders/{order.id}", flash=("success", "msg.order_cancelled"))


@router.post("/orders/{oid}/template")
async def order_template(oid: str, request: Request, db: Session = Depends(get_db),
                         me: Principal = Depends(require("order.create"))):
    form = await request.form()
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    orders.save_template(db, me.company, order, str(form.get("name", "")))
    db.commit()
    return redirect(f"/orders/{order.id}", flash=("success", "msg.template_saved"))


@router.post("/orders/{oid}/repeat")
def order_repeat(oid: str, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    src = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    new = orders.repeat_order(db, db.get(Company, me.company.id), src)
    db.commit()
    return redirect(f"/orders/{new.id}/edit", flash=("info", "msg.order_repeated"))


def _bid_for_client(db: Session, me: Principal, bid_id) -> Bid:
    bid = db.get(Bid, parse_uuid(bid_id))
    if bid is None:
        raise NotFound()
    orders.get_for_client(db, bid.order_id, me.company.id)
    return bid


@router.post("/bids/{bid_id}/accept")
async def bid_accept(bid_id: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(require("bid.accept"))):
    form = await request.form()
    bid = _bid_for_client(db, me, bid_id)
    deal = bids.accept(db, bid.id, db.get(Company, me.company.id), idempotency_key=str(form.get("idem", "")))
    db.commit()
    return redirect(f"/deals/{deal.id}", flash=("success", "msg.bid_accepted"))


@router.post("/bids/{bid_id}/counter")
async def bid_counter(bid_id: str, request: Request, db: Session = Depends(get_db),
                      me: Principal = Depends(require("bid.accept"))):
    form = await request.form()
    bid = _bid_for_client(db, me, bid_id)
    bids.counter_offer(db, bid, str(form.get("counter_price", "")), str(form.get("comment", "")))
    db.commit()
    return redirect(f"/orders/{bid.order_id}", flash=("success", "msg.counter_sent"))


@router.post("/bids/{bid_id}/reject")
def bid_reject(bid_id: str, db: Session = Depends(get_db), me: Principal = Depends(require("bid.accept"))):
    bid = _bid_for_client(db, me, bid_id)
    if bid.status in bids.OPEN_BID:
        bid.status = "rejected"
        bids._event(db, bid, "rejected")
    db.commit()
    return redirect(f"/orders/{bid.order_id}")


@router.get("/plan")
def plan(request: Request, week: str = "", db: Session = Depends(get_db), me: Principal = Depends(require("plan.view"))):
    """FR-PLAN-01: calendar of planned and confirmed loadings by day."""
    try:
        start = date.fromisoformat(week) if week else local_today()
    except ValueError:
        start = local_today()
    start = start - timedelta(days=start.weekday())
    days = [start + timedelta(days=i) for i in range(14)]
    begin = datetime.combine(days[0], time.min, tzinfo=timezone.utc) - timedelta(hours=6)
    end = datetime.combine(days[-1], time.max, tzinfo=timezone.utc)
    if me.company.kind == "client":
        rows = list(db.execute(select(Order).where(Order.client_company_id == me.company.id,
                                                   Order.load_from >= begin, Order.load_from <= end,
                                                   Order.status != flow.CANCELLED)).scalars())
        prelim = list(db.execute(select(Order).where(Order.client_company_id == me.company.id,
                                                     Order.is_preliminary.is_(True),
                                                     Order.status == flow.DRAFT)).scalars())
    else:
        rows = [o for _, o in db.execute(select(Deal, Order).join(Order, Order.id == Deal.order_id)
                                         .where(Deal.carrier_company_id == me.company.id,
                                                Order.load_from >= begin, Order.load_from <= end)).all()]
        prelim = []
    from app.core.i18n import fmt_date

    by_day: dict[str, list] = {fmt_date(d): [] for d in days}
    for o in rows:
        key = fmt_date(o.load_from)
        if key in by_day:
            by_day[key].append(o)
    return render(request, "client/plan.html", {"days": days, "by_day": by_day, "prelim": prelim,
                                                "prev": (start - timedelta(days=7)).isoformat(),
                                                "next": (start + timedelta(days=7)).isoformat()})


@router.get("/pool")
def pool(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.view"))):
    """FR-BID-05 / FR-RAT-05: trusted and blocked counterparties."""
    rows = db.execute(select(PoolMember, Company).join(Company, Company.id == PoolMember.other_company_id)
                      .where(PoolMember.owner_company_id == me.company.id)).all()
    kind = "carrier" if me.company.kind == "client" else "client"
    candidates = list(db.execute(select(Company).where(Company.kind == kind, Company.verification_level >= 1)
                                 .order_by(Company.name).limit(200)).scalars())
    return render(request, "client/pool.html", {"rows": rows, "candidates": candidates})


@router.post("/pool")
async def pool_add(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    other = db.get(Company, parse_uuid(form.get("company_id")))
    if other is None:
        raise NotFound()
    existing = db.execute(select(PoolMember).where(PoolMember.owner_company_id == me.company.id,
                                                   PoolMember.other_company_id == other.id)).scalar_one_or_none()
    kind = "blocked" if form.get("kind") == "blocked" else "trusted"
    if existing:
        existing.kind = kind
    else:
        db.add(PoolMember(owner_company_id=me.company.id, other_company_id=other.id, kind=kind))
    db.commit()
    return redirect("/pool", flash=("success", "msg.saved"))


@router.post("/pool/{pid}/remove")
def pool_remove(pid: str, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    row = db.get(PoolMember, parse_uuid(pid))
    if row is None or row.owner_company_id != me.company.id:
        raise NotFound()
    db.delete(row)
    db.commit()
    return redirect("/pool")
