"""Carrier cabinet: marketplace, bids, fleet (vehicles & drivers), saved searches."""
from __future__ import annotations

import json
from datetime import date

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.db import get_db
from app.modules.accounts.models import Company
from app.modules.bids import service as bids
from app.modules.bids.models import Bid
from app.modules.fleet import service as fleet
from app.modules.fleet.models import Driver, Vehicle
from app.modules.orders import service as orders
from app.modules.orders.models import Order, SavedSearch
from app.modules.platform.service import dictionary, dictionary_map, localized_setting
from app.web.deps import Principal, csrf_protect, parse_uuid, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])

FILTER_KEYS = ("from_city", "to_city", "body_type", "max_weight", "min_rate", "date_from", "date_to")


@router.get("/market")
def market(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("market.view"))):
    filters = {k: request.query_params.get(k, "").strip() for k in FILTER_KEYS}
    items = orders.marketplace(db, me.company, filters, limit=100)
    my_bids = {b.order_id: b for b in db.execute(select(Bid).where(Bid.carrier_company_id == me.company.id,
                                                                   Bid.order_id.in_([o.id for o in items] or [None])))
               .scalars()}
    saved = list(db.execute(select(SavedSearch).where(SavedSearch.company_id == me.company.id)).scalars())
    return render(request, "carrier/market.html", {"items": items, "filters": filters, "my_bids": my_bids,
                                                   "saved": saved, "body_types": dictionary(db, "body_types"),
                                                   "body_map": dictionary_map(db, "body_types")})


@router.post("/market/saved")
async def save_search(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("market.view"))):
    form = await request.form()
    filters = {k: str(form.get(k, "")).strip() for k in FILTER_KEYS if form.get(k)}
    db.add(SavedSearch(company_id=me.company.id, user_id=me.user.id,
                       name=str(form.get("name", "")).strip()[:100] or "Фильтр", filters=json.dumps(filters),
                       notify=True))
    db.commit()
    return redirect("/market", flash=("success", "msg.search_saved"))


@router.post("/market/saved/{sid}/delete")
def delete_search(sid: str, db: Session = Depends(get_db), me: Principal = Depends(require("market.view"))):
    s = db.get(SavedSearch, parse_uuid(sid))
    if s is None or s.company_id != me.company.id:
        raise NotFound()
    db.delete(s)
    db.commit()
    return redirect("/market")


@router.get("/market/{oid}")
def market_order(oid: str, request: Request, db: Session = Depends(get_db),
                 me: Principal = Depends(require("market.view"))):
    """FR-ACL-02: limited card before acceptance — route by city, cargo type, vehicle
    requirements and date window. Client contacts and exact addresses are not sent at all."""
    order = db.get(Order, parse_uuid(oid))
    if order is None:
        raise NotFound()
    my_bid = db.execute(select(Bid).where(Bid.order_id == order.id, Bid.carrier_company_id == me.company.id)
                        ).scalar_one_or_none()
    if not orders.carrier_can_see(db, order, me.company) and my_bid is None:
        raise NotFound()
    client = db.get(Company, order.client_company_id)
    from app.modules.platform.antifraud import track

    track(db, "card_view", company_id=me.company.id)  # SEC-APP-07: mass viewing of order cards
    from app.modules.analytics.product import track as product_event

    product_event(db, "market_card_view")
    db.commit()
    return render(request, "carrier/market_order.html", {
        "order": order, "my_bid": my_bid, "events": bids.bid_history(db, my_bid.id) if my_bid else [],
        "client_stats": fleet.company_stats(db, client.id), "client_level": client.verification_level,
        "vehicles": fleet.company_vehicles(db, me.company.id), "drivers": fleet.company_drivers(db, me.company.id),
        "body_map": dictionary_map(db, "body_types"), "cargo_map": dictionary_map(db, "cargo_types"),
        "role_text": localized_setting(db, "platform.role_explanation")})


@router.post("/market/{oid}/bid")
async def place_bid(oid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("bid.create"))):
    form = dict((await request.form()).items())
    try:
        bids.place_bid(db, parse_uuid(oid), db.get(Company, me.company.id), form)
    except ValidationFailed as exc:
        db.rollback()
        order = db.get(Order, parse_uuid(oid))
        client = db.get(Company, order.client_company_id)
        return render(request, "carrier/market_order.html", {
            "order": order, "my_bid": None, "events": [], "errors": exc.fields, "form": form,
            "client_stats": fleet.company_stats(db, client.id), "client_level": client.verification_level,
            "vehicles": fleet.company_vehicles(db, me.company.id), "drivers": fleet.company_drivers(db, me.company.id),
            "body_map": dictionary_map(db, "body_types"), "cargo_map": dictionary_map(db, "cargo_types"),
            "role_text": localized_setting(db, "platform.role_explanation")}, status_code=422)
    db.commit()
    return redirect(f"/market/{oid}", flash=("success", "msg.bid_sent"))


def _my_bid(db: Session, me: Principal, bid_id) -> Bid:
    bid = db.get(Bid, parse_uuid(bid_id))
    if bid is None or bid.carrier_company_id != me.company.id:
        raise NotFound()
    return bid


@router.post("/my-bids/{bid_id}/withdraw")
def withdraw(bid_id: str, db: Session = Depends(get_db), me: Principal = Depends(require("bid.create"))):
    bid = _my_bid(db, me, bid_id)
    bids.withdraw(db, bid)
    db.commit()
    return redirect(f"/market/{bid.order_id}", flash=("success", "msg.saved"))


@router.post("/my-bids/{bid_id}/counter")
async def counter_reply(bid_id: str, request: Request, db: Session = Depends(get_db),
                        me: Principal = Depends(require("bid.create"))):
    form = await request.form()
    bid = _my_bid(db, me, bid_id)
    bids.respond_counter(db, bid, accept=form.get("accept") == "1")
    db.commit()
    return redirect(f"/market/{bid.order_id}", flash=("success", "msg.saved"))


@router.post("/my-bids/{bid_id}/confirm")
def confirm_version(bid_id: str, db: Session = Depends(get_db), me: Principal = Depends(require("bid.create"))):
    bid = _my_bid(db, me, bid_id)
    bids.confirm_actual(db, bid)
    db.commit()
    return redirect(f"/market/{bid.order_id}", flash=("success", "msg.saved"))


@router.get("/my-bids")
def my_bids(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("bid.create"))):
    rows = db.execute(select(Bid, Order).join(Order, Order.id == Bid.order_id)
                      .where(Bid.carrier_company_id == me.company.id).order_by(Bid.created_at.desc()).limit(200)).all()
    return render(request, "carrier/my_bids.html", {"rows": rows})


# ------------------------------------------------------------------ fleet


def _parse_date(raw) -> date | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(str(raw))
    except ValueError:
        raise ValidationFailed({"date": "error.date"})


@router.get("/fleet")
def fleet_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("fleet.manage"))):
    return render(request, "carrier/fleet.html", {"vehicles": fleet.company_vehicles(db, me.company.id),
                                                  "drivers": fleet.company_drivers(db, me.company.id),
                                                  "body_types": dictionary(db, "body_types"),
                                                  "body_map": dictionary_map(db, "body_types")})


@router.post("/fleet/vehicles")
async def add_vehicle(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("fleet.manage"))):
    form = dict((await request.form()).items())
    form["insurance_until"] = _parse_date(form.get("insurance_until"))
    for k in ("capacity_kg", "volume_m3"):
        try:
            form[k] = int(form.get(k) or 0)
        except ValueError:
            raise ValidationFailed({k: "error.number"})
    fleet.add_vehicle(db, me.company, **form)
    db.commit()
    return redirect("/fleet", flash=("success", "msg.saved"))


@router.post("/fleet/drivers")
async def add_driver(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("fleet.manage"))):
    form = dict((await request.form()).items())
    form["license_until"] = _parse_date(form.get("license_until"))
    fleet.add_driver(db, me.company, **form)
    db.commit()
    return redirect("/fleet", flash=("success", "msg.saved"))


@router.post("/fleet/{kind}/{oid}/delete")
def remove(kind: str, oid: str, db: Session = Depends(get_db), me: Principal = Depends(require("fleet.manage"))):
    model = {"vehicles": Vehicle, "drivers": Driver}.get(kind)
    if model is None:
        raise NotFound()
    obj = db.get(model, parse_uuid(oid))
    if obj is None or obj.company_id != me.company.id:
        raise NotFound()
    obj.is_deleted = True  # soft delete keeps history of past deals
    db.commit()
    return redirect("/fleet", flash=("success", "msg.saved"))
