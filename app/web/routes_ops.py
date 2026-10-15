"""Cycle-2 cabinet features: rating, carrier matching invites, order series, vehicle occupancy, webhooks,
bulk document export, promo codes, support access and the end of a support session."""
from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.config import settings
from app.core import ratelimit
from app.core.audit import audit
from app.core.errors import NotFound
from app.core.i18n import translate
from app.db import get_db, utcnow
from app.modules.accounts import support_access
from app.modules.accounts.models import Company, User
from app.modules.bids import matching
from app.modules.billing import service as billing
from app.modules.documents import service as documents
from app.modules.fleet import schedule
from app.modules.orders import series as series_svc
from app.modules.orders import service as orders
from app.modules.orders.models import OrderSeries
from app.modules.rating import service as rating
from app.modules.webhooks import service as webhooks
from app.web.deps import SESSION_COOKIE, Principal, csrf_protect, get_principal, parse_uuid, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])
RETURN_COOKIE = "abdex_imp_return"


def _parse_day(raw: str | None, default: date) -> date:
    try:
        return date.fromisoformat(raw) if raw else default
    except ValueError:
        return default


# ------------------------------------------------------------------ rating (FR-RAT-01/02, FR-BID-08)


@router.get("/rating")
def rating_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    ctx = {"formula": rating.formula(db), "limit": rating.breakdown_limit(db), "weights": matching.weights(db)}
    if me.company is not None:
        ctx["r"] = rating.compute(db, me.company.id)
        ctx["events"] = rating.history(db, me.company.id, limit=50)
        ctx["breakdowns_window"] = rating.breakdowns(db, me.company.id, int(ctx["limit"]["days"]))
    return render(request, "cabinet/rating.html", ctx)


# ------------------------------------------------------------------ matching (FR-BID-04)


@router.post("/orders/{oid}/invite/{cid}")
def invite_carrier(oid: str, cid: str, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    carrier = db.get(Company, parse_uuid(cid))
    if carrier is None:
        raise NotFound()
    matching.invite(db, order, carrier)
    db.commit()
    return redirect(f"/orders/{order.id}", flash=("success", "match.invited_msg"))


# ------------------------------------------------------------------ order series (FR-ORD-05)


@router.get("/orders/series")
def series_list(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.view"))):
    items = series_svc.company_series(db, me.company.id)
    from app.modules.orders.models import Order

    sources = {s.id: db.get(Order, s.source_order_id) for s in items}
    return render(request, "client/series.html", {"items": items, "sources": sources,
                                                  "upcoming": {s.id: series_svc.upcoming_dates(s) for s in items}})


@router.post("/orders/{oid}/series")
async def series_create(oid: str, request: Request, db: Session = Depends(get_db),
                        me: Principal = Depends(require("order.create"))):
    order = orders.get_for_client(db, parse_uuid(oid), me.company.id)
    series_svc.create_series(db, me.company, order, await request.form())
    db.commit()
    return redirect("/orders/series", flash=("success", "series.created"))


@router.post("/orders/series/{sid}/{action}")
def series_action(sid: str, action: str, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    s = db.get(OrderSeries, parse_uuid(sid))
    if s is None or s.company_id != me.company.id or s.is_deleted or action not in ("pause", "resume", "delete"):
        raise NotFound()
    if action == "delete":
        s.is_deleted, s.active = True, False
    else:
        s.active = action == "resume"
    audit(db, f"order.series_{action}", object_type="order_series", object_id=s.id)
    db.commit()
    return redirect("/orders/series", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ vehicle occupancy (FR-PLAN-04)


@router.get("/fleet/schedule")
def fleet_schedule(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("fleet.manage"))):
    start = _parse_day(request.query_params.get("from"), utcnow().date())
    data = schedule.board(db, me.company.id, start, days=14)
    return render(request, "carrier/schedule.html", {"b": data, "start": start,
                                                     "prev": start - timedelta(days=14), "next": start + timedelta(days=14)})


# ------------------------------------------------------------------ webhooks (FR-API-03)


@router.get("/company/webhooks")
def webhooks_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    eps = webhooks.endpoints(db, me.company.id)
    resp = render(request, "company/webhooks.html", {
        "endpoints": eps, "log": {e.id: webhooks.deliveries(db, e.id, limit=10) for e in eps},
        "events": webhooks.EVENTS, "new_secret": request.cookies.get("abdex_wh_secret")})
    resp.delete_cookie("abdex_wh_secret", path="/company/webhooks")
    return resp


@router.post("/company/webhooks")
async def webhooks_create(request: Request, db: Session = Depends(get_db),
                          me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    _, secret = webhooks.create_endpoint(db, me.company.id, str(form.get("url", "")), form.getlist("events"))
    db.commit()
    resp = redirect("/company/webhooks", flash=("success", "webhook.created"))
    # the signing secret is shown exactly once, right after creation
    resp.set_cookie("abdex_wh_secret", secret, max_age=60, httponly=True, secure=settings.secure_cookies,
                    samesite="strict", path="/company/webhooks")
    return resp


@router.post("/company/webhooks/{wid}/{action}")
def webhooks_action(wid: str, action: str, db: Session = Depends(get_db),
                    me: Principal = Depends(require("company.manage"))):
    ep = webhooks.get_endpoint(db, me.company.id, parse_uuid(wid))
    if action == "delete":
        webhooks.delete_endpoint(db, ep)
    elif action == "test":
        ratelimit.hit("webhook_test", str(me.company.id))
        webhooks.send_test(db, ep)
    elif action == "enable":
        ep.active, ep.failures_in_row = True, 0
    else:
        raise NotFound()
    db.commit()
    return redirect("/company/webhooks", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ bulk documents (FR-DOC-09)


@router.get("/documents/export.zip")
def documents_export(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("export.bulk"))):
    today = utcnow().date()
    date_from = _parse_day(request.query_params.get("date_from"), today.replace(day=1))
    date_to = _parse_day(request.query_params.get("date_to"), today)
    ratelimit.hit("export", str(me.user.id))
    labels = {k: translate(f"zip.{k}") for k in ("deal", "type", "number", "status", "date", "file")}
    labels["title"] = translate("zip.title_col")
    for t in ("contract_order", "fee_invoice", "fee_act", "reconciliation_act", "transport_request", *documents.UPLOAD_DOC_TYPES):
        labels[f"doc.{t}"] = translate(f"doc.{t}")
    for st in ("required", "uploaded", "checked", "signed", "rejected"):
        labels[f"st.{st}"] = translate(f"status.{st}")
    data = documents.period_zip(db, me.company.id, date_from, date_to, labels)
    audit(db, "export.documents_zip", object_type="company", object_id=me.company.id,
          details={"from": date_from.isoformat(), "to": date_to.isoformat()})
    db.commit()
    name = f"abdex-documents-{date_from:%Y%m%d}-{date_to:%Y%m%d}.zip"
    return Response(data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ------------------------------------------------------------------ promo codes (FR-BIL-09)


@router.post("/finance/promo")
async def promo_redeem(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("finance.view"))):
    form = await request.form()
    ratelimit.hit("otp_check", f"promo:{me.company.id}")  # guessing codes is throttled like OTP checks
    billing.redeem_promo(db, me.company, str(form.get("code", "")))
    db.commit()
    return redirect("/finance", flash=("success", "promo.applied"))


# ------------------------------------------------------------------ support access (FR-ADM-05)


@router.post("/account/support-access")
async def support_grant(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    try:
        hours = int(form.get("hours") or 24)
    except ValueError:
        hours = 0
    support_access.grant(db, db.get(User, me.user.id), hours, str(form.get("ticket", "")))
    db.commit()
    return redirect("/account/security", flash=("success", "support.granted"))


@router.post("/account/support-access/revoke")
def support_revoke(db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    support_access.revoke_grants(db, db.get(User, me.user.id))
    db.commit()
    return redirect("/account/security", flash=("success", "support.revoked"))


@router.post("/impersonation/end")
def impersonation_end(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    if not me.session.impersonator_id:
        raise NotFound()
    from app.modules.accounts.models import UserSession

    support_access.end(db, db.get(UserSession, me.session.id))
    db.commit()
    back = request.cookies.get(RETURN_COOKIE)
    resp = redirect("/admin/users" if back else "/login")
    if back:
        resp.set_cookie(SESSION_COOKIE, back, httponly=True, secure=settings.secure_cookies, samesite="lax",
                        max_age=settings.session_absolute_days * 86400, path="/")
    else:
        resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(RETURN_COOKIE, path="/")
    return resp
