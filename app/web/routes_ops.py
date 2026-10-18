"""Cycle-2 cabinet features: rating, carrier matching invites, order series, vehicle occupancy, webhooks,
bulk document export, promo codes, support access and the end of a support session."""
from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import local_today
from app.config import settings
from app.core import ratelimit
from app.core.audit import audit
from app.core.errors import NotFound, ValidationFailed
from app.core.i18n import translate
from app.db import get_db
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


def _parse_day(raw: str | None, default: date | None) -> date | None:
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
    start = _parse_day(request.query_params.get("from"), local_today())
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
    _, secret = webhooks.create_endpoint(db, me.company.id, str(form.get("url", "")), form.getlist("events"),
                                         sandbox=form.get("sandbox") == "on")
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
    today = local_today()
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


# ------------------------------------------------------------------ plan / fact (FR-PLAN-03)


@router.get("/plan/periods")
def plan_periods(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("plan.view"))):
    from app.modules.orders import plan as plans

    if me.company.kind != "client":
        raise NotFound()
    items = plans.company_plans(db, me.company.id)
    pid = request.query_params.get("id")
    current = plans.get_plan(db, me.company.id, parse_uuid(pid)) if pid else (items[0] if items else None)
    return render(request, "client/plan_fact.html", {
        "items": items, "current": current, "pf": plans.plan_vs_fact(db, current) if current else None,
        "columns": plans.COLUMNS, "today": local_today()})


@router.get("/plan/periods/template.xlsx")
def plan_template(me: Principal = Depends(require("plan.view"))):
    from app.modules.orders import plan as plans

    return Response(plans.template_xlsx(),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="abdex-plan-template.xlsx"'})


@router.post("/plan/periods")
async def plan_upload(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    from app.modules.orders import plan as plans

    form = await request.form()
    upload = form.get("file")
    if upload is None or not getattr(upload, "filename", ""):
        raise ValidationFailed({"file": "error.required"})
    ratelimit.hit("upload", str(me.user.id))
    data = await upload.read()  # the request size is capped by the middleware (413)
    plan, problems = plans.upload(db, me.company, name=str(form.get("name", "")),
                                  period_from=_parse_day(str(form.get("period_from", "")), None),
                                  period_to=_parse_day(str(form.get("period_to", "")), None),
                                  filename=upload.filename, data=data)
    if problems:
        db.rollback()
        items = plans.company_plans(db, me.company.id)
        return render(request, "client/plan_fact.html", {"items": items, "current": None, "pf": None,
                                                         "problems": problems, "columns": plans.COLUMNS,
                                                         "today": local_today()}, status_code=422)
    db.commit()
    return redirect(f"/plan/periods?id={plan.id}", flash=("success", "planf.uploaded"))


@router.post("/plan/periods/{pid}/delete")
def plan_delete(pid: str, db: Session = Depends(get_db), me: Principal = Depends(require("order.create"))):
    from app.modules.orders import plan as plans

    p = plans.get_plan(db, me.company.id, parse_uuid(pid))
    p.is_deleted = True
    audit(db, "plan.deleted", object_type="shipment_plan", object_id=p.id)
    db.commit()
    return redirect("/plan/periods", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ driver biometrics (FR-KYC-08, SEC-DAT-10)


@router.get("/trips/biometrics")
def biometrics_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("trip.execute"))):
    from app.modules.accounts.service import has_consent
    from app.modules.fleet import biometrics

    driver = biometrics.driver_of(db, me.user)
    return render(request, "deals/biometrics.html", {"check": biometrics.latest(db, driver.id), "driver": driver,
                                                     "consent": has_consent(db, me.user.id, "biometrics")})


@router.post("/trips/biometrics")
async def biometrics_run(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("trip.execute"))):
    from app.modules.fleet import biometrics

    form = await request.form()
    ratelimit.hit("upload", str(me.user.id))
    data = {}
    for name in ("selfie", "selfie2", "document"):
        f = form.get(name)
        data[name] = await f.read() if f is not None and getattr(f, "filename", "") else b""
    check = biometrics.run_check(db, db.get(User, me.user.id), **data)
    db.commit()
    return redirect("/trips/biometrics", flash=("success" if check.status == "passed" else "error", f"bio.{check.status}"))


# ------------------------------------------------------------------ development signer (never in production)


@router.post("/dev/eds/certificate")
async def dev_eds_certificate(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("deal.sign"))):
    """Issues a TEST certificate for a public key generated in the browser (the private key stays there)."""
    from fastapi.responses import JSONResponse

    from app.modules.documents import eds

    if not eds.is_dev_signer():
        raise NotFound()
    form = await request.form()
    ratelimit.hit("otp_send", f"devcert:{me.user.id}")
    iin = me.company.bin_iin if me.company.legal_form == "ИП" else "000000000000"
    try:
        pem = eds.dev_issue(str(form.get("public_key", "")), full_name=me.user.full_name, iin=iin,
                            bin_iin=me.company.bin_iin)
    except ValueError:
        raise ValidationFailed({"public_key": "error.invalid_value"})
    audit(db, "eds.dev_certificate_issued", object_type="user", object_id=me.user.id)
    db.commit()
    return JSONResponse({"certificate": pem})


# ------------------------------------------------------------------ online payment (FR-BIL-06)


@router.post("/finance/invoices/{iid}/pay")
def invoice_pay(iid: str, db: Session = Depends(get_db), me: Principal = Depends(require("finance.view"))):
    from app.modules.billing import payments
    from app.modules.billing.models import Invoice

    invoice = db.get(Invoice, parse_uuid(iid))
    if invoice is None:
        raise NotFound()
    ratelimit.hit("export", f"pay:{me.company.id}")
    intent = payments.start(db, invoice, me.company.id)
    db.commit()
    return redirect(intent.checkout_url, status_code=303)


@router.api_route("/dev/pay/{ref}", methods=["GET", "POST"])
async def dev_checkout(ref: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """Simulated hosted checkout of the payment provider (development only, no card fields at all)."""
    from app.modules.billing import payments
    from app.modules.billing.models import PaymentIntent

    if settings.payment_provider_url or settings.is_production:
        raise NotFound()
    intent = db.execute(select(PaymentIntent).where(PaymentIntent.provider_ref == ref)).scalar_one_or_none()
    if intent is None or (me.company is None or intent.company_id != me.company.id):
        raise NotFound()
    if request.method == "POST":
        form = await request.form()
        result = payments.simulate(db, ref, succeed=form.get("decision") == "pay")
        db.commit()
        return redirect(f"/finance?payment={intent.id}", flash=("success" if result == "ok" else "error", f"pay.{result}"))
    return render(request, "finance/dev_checkout.html", {"intent": intent})


# ------------------------------------------------------------------ accounting export (FR-BIL-07)


def _acc_labels() -> dict:
    labels = {k: translate(f"acc.col.{k}") for k in ("date", "invoice", "deal", "buyer", "bin", "amount", "currency",
                                                       "status", "paid", "due")}
    labels.update({f"st.{s}": translate(f"status.{s}") for s in ("issued", "paid", "cancelled")})
    return labels


@router.get("/finance/export.xlsx")
def finance_export(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("finance.view"))):
    from app.modules.billing import accounting

    today = local_today()
    d1 = _parse_day(request.query_params.get("date_from"), today.replace(day=1))
    d2 = _parse_day(request.query_params.get("date_to"), today)
    ratelimit.hit("export", str(me.user.id))
    data = accounting.register_xlsx(accounting.rows(db, d1, d2, company_id=me.company.id), _acc_labels())
    audit(db, "export.accounting", object_type="company", object_id=me.company.id,
          details={"from": d1.isoformat(), "to": d2.isoformat()})
    db.commit()
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="abdex-invoices-{d1:%Y%m%d}-{d2:%Y%m%d}.xlsx"'})
