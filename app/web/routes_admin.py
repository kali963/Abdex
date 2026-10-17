"""Platform staff interface (FR-ACL-04): separate surface, mandatory 2FA in production,
every sensitive view/action audited (FR-ACL-05, FR-ADM-04)."""
from __future__ import annotations

import json
from datetime import date, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import ratelimit
from app.core.audit import audit
from app.core.errors import NotFound, ValidationFailed
from app.core.money import to_minor
from app.db import get_db, utcnow
from app.modules.accounts.models import AuditLog, Company, Membership, User
from app.modules.analytics import service as analytics
from app.modules.billing import service as billing
from app.modules.billing.models import Accrual, Invoice, Tariff
from app.modules.chat import service as chat
from app.modules.deals import service as deals
from app.modules.deals.models import Deal, Dispute
from app.modules.documents import service as documents
from app.modules.documents.models import DocumentTemplate
from app.modules.fleet import service as fleet
from app.modules.fleet.biometrics import latest as biometrics_latest
from app.modules.fleet.models import VerificationDocument, VerificationRequest
from app.modules.notifications.models import OutboxMessage
from app.modules.orders import flow
from app.modules.orders.models import Order
from app.modules.platform.models import (
    AntifraudAlert,
    DictionaryItem,
    FeatureFlag,
    IntegrationCall,
    KpiSnapshot,
    PlatformSetting,
    Restriction,
    Ticket,
)
from app.modules.platform.service import dictionary, dictionary_map, update_dictionary_item
from app.modules.support.service import problem_report
from app.web.deps import Principal, csrf_protect, parse_uuid, redirect, render, require, safe_next


def _admin_host(request: Request):
    if settings.admin_host and request.url.hostname != settings.admin_host:
        raise NotFound()


router = APIRouter(prefix="/admin", dependencies=[Depends(_admin_host), Depends(csrf_protect)])


def _d(raw: str, default: date) -> date:
    try:
        return date.fromisoformat(raw) if raw else default
    except ValueError:
        return default


@router.get("")
def home(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.access"))):
    ops = analytics.operations(db) if me.can("admin.kpi") or me.can("admin.orders") else None
    return render(request, "admin/home.html", {"ops": ops})


# ------------------------------------------------------------------ orders & deals


@router.get("/orders")
def orders_list(request: Request, status: str = "moderation", q: str = "", db: Session = Depends(get_db),
                me: Principal = Depends(require("admin.orders"))):
    stmt = select(Order).where(Order.is_deleted.is_(False))
    if status:
        stmt = stmt.where(Order.status == status)
    if q:
        stmt = stmt.where(Order.search_text.contains(q.lower()))
    items = list(db.execute(stmt.order_by(Order.created_at.desc()).limit(200)).scalars())
    names = {c.id: c.name for c in db.execute(select(Company)).scalars()}
    return render(request, "admin/orders.html", {"items": items, "status": status, "q": q, "names": names,
                                                 "statuses": flow.ALL_STATUSES})


@router.get("/orders/{oid}")
def order_view(oid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.orders"))):
    order = db.get(Order, parse_uuid(oid))
    if order is None:
        raise NotFound()
    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    audit(db, "staff.order_viewed", object_type="order", object_id=order.id)
    db.commit()
    from app.modules.orders.service import auto_moderation_problems

    return render(request, "admin/order.html", {"order": order, "deal": deal, "history": deals.history(db, order.id),
                                                "client": db.get(Company, order.client_company_id),
                                                "problems": auto_moderation_problems(db, order),
                                                "statuses": flow.ALL_STATUSES})


@router.post("/orders/{oid}/moderate")
async def moderate(oid: str, request: Request, db: Session = Depends(get_db),
                   me: Principal = Depends(require("admin.orders"))):
    form = await request.form()
    order = flow.lock_order(db, parse_uuid(oid))
    if form.get("decision") == "publish":
        flow.transition(db, order, flow.PUBLISHED, actor=flow.MANAGER, reason="manual moderation",
                        user_id=me.user.id)
        if order.bidding_deadline is None:
            order.bidding_deadline = utcnow() + timedelta(hours=24)
        from app.modules.orders.service import notify_saved_searches

        notify_saved_searches(db, order)
    else:
        flow.transition(db, order, flow.DRAFT, actor=flow.MANAGER, reason=str(form.get("reason", "")),
                        user_id=me.user.id)
        order.moderation_note = str(form.get("reason", ""))[:500]
    db.commit()
    return redirect(f"/admin/orders/{oid}", flash=("success", "msg.saved"))


@router.post("/orders/{oid}/rollback")
async def rollback(oid: str, request: Request, db: Session = Depends(get_db),
                   me: Principal = Depends(require("admin.rollback"))):
    """FR-FLOW-03 + SEC-AZ-05: manager asks with a reason; a second staff member confirms; both sides notified."""
    from app.modules.orders.models import StatusHistory
    from app.modules.platform import approvals

    form = await request.form()
    order = db.get(Order, parse_uuid(oid))
    if order is None:
        raise NotFound()
    to = str(form.get("to", ""))
    history = set(db.execute(select(StatusHistory.from_status).where(StatusHistory.order_id == order.id)).scalars())
    if to == order.status or to not in history:
        raise ValidationFailed({"to": "error.rollback_target_not_in_history"})
    approvals.request(db, "status_rollback", staff=db.get(User, me.user.id), object_id=order.id,
                      payload={"order_id": str(order.id), "to": to},
                      summary=f"{order.number}: {order.status} → {to}", reason=str(form.get("reason", "")))
    db.commit()
    return redirect(f"/admin/orders/{oid}", flash=("success", "approval.sent"))


@router.get("/deals/{did}")
def deal_view(did: str, request: Request, db: Session = Depends(get_db),
              me: Principal = Depends(require("admin.deal_content"))):
    from app.web.routes_deals import deal_card

    audit(db, "staff.deal_viewed", object_type="deal", object_id=did)
    db.commit()
    return deal_card(did, request, db, me)


@router.get("/deals/{did}/transport-docs/{rid}.xml")
def deal_transport_xml(did: str, rid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("admin.deal_content"))):
    from app.web.routes_deals import transport_xml

    audit(db, "staff.document_downloaded", object_type="deal", object_id=did, details={"transport_doc": rid})
    db.commit()
    return transport_xml(did, rid, request, db, me)


@router.get("/deals/{did}/customs.xml")
def deal_customs_xml(did: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(require("admin.deal_content"))):
    from app.web.routes_deals import customs_xml

    return customs_xml(did, request, db, me)


@router.api_route("/deals/{did}/docs/{doc_id}/signatures", methods=["GET", "POST"])
async def deal_doc_signatures(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
                              me: Principal = Depends(require("admin.deal_content"))):
    from app.web.routes_deals import doc_signatures

    audit(db, "staff.deal_viewed", object_type="deal", object_id=did, details={"signatures": doc_id})
    db.commit()
    return await doc_signatures(did, doc_id, request, db, me)


@router.post("/deals/{did}/clear-review")
async def clear_review(did: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("admin.antifraud"))):
    form = await request.form()
    deal = db.get(Deal, parse_uuid(did))
    if deal is None:
        raise NotFound()
    deals.clear_manual_review(db, deal, str(form.get("note", "")))
    db.commit()
    return redirect(f"/admin/deals/{did}", flash=("success", "msg.saved"))


@router.post("/messages/{mid}/hide")
async def hide_message(mid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("admin.antifraud"))):
    form = await request.form()
    chat.hide(db, parse_uuid(mid), str(form.get("reason", "")))
    db.commit()
    from urllib.parse import urlparse

    back = urlparse(request.headers.get("referer", "")).path
    return redirect(safe_next(back, "/admin"))


# ------------------------------------------------------------------ disputes


@router.get("/disputes")
def disputes(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.disputes"))):
    rows = db.execute(select(Dispute, Deal).join(Deal, Deal.id == Dispute.deal_id)
                      .order_by(Dispute.status, Dispute.created_at.desc())).all()
    return render(request, "admin/disputes.html", {"rows": rows, "subject_map": dictionary_map(db, "dispute_subjects")})


@router.post("/disputes/{dsid}/resolve")
async def resolve(dsid: str, request: Request, db: Session = Depends(get_db),
                  me: Principal = Depends(require("admin.disputes"))):
    form = await request.form()
    d = db.get(Dispute, parse_uuid(dsid))
    if d is None:
        raise NotFound()
    deals.resolve_dispute(db, d, outcome=str(form.get("outcome", "")), resolution=str(form.get("resolution", "")),
                          manager=db.get(User, me.user.id), fault=str(form.get("fault", "none")))
    db.commit()
    return redirect("/admin/disputes", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ verification


@router.get("/moderation")
def moderation(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.moderation"))):
    rows = db.execute(select(VerificationRequest, Company).join(Company, Company.id == VerificationRequest.company_id)
                      .order_by(VerificationRequest.status.desc(), VerificationRequest.priority,
                                VerificationRequest.created_at)).all()
    return render(request, "admin/moderation.html", {"rows": rows, "now": utcnow()})


@router.get("/moderation/{rid}")
def moderation_item(rid: str, request: Request, db: Session = Depends(get_db),
                    me: Principal = Depends(require("admin.moderation"))):
    req = db.get(VerificationRequest, parse_uuid(rid))
    if req is None:
        raise NotFound()
    company = db.get(Company, req.company_id)
    docs = list(db.execute(select(VerificationDocument).where(VerificationDocument.company_id == company.id)).scalars())
    from app.modules.fleet.models import RegistryCheck

    checks = list(db.execute(select(RegistryCheck).where(RegistryCheck.company_id == company.id)
                             .order_by(RegistryCheck.created_at.desc())).scalars())
    alerts = list(db.execute(select(AntifraudAlert).where(AntifraudAlert.company_id == company.id)).scalars())
    if req.assigned_to is None:
        req.assigned_to = me.user.id
    audit(db, "staff.verification_viewed", object_type="company", object_id=company.id)
    db.commit()
    return render(request, "admin/moderation_item.html", {
        "req": req, "company": company, "docs": docs, "checks": checks, "alerts": alerts,
        "vehicles": fleet.company_vehicles(db, company.id), "drivers": fleet.company_drivers(db, company.id),
        "bio": {d.id: biometrics_latest(db, d.id)
                for d in fleet.company_drivers(db, company.id)},
        "reasons": dictionary(db, "verification_reject_reasons")})


@router.post("/moderation/{rid}")
async def moderation_decide(rid: str, request: Request, db: Session = Depends(get_db),
                            me: Principal = Depends(require("admin.moderation"))):
    form = await request.form()
    req = db.get(VerificationRequest, parse_uuid(rid))
    if req is None:
        raise NotFound()
    fleet.decide_verification(db, req, approve=form.get("decision") == "approve",
                              reason_code=str(form.get("reason_code", "")), comment=str(form.get("comment", "")),
                              moderator=db.get(User, me.user.id))
    db.commit()
    return redirect("/admin/moderation", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ companies & users


@router.get("/companies")
def companies(request: Request, q: str = "", db: Session = Depends(get_db), me: Principal = Depends(require("admin.users"))):
    stmt = select(Company)
    if q:
        stmt = stmt.where(or_(Company.name.ilike(f"%{q}%"), Company.bin_iin.contains(q)))
    items = list(db.execute(stmt.order_by(Company.created_at.desc()).limit(200)).scalars())
    return render(request, "admin/companies.html", {"items": items, "q": q})


@router.get("/companies/{cid}")
def company_card(cid: str, request: Request, reveal: str = "", db: Session = Depends(get_db),
                 me: Principal = Depends(require("admin.users"))):
    c = db.get(Company, parse_uuid(cid))
    if c is None:
        raise NotFound()
    members = db.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                         .where(Membership.company_id == c.id)).all()
    restrictions = list(db.execute(select(Restriction).where(Restriction.company_id == c.id)
                                   .order_by(Restriction.created_at.desc())).scalars())
    revealed = False
    if reveal:
        # FR-ACL-05: access to contacts is logged with the stated reason
        audit(db, "staff.contacts_revealed", object_type="company", object_id=c.id, reason=reveal[:300])
        revealed = True
    else:
        audit(db, "staff.company_viewed", object_type="company", object_id=c.id)
    db.commit()
    from app.modules.accounts.support_access import active_grant
    from app.modules.rating import service as rating

    grants = {u.id: active_grant(db, u.id) for _, u in members}
    return render(request, "admin/company.html", {"c": c, "members": members, "restrictions": restrictions,
                                                  "stats": fleet.company_stats(db, c.id), "revealed": revealed,
                                                  "r": rating.compute(db, c.id), "grants": grants,
                                                  "rating_events": rating.history(db, c.id, limit=30)})


@router.post("/companies/{cid}/restrict")
async def restrict(cid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.users"))):
    """FR-RAT-04 / SEC-FRD-08: restrictions with reason, term and author; reversible."""
    form = await request.form()
    c = db.get(Company, parse_uuid(cid))
    if c is None:
        raise NotFound()
    reason = str(form.get("reason", "")).strip()
    if not reason:
        raise ValidationFailed({"reason": "error.reason_required"})
    kind = str(form.get("kind", "block"))
    if kind not in ("block", "limit", "no_new_orders", "no_bids"):
        raise ValidationFailed({"kind": "error.invalid_choice"})
    until = _d(str(form.get("until", "")), None) if form.get("until") else None
    if kind == "block":  # SEC-AZ-05: blocking a company needs a second staff member
        from app.modules.platform import approvals

        approvals.request(db, "company_block", staff=db.get(User, me.user.id), object_id=c.id,
                          payload={"company_id": str(c.id), "until": until.isoformat() if until else ""},
                          summary=f"{c.name} ({c.bin_iin})", reason=reason)
        db.commit()
        return redirect(f"/admin/companies/{cid}", flash=("success", "approval.sent"))
    db.add(Restriction(company_id=c.id, kind=kind, reason=reason, until=until, created_by=me.user.id))
    if kind == "limit" and form.get("limit"):
        c.deal_limit_minor = to_minor(str(form["limit"]))
    audit(db, "staff.company_restricted", object_type="company", object_id=c.id, reason=reason,
          details={"kind": kind})
    from app.modules.notifications.service import notify_company_owners

    notify_company_owners(db, c.id, "account.restricted", {"reason": reason}, link="/support", critical=True)
    db.commit()
    return redirect(f"/admin/companies/{cid}", flash=("success", "msg.saved"))


@router.post("/restrictions/{rid}/lift")
def lift(rid: str, db: Session = Depends(get_db), me: Principal = Depends(require("admin.users"))):
    r = db.get(Restriction, parse_uuid(rid))
    if r is None:
        raise NotFound()
    r.lifted_at = utcnow()
    r.lifted_by = me.user.id
    c = db.get(Company, r.company_id)
    if r.kind == "block":
        c.is_blocked = False
    audit(db, "staff.restriction_lifted", object_type="company", object_id=c.id)
    db.commit()
    return redirect(f"/admin/companies/{c.id}", flash=("success", "msg.saved"))


@router.get("/users")
def users(request: Request, q: str = "", db: Session = Depends(get_db), me: Principal = Depends(require("admin.users"))):
    stmt = select(User)
    if q:
        stmt = stmt.where(or_(User.full_name.ilike(f"%{q}%"), User.phone.contains(q), User.email.ilike(f"%{q}%")))
    items = list(db.execute(stmt.order_by(User.created_at.desc()).limit(200)).scalars())
    return render(request, "admin/users.html", {"items": items, "q": q})


@router.post("/users/{uid}/action")
async def user_action(uid: str, request: Request, db: Session = Depends(get_db),
                      me: Principal = Depends(require("admin.users"))):
    form = await request.form()
    u = db.get(User, parse_uuid(uid))
    if u is None:
        raise NotFound()
    action = str(form.get("action", ""))
    reason = str(form.get("reason", "")).strip()
    if not reason:
        raise ValidationFailed({"reason": "error.reason_required"})
    from app.modules.accounts import service as accounts_service
    from app.modules.accounts.service import revoke_all_sessions

    if action == "block":
        u.is_blocked = True
        revoke_all_sessions(db, u.id)
    elif action == "unblock":
        u.is_blocked = False
    elif action == "anonymize":
        # SEC-DAT-07: data subject requests are executed through the admin UI, never by SQL
        accounts_service.anonymize_user(db, u, reason=reason, by_staff=True)
    elif action == "reset_2fa":
        u.totp_enabled = False
        u.totp_secret = None
        revoke_all_sessions(db, u.id)
    else:
        raise ValidationFailed({"action": "error.invalid_choice"})
    audit(db, f"staff.user_{action}", object_type="user", object_id=u.id, reason=reason)
    db.commit()
    return redirect("/admin/users", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ antifraud


@router.get("/antifraud")
def antifraud(request: Request, status: str = "open", db: Session = Depends(get_db),
              me: Principal = Depends(require("admin.antifraud"))):
    items = list(db.execute(select(AntifraudAlert).where(AntifraudAlert.status == status)
                            .order_by(AntifraudAlert.created_at.desc()).limit(300)).scalars())
    names = {c.id: c.name for c in db.execute(select(Company)).scalars()}
    deal_nums = {d.id: d.number for d in db.execute(select(Deal)).scalars()}
    total = db.execute(select(func.count(AntifraudAlert.id)).where(AntifraudAlert.status != "open")).scalar_one()
    fp = db.execute(select(func.count(AntifraudAlert.id)).where(AntifraudAlert.status == "false_positive")).scalar_one()
    return render(request, "admin/antifraud.html", {"items": items, "status": status, "names": names,
                                                    "deal_nums": deal_nums,
                                                    "fp_rate": round(fp * 100 / total, 1) if total else 0})


@router.post("/antifraud/{aid}")
async def antifraud_decide(aid: str, request: Request, db: Session = Depends(get_db),
                           me: Principal = Depends(require("admin.antifraud"))):
    form = await request.form()
    a = db.get(AntifraudAlert, parse_uuid(aid))
    if a is None:
        raise NotFound()
    decision = str(form.get("decision", ""))
    if decision not in ("confirmed", "false_positive"):
        raise ValidationFailed({"decision": "error.invalid_choice"})
    a.status = decision
    a.decided_by = me.user.id
    a.decision_note = str(form.get("note", ""))[:500]
    audit(db, "staff.alert_decided", object_type="alert", object_id=a.id, details={"decision": decision})
    db.commit()
    return redirect("/admin/antifraud", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ finance


@router.get("/finance")
def finance(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    invoices = list(db.execute(select(Invoice).order_by(Invoice.created_at.desc()).limit(200)).scalars())
    accruals = list(db.execute(select(Accrual).order_by(Accrual.created_at.desc()).limit(100)).scalars())
    tariffs = list(db.execute(select(Tariff).where(Tariff.is_deleted.is_(False)).order_by(Tariff.valid_from.desc()))
                   .scalars())
    names = {c.id: c.name for c in db.execute(select(Company)).scalars()}
    clients = [c for c in db.execute(select(Company).where(Company.kind == "client").order_by(Company.name)).scalars()]
    return render(request, "admin/finance.html", {"invoices": invoices, "accruals": accruals, "tariffs": tariffs,
                                                  "names": names, "clients": clients,
                                                  "income_map": dictionary_map(db, "income_types")})


@router.post("/finance/invoices/{iid}/pay")
async def pay(iid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    form = await request.form()
    inv = billing.get_invoice(db, parse_uuid(iid))
    try:
        amount = to_minor(str(form.get("amount", "")))
    except ValueError:
        raise ValidationFailed({"amount": "error.number"})
    billing.register_payment(db, inv, amount, source="manual", reference=str(form.get("reference", "")))
    db.commit()
    return redirect("/admin/finance", flash=("success", "msg.saved"))


@router.post("/finance/statement")
async def statement(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise ValidationFailed({"file": "error.required"})
    res = billing.import_bank_statement(db, await upload.read())
    db.commit()
    resp = redirect("/admin/finance")
    from app.web.deps import set_flash

    set_flash(resp, "success", "msg.statement_imported", matched=res["matched"], unmatched=len(res["unmatched"]))
    return resp


@router.post("/finance/accruals/{aid}/storno")
async def storno(aid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    form = await request.form()
    a = db.get(Accrual, parse_uuid(aid))
    if a is None or a.storno_of_id:
        raise NotFound()
    from app.modules.platform import approvals

    approvals.request(db, "storno", staff=db.get(User, me.user.id), object_id=a.id, payload={"accrual_id": str(a.id)},
                      summary=f"storno {a.amount_minor / 100:.2f} {a.currency}", reason=str(form.get("reason", "")))
    db.commit()
    return redirect("/admin/finance", flash=("success", "approval.sent"))


@router.post("/finance/tariffs")
async def tariff_create(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    form = await request.form()
    model = str(form.get("model", "fixed"))
    if model not in ("fixed", "percent", "combined"):
        raise ValidationFailed({"model": "error.invalid_choice"})

    def money(key):
        raw = str(form.get(key, "") or "0")
        try:
            return to_minor(raw)
        except ValueError:
            raise ValidationFailed({key: "error.number"})

    try:
        percent_bp = int(round(float(str(form.get("percent", "0") or "0").replace(",", ".")) * 100))
    except ValueError:
        raise ValidationFailed({"percent": "error.number"})
    deal_type = str(form.get("deal_type", "any"))
    if deal_type not in ("any", "domestic", "international"):
        raise ValidationFailed({"deal_type": "error.invalid_choice"})
    company_id = parse_uuid(form["company_id"]) if form.get("company_id") else None
    valid_to = _d(str(form.get("valid_to", "")), None) if form.get("valid_to") else None
    payload = {"name": str(form.get("name", "")).strip()[:200] or "Тариф", "model": model, "fixed_minor": money("fixed"),
               "percent_bp": percent_bp, "min_minor": money("min"), "max_minor": money("max"),
               "company_id": str(company_id) if company_id else "", "deal_type": deal_type,
               "valid_from": _d(str(form.get("valid_from", "")), date.today()).isoformat(),
               "valid_to": valid_to.isoformat() if valid_to else ""}
    from app.modules.platform import approvals

    approvals.request(db, "tariff_change", staff=db.get(User, me.user.id), payload=payload,
                      summary=f"{payload['name']} · {model}", reason=str(form.get("reason", "")) or payload["name"])
    db.commit()
    return redirect("/admin/finance", flash=("success", "approval.sent"))


@router.get("/reports/pvd")
def pvd(request: Request, date_from: str = "", date_to: str = "", db: Session = Depends(get_db),
        me: Principal = Depends(require("admin.finance"))):
    df = _d(date_from, date.today().replace(day=1))
    dt = _d(date_to, date.today())
    report = billing.pvd_report(db, df, dt)
    return render(request, "admin/pvd.html", {"r": report, "labels": dictionary_map(db, "income_types")})


@router.get("/reports/pvd.{fmt}")
def pvd_export(fmt: str, date_from: str = "", date_to: str = "", db: Session = Depends(get_db),
               me: Principal = Depends(require("admin.finance"))):
    ratelimit.hit("export", str(me.user.id))
    report = billing.pvd_report(db, _d(date_from, date.today().replace(day=1)), _d(date_to, date.today()))
    labels = dictionary_map(db, "income_types")
    audit(db, "export.pvd_report", object_type="report", object_id="pvd", details={"fmt": fmt})
    db.commit()
    if fmt == "xlsx":
        return Response(billing.pvd_report_xlsx(report, labels),
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": 'attachment; filename="pvd-report.xlsx"'})
    if fmt == "pdf":
        return Response(billing.pvd_report_pdf(report, labels), media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="pvd-report.pdf"'})
    raise NotFound()


# ------------------------------------------------------------------ KPI


@router.get("/kpi")
def kpi(request: Request, date_from: str = "", date_to: str = "", db: Session = Depends(get_db),
        me: Principal = Depends(require("admin.kpi"))):
    df = _d(date_from, None) if date_from else None
    dt = _d(date_to, None) if date_to else None
    snaps = list(db.execute(select(KpiSnapshot).order_by(KpiSnapshot.report_date.desc()).limit(12)).scalars())
    return render(request, "admin/kpi.html", {"k": analytics.kpi(db, df, dt), "targets": analytics.KPI_TARGETS,
                                              "snaps": snaps, "date_from": date_from, "date_to": date_to})


@router.post("/kpi/snapshot")
async def kpi_snapshot(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.kpi"))):
    form = await request.form()
    analytics.fix_snapshot(db, _d(str(form.get("report_date", "")), date.today()))
    audit(db, "staff.kpi_fixed", object_type="kpi", object_id=str(form.get("report_date", "")))
    db.commit()
    return redirect("/admin/kpi", flash=("success", "msg.saved"))


@router.get("/kpi.xlsx")
def kpi_export(date_from: str = "", date_to: str = "", db: Session = Depends(get_db),
               me: Principal = Depends(require("admin.kpi"))):
    k = analytics.kpi(db, _d(date_from, None) if date_from else None, _d(date_to, None) if date_to else None)
    rows = [["Показатель", "Значение"], ["Компании-клиенты", k["clients"]], ["Перевозчики", k["carriers"]],
            ["Водители", k["drivers"]], ["Заявки", k["orders"]], ["Сделки", k["deals"]],
            ["Автоматически сформированные документы", k["auto_documents"]],
            ["Время обработки заявки, медиана (мин)", k["processing"]["all"]["median"]],
            ["Время обработки заявки, среднее (мин)", k["processing"]["all"]["mean"]]]
    return Response(analytics.to_xlsx(rows, "KPI"),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="kpi.xlsx"'})


# ------------------------------------------------------------------ dictionaries, templates, flags, settings


@router.get("/dictionaries")
def dictionaries(request: Request, name: str = "body_types", db: Session = Depends(get_db),
                 me: Principal = Depends(require("admin.dictionaries"))):
    names = [r for r in db.execute(select(DictionaryItem.dictionary).distinct().order_by(DictionaryItem.dictionary))
             .scalars()]
    return render(request, "admin/dictionaries.html", {"names": names, "name": name,
                                                       "items": dictionary(db, name, active_only=False)})


@router.post("/dictionaries")
async def dictionary_save(request: Request, db: Session = Depends(get_db),
                          me: Principal = Depends(require("admin.dictionaries"))):
    form = await request.form()
    name = str(form.get("dictionary", ""))
    try:
        sort = int(form.get("sort") or 100)
        if form.get("item_id"):
            item = db.get(DictionaryItem, parse_uuid(form["item_id"]))
            if item is None:
                raise NotFound()
            update_dictionary_item(db, item, name_ru=str(form.get("name_ru", "")), name_kk=str(form.get("name_kk", "")),
                                   extra=str(form.get("extra", "{}")), is_active=bool(form.get("is_active")), sort=sort)
        else:
            json.loads(str(form.get("extra", "{}") or "{}"))
            db.add(DictionaryItem(dictionary=name, code=str(form.get("code", "")).strip(),
                                  name_ru=str(form.get("name_ru", "")), name_kk=str(form.get("name_kk", "")),
                                  extra=str(form.get("extra", "{}") or "{}"), sort=sort, created_by=me.user.id))
    except ValueError:
        raise ValidationFailed({"extra": "error.json"})
    audit(db, "staff.dictionary_changed", object_type="dictionary", object_id=name)
    db.commit()
    return redirect(f"/admin/dictionaries?name={name}", flash=("success", "msg.saved"))


@router.get("/templates")
def templates_list(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.dictionaries"))):
    items = list(db.execute(select(DocumentTemplate).order_by(DocumentTemplate.doc_type, DocumentTemplate.locale,
                                                              DocumentTemplate.version.desc())).scalars())
    return render(request, "admin/templates.html", {"items": items, "edit": request.query_params.get("edit")})


@router.post("/templates")
async def template_save(request: Request, db: Session = Depends(get_db),
                        me: Principal = Depends(require("admin.dictionaries"))):
    form = await request.form()
    documents.save_template_version(db, str(form.get("doc_type", "")), str(form.get("locale", "ru")),
                                    str(form.get("title", "")), str(form.get("body", "")),
                                    _d(str(form.get("valid_from", "")), date.today()))
    db.commit()
    return redirect("/admin/templates", flash=("success", "msg.saved"))


@router.post("/templates/preview")
async def template_preview(request: Request, db: Session = Depends(get_db),
                           me: Principal = Depends(require("admin.dictionaries"))):
    """FR-DOC-02: preview on test data."""
    import string

    form = await request.form()
    documents.validate_template_body(str(form.get("doc_type", "")), str(form.get("body", "")))
    sample = {"number": "ДЗ-2026-000001", "date": date.today().strftime("%d.%m.%Y"), "deal_number": "SD-2026-000001",
              "order_number": "AX-2026-000001", "client_name": "ТОО «Тестовый клиент»", "client_bin": "123456789012",
              "carrier_name": "ТОО «Тестовый перевозчик»", "carrier_bin": "210987654321", "route": "Алматы → Астана",
              "cargo": "Тестовый груз", "weight": "20000", "price": "450 000 ₸", "amount": "35 000 ₸",
              "subject": billing.FEE_SUBJECT.format(deal="SD-2026-000001")}
    body = string.Template(str(form.get("body", ""))).safe_substitute(sample)
    pdf = documents.render_pdf(string.Template(str(form.get("title", ""))).safe_substitute(sample), body)
    return Response(pdf, media_type="application/pdf")


@router.get("/flags")
def flags(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.settings"))):
    return render(request, "admin/flags.html", {"items": list(db.execute(select(FeatureFlag).order_by(FeatureFlag.key))
                                                              .scalars())})


@router.post("/flags/{fid}")
async def flag_save(fid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.settings"))):
    form = await request.form()
    f = db.get(FeatureFlag, parse_uuid(fid))
    if f is None:
        raise NotFound()
    f.enabled = bool(form.get("enabled"))
    f.company_ids = str(form.get("company_ids", ""))[:2000]
    try:
        f.percent = max(0, min(100, int(form.get("percent") or 0)))
    except ValueError:
        raise ValidationFailed({"percent": "error.number"})
    audit(db, "staff.flag_changed", object_type="flag", object_id=f.key, details={"enabled": f.enabled})
    db.commit()
    return redirect("/admin/flags", flash=("success", "msg.saved"))


@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.settings"))):
    return render(request, "admin/settings.html", {"items": list(db.execute(select(PlatformSetting)
                                                                            .order_by(PlatformSetting.key)).scalars())})


@router.post("/settings/{sid}")
async def setting_save(sid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("admin.settings"))):
    form = await request.form()
    s = db.get(PlatformSetting, parse_uuid(sid))
    if s is None:
        raise NotFound()
    raw = str(form.get("value", ""))
    try:
        json.loads(raw)
    except ValueError:
        raise ValidationFailed({"value": "error.json"})
    before = s.value
    s.value = raw
    audit(db, "staff.setting_changed", object_type="setting", object_id=s.key, details={"before": before[:200]})
    if s.key == "ratelimit.limits":
        ratelimit.configure(json.loads(raw) if isinstance(json.loads(raw), dict) else {})
    db.commit()
    return redirect("/admin/settings", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ journals


@router.get("/audit")
def audit_log(request: Request, user: str = "", action: str = "", obj: str = "", date_from: str = "", date_to: str = "",
              db: Session = Depends(get_db), me: Principal = Depends(require("admin.audit"))):
    """FR-ADM-04 / SEC-LOG-03: read-only, filters by employee, object and period."""
    stmt = select(AuditLog)
    if user:
        stmt = stmt.where(AuditLog.user_id == parse_uuid(user))
    if action:
        stmt = stmt.where(AuditLog.action.contains(action))
    if obj:
        stmt = stmt.where(AuditLog.object_id == obj)
    if date_from:
        from datetime import datetime, time, timezone

        stmt = stmt.where(AuditLog.created_at >= datetime.combine(_d(date_from, date.today()), time.min, timezone.utc))
    if date_to:
        from datetime import datetime, time, timezone

        stmt = stmt.where(AuditLog.created_at <= datetime.combine(_d(date_to, date.today()), time.max, timezone.utc))
    items = list(db.execute(stmt.order_by(AuditLog.created_at.desc()).limit(500)).scalars())
    users = {u.id: u.full_name for u in db.execute(select(User)).scalars()}
    return render(request, "admin/audit.html", {"items": items, "users": users, "f": {
        "user": user, "action": action, "obj": obj, "date_from": date_from, "date_to": date_to}})


@router.get("/integrations")
def integrations(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.audit"))):
    calls = list(db.execute(select(IntegrationCall).order_by(IntegrationCall.created_at.desc()).limit(200)).scalars())
    outbox = list(db.execute(select(OutboxMessage).order_by(OutboxMessage.created_at.desc()).limit(100)).scalars())
    from app.modules.integrations.adapters import CHANNELS, registry, routing

    adapters = {a.name: {"metrics": a.metrics, "open": a.breaker.is_open} for a in (routing, registry, *CHANNELS.values())}
    return render(request, "admin/integrations.html", {"calls": calls, "outbox": outbox, "adapters": adapters})


@router.get("/support")
def support_admin(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.support"))):
    items = list(db.execute(select(Ticket).order_by(Ticket.status, Ticket.sla_due_at).limit(300)).scalars())
    return render(request, "admin/support.html", {"items": items, "report": problem_report(db), "now": utcnow(),
                                                  "cat_map": dictionary_map(db, "support_categories")})


@router.get("/support/{tid}")
def support_ticket(tid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.support"))):
    t = db.get(Ticket, parse_uuid(tid))
    if t is None:
        raise NotFound()
    from app.modules.accounts.support_access import active_grant

    return render(request, "admin/support_ticket.html", {"t": t, "messages": chat.thread_messages(db, ticket_id=t.id),
                                                         "cat_map": dictionary_map(db, "support_categories"),
                                                         "grant": active_grant(db, t.user_id)})


@router.post("/support/{tid}")
async def support_reply(tid: str, request: Request, db: Session = Depends(get_db),
                        me: Principal = Depends(require("admin.support"))):
    form = await request.form()
    t = db.get(Ticket, parse_uuid(tid))
    if t is None:
        raise NotFound()
    if form.get("body"):
        chat.post(db, ticket_id=t.id, body=str(form["body"]), kind="staff")
    if form.get("status") in ("open", "in_progress", "resolved"):
        t.status = str(form["status"])
    t.assigned_to = t.assigned_to or me.user.id
    from app.modules.notifications.service import notify_user

    notify_user(db, t.user_id, "support.reply", {"number": t.number}, link=f"/support/{t.id}")
    db.commit()
    return redirect(f"/admin/support/{tid}", flash=("success", "msg.saved"))
