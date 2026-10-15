"""Admin features of cycle 2: permission matrix (FR-ACL-06), promo codes (FR-BIL-09), rating corrections
(FR-RAT-02) and support sessions "as the user" (FR-ADM-05)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.errors import NotFound, ValidationFailed
from app.db import get_db
from app.modules.accounts import acl, support_access
from app.modules.accounts import permissions as P
from app.modules.accounts.models import Company, User
from app.modules.billing import service as billing
from app.modules.billing.models import PromoCode
from app.modules.rating import service as rating
from app.web.deps import SESSION_COOKIE, Principal, csrf_protect, parse_uuid, redirect, render, require
from app.web.routes_admin import _admin_host
from app.web.routes_ops import RETURN_COOKIE

router = APIRouter(prefix="/admin", dependencies=[Depends(_admin_host), Depends(csrf_protect)])


# ------------------------------------------------------------------ permission matrix (FR-ACL-06)


@router.get("/permissions")
def permissions_page(request: Request, scope: str = "client", db: Session = Depends(get_db),
                     me: Principal = Depends(require("admin.settings"))):
    if scope not in acl.SCOPES:
        raise NotFound()
    return render(request, "admin/permissions.html", {
        "scope": scope, "roles": acl.roles(db, scope), "perms": P.all_permissions(scope), "grants": acl.grants(db),
        "locked": P.LOCKED, "never": P.NEVER})


@router.post("/permissions")
async def permissions_save(request: Request, db: Session = Depends(get_db),
                           me: Principal = Depends(require("admin.settings"))):
    form = await request.form()
    scope = str(form.get("scope", ""))
    wanted = set()
    for key in form.keys():
        if key.startswith("g:"):
            _, role, perm = key.split(":", 2)
            wanted.add((role, perm))
    acl.save_matrix(db, scope, wanted)
    db.commit()
    return redirect(f"/admin/permissions?scope={scope}", flash=("success", "msg.saved"))


@router.post("/permissions/roles")
async def permissions_add_role(request: Request, db: Session = Depends(get_db),
                               me: Principal = Depends(require("admin.settings"))):
    form = await request.form()
    rd = acl.add_role(db, code=str(form.get("code", "")), scope=str(form.get("scope", "")),
                      name_ru=str(form.get("name_ru", "")), name_kk=str(form.get("name_kk", "")))
    db.commit()
    return redirect(f"/admin/permissions?scope={rd.scope}", flash=("success", "acl.role_added"))


# ------------------------------------------------------------------ promo codes (FR-BIL-09)


@router.get("/promo")
def promo_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    items = list(db.execute(select(PromoCode).where(PromoCode.is_deleted.is_(False))
                            .order_by(PromoCode.created_at.desc())).scalars())
    return render(request, "admin/promo.html", {"items": items})


@router.post("/promo")
async def promo_create(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    billing.create_promo(db, await request.form())
    db.commit()
    return redirect("/admin/promo", flash=("success", "msg.saved"))


@router.post("/promo/{pid}/toggle")
def promo_toggle(pid: str, db: Session = Depends(get_db), me: Principal = Depends(require("admin.finance"))):
    from app.core.audit import audit

    p = db.get(PromoCode, parse_uuid(pid))
    if p is None:
        raise NotFound()
    p.active = not p.active
    audit(db, "billing.promo_toggled", object_type="promo", object_id=p.id, details={"active": p.active})
    db.commit()
    return redirect("/admin/promo", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ rating corrections (FR-RAT-02)


@router.post("/companies/{cid}/rating")
async def rating_correct(cid: str, request: Request, db: Session = Depends(get_db),
                         me: Principal = Depends(require("admin.rating"))):
    c = db.get(Company, parse_uuid(cid))
    if c is None:
        raise NotFound()
    form = await request.form()
    try:
        delta = float(str(form.get("delta", "")).replace(",", "."))
    except ValueError:
        raise ValidationFailed({"delta": "error.rating_delta"})
    rating.correct(db, c.id, delta, str(form.get("reason", "")))
    db.commit()
    return redirect(f"/admin/companies/{c.id}#rating", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ support session (FR-ADM-05)


@router.post("/users/{uid}/impersonate")
async def impersonate(uid: str, request: Request, db: Session = Depends(get_db),
                      me: Principal = Depends(require("admin.impersonate"))):
    form = await request.form()
    target = db.get(User, parse_uuid(uid))
    if target is None:
        raise NotFound()
    raw, _ = support_access.start(db, db.get(User, me.user.id), target, reason=str(form.get("reason", "")),
                                  by_regulation=bool(form.get("regulation")))
    db.commit()
    resp = redirect("/dashboard")
    # The staff session is parked in its own cookie and restored when the support session ends.
    resp.set_cookie(RETURN_COOKIE, request.cookies.get(SESSION_COOKIE, ""), httponly=True,
                    secure=settings.secure_cookies, samesite="strict", path="/")
    resp.set_cookie(SESSION_COOKIE, raw, httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return resp


# ------------------------------------------------------------------ second-person approval (SEC-AZ-05)


@router.get("/approvals")
def approvals_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.access"))):
    from app.modules.platform import approvals

    items = approvals.pending(db)
    db.commit()  # persists expirations
    names = {u.id: u.full_name for u in db.execute(select(User).where(User.staff_role.is_not(None))).scalars()}
    return render(request, "admin/approvals.html", {
        "items": items, "recent": approvals.recent(db), "names": names,
        "can": {r.id: approvals.can_approve(me.user, r) for r in items}})


@router.post("/approvals/{rid}")
async def approvals_decide(rid: str, request: Request, db: Session = Depends(get_db),
                           me: Principal = Depends(require("admin.access"))):
    from app.modules.platform import approvals

    form = await request.form()
    req = approvals.decide(db, parse_uuid(rid), staff=db.get(User, me.user.id),
                           approve=form.get("decision") == "approve", note=str(form.get("note", "")))
    db.commit()
    flash = {"executed": ("success", "approval.executed"), "rejected": ("success", "approval.rejected"),
             "failed": ("error", "approval.failed")}.get(req.status, ("success", "msg.saved"))
    return redirect("/admin/approvals", flash=flash)


# ------------------------------------------------------------------ antifraud rules (SEC-FRD-01)


@router.get("/antifraud/rules")
def af_rules(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("admin.settings"))):
    from app.modules.platform.antifraud import ACTIONS, VELOCITY
    from app.modules.platform.models import AntifraudRule

    rules = list(db.execute(select(AntifraudRule).order_by(AntifraudRule.code)).scalars())
    return render(request, "admin/af_rules.html", {"rules": rules, "actions": ACTIONS,
                                                   "velocity": {c for c, _ in VELOCITY.values()}})


@router.post("/antifraud/rules/{rid}")
async def af_rule_save(rid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("admin.settings"))):
    from app.core.audit import audit
    from app.modules.platform.antifraud import ACTIONS
    from app.modules.platform.models import AntifraudRule

    r = db.get(AntifraudRule, parse_uuid(rid))
    if r is None:
        raise NotFound()
    form = await request.form()
    action, severity = str(form.get("action", "")), str(form.get("severity", ""))
    if action not in ACTIONS or severity not in ("low", "medium", "high"):
        raise ValidationFailed({"action": "error.invalid_choice"})
    try:
        threshold = int(form.get("threshold") or 0)
        window = int(form.get("window_minutes") or 0)
        if threshold < 0 or not 0 <= window <= 525600:
            raise ValueError
    except ValueError:
        raise ValidationFailed({"threshold": "error.number"})
    before = {"enabled": r.enabled, "action": r.action, "severity": r.severity, "threshold": r.threshold,
              "window": r.window_minutes}
    r.enabled, r.action, r.severity = bool(form.get("enabled")), action, severity
    r.threshold, r.window_minutes, r.updated_by = threshold, window, me.user.id
    audit(db, "antifraud.rule_changed", object_type="antifraud_rule", object_id=r.code,
          details={"before": before, "after": {"enabled": r.enabled, "action": action, "severity": severity,
                                               "threshold": threshold, "window": window}})
    db.commit()
    return redirect("/admin/antifraud/rules", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ security alerts & monthly report (SEC-LOG-06/08)


def _month(raw: str | None):
    from datetime import date

    from app.db import utcnow

    try:
        y, m = (int(x) for x in (raw or "").split("-")[:2])
        return date(y, m, 1)
    except ValueError:
        return utcnow().date().replace(day=1)


@router.get("/security")
def security_page(request: Request, status: str = "open", month: str = "", db: Session = Depends(get_db),
                  me: Principal = Depends(require("admin.audit"))):
    from app.modules.platform import security

    status = status if status in ("open", "closed") else "open"
    names = {u.id: u.full_name for u in db.execute(select(User).where(User.staff_role.is_not(None))).scalars()}
    m = _month(month)
    return render(request, "admin/security.html", {"alerts": security.alerts(db, status), "status": status,
                                                   "names": names, "report": security.monthly_report(db, m),
                                                   "month": m})


@router.post("/security/{aid}/close")
def security_close(aid: str, db: Session = Depends(get_db), me: Principal = Depends(require("admin.audit"))):
    from app.core.audit import audit
    from app.modules.platform.models import SecurityAlert

    a = db.get(SecurityAlert, parse_uuid(aid))
    if a is None:
        raise NotFound()
    a.status, a.closed_by = "closed", me.user.id
    audit(db, "security.alert_closed", object_type="security_alert", object_id=a.id)
    db.commit()
    return redirect("/admin/security", flash=("success", "msg.saved"))


@router.get("/security/report.pdf")
def security_report_pdf(month: str = "", db: Session = Depends(get_db), me: Principal = Depends(require("admin.audit"))):
    from fastapi.responses import Response

    from app.core.audit import audit
    from app.core.i18n import translate
    from app.modules.platform import security

    report = security.monthly_report(db, _month(month))
    keys = ("summary", "alerts", "open", "logins", "failed", "exports", "denied", "impersonations", "approvals",
            "antifraud", "rights", "vulns", "title")
    labels = {k: translate(f"secr.{k}") for k in keys}
    labels.update({f"k.{k}": translate(f"secalert.{k}") for k in report["alerts_by_kind"]})
    audit(db, "export.security_report", object_type="report", object_id=report["month"].isoformat())
    db.commit()
    return Response(security.report_pdf(report, labels), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="security-{report["month"]:%Y-%m}.pdf"'})


# ------------------------------------------------------------------ product funnels (FR-BI-07)


@router.get("/funnels")
def funnels_page(request: Request, date_from: str = "", date_to: str = "", db: Session = Depends(get_db),
                 me: Principal = Depends(require("admin.kpi"))):
    from datetime import date

    from app.modules.analytics import product

    d1, d2 = product.default_period()
    try:
        d1 = date.fromisoformat(date_from) if date_from else d1
        d2 = date.fromisoformat(date_to) if date_to else d2
    except ValueError:
        pass
    return render(request, "admin/funnels.html", {"funnels": product.funnels(db, d1, d2), "d1": d1, "d2": d2})
