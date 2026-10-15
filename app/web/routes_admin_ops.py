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
