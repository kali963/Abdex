"""HTTP-layer helpers: principal resolution, permission checks, CSRF, rendering, flash.

Business logic lives in services; this layer only translates HTTP <-> service calls
(NFR-ARC-02). Every handler declares the permission it needs (SEC-AZ-03).
"""
from __future__ import annotations

import hmac
import json
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import BASE_DIR, settings
from app.core.context import get_ctx
from app.core.errors import AppError, Forbidden, NotFound
from app.core.i18n import fmt_date, fmt_dt, to_local_input, translate
from app.core.money import format_money, from_minor
from app.core.security import sign_payload
from app.db import get_db
from app.modules.accounts.models import Company, User, UserSession
from app.modules.accounts.permissions import company_can, staff_can
from app.modules.accounts.service import load_session, memberships, role_in

SESSION_COOKIE = "abdex_session"
FLASH_COOKIE = "abdex_flash"
DEVICE_COOKIE = "abdex_device"
LANG_COOKIE = "abdex_lang"

templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
_flash_signer = URLSafeSerializer(settings.secret_key, salt="flash")


@dataclass
class Principal:
    user: User
    session: UserSession
    company: Company | None
    role: str | None

    @property
    def is_staff(self) -> bool:
        return bool(self.user.staff_role)

    def can(self, perm: str) -> bool:
        if perm.startswith("admin."):
            return staff_can(self.user.staff_role, perm)
        return company_can(self.role, perm)


class LoginRequired(Exception):
    pass


class MfaRequired(Exception):
    pass


def get_principal_optional(request: Request, db: Session = Depends(get_db)) -> Principal | None:
    if hasattr(request.state, "principal"):
        return request.state.principal
    sess = load_session(db, request.cookies.get(SESSION_COOKIE))
    principal = None
    if sess is not None:
        user = db.get(User, sess.user_id)
        if user is not None and not user.is_blocked and not user.is_deleted:
            company = db.get(Company, sess.active_company_id) if sess.active_company_id else None
            role = role_in(db, user.id, company.id) if company else None
            if company is not None and role is None:
                company = None  # membership revoked
            principal = Principal(user=user, session=sess, company=company, role=role)
            ctx = get_ctx()
            ctx.user_id = user.id
            ctx.company_id = company.id if company else None
            ctx.role = user.staff_role if sess.is_admin else (role or "")
            ctx.locale = request.cookies.get(LANG_COOKIE) or user.locale or ctx.locale
            ctx.timezone = user.timezone or ctx.timezone
            if sess.impersonator_id:
                ctx.extra["impersonator"] = str(sess.impersonator_id)
    request.state.principal = principal
    return principal


def get_principal(request: Request, principal: Principal | None = Depends(get_principal_optional)) -> Principal:
    if principal is None:
        raise LoginRequired()
    if not principal.session.mfa_passed and request.url.path not in ("/login/2fa", "/logout"):
        raise MfaRequired()
    if principal.session.impersonator_id and not getattr(request.state, "impersonation_logged", False):
        _impersonation_guard(request, principal)
    return principal


def _impersonation_guard(request: Request, principal: Principal) -> None:
    """FR-ADM-05: every request of a support session is journaled; sensitive actions are refused."""
    from app.core.audit import audit
    from app.db import SessionLocal
    from app.modules.accounts.support_access import is_forbidden

    request.state.impersonation_logged = True
    forbidden = is_forbidden(request.url.path, request.method)
    db = SessionLocal()
    try:
        audit(db, "impersonation.request", object_type="user", object_id=principal.user.id,
              user_id=principal.session.impersonator_id, result="denied" if forbidden else "ok",
              details={"method": request.method, "path": request.url.path[:200], "session": str(principal.session.id)})
        db.commit()
    finally:
        db.close()
    if forbidden:
        raise Forbidden("impersonation_forbidden")


def require(perm: str):
    """Dependency factory: default deny (SEC-AZ-03)."""

    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if perm.startswith("admin."):
            if not p.session.is_admin or not staff_can(p.user.staff_role, perm):
                raise NotFound()  # admin surface is invisible to non-staff
            if settings.require_2fa_privileged and not p.user.totp_enabled:
                raise Forbidden("2fa_required")
            return p
        if p.company is None or not company_can(p.role, perm):
            raise Forbidden()
        return p

    dep.__name__ = f"require_{perm.replace('.', '_')}"
    dep.permission = perm  # type: ignore[attr-defined]
    return dep


async def csrf_protect(request: Request) -> None:
    """SEC-APP-04: every state-changing browser request carries the session CSRF token."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.url.path.startswith("/api/") and request.headers.get("x-api-key"):
        return  # API-key clients are not browsers; no ambient credentials to forge
    from app.core.security import hash_token
    from app.db import SessionLocal

    expected: list[str] = []
    pre = request.cookies.get("abdex_pre_csrf", "")
    if pre:
        expected.append(pre)  # double-submit token for anonymous forms (login, registration)
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        db = SessionLocal()
        try:
            sess = db.execute(select(UserSession).where(UserSession.token_hash == hash_token(raw))).scalar_one_or_none()
            if sess is not None and sess.revoked_at is None:
                expected.append(sess.csrf_token)
        finally:
            db.close()
    sent = request.headers.get("x-csrf-token", "")
    if not sent:
        ctype = request.headers.get("content-type", "")
        if "form" in ctype:
            form = await request.form()
            sent = str(form.get("csrf_token", ""))
    if not sent or not any(hmac.compare_digest(e, sent) for e in expected if e):
        raise AppError("csrf_failed", status_code=403)


def safe_next(target: str | None, default: str = "/dashboard") -> str:
    """SEC-APP-09: redirects only to internal paths."""
    if not target:
        return default
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return default
    return target


def redirect(url: str, *, flash: tuple[str, str] | None = None, status_code: int = 303) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=status_code)
    if flash:
        set_flash(resp, *flash)
    return resp


def set_flash(resp, kind: str, key: str, **params) -> None:
    resp.set_cookie(FLASH_COOKIE, _flash_signer.dumps({"k": kind, "m": key, "p": params}), httponly=True,
                    samesite="lax", secure=settings.secure_cookies, max_age=60)


def pop_flash(request: Request) -> dict | None:
    raw = request.cookies.get(FLASH_COOKIE)
    if not raw:
        return None
    try:
        data = _flash_signer.loads(raw)
    except BadSignature:
        return None
    request.state.clear_flash = True
    return data


def file_url(file_id, ttl: int = 300) -> str:
    """FR-DOC-08: short-lived signed link; permission is re-checked on download too."""
    return f"/files/{file_id}?sig={sign_payload(str(file_id), ttl)}"


def parse_uuid(value) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        raise NotFound()


def render(request: Request, name: str, ctx: dict[str, Any] | None = None, *, status_code: int = 200):
    principal: Principal | None = getattr(request.state, "principal", None)
    data = dict(ctx or {})
    data.setdefault("errors", {})
    data.setdefault("form", {})
    data["request"] = request
    data["me"] = principal
    data["flash"] = pop_flash(request)
    data["csrf_token"] = principal.session.csrf_token if principal else getattr(request.state, "pre_csrf", "")
    data["locale"] = get_ctx().locale
    if principal is not None:
        from app.db import SessionLocal
        from app.modules.notifications.service import unread_count

        db = SessionLocal()
        try:
            data["unread"] = unread_count(db, principal.user.id)
            data["my_companies"] = memberships(db, principal.user.id)
            if principal.session.impersonator_id:
                staff = db.get(User, principal.session.impersonator_id)
                data["impersonator"] = staff.full_name if staff else "—"
        finally:
            db.close()
    resp = templates.TemplateResponse(request, name, data, status_code=status_code)
    if getattr(request.state, "clear_flash", False):
        resp.delete_cookie(FLASH_COOKIE)
    return resp


def _t(key: str, **params) -> str:
    return translate(key, **params)


def _role_label(code: str | None) -> str:
    """Built-in roles have translations; roles added by an administrator carry their own names (FR-ACL-06)."""
    if not code:
        return ""
    from app.modules.accounts.permissions import role_name

    text = translate(f"role.{code}")
    if text != f"role.{code}":
        return text
    return role_name(code, get_ctx().locale) or code


def _status_label(status: str) -> str:
    return translate(f"status.{status}")


def _sysmsg(body: str) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return body
    params = {k: (_status_label(v) if k in ("frm", "to") else translate(f"cp.{v}") if k == "kind" else v)
              for k, v in (data.get("params") or {}).items()}
    return translate(data.get("key", ""), **params)


templates.env.globals.update(
    _=_t,
    fmt_dt=fmt_dt,
    fmt_date=fmt_date,
    money=format_money,
    from_minor=from_minor,
    to_local_input=to_local_input,
    status_label=_status_label,
    role_label=_role_label,
    timedelta_days=lambda n: __import__("datetime").timedelta(days=n),
    sysmsg=_sysmsg,
    file_url=file_url,
    settings=settings,
    json_loads=json.loads,
    new_token=lambda: __import__("secrets").token_urlsafe(16),
)
