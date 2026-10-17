"""Public pages, authentication, registration, file downloads."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.config import BASE_DIR, settings
from app.core.errors import AppError, NotFound, ValidationFailed
from app.core.i18n import LOCALES
from app.core.security import verify_signed_payload
from app.db import get_db
from app.modules.accounts import service as accounts
from app.modules.accounts.models import User
from app.modules.platform.service import localized_setting
from app.web.deps import (
    LANG_COOKIE,
    SESSION_COOKIE,
    Principal,
    csrf_protect,
    get_principal,
    get_principal_optional,
    parse_uuid,
    redirect,
    render,
    safe_next,
    set_flash,
)

router = APIRouter(dependencies=[Depends(csrf_protect)])


def _set_session_cookie(resp, raw: str, *, admin: bool = False) -> None:
    resp.set_cookie(SESSION_COOKIE, raw, httponly=True, secure=settings.secure_cookies, samesite="lax",
                    max_age=settings.session_absolute_days * 86400, path="/")


@router.get("/")
def landing(request: Request, db: Session = Depends(get_db), me: Principal | None = Depends(get_principal_optional)):
    return render(request, "public/landing.html", {"role_text": localized_setting(db, "platform.role_explanation")})


@router.get("/lang/{code}")
def set_lang(code: str, request: Request, next: str = "/"):
    resp = redirect(safe_next(next, "/"))
    if code in LOCALES:
        resp.set_cookie(LANG_COOKIE, code, max_age=3600 * 24 * 365, samesite="lax", secure=settings.secure_cookies)
    return resp


def _eds_ctx(db: Session) -> dict:
    from app.modules.accounts import eds_login
    from app.modules.documents.eds import is_dev_signer

    return {"eds_login": eds_login.enabled(db), "eds_mode": "dev" if is_dev_signer() else "ncalayer"}


@router.get("/login")
def login_form(request: Request, next: str = "", db: Session = Depends(get_db),
               me: Principal | None = Depends(get_principal_optional)):
    return render(request, "public/login.html", {"next": safe_next(next, ""), **_eds_ctx(db)})


@router.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    nxt = safe_next(str(form.get("next", "")), "/dashboard")
    try:
        user = accounts.authenticate(db, str(form.get("login", "")), str(form.get("password", "")))
    except AppError as exc:
        db.commit()  # keep failed-attempt counters and audit entries
        return render(request, "public/login.html", {"error": exc.message_key, "form": {"login": form.get("login")},
                                                     "next": nxt, **_eds_ctx(db)}, status_code=exc.status_code)
    return _signed_in(db, user, nxt)


def _signed_in(db: Session, user: User, nxt: str):
    is_admin = bool(user.staff_role)
    raw, sess = accounts.create_session(db, user, mfa_passed=not accounts.requires_second_factor(db, user),
                                        is_admin=is_admin)
    db.commit()
    if not sess.mfa_passed:
        target = "/login/2fa"
        if user.sms_2fa_enabled and not user.totp_enabled:
            accounts.start_login_sms(db, user)  # SMS is the chosen second factor: send the code right away
            db.commit()
    elif accounts.must_enroll_2fa(db, user):
        target = "/account/security?enroll=1"
    elif not user.phone_verified:
        target = "/verify-phone"
    else:
        target = "/admin" if is_admin and nxt == "/dashboard" else nxt
    resp = redirect(target)
    _set_session_cookie(resp, raw)
    return resp


@router.post("/login/eds/challenge")
def eds_challenge(db: Session = Depends(get_db)):
    """FR-AUTH-09: a one-time text to sign (login or binding the EDS)."""
    from fastapi.responses import JSONResponse

    from app.modules.accounts import eds_login

    if not eds_login.enabled(db):
        raise NotFound()
    challenge = eds_login.new_challenge(db)
    db.commit()
    return JSONResponse({"challenge": challenge}, headers={"Cache-Control": "no-store"})


@router.post("/login/eds")
async def login_eds(request: Request, db: Session = Depends(get_db)):
    from app.modules.accounts import eds_login

    form = await request.form()
    nxt = safe_next(str(form.get("next", "")), "/dashboard")
    try:
        user = eds_login.authenticate(db, str(form.get("package", "")), str(form.get("challenge", "")))
    except AppError as exc:
        db.commit()
        resp = redirect("/login")
        set_flash(resp, "error", exc.message_key, **exc.params)
        return resp
    return _signed_in(db, user, nxt)


@router.get("/login/2fa")
def twofa_form(request: Request, me: Principal = Depends(get_principal)):
    from app.core.security import mask_phone

    if me.session.mfa_passed:
        return redirect("/dashboard")
    return render(request, "public/login_2fa.html", {"phone_masked": mask_phone(me.user.phone),
                                                     "sms_mode": me.user.sms_2fa_enabled and not me.user.totp_enabled})


@router.post("/login/2fa")
async def twofa(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    if form.get("send_sms"):
        accounts.send_otp(db, me.user.phone, "login_2fa")
        db.commit()
        return redirect("/login/2fa", flash=("info", "msg.code_sent"))
    user = db.get(User, me.user.id)
    if not accounts.verify_second_factor(db, user, str(form.get("code", ""))):
        db.commit()
        from app.core.security import mask_phone

        return render(request, "public/login_2fa.html", {
            "error": "error.code_invalid", "phone_masked": mask_phone(user.phone),
            "sms_mode": user.sms_2fa_enabled and not user.totp_enabled}, status_code=400)
    # SEC-AUT-06: new session id after privilege elevation
    sess = db.merge(me.session)
    accounts.revoke_session(db, sess)
    raw, new = accounts.create_session(db, user, mfa_passed=True, is_admin=sess.is_admin)
    db.commit()
    resp = redirect("/admin" if new.is_admin else "/dashboard")
    _set_session_cookie(resp, raw)
    return resp


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db), me: Principal | None = Depends(get_principal_optional)):
    if me:
        accounts.revoke_session(db, db.merge(me.session))
        db.commit()
    resp = redirect("/")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/register")
def register_form(request: Request, type: str = "client", db: Session = Depends(get_db),
                  me: Principal | None = Depends(get_principal_optional)):
    from app.modules.analytics.product import track

    track(db, "register_view", role=type if type in ("client", "carrier", "driver") else "")
    db.commit()
    return render(request, "public/register.html", {"form": {"account_type": type}})


@router.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    data = accounts.RegistrationData(
        full_name=str(form.get("full_name", "")), phone=str(form.get("phone", "")), email=str(form.get("email", "")),
        password=str(form.get("password", "")), account_type=str(form.get("account_type", "")),
        company_name=str(form.get("company_name", "")), bin_iin=str(form.get("bin_iin", "")),
        consent_registration=bool(form.get("consent_registration")), locale=request.cookies.get(LANG_COOKIE, "ru"))
    try:
        user = accounts.register(db, data)
    except ValidationFailed as exc:
        db.rollback()
        safe = {k: v for k, v in form.items() if k not in ("password", "csrf_token")}
        return render(request, "public/register.html", {"errors": exc.fields, "form": safe}, status_code=422)
    raw, _ = accounts.create_session(db, user, mfa_passed=True)
    from app.modules.analytics.product import track

    track(db, "register_done", role=data.account_type)
    db.commit()
    resp = redirect("/verify-phone", flash=("info", "msg.code_sent"))
    _set_session_cookie(resp, raw)
    return resp


@router.get("/verify-phone")
def verify_phone_form(request: Request, me: Principal = Depends(get_principal)):
    return render(request, "public/verify_phone.html")


@router.post("/verify-phone")
async def verify_phone(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    user = db.get(User, me.user.id)
    if form.get("resend"):
        accounts.send_otp(db, user.phone, "verify_phone")
        db.commit()
        return redirect("/verify-phone", flash=("info", "msg.code_sent"))
    if not accounts.check_otp(db, user.phone, "verify_phone", str(form.get("code", ""))):
        db.commit()
        return render(request, "public/verify_phone.html", {"error": "error.code_invalid"}, status_code=400)
    user.phone_verified = True
    from app.modules.analytics.product import track

    track(db, "phone_verified")
    db.commit()
    return redirect("/dashboard", flash=("success", "msg.phone_verified"))


@router.get("/forgot-password")
def forgot_form(request: Request):
    return render(request, "public/forgot.html")


@router.post("/forgot-password")
async def forgot(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    accounts.start_password_reset(db, str(form.get("login", "")))
    db.commit()
    return render(request, "public/forgot.html", {"sent": True})  # same answer either way (SEC-AUT-09)


@router.get("/reset-password")
def reset_form(request: Request, u: str = "", t: str = ""):
    return render(request, "public/reset.html", {"u": u, "t": t})


@router.post("/reset-password")
async def reset(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    try:
        accounts.finish_password_reset(db, str(form.get("u", "")), str(form.get("t", "")), str(form.get("password", "")))
    except AppError as exc:
        db.rollback()
        return render(request, "public/reset.html", {"u": form.get("u"), "t": form.get("t"),
                                                     "error": next(iter(exc.fields.values()), exc.message_key)},
                      status_code=400)
    db.commit()
    return redirect("/login", flash=("success", "msg.password_changed"))


@router.get("/invite/{raw}")
def invite_page(raw: str, request: Request, me: Principal | None = Depends(get_principal_optional)):
    return render(request, "public/invite.html", {"raw": raw})


@router.post("/invite/{raw}")
def invite_accept(raw: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    company = accounts.accept_invitation(db, db.get(User, me.user.id), raw)
    sess = db.merge(me.session)
    sess.active_company_id = company.id
    db.commit()
    return redirect("/dashboard", flash=("success", "msg.joined_company"))


@router.get("/legal/{page}")
def legal(page: str, request: Request, db: Session = Depends(get_db),
          me: Principal | None = Depends(get_principal_optional)):
    if page not in ("privacy", "terms", "security"):
        raise NotFound()
    ctx = {"role_text": localized_setting(db, "platform.role_explanation")}
    if page == "privacy":  # SEC-DAT-11: recipients and cross-border transfers are public
        from app.modules.platform.processing import records

        ctx["processing"] = records(db, active_only=True)
    return render(request, f"public/legal_{page}.html", ctx)


@router.get("/help")
def help_page(request: Request, me: Principal | None = Depends(get_principal_optional)):
    return render(request, "public/help.html")


@router.get("/files/{file_id}")
def download(file_id: str, sig: str, request: Request, db: Session = Depends(get_db),
             me: Principal = Depends(get_principal)):
    """FR-DOC-08 / SEC-FIL-04/05: signed short-lived link + permission check on every request."""
    from app.modules.documents.service import get_file
    from app.web.access import assert_file_access

    fid = parse_uuid(file_id)
    if not verify_signed_payload(str(fid), sig):
        raise NotFound()
    assert_file_access(db, me, fid)
    f, data = get_file(db, fid)
    db.commit()
    disposition = "inline" if f.content_type in ("application/pdf", "image/jpeg", "image/png", "image/webp") else "attachment"
    ascii_name = "".join(ch if ch.isascii() and ch not in '";\\' else "_" for ch in f.original_name)
    return Response(content=data, media_type=f.content_type, headers={
        "Content-Disposition": f'{disposition}; filename="{ascii_name}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox",
        "Cache-Control": "private, no-store"})


@router.get("/manifest.webmanifest")
def manifest():
    return FileResponse(BASE_DIR / "app" / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@router.get("/sw.js")
def service_worker():
    return FileResponse(BASE_DIR / "app" / "static" / "js" / "sw.js", media_type="application/javascript",
                        headers={"Service-Worker-Allowed": "/"})


@router.get("/healthz")
def health(db: Session = Depends(get_db)):
    from sqlalchemy import text

    db.execute(text("SELECT 1"))
    return {"status": "ok"}


@router.get("/dev/outbox")
def dev_outbox(request: Request, me: Principal | None = Depends(get_principal_optional)):
    """Development/demo only: shows the SMS / e-mail / Telegram messages that would have been sent.
    Only the signed-in user's own messages are listed: on a public demo the page must not hand out
    other people's login codes or password-reset links."""
    if not settings.is_dev:
        raise NotFound()
    from app.modules.integrations.adapters import _OutboundAdapter

    mine: list = []
    if me is not None and not me.session.impersonator_id:  # support never sees the user's codes
        targets = {me.user.phone, me.user.email or "", str(me.user.id)} - {""}
        mine = [m for m in reversed(_OutboundAdapter.sent) if m["to"] in targets]
    return render(request, "public/dev_outbox.html", {"messages": mine, "anonymous": me is None})
