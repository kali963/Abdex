"""Cabinet home, account security, sessions, consents, company profile, members, verification."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.i18n import LOCALES
from app.config import settings
from app.core.errors import AppError, Forbidden, NotFound, ValidationFailed
from app.core.security import mask_phone, new_totp_secret, token, totp_uri
from app.core.storage import save_upload
from app.db import get_db, utcnow
from app.modules.accounts import service as accounts
from app.modules.accounts.models import (
    Company,
    Consent,
    Invitation,
    Membership,
    User,
    UserSession,
)
from app.modules.accounts.permissions import roles_in_scope
from app.modules.documents.eds import is_dev_signer
from app.modules.fleet import level3
from app.modules.fleet import service as fleet
from app.modules.fleet.models import RegistryCheck, VerificationDocument, VerificationRequest
from app.modules.notifications.models import ChannelLink, Notification
from app.modules.platform.service import dictionary, flag_enabled
from app.web.deps import Principal, csrf_protect, get_principal, parse_uuid, redirect, render, require, set_flash

router = APIRouter(dependencies=[Depends(csrf_protect)])


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    if me.session.is_admin:
        return redirect("/admin")
    if me.company is None:
        return render(request, "cabinet/no_company.html")
    ctx: dict = {}
    from app.modules.deals.service import deals_for_company
    from app.modules.orders.service import client_orders

    if me.role == "driver":
        return redirect("/trips")
    if me.company.kind == "client":
        ctx["orders"] = client_orders(db, me.company.id, limit=8)
    else:
        from app.modules.orders.service import marketplace

        ctx["market"] = marketplace(db, me.company, {}, limit=6)
    ctx["deals"] = deals_for_company(db, me.company.id, active_only=True)[:8]
    ctx["stats"] = fleet.company_stats(db, me.company.id)
    return render(request, "cabinet/dashboard.html", ctx)


@router.post("/switch-company")
async def switch_company(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-AUTH-02: switch between companies without re-login."""
    form = await request.form()
    cid = parse_uuid(form.get("company_id"))
    if accounts.role_in(db, me.user.id, cid) is None:
        raise NotFound()
    sess = db.merge(me.session)
    sess.active_company_id = cid
    audit(db, "auth.company_switched", object_type="company", object_id=cid)
    db.commit()
    return redirect("/dashboard")


@router.get("/notifications")
def notifications(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    rows = list(db.execute(select(Notification).where(Notification.user_id == me.user.id)
                           .order_by(Notification.created_at.desc()).limit(100)).scalars())
    for n in rows:
        if n.read_at is None:
            n.read_at = utcnow()
    db.commit()
    return render(request, "cabinet/notifications.html", {"items": rows})


# ------------------------------------------------------------------ account


@router.get("/account")
def account(request: Request, me: Principal = Depends(get_principal)):
    return render(request, "account/profile.html")


@router.post("/account")
async def account_save(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    user = db.get(User, me.user.id)
    user.full_name = str(form.get("full_name", user.full_name)).strip()[:200] or user.full_name
    if form.get("locale") in LOCALES:
        user.locale = str(form["locale"])
    tz = str(form.get("timezone", ""))
    if tz in ("Asia/Almaty", "Asia/Aqtobe", "Asia/Oral", "Asia/Aqtau", "Asia/Atyrau", "Asia/Qostanay", "Asia/Qyzylorda"):
        user.timezone = tz
    db.commit()
    resp = redirect("/account", flash=("success", "msg.saved"))
    resp.set_cookie("abdex_lang", user.locale, max_age=3600 * 24 * 365, samesite="lax")
    return resp


@router.post("/account/delete")
async def delete_account(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-AUTH-10: soft delete with anonymised history; confirmed by the current password."""
    from app.core.security import verify_password

    form = await request.form()
    user = db.get(User, me.user.id)
    if user.staff_role:
        raise AppError("staff_delete_via_admin")
    if not verify_password(user.password_hash, str(form.get("password", ""))):
        raise ValidationFailed({"password": "error.invalid_password"})
    if form.get("confirm") != "on":
        raise ValidationFailed({"confirm": "error.confirm_required"})
    accounts.anonymize_user(db, user, reason="self-service request")
    db.commit()
    from app.web.deps import SESSION_COOKIE

    resp = redirect("/", flash=("success", "msg.account_deleted"))
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/account/security")
def security(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal), enroll: int = 0):
    ctx = {"enroll": enroll, "must": accounts.must_enroll_2fa(db, me.user),
           "sms_action": request.query_params.get("sms", ""), "phone_masked": mask_phone(me.user.phone)}
    from app.modules.accounts.support_access import MAX_GRANT_HOURS, active_grant

    ctx["support_grant"] = active_grant(db, me.user.id)
    ctx["max_grant_hours"] = MAX_GRANT_HOURS
    # a support session never sees the authenticator secret of the user (FR-ADM-05)
    if not me.user.totp_enabled and not me.session.impersonator_id:
        user = db.get(User, me.user.id)
        if not user.totp_secret:
            user.totp_secret = new_totp_secret()
            db.commit()
        ctx["secret"] = user.totp_secret
        ctx["uri"] = totp_uri(user.totp_secret, user.email or user.phone)
        import segno

        ctx["qr"] = segno.make(ctx["uri"], error="m").svg_data_uri(scale=4, border=2)
    from app.modules.accounts import eds_login
    from app.modules.documents.eds import is_dev_signer

    from app.modules.accounts import egov_mobile

    ctx["eds_login"] = eds_login.enabled(db)
    ctx["egov_login"] = egov_mobile.enabled(db)
    ctx["eds_mode"] = "dev" if is_dev_signer() else "ncalayer"
    return render(request, "account/security.html", ctx)


@router.post("/account/eds/link")
async def eds_link(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-AUTH-09: bind the EDS for login (the IIN comes from the verified certificate)."""
    from app.modules.accounts import eds_login

    if me.session.impersonator_id:
        raise Forbidden("impersonation_forbidden")
    form = await request.form()
    user = db.get(User, me.user.id)
    try:
        eds_login.link(db, user, str(form.get("package", "")), str(form.get("challenge", "")),
                       request.cookies.get(eds_login.BIND_COOKIE, ""))
    except AppError as exc:
        db.commit()
        resp = redirect("/account/security#eds")
        set_flash(resp, "error", exc.message_key, **exc.params)
        return resp
    db.commit()
    return redirect("/account/security#eds", flash=("success", "eds.linked"))


EGOV_LINK_COOKIE = "abdex_egov_link"


@router.post("/account/egov/link/start")
def egov_link_start(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-AUTH-09: bind the EDS kept in eGov mobile / eGov Business (QR code or a button on the same phone)."""
    from fastapi.responses import JSONResponse

    from app.modules.accounts import egov_mobile
    from app.web.routes_public import _public_base

    if not egov_mobile.enabled(db):
        raise NotFound()
    if me.session.impersonator_id:
        raise Forbidden("impersonation_forbidden")
    token, browser, show = egov_mobile.start_safely(db, base=_public_base(request), link_user_id=me.user.id)
    db.commit()
    if "launch" in show:
        show.pop("launch")()  # SIGEX: wait for the signature in the background
    data = egov_mobile.for_browser(token, show, f"/account/egov/link/{token}/status")
    resp = JSONResponse(data, headers={"Cache-Control": "no-store"})
    resp.set_cookie(EGOV_LINK_COOKIE, browser, max_age=300, httponly=True, secure=settings.secure_cookies,
                    samesite="strict", path="/account/egov")
    return resp


@router.get("/account/egov/link/{token}/status")
def egov_link_status(token: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(get_principal)):
    from fastapi.responses import JSONResponse

    from app.core.i18n import translate
    from app.modules.accounts import egov_mobile

    try:
        state = egov_mobile.poll_link(db, token, request.cookies.get(EGOV_LINK_COOKIE, ""), user_id=me.user.id)
    except AppError as exc:
        if isinstance(exc, NotFound):
            raise
        db.commit()
        return JSONResponse({"status": "failed", "message": translate(exc.message_key, **exc.params)})
    db.commit()
    if state != "signed":
        return JSONResponse({"status": state})
    resp = JSONResponse({"status": "signed", "redirect": "/account/security#eds"})
    set_flash(resp, "success", "eds.linked")
    resp.delete_cookie(EGOV_LINK_COOKIE, path="/account/egov")
    return resp


@router.post("/account/eds/unlink")
def eds_unlink(db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    from app.modules.accounts import eds_login

    if me.session.impersonator_id:
        raise Forbidden("impersonation_forbidden")
    eds_login.unlink(db, db.get(User, me.user.id))
    db.commit()
    return redirect("/account/security#eds", flash=("success", "eds.unlinked"))


@router.post("/dev/eds/login-certificate")
async def dev_login_certificate(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """Development only: a TEST personal certificate for a browser-generated key (kept in the browser)."""
    from fastapi.responses import JSONResponse

    from app.core import ratelimit
    from app.modules.accounts import eds_login
    from app.modules.documents import eds

    if not eds.is_dev_signer() or me.session.impersonator_id:
        raise NotFound()
    form = await request.form()
    ratelimit.hit("otp_send", f"devcert:{me.user.id}")
    try:
        pem = eds.dev_issue(str(form.get("public_key", "")), full_name=me.user.full_name, iin=eds_login.dev_iin(me.user),
                            bin_iin=me.company.bin_iin if me.company else "")
    except ValueError:
        raise ValidationFailed({"public_key": "error.invalid_value"})
    audit(db, "eds.dev_certificate_issued", object_type="user", object_id=me.user.id)
    db.commit()
    return JSONResponse({"certificate": pem})


@router.post("/account/password")
async def change_password(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    user = db.get(User, me.user.id)
    accounts.change_password(db, user, str(form.get("current_password", "")), str(form.get("new_password", "")))
    # SEC-AUT-06: new session after password change; other sessions are ended
    accounts.revoke_all_sessions(db, user.id, except_id=None)
    raw, _ = accounts.create_session(db, user, mfa_passed=True, is_admin=me.session.is_admin)
    db.commit()
    from app.web.routes_public import _set_session_cookie

    resp = redirect("/account/security", flash=("success", "msg.password_changed"))
    _set_session_cookie(resp, raw)
    return resp


@router.post("/account/2fa/enable")
async def enable_2fa(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """Authenticator app (TOTP)."""
    form = await request.form()
    user = db.get(User, me.user.id)
    if not accounts.verify_totp_code(user, str(form.get("code", ""))):
        db.commit()
        raise ValidationFailed({"code": "error.code_invalid"})
    user.totp_enabled = True
    audit(db, "auth.2fa_enabled", object_type="user", object_id=user.id)
    from app.modules.notifications.service import notify_user

    notify_user(db, user.id, "security.2fa_changed", {}, link="/account/security", critical=True)
    db.commit()
    return redirect("/admin" if me.session.is_admin else "/account/security", flash=("success", "msg.2fa_enabled"))


@router.post("/account/2fa/disable")
async def disable_2fa(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    user = db.get(User, me.user.id)
    if accounts.must_enroll_2fa(db, user, totp=False):
        raise AppError("2fa_mandatory")
    if not accounts.verify_totp_code(user, str(form.get("code", ""))):
        db.commit()
        raise ValidationFailed({"code": "error.code_invalid"})
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_step = 0
    audit(db, "auth.2fa_disabled", object_type="user", object_id=user.id)
    from app.modules.notifications.service import notify_user

    notify_user(db, user.id, "security.2fa_changed", {}, link="/account/security", critical=True)
    db.commit()
    return redirect("/account/security", flash=("success", "msg.saved"))


@router.post("/account/2fa/sms/code")
async def sms_2fa_code(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """Step 1 of enabling or disabling SMS 2FA: a code to the account phone proves possession."""
    form = await request.form()
    action = "enable" if form.get("action") == "enable" else "disable"
    user = db.get(User, me.user.id)
    if action == "disable" and accounts.must_enroll_2fa(db, user, sms=False):
        raise AppError("2fa_mandatory")
    accounts.send_otp(db, user.phone, f"sms_2fa_{action}")
    db.commit()
    return redirect(f"/account/security?sms={action}#sms", flash=("info", "msg.code_sent"))


@router.post("/account/2fa/sms/confirm")
async def sms_2fa_confirm(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    action = "enable" if form.get("action") == "enable" else "disable"
    user = db.get(User, me.user.id)
    if action == "disable" and accounts.must_enroll_2fa(db, user, sms=False):
        raise AppError("2fa_mandatory")
    if not accounts.check_otp(db, user.phone, f"sms_2fa_{action}", str(form.get("code", ""))):
        db.commit()
        raise ValidationFailed({"code": "error.code_invalid"})
    accounts.set_sms_2fa(db, user, action == "enable")
    db.commit()
    message = "msg.2fa_enabled" if action == "enable" else "msg.2fa_sms_disabled"
    return redirect("/admin" if me.session.is_admin and action == "enable" else "/account/security",
                    flash=("success", message))


@router.get("/account/sessions")
def sessions(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    rows = list(db.execute(select(UserSession).where(UserSession.user_id == me.user.id,
                                                     UserSession.revoked_at.is_(None))
                           .order_by(UserSession.last_seen_at.desc())).scalars())
    return render(request, "account/sessions.html", {"items": rows})


@router.post("/account/sessions/{sid}/revoke")
def revoke(sid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    s = db.get(UserSession, parse_uuid(sid))
    if s is None or s.user_id != me.user.id:
        raise NotFound()
    accounts.revoke_session(db, s)
    db.commit()
    return redirect("/account/sessions", flash=("success", "msg.session_ended"))


@router.post("/account/sessions/revoke-all")
def revoke_all(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    accounts.revoke_all_sessions(db, me.user.id, except_id=me.session.id)
    db.commit()
    return redirect("/account/sessions", flash=("success", "msg.sessions_ended"))


@router.get("/account/consents")
def consents(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    rows = list(db.execute(select(Consent).where(Consent.user_id == me.user.id).order_by(Consent.created_at.desc()))
                .scalars())
    active = {c.purpose for c in rows if c.revoked_at is None}
    return render(request, "account/consents.html", {"items": rows, "active": active,
                                                     "purposes": ("registration", "verification", "biometrics",
                                                                  "geolocation", "marketing")})


@router.post("/account/consents/{purpose}")
async def consent_toggle(purpose: str, request: Request, db: Session = Depends(get_db),
                         me: Principal = Depends(get_principal)):
    if purpose not in ("verification", "biometrics", "geolocation", "marketing"):
        raise NotFound()
    form = await request.form()
    if form.get("grant"):
        accounts.record_consent(db, me.user.id, purpose)
    else:
        accounts.revoke_consent(db, me.user.id, purpose)
    db.commit()
    from app.web.deps import safe_next

    return redirect(safe_next(str(form.get("next", "")), "/account/consents"), flash=("success", "msg.saved"))


@router.get("/account/notifications")
def notif_settings(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    from app.modules.notifications.service import USER_CATEGORIES, USER_CHANNELS, prefs_for

    links = {cl.channel: cl for cl in db.execute(select(ChannelLink).where(ChannelLink.user_id == me.user.id)).scalars()}
    disabled = {(ch, e) for ch, cl in links.items() for e in cl.disabled_events.split(",") if e}
    return render(request, "account/notifications.html", {
        "tg": links.get("telegram"), "categories": USER_CATEGORIES, "channels": USER_CHANNELS,
        "disabled": disabled, "prefs": prefs_for(db, me.user.id), "hours": [(h, f"{h:02d}:00") for h in range(24)],
        "push_key": _push_key(), "push_count": _push_count(db, me.user.id), "tg_bot": _tg_bot()})


def _tg_bot() -> dict:
    from app.modules.notifications import telegram_bot

    return {"enabled": telegram_bot.enabled(), "username": telegram_bot.bot_username() if telegram_bot.enabled() else ""}


def _push_key() -> str:
    from app.modules.notifications import webpush

    return webpush.public_key() if webpush.enabled() else ""


def _push_count(db: Session, user_id) -> int:
    from sqlalchemy import func

    from app.modules.notifications.models import PushSubscription

    return db.execute(select(func.count(PushSubscription.id)).where(PushSubscription.user_id == user_id)).scalar_one()


# ------------------------------------------------------------------ Web Push (FR-MOB-02)

MAX_PUSH_SUBSCRIPTIONS = 10


@router.post("/account/push/subscribe")
async def push_subscribe(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    from fastapi.responses import JSONResponse

    from app.core import ratelimit
    from app.modules.notifications import webpush
    from app.modules.notifications.models import PushSubscription

    if me.session.impersonator_id or not webpush.enabled():
        raise Forbidden()
    ratelimit.hit("invite", f"push:{me.user.id}")
    try:
        data = await request.json()
        endpoint = str(data["endpoint"])[:1000]
        p256dh, auth = str(data["keys"]["p256dh"])[:200], str(data["keys"]["auth"])[:100]
        if len(webpush.b64u_dec(p256dh)) != 65 or len(webpush.b64u_dec(auth)) != 16:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValidationFailed({"endpoint": "error.invalid_value"})
    if not webpush.endpoint_allowed(endpoint):
        raise ValidationFailed({"endpoint": "error.invalid_value"})
    sub = db.execute(select(PushSubscription).where(PushSubscription.endpoint == endpoint)).scalar_one_or_none()
    if sub is None:
        mine = list(db.execute(select(PushSubscription).where(PushSubscription.user_id == me.user.id)
                               .order_by(PushSubscription.created_at)).scalars())
        for old in mine[: max(0, len(mine) - MAX_PUSH_SUBSCRIPTIONS + 1)]:
            db.delete(old)
        sub = PushSubscription(user_id=me.user.id, endpoint=endpoint, p256dh=p256dh, auth=auth)
        db.add(sub)
    else:  # the same browser re-subscribed (possibly after another user signed in on it)
        sub.user_id, sub.p256dh, sub.auth = me.user.id, p256dh, auth
    sub.user_agent = request.headers.get("user-agent", "")[:300]
    audit(db, "push.subscribed", object_type="user", object_id=me.user.id)
    db.commit()
    return JSONResponse({"ok": True})


@router.post("/account/push/unsubscribe")
async def push_unsubscribe(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    from fastapi.responses import JSONResponse

    from app.modules.notifications.models import PushSubscription

    try:
        endpoint = str((await request.json()).get("endpoint", ""))
    except ValueError:
        endpoint = ""
    q = select(PushSubscription).where(PushSubscription.user_id == me.user.id)
    if endpoint:
        q = q.where(PushSubscription.endpoint == endpoint)
    for sub in db.execute(q).scalars():
        db.delete(sub)
    audit(db, "push.unsubscribed", object_type="user", object_id=me.user.id)
    db.commit()
    return JSONResponse({"ok": True})


@router.post("/account/notifications/telegram")
def telegram_link(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-NTF-02: the user sends /start <code> to the bot; the bot webhook binds chat_id."""
    tg = db.execute(select(ChannelLink).where(ChannelLink.user_id == me.user.id, ChannelLink.channel == "telegram")
                    ).scalar_one_or_none()
    if tg is None:
        tg = ChannelLink(user_id=me.user.id, channel="telegram")
        db.add(tg)
    tg.link_code = token(6)[:8].upper()
    db.commit()
    return redirect("/account/notifications")


@router.post("/account/notifications/prefs")
async def notif_prefs(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-NTF-04: channels on/off per event category; security events are not listed and always delivered."""
    from app.modules.notifications.service import USER_CATEGORIES, USER_CHANNELS

    form = await request.form()
    for ch in USER_CHANNELS:
        disabled = ",".join(e for e in USER_CATEGORIES if not form.get(f"on:{ch}:{e}"))
        link = db.execute(select(ChannelLink).where(ChannelLink.user_id == me.user.id, ChannelLink.channel == ch)
                          ).scalar_one_or_none()
        if link is None:
            link = ChannelLink(user_id=me.user.id, channel=ch, address="")
            db.add(link)
        link.disabled_events = disabled
    db.commit()
    return redirect("/account/notifications", flash=("success", "msg.saved"))


@router.post("/account/notifications/schedule")
async def notif_schedule(request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-NTF-04: quiet hours and digest instead of a stream."""
    import re

    from app.modules.notifications.models import NotificationPrefs

    form = await request.form()
    hm = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
    quiet_from, quiet_to = str(form.get("quiet_from", "")), str(form.get("quiet_to", ""))
    digest = str(form.get("digest", "off"))
    errors = {}
    if not hm.match(quiet_from):
        errors["quiet_from"] = "error.time"
    if not hm.match(quiet_to):
        errors["quiet_to"] = "error.time"
    if digest not in ("off", "hourly", "daily"):
        errors["digest"] = "error.invalid_choice"
    try:
        hour = int(form.get("digest_hour") or 9)
        if not 0 <= hour <= 23:
            raise ValueError
    except ValueError:
        errors["digest_hour"] = "error.number"
        hour = 9
    if errors:
        raise ValidationFailed(errors)
    prefs = db.execute(select(NotificationPrefs).where(NotificationPrefs.user_id == me.user.id)).scalar_one_or_none()
    if prefs is None:
        prefs = NotificationPrefs(user_id=me.user.id)
        db.add(prefs)
    prefs.quiet_enabled = bool(form.get("quiet_enabled"))
    prefs.quiet_from, prefs.quiet_to, prefs.digest, prefs.digest_hour = quiet_from, quiet_to, digest, hour
    db.commit()
    return redirect("/account/notifications", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ company


@router.get("/company")
def company(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.view"))):
    members = db.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                         .where(Membership.company_id == me.company.id).order_by(Membership.created_at)).all()
    invites = list(db.execute(select(Invitation).where(Invitation.company_id == me.company.id,
                                                       Invitation.used_at.is_(None), Invitation.revoked_at.is_(None),
                                                       Invitation.expires_at > utcnow())).scalars())
    from app.modules.accounts.models import BankAccount

    banks = list(db.execute(select(BankAccount).where(BankAccount.company_id == me.company.id)
                            .order_by(BankAccount.created_at.desc())).scalars())
    roles = roles_in_scope("client" if me.company.kind == "client" else "carrier")
    from app.modules.deals.models import TelematicsConnection

    telem = db.execute(select(TelematicsConnection).where(TelematicsConnection.company_id == me.company.id)
                       ).scalar_one_or_none() if me.company.kind == "carrier" else None
    return render(request, "company/company.html", {"members": members, "invites": invites, "banks": banks,
                                                     "roles": roles, "now": utcnow(), "telematics": telem,
                                                     "new_invite": request.query_params.get("invite")})


@router.post("/company/telematics")
async def company_telematics(request: Request, db: Session = Depends(get_db),
                             me: Principal = Depends(require("company.manage"))):
    """FR-TRK-05: the carrier's GPS system polled by the platform."""
    from app.modules.deals import telematics

    if me.company.kind != "carrier":
        raise NotFound()
    form = await request.form()
    telematics.save_connection(db, me.company, str(form.get("url", "")), str(form.get("token", "")),
                               active=bool(form.get("active")))
    db.commit()
    return redirect("/company#telematics", flash=("success", "msg.saved"))


@router.post("/company")
async def company_save(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    c = db.get(Company, me.company.id)
    for f in ("name", "legal_form", "legal_address", "actual_address", "contact_phone", "contact_email"):
        if f in form:
            setattr(c, f, str(form[f]).strip()[:500])
    c.vat_payer = bool(form.get("vat_payer"))
    if me.company.kind == "carrier":
        c.show_finance_to_drivers = bool(form.get("show_finance_to_drivers"))
    if form.get("locale") in LOCALES:
        c.locale = str(form["locale"])
    audit(db, "company.updated", object_type="company", object_id=c.id)
    db.commit()
    return redirect("/company", flash=("success", "msg.saved"))


@router.post("/company/invite")
async def invite(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    raw = accounts.create_invitation(db, me.company, str(form.get("role", "")), str(form.get("note", "")))
    db.commit()
    return redirect(f"/company?invite={raw}")


@router.post("/company/invite/{iid}/revoke")
def invite_revoke(iid: str, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    inv = db.get(Invitation, parse_uuid(iid))
    if inv is None or inv.company_id != me.company.id:
        raise NotFound()
    inv.revoked_at = utcnow()
    db.commit()
    return redirect("/company", flash=("success", "msg.saved"))


@router.post("/company/members/{mid}/disable")
def member_disable(mid: str, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    accounts.deactivate_member(db, me.company, parse_uuid(mid))
    db.commit()
    return redirect("/company", flash=("success", "msg.saved"))


@router.post("/company/bank")
async def bank_request(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    acc = accounts.request_bank_change(db, me.company, db.get(User, me.user.id), str(form.get("iban", "")),
                                       str(form.get("bank_name", "")), str(form.get("bik", "")))
    db.commit()
    return redirect(f"/company?confirm_bank={acc.id}#bank", flash=("info", "msg.code_sent"))


@router.post("/company/bank/{aid}/confirm")
async def bank_confirm(aid: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    accounts.confirm_bank_change(db, me.company, db.get(User, me.user.id), parse_uuid(aid), str(form.get("code", "")))
    db.commit()
    return redirect("/company#bank", flash=("success", "msg.bank_changed"))


@router.get("/company/verification")
def verification(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.view"))):
    docs = list(db.execute(select(VerificationDocument).where(VerificationDocument.company_id == me.company.id)
                           .order_by(VerificationDocument.created_at.desc())).scalars())
    reqs = list(db.execute(select(VerificationRequest).where(VerificationRequest.company_id == me.company.id)
                           .order_by(VerificationRequest.created_at.desc())).scalars())
    checks = list(db.execute(select(RegistryCheck).where(RegistryCheck.company_id == me.company.id)
                             .order_by(RegistryCheck.created_at.desc()).limit(5)).scalars())
    return render(request, "company/verification.html", {
        "docs": docs, "reqs": reqs, "checks": checks, "reasons": {i.code: i.name_ru for i in dictionary(db, "verification_reject_reasons")},
        "vehicles": fleet.company_vehicles(db, me.company.id), "drivers": fleet.company_drivers(db, me.company.id),
        "l3": level3.requirements(db, me.company),
        "eds_enabled": flag_enabled(db, "qualified_signature", me.company.id),
        "eds_mode": "dev" if is_dev_signer() else "ncalayer"})


@router.post("/company/eds/challenge")
def company_eds_challenge(request: Request, db: Session = Depends(get_db),
                          me: Principal = Depends(require("company.manage"))):
    """L3: a one-time text the company signs with its qualified certificate."""
    from app.web.routes_public import eds_challenge_response

    return eds_challenge_response(db, request)


@router.post("/company/eds/confirm")
async def company_eds_confirm(request: Request, db: Session = Depends(get_db),
                              me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    company = db.get(Company, me.company.id)
    try:
        from app.modules.accounts.eds_login import BIND_COOKIE

        level3.confirm_eds(db, company, str(form.get("package", "")), str(form.get("challenge", "")),
                           request.cookies.get(BIND_COOKIE, ""))
    except AppError as exc:
        db.commit()
        resp = redirect("/company/verification#l3")
        set_flash(resp, "error", exc.message_key, **exc.params)
        return resp
    db.commit()
    return redirect("/company/verification#l3", flash=("success", "l3.eds_confirmed"))


@router.post("/company/verification/upload")
async def verification_upload(request: Request, db: Session = Depends(get_db),
                              me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    upload = form.get("file")
    if not isinstance(upload, UploadFile) and not hasattr(upload, "read"):
        raise ValidationFailed({"file": "error.required"})
    data = await upload.read()
    f = save_upload(db, data=data, original_name=upload.filename or "doc", company_id=me.company.id, user_id=me.user.id)
    expires = None
    if form.get("expires_on"):
        try:
            expires = date.fromisoformat(str(form["expires_on"]))
        except ValueError:
            raise ValidationFailed({"expires_on": "error.date"})
    subject = str(form.get("subject", "company"))
    subject_type, _, sid = subject.partition(":")
    fleet.attach_verification_document(db, me.company, subject_type=subject_type,
                                       subject_id=parse_uuid(sid) if sid else me.company.id,
                                       doc_type=str(form.get("doc_type", "other"))[:40], file_id=f.id,
                                       expires_on=expires)
    if not accounts.has_consent(db, me.user.id, "verification"):
        accounts.record_consent(db, me.user.id, "verification")
    db.commit()
    return redirect("/company/verification", flash=("success", "msg.uploaded"))


@router.post("/company/verification/submit")
def verification_submit(db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    fleet.submit_for_verification(db, db.get(Company, me.company.id))
    db.commit()
    return redirect("/company/verification", flash=("success", "msg.verification_submitted"))


@router.get("/company/card/{cid}")
def public_card(cid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-KYC-10: public participant card without personal data or documents."""
    c = db.get(Company, parse_uuid(cid))
    if c is None:
        raise NotFound()
    return render(request, "company/card.html", {"c": c, "stats": fleet.company_stats(db, c.id)})


def _ensure_company(me: Principal) -> Company:
    if me.company is None:
        raise Forbidden()
    return me.company
