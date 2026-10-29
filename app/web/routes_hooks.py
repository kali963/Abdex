"""Inbound webhooks from external systems. No browser session and no CSRF token here:
each hook authenticates the caller itself (SEC-APP-12)."""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core import ratelimit
from app.core.errors import NotFound
from app.db import get_db

router = APIRouter()


@router.post("/hooks/telegram")
async def telegram_webhook(request: Request, db: Session = Depends(get_db),
                           x_telegram_bot_api_secret_token: str = Header(default="")):
    """FR-NTF-02: the user sends `/start <code>` to the bot; the chat is bound to the account
    that generated the code. Telegram proves itself with the secret set in setWebhook."""
    secret = settings.telegram_webhook_secret
    if not secret or not hmac.compare_digest(secret, x_telegram_bot_api_secret_token):
        raise NotFound()
    ratelimit.hit("api", "telegram-hook")
    from app.modules.notifications.telegram_bot import handle_update

    handle_update(db, await request.json())
    db.commit()
    return {"ok": True}


@router.get("/metrics")
def metrics(request: Request, db: Session = Depends(get_db)):
    """NFR-OBS-01/02: Prometheus scrape endpoint; invisible without the bearer token."""
    from fastapi.responses import PlainTextResponse

    from app.core.metrics import render

    sent = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not settings.metrics_token or not hmac.compare_digest(sent, settings.metrics_token):
        raise NotFound()
    from app.core import rls

    with rls.system(db):  # platform-wide counts: every company's rows (read-only queries)
        body = render(db)
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


@router.post("/hooks/payments")
async def payment_callback(request: Request, db: Session = Depends(get_db),
                           x_abdex_pay_signature: str = Header(default="")):
    """FR-BIL-06, SEC-APP-12: provider callback, authenticated by HMAC signature with a time stamp."""
    from app.modules.billing import payments

    ratelimit.hit("api", "payment-hook")
    body = await request.body()
    status = payments.handle_callback(db, body, x_abdex_pay_signature)
    db.commit()
    return {"ok": True, "status": status}
