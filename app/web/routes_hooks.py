"""Inbound webhooks from external systems. No browser session and no CSRF token here:
each hook authenticates the caller itself (SEC-APP-12)."""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import ratelimit
from app.core.audit import audit
from app.core.errors import NotFound
from app.db import get_db
from app.modules.notifications.models import ChannelLink

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
    update = await request.json()
    message = (update or {}).get("message") or {}
    # SEC-APP-12: timestamp and replay protection on top of the secret header
    import time
    import uuid

    from sqlalchemy.exc import IntegrityError

    from app.modules.platform.models import IdempotencyKey

    sent_at = int(message.get("date") or 0)
    if not sent_at or abs(time.time() - sent_at) > 600:
        return {"ok": True}
    update_id = str((update or {}).get("update_id") or "")
    if update_id:
        try:
            with db.begin_nested():
                db.add(IdempotencyKey(user_id=uuid.UUID(int=0), key=f"tg:{update_id}"[:80], scope="telegram_update"))
                db.flush()
        except IntegrityError:
            return {"ok": True}  # the same update delivered twice
        db.commit()
    text = str(message.get("text") or "").strip()
    chat_id = str((message.get("chat") or {}).get("id") or "")
    if not chat_id or not text.startswith("/start "):
        return {"ok": True}
    code = text.split(" ", 1)[1].strip().upper()[:20]
    link = db.execute(select(ChannelLink).where(ChannelLink.channel == "telegram", ChannelLink.link_code == code,
                                                ChannelLink.link_code != "")).scalar_one_or_none()
    if link is None:
        return {"ok": True}
    link.address = chat_id
    link.link_code = ""  # one-time code
    audit(db, "notifications.telegram_linked", object_type="user", object_id=link.user_id, user_id=link.user_id)
    db.commit()
    from app.modules.integrations.adapters import telegram

    telegram.send(chat_id, "AbdEX: Telegram привязан к вашему аккаунту.")
    return {"ok": True}


@router.get("/metrics")
def metrics(request: Request, db: Session = Depends(get_db)):
    """NFR-OBS-01/02: Prometheus scrape endpoint; invisible without the bearer token."""
    from fastapi.responses import PlainTextResponse

    from app.core.metrics import render

    sent = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not settings.metrics_token or not hmac.compare_digest(sent, settings.metrics_token):
        raise NotFound()
    return PlainTextResponse(render(db), media_type="text/plain; version=0.0.4")
