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
