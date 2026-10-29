"""The AbdEX Telegram bot (FR-NTF-02): linking a chat to an account and receiving the bot's messages.

Set up once: create a bot with @BotFather, put its token into TELEGRAM_BOT_TOKEN (and, optionally, its name
into TELEGRAM_BOT_USERNAME — otherwise it is asked from Telegram). The user presses "Open in Telegram" on
/account/notifications: Telegram opens the bot with ``/start <code>`` and the chat is bound to the account.

Two ways to receive the bot's messages:
* webhook — Telegram calls POST /hooks/telegram (needs a public https address and TELEGRAM_WEBHOOK_SECRET,
  registered with setWebhook); for the production server;
* polling — without TELEGRAM_WEBHOOK_SECRET the background worker asks Telegram for new messages itself
  (getUpdates) every few seconds; works anywhere, also on a computer without a public address.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import audit

log = logging.getLogger("abdex.telegram")
OFFSET_SETTING = "telegram.update_offset"
_username_cache: tuple[float, str] = (float("-inf"), "")


def enabled() -> bool:
    return bool(settings.telegram_bot_token)


def _api(method: str, payload: dict | None = None, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(f"https://api.telegram.org/bot{settings.telegram_bot_token}/{method}",
                                 data=json.dumps(payload or {}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
        return json.loads(resp.read(2_000_000))


def bot_username() -> str:
    """@name of the bot without the @: TELEGRAM_BOT_USERNAME, or asked from Telegram once an hour."""
    import os

    global _username_cache
    configured = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
    if configured or not enabled():
        return configured
    if time.monotonic() - _username_cache[0] < 3600 and _username_cache[1]:
        return _username_cache[1]
    try:
        name = str((_api("getMe", timeout=5).get("result") or {}).get("username") or "")
    except Exception as exc:  # noqa: BLE001 — the page still works without the name
        log.warning("telegram getMe failed: %s", type(exc).__name__)
        name = ""
    _username_cache = (time.monotonic(), name)
    return name


def handle_update(db: Session, update: dict) -> bool:
    """One message to the bot. ``/start <code>`` binds the chat to the account that generated the code.
    Returns True when a chat was linked."""
    from app.modules.notifications.models import ChannelLink
    from app.modules.platform.models import IdempotencyKey

    message = (update or {}).get("message") or {}
    # SEC-APP-12: old messages and repeated deliveries are ignored
    sent_at = int(message.get("date") or 0)
    if not sent_at or abs(time.time() - sent_at) > 600:
        return False
    update_id = str((update or {}).get("update_id") or "")
    if update_id:
        try:
            with db.begin_nested():
                db.add(IdempotencyKey(user_id=uuid.UUID(int=0), key=f"tg:{update_id}"[:80], scope="telegram_update"))
                db.flush()
        except IntegrityError:
            return False  # the same update delivered twice
    text = str(message.get("text") or "").strip()
    chat_id = str((message.get("chat") or {}).get("id") or "")
    if not chat_id or not text.startswith("/start"):
        return False
    parts = text.split(" ", 1)
    if len(parts) < 2 or not parts[1].strip():
        _reply(chat_id, "AbdEX: чтобы получать уведомления, откройте на сайте «Профиль → Уведомления» и нажмите "
                        "«Открыть в Telegram».")
        return False
    code = parts[1].strip().upper()[:20]
    link = db.execute(select(ChannelLink).where(ChannelLink.channel == "telegram", ChannelLink.link_code == code,
                                                ChannelLink.link_code != "")).scalar_one_or_none()
    if link is None:
        _reply(chat_id, "AbdEX: код привязки не найден или уже использован. Получите новый код на сайте.")
        return False
    link.address = chat_id
    link.link_code = ""  # one-time code
    audit(db, "notifications.telegram_linked", object_type="user", object_id=link.user_id, user_id=link.user_id)
    db.flush()
    _reply(chat_id, "AbdEX: Telegram привязан к вашему аккаунту.")
    return True


def _reply(chat_id: str, text: str) -> None:
    from app.modules.integrations.adapters import telegram

    try:
        telegram.send(chat_id, text)
    except Exception:  # noqa: BLE001 — a reply that did not go out never breaks the linking
        log.warning("telegram reply failed")


def poll(db: Session) -> int:
    """Worker job (polling mode): fetch the bot's new messages and handle them. Without a token, or with a
    webhook configured (TELEGRAM_WEBHOOK_SECRET), it does nothing."""
    if not enabled() or settings.telegram_webhook_secret:
        return 0
    from app.modules.platform.service import get_setting, set_setting

    offset = int(get_setting(db, OFFSET_SETTING, 0) or 0)
    try:
        out = _api("getUpdates", {"offset": offset, "timeout": 0, "limit": 50, "allowed_updates": ["message"]})
    except Exception as exc:  # noqa: BLE001 — Telegram unreachable: next tick
        log.warning("telegram getUpdates failed: %s", str(exc)[:200])
        return 0
    linked = 0
    for update in out.get("result") or []:
        offset = max(offset, int(update.get("update_id", 0)) + 1)
        linked += int(handle_update(db, update))
    set_setting(db, OFFSET_SETTING, offset, "Telegram: the next update to fetch (polling mode)")
    db.commit()
    return linked
