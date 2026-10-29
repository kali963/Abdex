"""FR-NTF-02: linking Telegram through the AbdEX bot — the page names the bot, the worker polls Telegram."""
from __future__ import annotations

import re
import time

import pytest
from sqlalchemy import select

from app.config import settings
from tests.conftest import csrf_from


@pytest.fixture
def bot(monkeypatch):
    from app.modules.integrations import adapters
    from app.modules.notifications import telegram_bot

    old = settings.telegram_bot_token, settings.telegram_webhook_secret
    object.__setattr__(settings, "telegram_bot_token", "123:test")
    object.__setattr__(settings, "telegram_webhook_secret", "")
    monkeypatch.setenv("TELEGRAM_BOT_USERNAME", "abdex_test_bot")
    sent = []
    monkeypatch.setattr(adapters.telegram, "send", lambda chat, text: sent.append((chat, text)))
    updates = []

    def api(method, payload=None, timeout=10.0):
        assert method == "getUpdates"
        return {"ok": True, "result": [u for u in updates if u["update_id"] >= payload["offset"]]}

    monkeypatch.setattr(telegram_bot, "_api", api)
    yield updates, sent
    object.__setattr__(settings, "telegram_bot_token", old[0])
    object.__setattr__(settings, "telegram_webhook_secret", old[1])


def test_page_without_bot_says_not_connected(login):
    page = login("+77010000001").c.get("/account/notifications").text
    assert "ещё не подключён" in page and "Получить код привязки" not in page


def test_link_through_the_bot_by_polling(login, bot):
    from app.db import SessionLocal
    from app.modules.notifications.models import ChannelLink
    from app.modules.notifications.telegram_bot import poll

    updates, sent = bot
    s = login("+77010000002")
    page = s.c.get("/account/notifications").text
    assert "@abdex_test_bot" in page
    s.c.post("/account/notifications/telegram", data={"csrf_token": csrf_from(page)})
    page = s.c.get("/account/notifications").text
    code = re.search(r"https://t\.me/abdex_test_bot\?start=([A-Z0-9_-]+)", page).group(1)

    updates.append({"update_id": 501, "message": {"date": int(time.time()), "chat": {"id": 777001},
                                                  "text": f"/start {code}"}})
    db = SessionLocal()
    try:
        assert poll(db) == 1
        link = db.execute(select(ChannelLink).where(ChannelLink.channel == "telegram",
                                                    ChannelLink.address == "777001")).scalar_one()
        assert link.link_code == ""
        assert poll(db) == 0  # the offset moved on: the same message is not handled again
    finally:
        db.close()
    assert sent and "привязан" in sent[-1][1]
    assert "Telegram привязан" in s.c.get("/account/notifications").text


def test_unknown_code_gets_an_answer(client_app, bot):
    from app.db import SessionLocal
    from app.modules.notifications.telegram_bot import poll

    updates, sent = bot
    updates.append({"update_id": 601, "message": {"date": int(time.time()), "chat": {"id": 777002},
                                                  "text": "/start NOPE1234"}})
    db = SessionLocal()
    try:
        assert poll(db) == 0
    finally:
        db.close()
    assert "не найден" in sent[-1][1]
