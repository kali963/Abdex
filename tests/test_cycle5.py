"""Real-time chat over WebSocket with read receipts (FR-CHAT-06)."""
from __future__ import annotations

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.db import SessionLocal
from app.modules.deals.models import Deal


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _deal_of(db, phone_client="+77010000001"):
    from app.modules.accounts.models import Company

    client = db.execute(select(Company).where(Company.name.contains("Агро Трейд"))).scalar_one()
    return db.execute(select(Deal).where(Deal.client_company_id == client.id)).scalars().first()


def test_chat_websocket_delivery_and_read(login, db):
    deal = _deal_of(db)
    owner = login("+77010000001")
    carrier = login("+77020000001")
    origin = {"origin": "http://testserver"}
    with carrier.c.websocket_connect(f"/deals/{deal.id}/chat/ws", headers=origin) as ws:
        first = ws.receive_json()  # the existing thread
        assert "messages" in first
        owner.post(f"/deals/{deal.id}/chat", {"body": "Привет по сокету"}, headers={"Accept": "application/json"})
        got = ws.receive_json()
        assert any(m["text"] == "Привет по сокету" and not m["mine"] for m in got["messages"])
    # the carrier received it through the socket, so for the owner it is read (✓✓)
    data = owner.get(f"/deals/{deal.id}/chat.json").json()
    msg_id = next(m["id"] for m in data["messages"] if m["text"] == "Привет по сокету")
    assert msg_id in data["read"]


def test_chat_websocket_refuses_foreign_origin_and_strangers(login, db):
    deal = _deal_of(db)
    owner = login("+77010000001")
    with pytest.raises(WebSocketDisconnect):
        with owner.c.websocket_connect(f"/deals/{deal.id}/chat/ws", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_json()
    stranger = login("+77030000001")  # another carrier, not a side of this deal
    with pytest.raises(WebSocketDisconnect):
        with stranger.c.websocket_connect(f"/deals/{deal.id}/chat/ws", headers={"origin": "http://testserver"}) as ws:
            ws.receive_json()
    from fastapi.testclient import TestClient

    from app.main import app

    with pytest.raises(WebSocketDisconnect):  # no session at all
        with TestClient(app).websocket_connect(f"/deals/{deal.id}/chat/ws", headers={"origin": "http://testserver"}) as ws:
            ws.receive_json()
