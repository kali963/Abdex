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


# ------------------------------------------------------------------ FR-MOB-02 Web Push


def _decrypt(body: bytes, ua_private, ua_public: bytes, auth: bytes) -> bytes:
    """Receiver side of RFC 8291, to prove the server's encryption is correct."""
    import struct

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    salt, rs, idlen = body[:16], struct.unpack("!I", body[16:20])[0], body[20]
    as_public = body[21:21 + idlen]
    assert rs == 4096
    shared = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth, info=b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\x00").derive(ikm)
    plain = AESGCM(cek).decrypt(nonce, body[21 + idlen:], None)
    assert plain.endswith(b"\x02")
    assert serialization  # imported for symmetry with the server code
    return plain[:-1]


def _browser_keys():
    import os

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.modules.notifications.webpush import b64u

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    auth = os.urandom(16)
    return priv, pub, auth, b64u(pub), b64u(auth)


def test_webpush_encryption_and_vapid(client_app):
    import json as _json

    from app.modules.notifications import webpush

    priv, pub, auth, p256dh, auth_b64 = _browser_keys()
    body = webpush.encrypt(_json.dumps({"title": "AbdEX", "body": "Тест"}).encode(), p256dh, auth_b64)
    assert _json.loads(_decrypt(body, priv, pub, auth))["body"] == "Тест"
    h = webpush.vapid_headers("https://fcm.googleapis.com/fcm/send/abc")["Authorization"]
    assert h.startswith("vapid t=") and webpush.public_key() in h
    assert webpush.endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc")
    assert webpush.endpoint_allowed("https://db5p.notify.windows.com/w/?token=1")
    for bad in ("http://fcm.googleapis.com/x", "https://evil.example/fcm.googleapis.com", "https://169.254.169.254/",
                "https://fcm.googleapis.com.evil.example/x", "https://user@fcm.googleapis.com/x"):
        assert not webpush.endpoint_allowed(bad), bad


def test_push_subscription_and_delivery(login, db, monkeypatch):
    from app.modules.integrations.adapters import push
    from app.modules.notifications import webpush
    from app.modules.notifications.models import PushSubscription

    s = login("+77020000003")
    assert "data-push-key" in s.get("/account/notifications").text
    _, _, _, p256dh, auth_b64 = _browser_keys()
    ep = "https://fcm.googleapis.com/fcm/send/test-device-1"
    h = {"X-CSRF-Token": s.csrf, "Accept": "application/json"}
    assert s.c.post("/account/push/subscribe", json={"endpoint": "https://evil.example/x", "keys": {"p256dh": p256dh, "auth": auth_b64}},
                    headers=h).status_code in (400, 422)
    assert s.c.post("/account/push/subscribe", json={"endpoint": ep, "keys": {"p256dh": p256dh, "auth": auth_b64}},
                    headers=h).status_code == 200
    assert s.c.post("/account/push/subscribe", json={"endpoint": ep, "keys": {"p256dh": p256dh}}).status_code == 403  # no CSRF
    db.expire_all()
    sub = db.execute(select(PushSubscription).where(PushSubscription.endpoint == ep)).scalar_one()

    sent = []
    monkeypatch.setattr(webpush, "send", lambda endpoint, p, a, payload, timeout=10: sent.append((endpoint, payload)) or 201)
    push._deliver(str(sub.user_id), "Новый этап рейса\n/deals/123")
    assert sent == [(ep, {"title": "AbdEX", "body": "Новый этап рейса", "url": "/deals/123"})]
    # a subscription the push service no longer knows is removed
    monkeypatch.setattr(webpush, "send", lambda *a, **k: 410)
    sub_id, user_id = sub.id, sub.user_id
    push._deliver(str(user_id), "x")
    db.rollback()
    assert db.execute(select(PushSubscription.id).where(PushSubscription.id == sub_id)).first() is None
