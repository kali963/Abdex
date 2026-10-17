"""API sandbox with test keys and public docs (FR-API-05); customs data for international trips (GOV-TR-06)."""
from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import SessionLocal, utcnow
from app.main import app
from app.modules.bids.models import Bid
from app.modules.deals.models import Deal
from app.modules.orders.models import Order
from app.modules.platform.models import SandboxObject
from app.modules.webhooks.models import WebhookDelivery, WebhookEndpoint


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _key(session, env: str, scopes) -> str:
    r = session.post("/company/api-keys", {"name": f"{env} key", "scopes": scopes, "days": "30", "environment": env},
                     follow_redirects=True)
    prefix = "abxtest" if env == "test" else "abx"
    return re.search(rf"({prefix}_[A-Za-z0-9\-]+_[A-Za-z0-9\-]+)", r.text).group(1)


def _counts(db):
    return (db.execute(select(func.count(Order.id))).scalar_one(), db.execute(select(func.count(Bid.id))).scalar_one(),
            db.execute(select(func.count(Deal.id))).scalar_one())


# ------------------------------------------------------------------ FR-API-05


def test_sandbox_client_flow(login, db):
    owner = login("+77010000001")
    key = _key(owner, "test", ["orders:read", "orders:write", "dictionaries:read"])
    live_key = _key(owner, "live", ["orders:read"])
    assert key.startswith("abxtest_") and "abxtest_" in owner.get("/company/api-keys").text
    # a sandbox webhook endpoint receives the test events; a live one never does
    owner.post("/company/webhooks", {"url": "https://example.com/sandbox-hook", "events": ["deal.created",
                                                                                            "deal.status_changed"],
                                     "sandbox": "on"})
    owner.post("/company/webhooks", {"url": "https://example.com/live-hook", "events": ["deal.created",
                                                                                         "deal.status_changed"]})
    db.expire_all()
    sandbox_ep = db.execute(select(WebhookEndpoint).where(WebhookEndpoint.url.endswith("sandbox-hook"))).scalar_one()
    live_ep = db.execute(select(WebhookEndpoint).where(WebhookEndpoint.url.endswith("live-hook"))).scalar_one()
    assert sandbox_ep.sandbox and not live_ep.sandbox

    before = _counts(db)
    api = TestClient(app)
    h = {"X-API-Key": key}
    body = {"cargo_name": "Тест API", "weight_kg": 5000, "load_from": (utcnow() + timedelta(days=3)).isoformat(),
            "desired_rate_minor": 30_000_000,
            "points": [{"kind": "load", "city": "Алматы"}, {"kind": "unload", "city": "Тараз"}], "publish": True}
    r1 = api.post("/api/v1/orders", json=body, headers={**h, "Idempotency-Key": "sbx-1"})
    r2 = api.post("/api/v1/orders", json=body, headers={**h, "Idempotency-Key": "sbx-1"})
    assert r1.status_code == 201 and r1.json()["id"] == r2.json()["id"] and r1.json()["number"].startswith("TEST-")
    oid = r1.json()["id"]
    assert r1.json()["status"] == "bidding"
    # the same validation as live
    bad = api.post("/api/v1/orders", json={**body, "points": [{"kind": "unload", "city": "А"}, {"kind": "load", "city": "Б"}]},
                   headers=h)
    assert bad.status_code == 422 and bad.json()["error"]["request_id"]
    assert api.post("/api/v1/orders", json={**body, "hack": 1}, headers=h).status_code == 422
    assert api.post("/api/v1/orders", json={**body, "load_from": "2020-01-01T00:00:00+05:00"}, headers=h).status_code == 422

    bids = api.get(f"/api/v1/orders/{oid}/bids", headers=h).json()["items"]
    assert len(bids) == 2 and all(b["status"] == "active" for b in bids)
    deal = api.post(f"/api/v1/orders/{oid}/bids/{bids[0]['id']}/accept", headers={**h, "Idempotency-Key": "acc-1"})
    again = api.post(f"/api/v1/orders/{oid}/bids/{bids[0]['id']}/accept", headers={**h, "Idempotency-Key": "acc-1"})
    assert deal.status_code == 201 and again.json()["id"] == deal.json()["id"]
    assert api.post(f"/api/v1/orders/{oid}/bids/{bids[1]['id']}/accept", headers=h).status_code == 409
    r = api.post(f"/api/v1/sandbox/orders/{oid}/advance", json={"to": "in_transit"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "in_transit"
    assert api.post(f"/api/v1/sandbox/orders/{oid}/advance", json={"to": "assigned"}, headers=h).status_code == 422
    assert api.get(f"/api/v1/orders/{oid}", headers=h).json()["status"] == "in_transit"
    assert len(api.get("/api/v1/orders", headers=h).json()["items"]) == 1

    # nothing real was created; events went to the sandbox endpoint only, marked as test
    db.expire_all()
    assert _counts(db) == before
    sandbox_events = db.execute(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == sandbox_ep.id)).scalars().all()
    assert [json.loads(d.payload)["data"]["to"] for d in sandbox_events] == ["assigned", "docs_signed", "loading", "in_transit"]
    assert all(json.loads(d.payload)["livemode"] is False for d in sandbox_events)
    assert not db.execute(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == live_ep.id)).first()

    # the live key does not see test data, and the sandbox controls do not exist for it
    assert all(not o["number"].startswith("TEST-") for o in api.get("/api/v1/orders", headers={"X-API-Key": live_key}).json()["items"])
    assert api.post("/api/v1/sandbox/reset", headers={"X-API-Key": live_key}).status_code == 404
    # a test key cannot be turned into a live one by changing its prefix
    assert api.get("/api/v1/orders", headers={"X-API-Key": "abx_" + key.split("_", 1)[1]}).status_code == 401
    assert api.post("/api/v1/sandbox/reset", headers=h).json()["deleted"] >= 4
    db.expire_all()
    assert not db.execute(select(SandboxObject.id)).first()


def test_sandbox_carrier_and_live_accept(login, db):
    carrier = login("+77020000001")
    key = _key(carrier, "test", ["market:read", "bids:write"])
    api = TestClient(app)
    h = {"X-API-Key": key}
    market = api.get("/api/v1/market", headers=h).json()["items"]
    assert len(market) == 3 and all(p["address"] is None for o in market for p in o["points"])
    r = api.post(f"/api/v1/orders/{market[0]['id']}/bids", json={"price_minor": 45_000_000}, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "active"
    assert api.post(f"/api/v1/orders/{market[0]['id']}/bids", json={"price_minor": 1}, headers=h).status_code == 409
    assert api.post("/api/v1/orders/00000000-0000-0000-0000-000000000000/bids", json={"price_minor": 1},
                    headers=h).status_code == 404

    # live API: the client lists bids on its real order and accepts one (idempotent)
    owner = login("+77010000001")
    live = _key(owner, "live", ["orders:read", "orders:write"])
    lh = {"X-API-Key": live}
    order = db.execute(select(Order).where(Order.status == "bidding")).scalars().first()
    assert order is not None
    items = api.get(f"/api/v1/orders/{order.id}/bids", headers=lh).json()["items"]
    active = [b for b in items if b["status"] == "active"]
    assert active
    r1 = api.post(f"/api/v1/orders/{order.id}/bids/{active[0]['id']}/accept", headers={**lh, "Idempotency-Key": "live-acc"})
    r2 = api.post(f"/api/v1/orders/{order.id}/bids/{active[0]['id']}/accept", headers={**lh, "Idempotency-Key": "live-acc"})
    assert r1.status_code == 201 and r1.json()["id"] == r2.json()["id"] and r1.json()["status"] == "assigned"


def test_developer_docs_public(client_app):
    c = TestClient(app)
    page = c.get("/developers")
    assert page.status_code == 200
    text = page.text
    for path in ("/api/v1/orders", "/api/v1/orders/{oid}/bids/{bid_id}/accept", "/api/v1/sandbox/orders/{oid}/advance",
                 "/api/v1/market"):
        assert path in text
    assert "OrderIn" in text and "abxtest_" in text and "Idempotency-Key" in text and "X-AbdEX-Signature" in text


# ------------------------------------------------------------------ GOV-TR-06


def test_customs_dossier(login, db):
    from app.modules.documents import customs

    order = db.execute(select(Order).where(Order.cargo_name.contains("импорт КНР"))).scalar_one()
    owner = login("+77010000001")
    # the demo import order may still be open: give it a deal through the normal flow if needed
    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    if deal is None:
        bid = db.execute(select(Bid).where(Bid.order_id == order.id, Bid.status == "active")).scalars().first()
        if bid is None:
            carrier = login("+77020000001")
            carrier.post(f"/market/{order.id}/bid", {"price": "300000"})
            db.expire_all()
            bid = db.execute(select(Bid).where(Bid.order_id == order.id)).scalars().first()
        owner.post(f"/orders/{order.id}/bids/{bid.id}/accept")
        db.expire_all()
        deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one()

    assert customs.countries_of(db, order) == ["CN"]
    page = owner.get(f"/deals/{deal.id}").text
    assert 'id="customs"' in page and "ТН ВЭД" in page
    req = customs.requirements(db, order)
    assert req["customs"] and "hs_code" in req["fields"] and "origin_certificate" in req["documents"]

    bad = owner.post(f"/deals/{deal.id}/customs", {"hs_code": "8471", "net_kg": "20000", "gross_kg": "19000"})
    assert bad.status_code in (303, 422)
    db.expire_all()
    assert customs.get(db, deal) is None or "8471" not in customs.get(db, deal).data

    owner.post(f"/deals/{deal.id}/customs", {
        "hs_code": "8471 30 000 0", "goods_description": "Ноутбуки", "gross_kg": "19000", "net_kg": "18000",
        "places": "40", "invoice_number": "INV-77", "invoice_date": "2026-10-01", "invoice_value": "125000",
        "invoice_currency": "usd", "origin_country": "CN", "consignee_name": "ТОО Казахстан Агро Трейд",
        "consignee_address": "г. Алматы, пр. Абая, 10", "consignee_country": "KZ"})
    carrier = login("+77020000001")
    carrier.post(f"/deals/{deal.id}/customs", {"transit_mode": "tir", "tir_carnet": "XC12345678",
                                              "border_crossing": "khorgos", "hs_code": "0000000000"})
    db.expire_all()
    dossier = customs.get(db, deal)
    data = json.loads(dossier.data)
    assert data["hs_code"] == "8471300000" and data["invoice_currency"] == "USD" and data["tir_carnet"] == "XC12345678"
    check = customs.checklist(db, deal, order, dossier)
    assert not check["missing_fields"]
    assert set(check["missing_documents"]) >= {"commercial_invoice", "packing_list", "origin_certificate", "tir_carnet"}
    # not complete yet: cannot be marked ready
    owner.post(f"/deals/{deal.id}/customs/ready")
    db.expire_all()
    assert customs.get(db, deal).status == "draft"

    from app.modules.documents.models import Document

    for t in check["missing_documents"]:
        db.add(Document(deal_id=deal.id, company_id=deal.client_company_id, doc_type=t, number=f"T-{t}", title=t,
                        status="checked", sha256="0" * 64))
    db.commit()
    r = owner.post(f"/deals/{deal.id}/customs/ready")
    assert r.status_code == 303
    db.expire_all()
    assert customs.get(db, deal).status == "ready"
    assert db.execute(select(Document).where(Document.deal_id == deal.id, Document.doc_type == "customs_info")).first()
    xml = owner.get(f"/deals/{deal.id}/customs.xml")
    assert xml.status_code == 200 and b"<hsCode>8471300000</hsCode>" in xml.content and b"<tirCarnet>XC12345678" in xml.content
    assert login("manager@abdex.kz").get(f"/admin/deals/{deal.id}/customs.xml").status_code == 200
    # inside the EAEU only shipping documents are asked
    order.countries = "Россия"
    assert customs.requirements(db, order)["customs"] is False
    db.rollback()
